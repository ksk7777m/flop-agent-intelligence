#!/usr/bin/env python3
"""Run one fixed-endpoint engagement observation. This is not a scheduler."""

from __future__ import annotations

import argparse, hashlib, json, os, socket, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from flop_agent.engagement import SOURCE_URL, build_sample, diff, series
from flop_agent.engagement_history import append, load, range_rows
from flop_agent.engagement_history import HistoryLockError

VERSION = "0.1.0"
BACKOFF_SECONDS = (900, 1800, 3600, 7200, 14400, 21600)
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
SOCKET_TIMEOUT_SECONDS = 20.0
TOTAL_COLLECTION_DEADLINE_SECONDS = 30.0
MIN_TOTAL_COLLECTION_DEADLINE_SECONDS = 1.0
MAX_TOTAL_COLLECTION_DEADLINE_SECONDS = 30.0
TERMINATION_GRACE_SECONDS = 0.1


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None


class CollectionError(RuntimeError):
    def __init__(self, status: int | None, retry_after: int | None = None,
                 code: str = "COLLECTION_FAILED"):
        super().__init__(code if code == "RESPONSE_TOO_LARGE"
                         else f"engagement collection failed: HTTP {status or 'NETWORK'}")
        self.status, self.retry_after, self.code = status, retry_after, code


class TotalDeadlineExceeded(RuntimeError):
    def __init__(self, metadata: dict):
        super().__init__("TOTAL_DEADLINE_EXCEEDED")
        self.metadata = metadata


def validate_endpoint(url: str) -> str:
    if url != SOURCE_URL: raise ValueError("engagement source is an exact fixed allowlist entry")
    return url


def interval_minutes(value: str | None = None) -> int:
    try: minutes = int(value if value is not None else os.getenv("ENGAGEMENT_INTERVAL_MIN", "15"))
    except ValueError: raise ValueError("ENGAGEMENT_INTERVAL_MIN must be an integer") from None
    if minutes < 5: raise ValueError("ENGAGEMENT_INTERVAL_MIN must be at least 5")
    return minutes


def total_deadline_seconds(value: float = TOTAL_COLLECTION_DEADLINE_SECONDS) -> float:
    try: seconds = float(value)
    except (TypeError, ValueError): raise ValueError("total deadline must be numeric") from None
    if not MIN_TOTAL_COLLECTION_DEADLINE_SECONDS <= seconds <= MAX_TOTAL_COLLECTION_DEADLINE_SECONDS:
        raise ValueError(f"total deadline must be between {MIN_TOTAL_COLLECTION_DEADLINE_SECONDS:g} and {MAX_TOTAL_COLLECTION_DEADLINE_SECONDS:g} seconds")
    return seconds


def retry_after(value: str | None) -> int | None:
    value = value.strip() if isinstance(value, str) else ""
    return int(value) if value.isdigit() and 1 <= int(value) <= 21600 else None


def backoff(status: int, failure_count: int = 1, retry_header: str | None = None) -> int | None:
    if status == 429: return retry_after(retry_header)
    if 500 <= status <= 599: return BACKOFF_SECONDS[min(max(failure_count, 1) - 1, 5)]
    return None


def fetch(*, timeout: float = 20.0, opener=None) -> tuple[bytes, int, object]:
    request = Request(validate_endpoint(SOURCE_URL), method="GET", headers={
        "Accept": "application/json",
        "User-Agent": f"flop-agent-intelligence/{VERSION} (+https://github.com/ksk7777m/flop-agent-intelligence)",
    })
    open_fn = opener or build_opener(NoRedirect()).open
    try:
        with open_fn(request, timeout=timeout) as response:
            if response.geturl() != SOURCE_URL: raise CollectionError(response.status)
            declared = response.headers.get("Content-Length")
            if isinstance(declared, str) and declared.strip().isdigit() and int(declared) > MAX_RESPONSE_BYTES:
                raise CollectionError(response.status, code="RESPONSE_TOO_LARGE")
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise CollectionError(response.status, code="RESPONSE_TOO_LARGE")
            return body, response.status, response.headers
    except HTTPError as error:
        # Deliberately discard every error body and perform no retry.
        raise CollectionError(error.code, backoff(error.code, retry_header=error.headers.get("Retry-After"))) from None


def collect(root: Path, *, timeout: float = 20.0, opener=None,
            fetched_at: str | None = None) -> dict:
    interval_minutes()
    body, status, _headers = fetch(timeout=timeout, opener=opener)
    try: raw = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError): raise ValueError("official endpoint returned invalid JSON") from None
    if not isinstance(raw, dict): raise ValueError("official endpoint returned a non-object")
    fetched_at = fetched_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    try:
        revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                                  capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError): revision = None
    sample = build_sample(raw, fetched_at=fetched_at, source_sha256=hashlib.sha256(body).hexdigest(),
                          collector_version=VERSION, git_revision=revision, content_length=len(body))
    history_path = root / "runtime/engagement/history.jsonl"
    before = load(history_path)
    append(history_path, sample)
    rows = load(history_path)
    output = root / "runtime/engagement/public-preview"; output.mkdir(parents=True, exist_ok=True)
    (output / "engagement-sample.json").write_text(json.dumps(sample, indent=2) + "\n", encoding="utf-8")
    (output / "engagement-diff.json").write_text(json.dumps(diff(before[-1] if before else None, sample), indent=2) + "\n", encoding="utf-8")
    stamp = datetime.fromisoformat(fetched_at.replace("Z", "+00:00"))
    (output / "engagement-series.json").write_text(json.dumps(series(range_rows(rows, now=stamp)), indent=2) + "\n", encoding="utf-8")
    return sample


def _runtime_files(root: Path) -> tuple[Path, ...]:
    base = root / "runtime/engagement"
    preview = base / "public-preview"
    return (base / "history.jsonl", base / "history.jsonl.lock",
            base / "history.jsonl.recovery-tail", preview / "engagement-sample.json",
            preview / "engagement-diff.json", preview / "engagement-series.json")


def _snapshot_runtime(root: Path) -> dict[Path, bytes | None]:
    return {path: path.read_bytes() if path.exists() else None for path in _runtime_files(root)}


def _restore_runtime(root: Path, snapshot: dict[Path, bytes | None]) -> None:
    for path, content in snapshot.items():
        if content is None:
            path.unlink(missing_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_name(f".{path.name}.restore-{os.getpid()}")
            temporary.write_bytes(content)
            os.replace(temporary, path)
    base = root / "runtime/engagement"
    if base.exists():
        for temporary in base.rglob("*.deadline-*"): temporary.unlink(missing_ok=True)


def _git_revision(root: Path) -> str | None:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                              capture_output=True, text=True, timeout=2).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def run_with_total_deadline(root: Path, *, timeout: float = SOCKET_TIMEOUT_SECONDS,
                            total_deadline: float = TOTAL_COLLECTION_DEADLINE_SECONDS,
                            command: list[str] | None = None,
                            popen=subprocess.Popen) -> dict:
    """Run one worker under a process deadline that also bounds blocking DNS."""
    deadline = total_deadline_seconds(total_deadline)
    started = time.monotonic()
    snapshot = _snapshot_runtime(root)
    revision = _git_revision(root)
    worker = command or [sys.executable, str(Path(__file__).resolve()), "--worker",
                         "--root", str(root), "--timeout", str(timeout)]
    process = popen(worker, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    text=True, start_new_session=True)
    try:
        worker_budget = deadline - (time.monotonic() - started) - (2 * TERMINATION_GRACE_SECONDS)
        stdout, _ = process.communicate(timeout=max(0.001, worker_budget))
    except subprocess.TimeoutExpired:
        process.terminate()
        try: process.communicate(timeout=TERMINATION_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill(); process.communicate(timeout=TERMINATION_GRACE_SECONDS)
        _restore_runtime(root, snapshot)
        elapsed = min(time.monotonic() - started, deadline + TERMINATION_GRACE_SECONDS * 2)
        raise TotalDeadlineExceeded({
            "error_class": "TOTAL_DEADLINE_EXCEEDED",
            "elapsed_seconds": round(elapsed, 3),
            "configured_total_deadline": deadline,
            "collector_version": VERSION,
            "git_revision": revision,
        }) from None
    try: envelope = json.loads(stdout)
    except json.JSONDecodeError: envelope = {"ok": False, "error_class": "VALIDATION_FAILED"}
    if process.returncode != 0 or not envelope.get("ok"):
        raise CollectionError(None, code=str(envelope.get("error_class", "VALIDATION_FAILED")))
    return envelope["sample"]


def _worker(root: Path, timeout: float) -> int:
    try:
        sample = collect(root, timeout=timeout)
        envelope = {"ok": True, "sample": sample}
    except (TimeoutError, socket.timeout):
        envelope = {"ok": False, "error_class": "HTTP_TIMEOUT"}
    except URLError as error:
        envelope = {"ok": False, "error_class":
                    "HTTP_TIMEOUT" if isinstance(error.reason, (TimeoutError, socket.timeout))
                    else "VALIDATION_FAILED"}
    except HistoryLockError:
        envelope = {"ok": False, "error_class": "HISTORY_LOCK_TIMEOUT"}
    except (ValueError, json.JSONDecodeError):
        envelope = {"ok": False, "error_class": "VALIDATION_FAILED"}
    except CollectionError as error:
        envelope = {"ok": False, "error_class": error.code}
    except Exception:
        envelope = {"ok": False, "error_class": "VALIDATION_FAILED"}
    print(json.dumps(envelope, separators=(",", ":")))
    return 0 if envelope["ok"] else 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--timeout", type=float, default=SOCKET_TIMEOUT_SECONDS)
    parser.add_argument("--total-deadline", type=float, default=TOTAL_COLLECTION_DEADLINE_SECONDS)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker: raise SystemExit(_worker(args.root, args.timeout))
    try: result = run_with_total_deadline(args.root, timeout=args.timeout, total_deadline=args.total_deadline)
    except TotalDeadlineExceeded as error:
        print(json.dumps(error.metadata, indent=2)); raise SystemExit(2) from None
    except CollectionError as error:
        print(json.dumps({"error_class": error.code, "collector_version": VERSION,
                          "git_revision": _git_revision(args.root)}, indent=2)); raise SystemExit(1) from None
    print(json.dumps(result, indent=2))


if __name__ == "__main__": main()
