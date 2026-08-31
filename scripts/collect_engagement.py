#!/usr/bin/env python3
"""Run one fixed-endpoint engagement observation. This is not a scheduler."""

from __future__ import annotations

import argparse, hashlib, json, multiprocessing, os, signal, socket, subprocess, threading, time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from flop_agent.engagement import SOURCE_URL, build_sample, diff, series
from flop_agent.engagement_history import append, load, range_rows, validate
from flop_agent.engagement_history import HistoryDeadlineExceeded, HistoryLockError

VERSION = "0.1.0"
BACKOFF_SECONDS = (900, 1800, 3600, 7200, 14400, 21600)
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
SOCKET_TIMEOUT_SECONDS = 20.0
TOTAL_COLLECTION_DEADLINE_SECONDS = 30.0
MIN_TOTAL_COLLECTION_DEADLINE_SECONDS = 1.0
MAX_TOTAL_COLLECTION_DEADLINE_SECONDS = 30.0
TERMINATION_GRACE_SECONDS = 0.1
MAX_IPC_BYTES = 256 * 1024
MIN_COMMIT_BUDGET_SECONDS = 0.5
WORKER_ERRORS = {"HTTP_TIMEOUT", "VALIDATION_FAILED", "RESPONSE_TOO_LARGE"}


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


def prepare_sample(root: Path, *, timeout: float = SOCKET_TIMEOUT_SECONDS, opener=None,
                   fetched_at: str | None = None, git_revision: str | None = None) -> dict:
    interval_minutes()
    body, status, _headers = fetch(timeout=timeout, opener=opener)
    try: raw = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError): raise ValueError("official endpoint returned invalid JSON") from None
    if not isinstance(raw, dict): raise ValueError("official endpoint returned a non-object")
    fetched_at = fetched_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    sample = build_sample(raw, fetched_at=fetched_at, source_sha256=hashlib.sha256(body).hexdigest(),
                          collector_version=VERSION, git_revision=git_revision, content_length=len(body))
    return validate(sample)


def commit_sample(root: Path, sample: dict, *, deadline_at: float | None = None) -> bool:
    sample = validate(sample)
    history_path = root / "runtime/engagement/history.jsonl"
    before = load(history_path)
    committed = append(history_path, sample, deadline_at=deadline_at)
    rows = load(history_path)
    output = root / "runtime/engagement/public-preview"; output.mkdir(parents=True, exist_ok=True)
    (output / "engagement-sample.json").write_text(json.dumps(sample, indent=2) + "\n", encoding="utf-8")
    (output / "engagement-diff.json").write_text(json.dumps(diff(before[-1] if before else None, sample), indent=2) + "\n", encoding="utf-8")
    stamp = datetime.fromisoformat(sample["fetched_at"].replace("Z", "+00:00"))
    (output / "engagement-series.json").write_text(json.dumps(series(range_rows(rows, now=stamp)), indent=2) + "\n", encoding="utf-8")
    return committed


def _git_revision(root: Path) -> str | None:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                              capture_output=True, text=True, timeout=2).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def _error_envelope(error_class: str) -> dict:
    return {"ok": False, "error_class": error_class}


def _worker_entry(connection, root: str, timeout: float, revision: str | None) -> None:
    try:
        try:
            envelope = {"ok": True, "sample": prepare_sample(Path(root), timeout=timeout,
                                                               git_revision=revision)}
        except (TimeoutError, socket.timeout): envelope = _error_envelope("HTTP_TIMEOUT")
        except URLError as error:
            envelope = _error_envelope("HTTP_TIMEOUT" if isinstance(error.reason, (TimeoutError, socket.timeout))
                                       else "VALIDATION_FAILED")
        except CollectionError as error:
            envelope = _error_envelope(error.code if error.code in WORKER_ERRORS else "VALIDATION_FAILED")
        except Exception: envelope = _error_envelope("VALIDATION_FAILED")
        encoded = json.dumps(envelope, separators=(",", ":"), allow_nan=False).encode("utf-8")
        connection.send_bytes(encoded)
    except BaseException:
        pass
    finally:
        connection.close()


def _process_bootstrap(target, connection, root: str, timeout: float, revision: str | None) -> None:
    try: os.setsid()
    except OSError: pass
    target(connection, root, timeout, revision)


def _stop_process_group(process) -> None:
    if process.pid is None: return
    def group_exists() -> bool:
        try: os.killpg(process.pid, 0); return True
        except ProcessLookupError: return False
        except PermissionError: return True
    try: os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError: pass
    except OSError:
        try: process.terminate()
        except (ProcessLookupError, OSError, AttributeError): pass
    try: process.join(TERMINATION_GRACE_SECONDS)
    except (OSError, AssertionError): pass
    if process.is_alive() or group_exists():
        try: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        except OSError:
            try: process.kill()
            except (ProcessLookupError, OSError, AttributeError): pass
        try: process.join(TERMINATION_GRACE_SECONDS)
        except (OSError, AssertionError): pass
    if process.is_alive():
        try: process.kill(); process.join(TERMINATION_GRACE_SECONDS)
        except (ProcessLookupError, OSError, AssertionError, AttributeError): pass


def _decode_worker_result(payload: bytes, exit_code: int | None) -> dict:
    if exit_code not in (0, None): raise CollectionError(None, code="WORKER_CRASHED")
    if not payload or len(payload) > MAX_IPC_BYTES: raise CollectionError(None, code="WORKER_PROTOCOL_ERROR")
    try: envelope = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError): raise CollectionError(None, code="WORKER_PROTOCOL_ERROR") from None
    if not isinstance(envelope, dict) or type(envelope.get("ok")) is not bool:
        raise CollectionError(None, code="WORKER_PROTOCOL_ERROR")
    if envelope["ok"]:
        if set(envelope) != {"ok", "sample"} or not isinstance(envelope.get("sample"), dict):
            raise CollectionError(None, code="WORKER_PROTOCOL_ERROR")
        try: envelope["sample"] = validate(envelope["sample"])
        except ValueError: raise CollectionError(None, code="WORKER_PROTOCOL_ERROR") from None
    else:
        if set(envelope) != {"ok", "error_class"} or envelope.get("error_class") not in WORKER_ERRORS:
            raise CollectionError(None, code="WORKER_PROTOCOL_ERROR")
    return envelope


@contextmanager
def _commit_alarm(seconds: float):
    if not hasattr(signal, "setitimer") or threading.current_thread() is not threading.main_thread():
        yield; return
    previous = signal.getsignal(signal.SIGALRM)
    def expired(_signum, _frame): raise HistoryDeadlineExceeded("TOTAL_DEADLINE_EXCEEDED")
    signal.signal(signal.SIGALRM, expired); signal.setitimer(signal.ITIMER_REAL, max(0.001, seconds))
    try: yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0); signal.signal(signal.SIGALRM, previous)


def run_with_total_deadline(root: Path, *, timeout: float = SOCKET_TIMEOUT_SECONDS,
                            total_deadline: float = TOTAL_COLLECTION_DEADLINE_SECONDS,
                            worker_target=_worker_entry,
                            context=None,
                            commit=commit_sample) -> dict:
    """Run one worker under a process deadline that also bounds blocking DNS."""
    deadline = total_deadline_seconds(total_deadline)
    started = time.monotonic()
    revision = _git_revision(root)
    ctx = context or multiprocessing.get_context("fork")
    parent_connection, child_connection = ctx.Pipe(duplex=False)
    process = ctx.Process(target=_process_bootstrap,
                          args=(worker_target, child_connection, str(root), timeout, revision))
    process.start(); child_connection.close()
    try:
        worker_budget = deadline - (time.monotonic() - started) - (2 * TERMINATION_GRACE_SECONDS)
        if worker_budget <= 0 or not parent_connection.poll(max(0.001, worker_budget)):
            raise TotalDeadlineExceeded({})
        try: payload = parent_connection.recv_bytes(MAX_IPC_BYTES)
        except (EOFError, OSError):
            process.join(TERMINATION_GRACE_SECONDS)
            code = "WORKER_CRASHED" if process.exitcode not in (0, None) else "WORKER_PROTOCOL_ERROR"
            raise CollectionError(None, code=code) from None
        process.join(TERMINATION_GRACE_SECONDS)
        if process.is_alive(): raise TotalDeadlineExceeded({})
        envelope = _decode_worker_result(payload, process.exitcode)
        if not envelope["ok"]: raise CollectionError(None, code=envelope["error_class"])
        remaining = deadline - (time.monotonic() - started)
        if remaining < MIN_COMMIT_BUDGET_SECONDS: raise TotalDeadlineExceeded({})
        try:
            with _commit_alarm(remaining): commit(root, envelope["sample"], deadline_at=started + deadline)
        except HistoryLockError: raise CollectionError(None, code="HISTORY_LOCK_TIMEOUT") from None
        except HistoryDeadlineExceeded: raise TotalDeadlineExceeded({}) from None
        if time.monotonic() - started > deadline: raise TotalDeadlineExceeded({})
        return envelope["sample"]
    except TotalDeadlineExceeded:
        _stop_process_group(process)
        raise TotalDeadlineExceeded({
            "error_class": "TOTAL_DEADLINE_EXCEEDED", "elapsed_seconds": round(time.monotonic() - started, 3),
            "configured_total_deadline": deadline, "collector_version": VERSION, "git_revision": revision,
        }) from None
    finally:
        parent_connection.close()
        _stop_process_group(process)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--timeout", type=float, default=SOCKET_TIMEOUT_SECONDS)
    parser.add_argument("--total-deadline", type=float, default=TOTAL_COLLECTION_DEADLINE_SECONDS)
    args = parser.parse_args()
    try: result = run_with_total_deadline(args.root, timeout=args.timeout, total_deadline=args.total_deadline)
    except TotalDeadlineExceeded as error:
        print(json.dumps(error.metadata, indent=2)); raise SystemExit(2) from None
    except CollectionError as error:
        print(json.dumps({"error_class": error.code, "collector_version": VERSION,
                          "git_revision": _git_revision(args.root)}, indent=2)); raise SystemExit(1) from None
    print(json.dumps(result, indent=2))


if __name__ == "__main__": main()
