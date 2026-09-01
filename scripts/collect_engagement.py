#!/usr/bin/env python3
"""Run one fixed-endpoint engagement observation. This is not a scheduler."""

from __future__ import annotations

import argparse, hashlib, json, multiprocessing, os, signal, socket, subprocess, threading, time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
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
STARTUP_IPC_BYTES = 1024
COMMIT_STATES = {"PRE_COMMIT", "COMMITTED", "DURABLE"}
PREVIEW_STATES = {"NOT_ATTEMPTED", "UPDATED", "FAILED"}
DURABILITY_WARNINGS = {None, "POST_COMMIT_DURABILITY_WARNING"}
PREVIEW_WARNINGS = {None, "POST_COMMIT_PREVIEW_WARNING"}
CLEANUP_ERRORS = {None, "WORKER_CLEANUP_FAILED", "WORKER_CLEANUP_UNVERIFIED"}
RESULT_ERRORS = {None, "TOTAL_DEADLINE_EXCEEDED", "POST_COMMIT_WARNING"}


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


def _atomic_preview(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.candidate-{os.getpid()}-{threading.get_ident()}")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0: raise OSError("short preview write")
            written += count
        os.fsync(descriptor)
        os.close(descriptor); descriptor = -1
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if descriptor >= 0: os.close(descriptor)
        temporary.unlink(missing_ok=True)


def commit_sample(root: Path, sample: dict, *, deadline_at: float | None = None,
                  transaction: dict[str, str] | None = None) -> bool:
    sample = validate(sample)
    transaction = transaction if transaction is not None else {}
    transaction["preview_state"] = "NOT_ATTEMPTED"
    transaction.setdefault("durability_warning", None)
    transaction.setdefault("preview_warning", None)
    history_path = root / "runtime/engagement/history.jsonl"
    before = load(history_path)
    committed = append(history_path, sample, deadline_at=deadline_at, transaction=transaction)
    if transaction.get("durability_warning") == "POST_COMMIT_DURABILITY_WARNING":
        return committed
    if deadline_at is not None and time.monotonic() >= deadline_at:
        raise HistoryDeadlineExceeded("TOTAL_DEADLINE_EXCEEDED")
    try:
        rows = load(history_path)
    except HistoryDeadlineExceeded:
        raise
    except Exception:
        raise
    transaction["_preview_started"] = True
    try:
        output = root / "runtime/engagement/public-preview"; output.mkdir(parents=True, exist_ok=True)
        _atomic_preview(output / "engagement-sample.json", (json.dumps(sample, indent=2) + "\n").encode())
        _atomic_preview(output / "engagement-diff.json", (json.dumps(diff(before[-1] if before else None, sample), indent=2) + "\n").encode())
        stamp = datetime.fromisoformat(sample["fetched_at"].replace("Z", "+00:00"))
        _atomic_preview(output / "engagement-series.json", (json.dumps(series(range_rows(rows, now=stamp)), indent=2) + "\n").encode())
    except HistoryDeadlineExceeded:
        transaction["preview_state"] = "FAILED"
        transaction["preview_warning"] = "POST_COMMIT_PREVIEW_WARNING"
        raise
    except Exception:
        transaction["preview_state"] = "FAILED"
        transaction["preview_warning"] = "POST_COMMIT_PREVIEW_WARNING"
    else:
        transaction["preview_state"] = "UPDATED"
    return committed


def _structured_result(sample: dict, transaction: dict[str, str], *,
                       deadline_cleanup_overrun: bool = False,
                       cleanup_state: str = "COMPLETED", cleanup_error: str | None = None,
                       success: bool | None = None) -> dict:
    state = transaction.get("state", "PRE_COMMIT")
    preview = transaction.get("preview_state", "NOT_ATTEMPTED")
    error = transaction.get("error_class")
    durability_warning = transaction.get("durability_warning")
    preview_warning = transaction.get("preview_warning")
    expected_success = state in {"COMMITTED", "DURABLE"}
    success = expected_success if success is None else success
    if (state not in COMMIT_STATES or preview not in PREVIEW_STATES
            or cleanup_state not in {"COMPLETED", "FAILED"}
            or error not in RESULT_ERRORS
            or durability_warning not in DURABILITY_WARNINGS
            or preview_warning not in PREVIEW_WARNINGS
            or cleanup_error not in CLEANUP_ERRORS
            or success is not expected_success
            or (state == "PRE_COMMIT" and preview != "NOT_ATTEMPTED")
            or (preview != "NOT_ATTEMPTED" and state != "DURABLE")
            or (error == "POST_COMMIT_WARNING" and not expected_success)
            or (durability_warning is not None and state != "COMMITTED")
            or ((preview == "FAILED") != (preview_warning == "POST_COMMIT_PREVIEW_WARNING"))
            or (preview != "FAILED" and preview_warning is not None)
            or ((cleanup_state == "FAILED") != (cleanup_error in CLEANUP_ERRORS - {None}))
            or (cleanup_state == "COMPLETED" and cleanup_error is not None)):
        raise ValueError("invalid collection result state")
    return {"ok": success, "success": success, "sample": sample,
            "commit_state": state, "preview_state": preview,
            "cleanup_state": cleanup_state, "deadline_cleanup_overrun": deadline_cleanup_overrun,
            "error_class": error, "durability_warning": durability_warning,
            "preview_warning": preview_warning, "cleanup_error": cleanup_error}


def _git_revision(root: Path, deadline_at: float) -> str | None:
    remaining = deadline_at - time.monotonic()
    if remaining <= 0: raise TotalDeadlineExceeded({})
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                              capture_output=True, text=True, timeout=min(2.0, remaining)).stdout.strip()
    except subprocess.TimeoutExpired: raise TotalDeadlineExceeded({}) from None
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


def _process_bootstrap(target, connection, root: str, timeout: float, revision: str | None,
                       startup_timeout: float, session_setup) -> None:
    try:
        session_setup()
        pid, pgid, sid = os.getpid(), os.getpgrp(), os.getsid(0)
        if pid != pgid or pid != sid: raise OSError("worker session identity mismatch")
        connection.send_bytes(json.dumps({"type":"READY","pid":pid,"pgid":pgid,"sid":sid},
                                         separators=(",", ":")).encode())
    except BaseException:
        try: connection.send_bytes(b'{"type":"STARTUP_FAILED"}')
        except BaseException: pass
        connection.close()
        return
    try:
        if not connection.poll(startup_timeout) or connection.recv_bytes(16) != b"READY_ACK":
            connection.close(); return
    except BaseException:
        connection.close(); return
    target(connection, root, timeout, revision)


class OwnershipState(Enum):
    STARTING = "STARTING"
    OWNED = "OWNED"
    TERMINATING = "TERMINATING"
    REAPED = "REAPED"
    RELEASED = "OWNERSHIP_RELEASED"


@dataclass
class WorkerOwnership:
    state: OwnershipState = OwnershipState.STARTING
    pid: int | None = None
    pgid: int | None = None
    sid: int | None = None

    def release(self) -> None:
        self.state = OwnershipState.RELEASED
        self.pid = self.pgid = self.sid = None


def _validate_ready(payload: bytes, process, ownership: WorkerOwnership,
                    getpgid=os.getpgid, getsid=os.getsid) -> None:
    try: ready = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CollectionError(None, code="WORKER_STARTUP_FAILED") from None
    expected = process.pid
    if (not isinstance(ready, dict) or set(ready) != {"type","pid","pgid","sid"}
            or ready.get("type") != "READY" or type(ready.get("pid")) is not int
            or ready["pid"] != expected or ready.get("pgid") != expected or ready.get("sid") != expected):
        raise CollectionError(None, code="WORKER_STARTUP_FAILED")
    try:
        if getpgid(expected) != expected or getsid(expected) != expected:
            raise CollectionError(None, code="WORKER_STARTUP_FAILED")
    except ProcessLookupError: raise CollectionError(None, code="WORKER_STARTUP_FAILED") from None
    ownership.state, ownership.pid, ownership.pgid, ownership.sid = OwnershipState.OWNED, expected, expected, expected


def _owned_identity_matches(ownership: WorkerOwnership, getpgid=os.getpgid,
                            getsid=os.getsid) -> bool:
    if ownership.state not in {OwnershipState.OWNED, OwnershipState.TERMINATING} or ownership.pid is None:
        return False
    try: return getpgid(ownership.pid) == ownership.pgid and getsid(ownership.pid) == ownership.sid
    except (ProcessLookupError, PermissionError): return False


def _cleanup_unowned(process) -> None:
    """Bound direct-child cleanup before session ownership is established."""
    if process.pid is None: return
    try: process.terminate()
    except (ProcessLookupError, OSError, AttributeError): pass
    process.join(TERMINATION_GRACE_SECONDS)
    if process.is_alive():
        try: process.kill()
        except (ProcessLookupError, OSError, AttributeError): pass
        process.join(TERMINATION_GRACE_SECONDS)
    if process.is_alive(): raise CollectionError(None, code="WORKER_CLEANUP_FAILED")


def _cleanup_owned(process, ownership: WorkerOwnership, killpg=os.killpg,
                   getpgid=os.getpgid, getsid=os.getsid) -> None:
    """Signal only while the unreaped direct child proves group ownership."""
    if ownership.state == OwnershipState.RELEASED: return
    if not _owned_identity_matches(ownership, getpgid, getsid):
        raise CollectionError(None, code="WORKER_CLEANUP_UNVERIFIED")
    ownership.state = OwnershipState.TERMINATING
    try: killpg(ownership.pgid, signal.SIGTERM)
    except ProcessLookupError: pass
    except OSError: raise CollectionError(None, code="WORKER_CLEANUP_FAILED") from None
    time.sleep(TERMINATION_GRACE_SECONDS)
    # The direct child has deliberately not been joined, so its verified PID
    # cannot be reused during this grace period.  The cached PGID remains owned
    # until the escalation signal is sent and only then is the child reaped.
    try: killpg(ownership.pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError): pass  # macOS: group contains only the terminated zombie leader.
    except OSError: raise CollectionError(None, code="WORKER_CLEANUP_FAILED") from None
    process.join(TERMINATION_GRACE_SECONDS)
    if process.is_alive(): raise CollectionError(None, code="WORKER_CLEANUP_FAILED")
    ownership.state = OwnershipState.REAPED
    ownership.release()


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
                            commit=commit_sample, post_commit_cleanup=None,
                            session_setup=os.setsid) -> dict:
    """Run one worker under a process deadline that also bounds blocking DNS."""
    deadline = total_deadline_seconds(total_deadline)
    started = time.monotonic()
    deadline_at = started + deadline
    try: revision = _git_revision(root, deadline_at)
    except TotalDeadlineExceeded:
        raise TotalDeadlineExceeded({
            "error_class":"TOTAL_DEADLINE_EXCEEDED", "elapsed_seconds":round(time.monotonic()-started,3),
            "configured_total_deadline":deadline, "collector_version":VERSION, "git_revision":None,
        }) from None
    if time.monotonic() >= deadline_at:
        raise TotalDeadlineExceeded({"error_class":"TOTAL_DEADLINE_EXCEEDED",
                                     "elapsed_seconds":round(time.monotonic()-started,3),
                                     "configured_total_deadline":deadline,
                                     "collector_version":VERSION,"git_revision":revision})
    ctx = context or multiprocessing.get_context("fork")
    parent_connection, child_connection = ctx.Pipe(duplex=True)
    process = ctx.Process(target=_process_bootstrap,
                          args=(worker_target, child_connection, str(root), timeout, revision,
                                max(0.001, deadline_at - time.monotonic()), session_setup))
    ownership = WorkerOwnership()
    process.start(); child_connection.close()
    try:
        startup_budget = deadline_at - time.monotonic()
        if startup_budget <= 0 or not parent_connection.poll(startup_budget):
            raise TotalDeadlineExceeded({})
        try: startup_payload = parent_connection.recv_bytes(STARTUP_IPC_BYTES)
        except (EOFError, OSError): raise CollectionError(None, code="WORKER_STARTUP_FAILED") from None
        if startup_payload == b'{"type":"STARTUP_FAILED"}':
            raise CollectionError(None, code="WORKER_STARTUP_FAILED")
        _validate_ready(startup_payload, process, ownership)
        parent_connection.send_bytes(b"READY_ACK")
        worker_budget = deadline_at - time.monotonic() - (2 * TERMINATION_GRACE_SECONDS)
        if worker_budget <= 0 or not parent_connection.poll(worker_budget): raise TotalDeadlineExceeded({})
        try: payload = parent_connection.recv_bytes(MAX_IPC_BYTES)
        except (EOFError, OSError):
            raise CollectionError(None, code="WORKER_CRASHED") from None
        exit_budget = max(0.0, deadline_at - time.monotonic())
        process.join(min(TERMINATION_GRACE_SECONDS, exit_budget))
        if process.is_alive(): _cleanup_owned(process, ownership)
        else: ownership.state = OwnershipState.REAPED; ownership.release()
        envelope = _decode_worker_result(payload, process.exitcode)
        if not envelope["ok"]: raise CollectionError(None, code=envelope["error_class"])
        remaining = deadline_at - time.monotonic()
        if remaining < MIN_COMMIT_BUDGET_SECONDS: raise TotalDeadlineExceeded({})
        transaction = {"state":"PRE_COMMIT", "preview_state":"NOT_ATTEMPTED",
                       "durability_warning":None, "preview_warning":None}
        try:
            with _commit_alarm(remaining):
                commit(root, envelope["sample"], deadline_at=deadline_at, transaction=transaction)
        except HistoryLockError: raise CollectionError(None, code="HISTORY_LOCK_TIMEOUT") from None
        except HistoryDeadlineExceeded:
            if transaction["state"] in {"COMMITTED","DURABLE","DEDUPED"}:
                transaction["error_class"] = "TOTAL_DEADLINE_EXCEEDED"
                if transaction["state"] == "DEDUPED": transaction["state"] = "DURABLE"
                return _structured_result(envelope["sample"], transaction,
                                          deadline_cleanup_overrun=True)
            raise TotalDeadlineExceeded({}) from None
        except Exception:
            if transaction["state"] in {"COMMITTED", "DURABLE", "DEDUPED"}:
                if transaction["state"] == "DEDUPED": transaction["state"] = "DURABLE"
                if transaction.pop("_preview_started", False):
                    transaction["preview_state"] = "FAILED"
                    transaction["preview_warning"] = "POST_COMMIT_PREVIEW_WARNING"
                else:
                    transaction["error_class"] = "POST_COMMIT_WARNING"
                return _structured_result(envelope["sample"], transaction,
                                          deadline_cleanup_overrun=time.monotonic() > deadline_at)
            raise
        if transaction["state"] == "DEDUPED": transaction["state"] = "DURABLE"
        if post_commit_cleanup is not None:
            try: post_commit_cleanup()
            except CollectionError as error:
                return _structured_result(envelope["sample"], transaction,
                                          deadline_cleanup_overrun=time.monotonic() > deadline_at,
                                          cleanup_state="FAILED", cleanup_error=error.code)
            except Exception:
                return _structured_result(envelope["sample"], transaction,
                                          deadline_cleanup_overrun=time.monotonic() > deadline_at,
                                          cleanup_state="FAILED", cleanup_error="WORKER_CLEANUP_FAILED")
        overrun = time.monotonic() > deadline_at
        return _structured_result(envelope["sample"], transaction,
                                  deadline_cleanup_overrun=overrun)
    except TotalDeadlineExceeded as error:
        if ownership.state == OwnershipState.OWNED: _cleanup_owned(process, ownership)
        elif ownership.state == OwnershipState.STARTING: _cleanup_unowned(process)
        raise TotalDeadlineExceeded({
            "error_class": "TOTAL_DEADLINE_EXCEEDED", "elapsed_seconds": round(time.monotonic() - started, 3),
            "configured_total_deadline": deadline, "collector_version": VERSION, "git_revision": revision,
        }) from None
    finally:
        parent_connection.close()
        if ownership.state == OwnershipState.OWNED:
            if process.is_alive():
                _cleanup_owned(process, ownership)
            else:
                process.join(0); ownership.state = OwnershipState.REAPED; ownership.release()
        elif ownership.state == OwnershipState.STARTING and process.is_alive():
            _cleanup_unowned(process)


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
                          "git_revision": None}, indent=2)); raise SystemExit(1) from None
    print(json.dumps(result, indent=2))


if __name__ == "__main__": main()
