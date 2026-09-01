#!/usr/bin/env python3
"""Run one fixed-endpoint engagement observation. This is not a scheduler."""

from __future__ import annotations

import argparse, hashlib, json, math, multiprocessing, os, signal, socket, subprocess, threading, time
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
TIMING_EPSILON_SECONDS = 0.01
MAX_NETWORK_ELAPSED_SECONDS = MAX_TOTAL_COLLECTION_DEADLINE_SECONDS + TIMING_EPSILON_SECONDS
WORKER_ERRORS = {"HTTP_TIMEOUT", "HTTP_OPEN_TIMEOUT", "HTTP_BODY_TIMEOUT",
                 "HTTP_OPEN_FAILED", "HTTP_BODY_FAILED", "VALIDATION_FAILED",
                 "RESPONSE_TOO_LARGE"}
STARTUP_IPC_BYTES = 1024
COMMIT_STATES = {"PRE_COMMIT", "COMMITTED", "DURABLE"}
PREVIEW_STATES = {"NOT_ATTEMPTED", "UPDATED", "FAILED"}
DURABILITY_WARNINGS = {None, "POST_COMMIT_DURABILITY_WARNING"}
PREVIEW_WARNINGS = {None, "POST_COMMIT_PREVIEW_WARNING"}
CLEANUP_ERRORS = {None, "WORKER_CLEANUP_FAILED", "WORKER_CLEANUP_UNVERIFIED"}
RESULT_ERRORS = {None, "TOTAL_DEADLINE_EXCEEDED", "POST_COMMIT_WARNING", "PRE_COMMIT_FAILURE"}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None


class CollectionError(RuntimeError):
    def __init__(self, status: int | None, retry_after: int | None = None,
                 code: str = "COLLECTION_FAILED", diagnostics: dict | None = None):
        super().__init__(code if code == "RESPONSE_TOO_LARGE"
                         else f"engagement collection failed: HTTP {status or 'NETWORK'}")
        self.status, self.retry_after, self.code = status, retry_after, code
        self.diagnostics = diagnostics


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


def _network_diagnostics(timeout: float) -> dict:
    return {"failure_stage":None, "total_elapsed_seconds":None,
            "open_elapsed_seconds":None, "body_elapsed_seconds":None,
            "http_status":None, "response_bytes":None,
            "configured_socket_timeout":float(timeout)}


def _elapsed(start: float, end: float | None = None) -> float:
    return round(max(0.0, (time.monotonic() if end is None else end) - start), 6)


def _validate_network_diagnostics(value: dict) -> dict:
    keys = {"failure_stage","total_elapsed_seconds","open_elapsed_seconds",
            "body_elapsed_seconds","http_status","response_bytes","configured_socket_timeout"}
    if not isinstance(value, dict) or set(value) != keys or value["failure_stage"] not in {None,"HTTP_OPEN","HTTP_BODY"}:
        raise ValueError("invalid network diagnostics")
    for name in ("total_elapsed_seconds","open_elapsed_seconds","body_elapsed_seconds"):
        number=value[name]
        if number is not None and (type(number) not in (int,float) or not math.isfinite(number)
                                   or not 0 <= number <= MAX_NETWORK_ELAPSED_SECONDS):
            raise ValueError("invalid network diagnostics")
    socket_timeout=value["configured_socket_timeout"]
    if (type(socket_timeout) not in (int,float) or not math.isfinite(socket_timeout)
            or not 0 < socket_timeout <= MAX_TOTAL_COLLECTION_DEADLINE_SECONDS):
        raise ValueError("invalid network diagnostics")
    status=value["http_status"]
    if status is not None and (type(status) is not int or not 100 <= status <= 599): raise ValueError("invalid network diagnostics")
    size=value["response_bytes"]
    if size is not None and (type(size) is not int or not 0 <= size <= MAX_RESPONSE_BYTES): raise ValueError("invalid network diagnostics")
    return dict(value)


def _validate_worker_diagnostics(value: dict, *, ok: bool, error_class: str | None = None) -> dict:
    diagnostics = _validate_network_diagnostics(value)
    stage = diagnostics["failure_stage"]
    total = diagnostics["total_elapsed_seconds"]
    opened = diagnostics["open_elapsed_seconds"]
    body = diagnostics["body_elapsed_seconds"]
    status = diagnostics["http_status"]
    size = diagnostics["response_bytes"]
    complete = (stage is None and total is not None and opened is not None and body is not None
                and status is not None and size is not None)
    timing_consistent = (total is not None and opened is not None
                         and total + TIMING_EPSILON_SECONDS >= opened
                         and (body is None or total + TIMING_EPSILON_SECONDS >= opened + body))
    if ok:
        if error_class is not None or not complete or not 200 <= status < 300 or not timing_consistent:
            raise ValueError("invalid network diagnostics")
        return diagnostics
    if error_class in {"HTTP_OPEN_TIMEOUT", "HTTP_OPEN_FAILED"}:
        if (stage != "HTTP_OPEN" or opened is None or total is None or body is not None
                or size is not None or not timing_consistent
                or (error_class == "HTTP_OPEN_TIMEOUT" and status is not None)):
            raise ValueError("invalid network diagnostics")
    elif error_class in {"HTTP_BODY_TIMEOUT", "HTTP_BODY_FAILED"}:
        if (stage != "HTTP_BODY" or opened is None or body is None or total is None
                or status is None or size is not None or not timing_consistent):
            raise ValueError("invalid network diagnostics")
    elif error_class == "HTTP_TIMEOUT":
        if (stage is not None or any(item is not None for item in (total, opened, body, status, size))):
            raise ValueError("invalid network diagnostics")
    elif error_class == "VALIDATION_FAILED":
        empty = stage is None and all(item is None for item in (total, opened, body, status, size))
        if not empty and (not complete or not 200 <= status < 300 or not timing_consistent):
            raise ValueError("invalid network diagnostics")
    elif error_class == "RESPONSE_TOO_LARGE":
        header_rejection = (stage is None and opened is not None and body is None and total is None
                            and status is not None and size is None)
        completed_oversize_read = (stage is None and opened is not None and body is not None
                                   and total is not None and status is not None and size is None
                                   and timing_consistent)
        if not header_rejection and not completed_oversize_read:
            raise ValueError("invalid network diagnostics")
    else:
        raise ValueError("invalid network diagnostics")
    return diagnostics


def fetch(*, timeout: float = 20.0, opener=None, diagnostics: dict | None = None) -> tuple[bytes, int, object]:
    diagnostics = diagnostics if diagnostics is not None else _network_diagnostics(timeout)
    request_start = open_start = time.monotonic()
    request = Request(validate_endpoint(SOURCE_URL), method="GET", headers={
        "Accept": "application/json",
        "User-Agent": f"flop-agent-intelligence/{VERSION} (+https://github.com/ksk7777m/flop-agent-intelligence)",
    })
    open_fn = opener or build_opener(NoRedirect()).open
    try:
        try:
            response = open_fn(request, timeout=timeout)
        except (TimeoutError, socket.timeout):
            diagnostics.update(failure_stage="HTTP_OPEN", open_elapsed_seconds=_elapsed(open_start),
                               total_elapsed_seconds=_elapsed(request_start))
            raise CollectionError(None, code="HTTP_OPEN_TIMEOUT", diagnostics=diagnostics) from None
        except HTTPError as error:
            diagnostics.update(failure_stage="HTTP_OPEN", open_elapsed_seconds=_elapsed(open_start),
                               total_elapsed_seconds=_elapsed(request_start), http_status=error.code)
            retry_after = error.headers.get("Retry-After") if error.headers is not None else None
            raise CollectionError(error.code, backoff(error.code, retry_header=retry_after),
                                  code="HTTP_OPEN_FAILED", diagnostics=diagnostics) from None
        except URLError as error:
            code = "HTTP_OPEN_TIMEOUT" if isinstance(error.reason, (TimeoutError, socket.timeout)) else "HTTP_OPEN_FAILED"
            diagnostics.update(failure_stage="HTTP_OPEN", open_elapsed_seconds=_elapsed(open_start),
                               total_elapsed_seconds=_elapsed(request_start))
            raise CollectionError(None, code=code, diagnostics=diagnostics) from None
        except OSError:
            diagnostics.update(failure_stage="HTTP_OPEN", open_elapsed_seconds=_elapsed(open_start),
                               total_elapsed_seconds=_elapsed(request_start))
            raise CollectionError(None, code="HTTP_OPEN_FAILED", diagnostics=diagnostics) from None
        open_end=time.monotonic(); diagnostics["open_elapsed_seconds"]=_elapsed(open_start,open_end)
        with response:
            diagnostics["http_status"] = response.status
            if response.geturl() != SOURCE_URL:
                diagnostics.update(failure_stage="HTTP_OPEN",
                                   total_elapsed_seconds=_elapsed(request_start))
                raise CollectionError(response.status, code="HTTP_OPEN_FAILED", diagnostics=diagnostics)
            declared = response.headers.get("Content-Length")
            if isinstance(declared, str) and declared.strip().isdigit() and int(declared) > MAX_RESPONSE_BYTES:
                raise CollectionError(response.status, code="RESPONSE_TOO_LARGE", diagnostics=diagnostics)
            body_start=time.monotonic()
            try: body = response.read(MAX_RESPONSE_BYTES + 1)
            except (TimeoutError, socket.timeout):
                diagnostics.update(failure_stage="HTTP_BODY", body_elapsed_seconds=_elapsed(body_start),
                                   total_elapsed_seconds=_elapsed(request_start))
                raise CollectionError(response.status, code="HTTP_BODY_TIMEOUT", diagnostics=diagnostics) from None
            except Exception:
                diagnostics.update(failure_stage="HTTP_BODY", body_elapsed_seconds=_elapsed(body_start),
                                   total_elapsed_seconds=_elapsed(request_start))
                raise CollectionError(response.status, code="HTTP_BODY_FAILED", diagnostics=diagnostics) from None
            diagnostics.update(body_elapsed_seconds=_elapsed(body_start), total_elapsed_seconds=_elapsed(request_start))
            if len(body) > MAX_RESPONSE_BYTES:
                raise CollectionError(response.status, code="RESPONSE_TOO_LARGE", diagnostics=diagnostics)
            diagnostics["response_bytes"] = len(body)
            return body, response.status, response.headers
    except HTTPError as error:
        # Defensive fallback: discard every error body and perform no retry.
        raise CollectionError(error.code, code="HTTP_OPEN_FAILED", diagnostics=diagnostics) from None


def prepare_sample(root: Path, *, timeout: float = SOCKET_TIMEOUT_SECONDS, opener=None,
                   fetched_at: str | None = None, git_revision: str | None = None,
                   diagnostics: dict | None = None) -> dict:
    interval_minutes()
    body, status, _headers = fetch(timeout=timeout, opener=opener, diagnostics=diagnostics)
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
    network_diagnostics = transaction.get("network_diagnostics")
    if network_diagnostics is not None: network_diagnostics = _validate_network_diagnostics(network_diagnostics)
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
            "preview_warning": preview_warning, "cleanup_error": cleanup_error,
            "network_diagnostics": network_diagnostics}


def _merge_cleanup_failure(result: dict, cleanup_error: str = "WORKER_CLEANUP_FAILED") -> dict:
    """Return a revalidated result without discarding an earlier cleanup error."""
    transaction = {
        "state": result["commit_state"], "preview_state": result["preview_state"],
        "error_class": result["error_class"],
        "durability_warning": result["durability_warning"],
        "preview_warning": result["preview_warning"],
        "network_diagnostics": result.get("network_diagnostics"),
    }
    return _structured_result(
        result["sample"], transaction,
        deadline_cleanup_overrun=result["deadline_cleanup_overrun"],
        cleanup_state="FAILED", cleanup_error=result.get("cleanup_error") or cleanup_error,
        success=result["success"],
    )


def _precommit_failure_result(error: CollectionError, total_deadline: float) -> dict:
    diagnostics = (_validate_worker_diagnostics(error.diagnostics, ok=False, error_class=error.code)
                   if error.diagnostics is not None and error.code in WORKER_ERRORS
                   else _validate_network_diagnostics(error.diagnostics) if error.diagnostics is not None else None)
    if diagnostics is not None: diagnostics["configured_total_deadline"] = total_deadline
    return {"success":False, "commit_state":"PRE_COMMIT",
            "durability_warning":None, "preview_state":"NOT_ATTEMPTED",
            "preview_warning":None, "cleanup_state":"COMPLETED", "cleanup_error":None,
            "deadline_cleanup_overrun":False, "error_class":error.code,
            "network_diagnostics":diagnostics, "collector_version":VERSION,
            "git_revision":None}


def _cli_failure_result(result: dict) -> dict:
    """Normalize an already-validated internal failure for CLI consumers."""
    return {"success":False, "commit_state":result["commit_state"],
            "durability_warning":result["durability_warning"],
            "preview_state":result["preview_state"], "preview_warning":result["preview_warning"],
            "cleanup_state":result["cleanup_state"], "cleanup_error":result["cleanup_error"],
            "deadline_cleanup_overrun":result["deadline_cleanup_overrun"],
            "error_class":result["error_class"],
            "network_diagnostics":result.get("network_diagnostics"),
            "collector_version":VERSION, "git_revision":None}


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
    diagnostics = _network_diagnostics(timeout)
    try:
        try:
            envelope = {"ok": True, "sample": prepare_sample(Path(root), timeout=timeout,
                                                               git_revision=revision,
                                                               diagnostics=diagnostics),
                        "network_diagnostics":diagnostics}
        except (TimeoutError, socket.timeout): envelope = {**_error_envelope("HTTP_TIMEOUT"), "network_diagnostics":diagnostics}
        except URLError as error:
            envelope = {**_error_envelope("HTTP_TIMEOUT" if isinstance(error.reason, (TimeoutError, socket.timeout))
                                          else "HTTP_OPEN_FAILED"), "network_diagnostics":diagnostics}
        except CollectionError as error:
            envelope = {**_error_envelope(error.code if error.code in WORKER_ERRORS else "VALIDATION_FAILED"),
                        "network_diagnostics":error.diagnostics or diagnostics}
        except Exception: envelope = {**_error_envelope("VALIDATION_FAILED"), "network_diagnostics":diagnostics}
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
        if set(envelope) != {"ok", "sample", "network_diagnostics"} or not isinstance(envelope.get("sample"), dict):
            raise CollectionError(None, code="WORKER_PROTOCOL_ERROR")
        try: envelope["sample"] = validate(envelope["sample"])
        except ValueError: raise CollectionError(None, code="WORKER_PROTOCOL_ERROR") from None
    else:
        if set(envelope) != {"ok", "error_class", "network_diagnostics"} or envelope.get("error_class") not in WORKER_ERRORS:
            raise CollectionError(None, code="WORKER_PROTOCOL_ERROR")
    try: envelope["network_diagnostics"] = _validate_worker_diagnostics(
        envelope["network_diagnostics"], ok=envelope["ok"], error_class=envelope.get("error_class"))
    except ValueError: raise CollectionError(None, code="WORKER_PROTOCOL_ERROR") from None
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
    transaction = {"state":"PRE_COMMIT", "preview_state":"NOT_ATTEMPTED",
                   "durability_warning":None, "preview_warning":None}
    final_result = None
    result_sample = None
    process.start()
    try: child_connection.close()
    except Exception:
        cleanup_error = "WORKER_CLEANUP_FAILED"
        try: _cleanup_unowned(process)
        except CollectionError as error: cleanup_error = error.code
        except Exception: pass
        try: parent_connection.close()
        except Exception: pass
        transaction["error_class"] = "PRE_COMMIT_FAILURE"
        return _structured_result(None, transaction, cleanup_state="FAILED",
                                  cleanup_error=cleanup_error, success=False)
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
        result_sample = envelope.get("sample")
        transaction["network_diagnostics"] = envelope["network_diagnostics"]
        if not envelope["ok"]:
            raise CollectionError(None, code=envelope["error_class"], diagnostics=envelope["network_diagnostics"])
        remaining = deadline_at - time.monotonic()
        if remaining < MIN_COMMIT_BUDGET_SECONDS: raise TotalDeadlineExceeded({})
        try:
            with _commit_alarm(remaining):
                commit(root, envelope["sample"], deadline_at=deadline_at, transaction=transaction)
        except HistoryLockError: raise CollectionError(None, code="HISTORY_LOCK_TIMEOUT") from None
        except HistoryDeadlineExceeded:
            if transaction["state"] in {"COMMITTED","DURABLE","DEDUPED"}:
                transaction["error_class"] = "TOTAL_DEADLINE_EXCEEDED"
                if transaction["state"] == "DEDUPED": transaction["state"] = "DURABLE"
                final_result = _structured_result(envelope["sample"], transaction,
                                                  deadline_cleanup_overrun=True)
                return final_result
            raise TotalDeadlineExceeded({}) from None
        except Exception:
            if transaction["state"] in {"COMMITTED", "DURABLE", "DEDUPED"}:
                if transaction["state"] == "DEDUPED": transaction["state"] = "DURABLE"
                if transaction.pop("_preview_started", False):
                    transaction["preview_state"] = "FAILED"
                    transaction["preview_warning"] = "POST_COMMIT_PREVIEW_WARNING"
                else:
                    transaction["error_class"] = "POST_COMMIT_WARNING"
                final_result = _structured_result(envelope["sample"], transaction,
                                                  deadline_cleanup_overrun=time.monotonic() > deadline_at)
                return final_result
            raise
        if transaction["state"] == "DEDUPED": transaction["state"] = "DURABLE"
        if post_commit_cleanup is not None:
            try: post_commit_cleanup()
            except CollectionError as error:
                final_result = _structured_result(envelope["sample"], transaction,
                                                  deadline_cleanup_overrun=time.monotonic() > deadline_at,
                                                  cleanup_state="FAILED", cleanup_error=error.code)
                return final_result
            except Exception:
                final_result = _structured_result(envelope["sample"], transaction,
                                                  deadline_cleanup_overrun=time.monotonic() > deadline_at,
                                                  cleanup_state="FAILED", cleanup_error="WORKER_CLEANUP_FAILED")
                return final_result
        overrun = time.monotonic() > deadline_at
        final_result = _structured_result(envelope["sample"], transaction,
                                          deadline_cleanup_overrun=overrun)
        return final_result
    except TotalDeadlineExceeded:
        if ownership.state == OwnershipState.OWNED: _cleanup_owned(process, ownership)
        elif ownership.state == OwnershipState.STARTING: _cleanup_unowned(process)
        raise TotalDeadlineExceeded({
            "error_class": "TOTAL_DEADLINE_EXCEEDED", "elapsed_seconds": round(time.monotonic() - started, 3),
            "configured_total_deadline": deadline, "collector_version": VERSION, "git_revision": revision,
        }) from None
    finally:
        close_failed = False
        try: parent_connection.close()
        except Exception: close_failed = True
        final_cleanup_error = "WORKER_CLEANUP_FAILED" if close_failed else None
        try:
            if ownership.state == OwnershipState.OWNED:
                if process.is_alive():
                    _cleanup_owned(process, ownership)
                else:
                    process.join(0); ownership.state = OwnershipState.REAPED; ownership.release()
            elif ownership.state == OwnershipState.STARTING and process.is_alive():
                _cleanup_unowned(process)
        except CollectionError as error:
            final_cleanup_error = error.code
        except Exception:
            final_cleanup_error = "WORKER_CLEANUP_FAILED"
        if final_cleanup_error is not None:
            if final_result is None:
                transaction["state"] = "PRE_COMMIT"
                transaction["preview_state"] = "NOT_ATTEMPTED"
                transaction["error_class"] = "PRE_COMMIT_FAILURE"
                final_result = _structured_result(
                    result_sample, transaction, cleanup_state="FAILED",
                    cleanup_error=final_cleanup_error, success=False,
                )
            else:
                final_result = _merge_cleanup_failure(final_result, final_cleanup_error)
            return final_result


def main(*, run=run_with_total_deadline) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--timeout", type=float, default=SOCKET_TIMEOUT_SECONDS)
    parser.add_argument("--total-deadline", type=float, default=TOTAL_COLLECTION_DEADLINE_SECONDS)
    args = parser.parse_args()
    try: result = run(args.root, timeout=args.timeout, total_deadline=args.total_deadline)
    except TotalDeadlineExceeded as error:
        failure = CollectionError(None, code="TOTAL_DEADLINE_EXCEEDED")
        print(json.dumps(_precommit_failure_result(failure,args.total_deadline),indent=2))
        raise SystemExit(2) from None
    except CollectionError as error:
        print(json.dumps(_precommit_failure_result(error,args.total_deadline),indent=2))
        raise SystemExit(1) from None
    if not result["success"]: result = _cli_failure_result(result)
    if result.get("network_diagnostics") is not None:
        result["network_diagnostics"]["configured_total_deadline"] = args.total_deadline
    print(json.dumps(result, indent=2))
    if not result["success"]: raise SystemExit(1)


if __name__ == "__main__": main()
