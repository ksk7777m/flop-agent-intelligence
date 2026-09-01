"""Disabled-by-default, local scheduler policy for the Engagement collector."""

from __future__ import annotations

import fcntl
import json
import os
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Mapping, Any

SCHEMA = "engagement-scheduler-v0.1"
NORMAL_INTERVAL = timedelta(minutes=60)
MINIMUM_INTERVAL = timedelta(minutes=30)
DAILY_WINDOW = timedelta(hours=24)
MAX_REQUESTS_PER_DAY = 24
FAILURE_THRESHOLD = 2
STATES = {"READY_DISABLED", "READY", "DEGRADED", "CIRCUIT_OPEN"}
FAILURE_CLASSES = {
    "HTTP_OPEN_TIMEOUT", "HTTP_OPEN_FAILED", "HTTP_BODY_TIMEOUT", "HTTP_BODY_FAILED",
    "TOTAL_DEADLINE_EXCEEDED", "VALIDATION_FAILED", "HISTORY_LOCK_TIMEOUT",
    "WORKER_PROTOCOL_ERROR", "WORKER_CRASHED", "WORKER_STARTUP_FAILED",
    "WORKER_CLEANUP_FAILED", "WORKER_CLEANUP_UNVERIFIED",
}
OUTCOMES = {
    "SCHEDULER_DISABLED", "SCHEDULER_READY", "SCHEDULER_MIN_INTERVAL",
    "SCHEDULER_DAILY_BUDGET_EXCEEDED", "SCHEDULER_RUN_ALREADY_ACTIVE",
    "SCHEDULER_CIRCUIT_OPEN", "SCHEDULER_STATE_MISSING", "SCHEDULER_STATE_INVALID",
    "SCHEDULER_STATE_PERMISSIONS", "SCHEDULER_COLLECTION_SUCCEEDED",
    "SCHEDULER_COLLECTION_FAILED", "SCHEDULER_RESET_APPROVED",
    "SCHEDULER_RECOVERED_INTERRUPTED_RUN",
}


class SchedulerStateError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(value: datetime) -> str:
    if value.tzinfo is None: raise ValueError("scheduler timestamp must be timezone-aware")
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_stamp(value: object, now: datetime) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise SchedulerStateError("SCHEDULER_STATE_INVALID")
    try: parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError: raise SchedulerStateError("SCHEDULER_STATE_INVALID") from None
    if parsed.tzinfo is None or parsed > now + timedelta(seconds=1):
        raise SchedulerStateError("SCHEDULER_STATE_INVALID")
    return parsed.astimezone(timezone.utc)


def disabled_state() -> dict[str, Any]:
    return {
        "schema": SCHEMA, "scheduler_enabled": False, "circuit_state": "READY_DISABLED",
        "normal_interval_minutes": 60,
        "last_attempt_at": None, "last_success_at": None, "consecutive_failures": 0,
        "last_error_class": None, "attempts_24h": [], "run_in_progress": False,
    }


def validate_state(value: Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    now = (now or utc_now()).astimezone(timezone.utc)
    keys = {"schema", "scheduler_enabled", "circuit_state", "last_attempt_at",
            "last_success_at", "consecutive_failures", "last_error_class",
            "attempts_24h", "run_in_progress", "normal_interval_minutes"}
    if (not isinstance(value, Mapping) or set(value) != keys or value.get("schema") != SCHEMA
            or type(value.get("scheduler_enabled")) is not bool
            or value.get("circuit_state") not in STATES
            or type(value.get("run_in_progress")) is not bool
            or type(value.get("normal_interval_minutes")) is not int
            or not 30 <= value["normal_interval_minutes"] <= 1440
            or type(value.get("consecutive_failures")) is not int
            or not 0 <= value["consecutive_failures"] <= FAILURE_THRESHOLD
            or value.get("last_error_class") not in FAILURE_CLASSES | {None}
            or not isinstance(value.get("attempts_24h"), list)
            or len(value["attempts_24h"]) > MAX_REQUESTS_PER_DAY):
        raise SchedulerStateError("SCHEDULER_STATE_INVALID")
    parsed = {}
    for field in ("last_attempt_at", "last_success_at"):
        parsed[field] = None if value[field] is None else _parse_stamp(value[field], now)
    attempts = [_parse_stamp(item, now) for item in value["attempts_24h"]]
    if attempts != sorted(attempts) or len(set(attempts)) != len(attempts):
        raise SchedulerStateError("SCHEDULER_STATE_INVALID")
    state = value["circuit_state"]
    enabled = value["scheduler_enabled"]
    failures = value["consecutive_failures"]
    error = value["last_error_class"]
    if ((state == "READY_DISABLED" and (enabled or failures != 0 or error is not None))
            or (state == "READY" and (not enabled or failures != 0 or error is not None))
            or (state == "DEGRADED" and (not enabled or failures != 1 or error is None))
            or (state == "CIRCUIT_OPEN" and (enabled or failures != FAILURE_THRESHOLD or error is None))
            or (parsed["last_success_at"] is not None and parsed["last_attempt_at"] is None)
            or (parsed["last_success_at"] is not None
                and parsed["last_success_at"] > parsed["last_attempt_at"])
            or (parsed["last_attempt_at"] is not None
                and parsed["last_attempt_at"] > now - DAILY_WINDOW and not attempts)
            or (attempts and parsed["last_attempt_at"] != attempts[-1])):
        raise SchedulerStateError("SCHEDULER_STATE_INVALID")
    return dict(value)


def load_state(path: Path, *, now: datetime | None = None) -> dict[str, Any]:
    if not path.exists(): raise SchedulerStateError("SCHEDULER_STATE_MISSING")
    if path.stat().st_mode & 0o777 != 0o600:
        raise SchedulerStateError("SCHEDULER_STATE_PERMISSIONS")
    try: value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise SchedulerStateError("SCHEDULER_STATE_INVALID") from None
    return validate_state(value, now=now)


def write_state(path: Path, state: Mapping[str, Any], *, now: datetime | None = None) -> None:
    state = validate_state(state, now=now)
    payload = (json.dumps(state, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.candidate-{os.getpid()}")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0: raise OSError("short scheduler state write")
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


@contextmanager
def scheduler_lock(path: Path, *, blocking: bool = False):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as lock:
        os.chmod(path, 0o600)
        flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
        try: fcntl.flock(lock.fileno(), flags)
        except BlockingIOError: raise SchedulerStateError("SCHEDULER_RUN_ALREADY_ACTIVE") from None
        try: yield
        finally: fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _recent_attempts(state: Mapping[str, Any], now: datetime) -> list[datetime]:
    cutoff = now - DAILY_WINDOW
    return [parsed for value in state["attempts_24h"]
            if (parsed := _parse_stamp(value, now)) > cutoff]


def evaluate(state: Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    now = (now or utc_now()).astimezone(timezone.utc)
    state = validate_state(state, now=now)
    attempts = _recent_attempts(state, now)
    last_attempt = None if state["last_attempt_at"] is None else _parse_stamp(state["last_attempt_at"], now)
    configured_interval = timedelta(minutes=max(30,state["normal_interval_minutes"]))
    next_spacing = now if last_attempt is None else last_attempt + configured_interval
    next_budget = now if len(attempts) < MAX_REQUESTS_PER_DAY else attempts[0] + DAILY_WINDOW
    next_eligible = max(now, next_spacing, next_budget)
    if state["circuit_state"] == "CIRCUIT_OPEN": outcome = "SCHEDULER_CIRCUIT_OPEN"
    elif not state["scheduler_enabled"]: outcome = "SCHEDULER_DISABLED"
    elif now < next_spacing: outcome = "SCHEDULER_MIN_INTERVAL"
    elif len(attempts) >= MAX_REQUESTS_PER_DAY: outcome = "SCHEDULER_DAILY_BUDGET_EXCEEDED"
    else: outcome = "SCHEDULER_READY"
    return {"allowed":outcome == "SCHEDULER_READY", "outcome":outcome,
            "overlap_active":False,
            "circuit_state":state["circuit_state"], "scheduler_enabled":state["scheduler_enabled"],
            "last_attempt_at":state["last_attempt_at"], "last_success_at":state["last_success_at"],
            "consecutive_failures":state["consecutive_failures"],
            "last_error_class":state["last_error_class"],
            "normal_interval_minutes":state["normal_interval_minutes"],
            "minimum_interval_minutes":int(MINIMUM_INTERVAL.total_seconds()//60),
            "next_eligible_at":_stamp(next_eligible), "requests_24h":len(attempts)}


def dry_run(state_path: Path, lock_path: Path, *, now: datetime | None = None) -> dict[str, Any]:
    now = (now or utc_now()).astimezone(timezone.utc)
    try:
        with scheduler_lock(lock_path): return evaluate(load_state(state_path, now=now), now=now)
    except SchedulerStateError as error:
        return {"allowed":False, "outcome":error.code,
                "overlap_active":error.code == "SCHEDULER_RUN_ALREADY_ACTIVE"}


def _record_failure(state: dict[str, Any], error_class: str) -> None:
    failures = min(FAILURE_THRESHOLD, state["consecutive_failures"] + 1)
    state.update(consecutive_failures=failures, last_error_class=error_class,
                 run_in_progress=False, scheduler_enabled=failures < FAILURE_THRESHOLD,
                 circuit_state="DEGRADED" if failures < FAILURE_THRESHOLD else "CIRCUIT_OPEN")


def run_once(state_path: Path, lock_path: Path, collector: Callable[[], Mapping[str, Any]],
             *, now: datetime | None = None) -> dict[str, Any]:
    now = (now or utc_now()).astimezone(timezone.utc)
    try:
        with scheduler_lock(lock_path):
            state = load_state(state_path, now=now)
            if state["run_in_progress"]:
                _record_failure(state, "WORKER_CRASHED")
                write_state(state_path, state, now=now)
                return {"success":False,"outcome":"SCHEDULER_RECOVERED_INTERRUPTED_RUN",
                        "circuit_state":state["circuit_state"],"collector_invocations":0}
            decision = evaluate(state, now=now)
            if not decision["allowed"]:
                return {"success":False, **decision, "collector_invocations":0}
            attempts = _recent_attempts(state, now) + [now]
            state.update(last_attempt_at=_stamp(now), attempts_24h=[_stamp(item) for item in attempts],
                         run_in_progress=True)
            write_state(state_path, state, now=now)
            try: result = collector()
            except Exception: result = {"success":False,"error_class":"WORKER_CRASHED"}
            success = result.get("success") is True
            error_class = result.get("error_class")
            if success:
                state.update(circuit_state="READY",scheduler_enabled=True,last_success_at=_stamp(now),
                             consecutive_failures=0,last_error_class=None,run_in_progress=False)
                outcome = "SCHEDULER_COLLECTION_SUCCEEDED"
            else:
                if error_class not in FAILURE_CLASSES: error_class = "VALIDATION_FAILED"
                _record_failure(state,error_class)
                outcome = "SCHEDULER_COLLECTION_FAILED"
            write_state(state_path,state,now=now)
            return {"success":success,"outcome":outcome,"error_class":None if success else error_class,
                    "circuit_state":state["circuit_state"],"collector_invocations":1}
    except SchedulerStateError as error:
        return {"success":False,"allowed":False,"outcome":error.code,"collector_invocations":0}


def approve_reset(state_path: Path, lock_path: Path, *, now: datetime | None = None) -> dict[str, Any]:
    now = (now or utc_now()).astimezone(timezone.utc)
    try:
        with scheduler_lock(lock_path):
            state = load_state(state_path, now=now)
            if state["circuit_state"] != "CIRCUIT_OPEN":
                return {"success":False,"outcome":"SCHEDULER_STATE_INVALID","collector_invocations":0}
            state.update(scheduler_enabled=False,circuit_state="READY_DISABLED",consecutive_failures=0,
                         last_error_class=None,run_in_progress=False)
            write_state(state_path,state,now=now)
            return {"success":True,"outcome":"SCHEDULER_RESET_APPROVED",
                    "circuit_state":"READY_DISABLED","collector_invocations":0}
    except SchedulerStateError as error:
        return {"success":False,"outcome":error.code,"collector_invocations":0}
