"""Validated, append-safe runtime history for engagement samples."""

from __future__ import annotations

import json
import os
import fcntl
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Mapping, Any

import jsonschema

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "schemas/engagement-sample.v1.json"


class HistoryCorruption(ValueError): pass


class RecoverableTailTruncation(ValueError): pass
class HistoryLockError(RuntimeError): pass


def validate(sample: Mapping[str, Any]) -> dict[str, Any]:
    required = {"schema", "fetched_at", "source_sha256", "per_room", "coverage", "warnings"}
    if not required.issubset(sample) or sample.get("schema") != "engagement-sample-v1":
        raise ValueError("invalid engagement sample")
    datetime.fromisoformat(str(sample["fetched_at"]).replace("Z", "+00:00"))
    digest = sample["source_sha256"]
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("invalid source hash")
    if not isinstance(sample["per_room"], list) or not isinstance(sample["warnings"], list):
        raise ValueError("invalid engagement collections")
    row = dict(sample)
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(row)
    except (OSError, json.JSONDecodeError, jsonschema.ValidationError) as error:
        raise ValueError("invalid engagement sample") from error
    return row


def key(row: Mapping[str, Any]) -> tuple[str, str]:
    return str(row["fetched_at"]), str(row["source_sha256"])


def load(path: Path, *, strict: bool = True, recover_tail: bool = True) -> list[dict[str, Any]]:
    if not path.exists(): return []
    rows = {}
    data = path.read_bytes()
    try: text = data.decode("utf-8")
    except UnicodeDecodeError as error: raise HistoryCorruption("HISTORY_CORRUPTION") from error
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines, 1):
        if not line.strip(): continue
        try: row = validate(json.loads(line))
        except (ValueError, json.JSONDecodeError, TypeError):
            is_tail = index == len(lines) and not line.endswith(("\n", "\r"))
            if is_tail and recover_tail:
                continue
            if strict: raise HistoryCorruption(f"HISTORY_CORRUPTION line {index}") from None
            continue
        rows[key(row)] = row
    return sorted(rows.values(), key=key)


def append(path: Path, sample: Mapping[str, Any]) -> bool:
    row = validate(sample)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("a+b") as lock:
        deadline = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise HistoryLockError("HISTORY_LOCK_TIMEOUT") from None
                time.sleep(0.05)
        try:
            separator = b""
            existing_data = b""
            if path.exists():
                data = path.read_bytes()
                existing_data = data
                lines = data.splitlines(keepends=True)
                if lines and not lines[-1].endswith((b"\n", b"\r")):
                    try:
                        validate(json.loads(lines[-1]))
                        separator = b"\n"
                    except (ValueError, json.JSONDecodeError, TypeError):
                        recovery = path.with_suffix(path.suffix + ".recovery-tail")
                        recovery.write_bytes(lines[-1])
                        existing_data = data[:-len(lines[-1])]
            if any(key(existing) == key(row) for existing in load(path)): return False
            payload = separator + (json.dumps(row, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n").encode()
            # Replace a fully fsynced candidate atomically.  This retains the
            # complete-write loop while ensuring forced worker termination can
            # never expose a partially appended JSONL record.
            temporary = path.with_name(f".{path.name}.deadline-{os.getpid()}")
            descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                payload = existing_data + payload
                written = 0
                while written < len(payload):
                    count = os.write(descriptor, payload[written:])
                    if count <= 0: raise OSError("short history write")
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
            return True
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def latest(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any] | None:
    values = sorted((validate(row) for row in rows), key=key)
    return values[-1] if values else None


def range_rows(rows: Iterable[Mapping[str, Any]], *, days: int = 7,
               now: datetime | None = None) -> list[dict[str, Any]]:
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=days)
    return [row for row in sorted((validate(row) for row in rows), key=key)
            if datetime.fromisoformat(row["fetched_at"].replace("Z", "+00:00")) >= cutoff]
