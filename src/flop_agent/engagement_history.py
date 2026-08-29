"""Validated, append-safe runtime history for engagement samples."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Mapping, Any


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
    return dict(sample)


def key(row: Mapping[str, Any]) -> tuple[str, str]:
    return str(row["fetched_at"]), str(row["source_sha256"])


def load(path: Path, *, strict: bool = True) -> list[dict[str, Any]]:
    if not path.exists(): return []
    rows = {}
    lines = path.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines, 1):
        if not line.strip(): continue
        try: row = validate(json.loads(line))
        except (ValueError, json.JSONDecodeError, TypeError):
            if strict: raise ValueError(f"invalid history line {index}") from None
            continue
        rows[key(row)] = row
    return sorted(rows.values(), key=key)


def append(path: Path, sample: Mapping[str, Any]) -> bool:
    row = validate(sample)
    if any(key(existing) == key(row) for existing in load(path)): return False
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n").encode()
    descriptor = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try: os.write(descriptor, payload); os.fsync(descriptor)
    finally: os.close(descriptor)
    return True


def latest(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any] | None:
    values = sorted((validate(row) for row in rows), key=key)
    return values[-1] if values else None


def range_rows(rows: Iterable[Mapping[str, Any]], *, days: int = 7,
               now: datetime | None = None) -> list[dict[str, Any]]:
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=days)
    return [row for row in sorted((validate(row) for row in rows), key=key)
            if datetime.fromisoformat(row["fetched_at"].replace("Z", "+00:00")) >= cutoff]
