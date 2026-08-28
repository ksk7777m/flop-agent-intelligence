"""Technocore Presence Adapter V0: observe one room and prepare only.

There is intentionally no HTTP write primitive in this module. Room listing
data is untrusted input and only its exact configured room name and integer
sequence are used. V0 can emit the official conditional-note body, but it can
never submit that body.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Mapping

from .technocore import conditional_note_payload, read_official

CONFIG_SCHEMA = "technocore-presence-config-v0"
STATE_SCHEMA = "technocore-presence-state-v0"
NOTE_SCHEMA = "technocore-presence-note-v0"
ROOMS_PATH = "/rooms"


class PresenceError(RuntimeError):
    """Fail-closed presence observation error."""


class DryRunOnly(PermissionError):
    """Raised whenever live application is requested."""


@dataclass(frozen=True)
class PresenceConfig:
    room: str
    note_path: str
    current_note_value: str
    minimum_update_seconds: int = 3600
    enabled: bool = True
    dry_run: bool = True

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "PresenceConfig":
        if raw.get("schema") != CONFIG_SCHEMA:
            raise PresenceError(f"config schema must be {CONFIG_SCHEMA}")
        room = raw.get("room")
        if not isinstance(room, str) or not room or room.startswith("mb-") or "/" in room:
            raise PresenceError("exactly one valid public room must be configured")
        note_path, current = raw.get("note_path"), raw.get("current_note_value")
        if not isinstance(note_path, str) or not note_path.startswith("/kv/"):
            raise PresenceError("an official note path must be configured")
        if not isinstance(current, str) or not current:
            raise PresenceError("current_note_value is required for conditional update preparation")
        interval = raw.get("minimum_update_seconds", 3600)
        if isinstance(interval, bool) or not isinstance(interval, int) or interval < 60:
            raise PresenceError("minimum_update_seconds must be an integer of at least 60")
        return cls(room, note_path, current, interval, raw.get("enabled") is True, raw.get("dry_run") is True)


def load_config(path: Path) -> PresenceConfig:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PresenceError(f"could not load presence config: {error}") from error
    if not isinstance(raw, dict):
        raise PresenceError("presence config must be a JSON object")
    return PresenceConfig.from_mapping(raw)


def _latest_seq(response: Any, configured_room: str) -> int:
    if not isinstance(response, Mapping) or not isinstance(response.get("rooms"), list):
        raise PresenceError("malformed Technocore rooms response")
    matches = [item for item in response["rooms"] if isinstance(item, Mapping) and item.get("room") == configured_room]
    if not matches:
        raise PresenceError("configured public room is missing from the official response")
    if len(matches) != 1:
        raise PresenceError("configured public room is ambiguous in the official response")
    seq = matches[0].get("last_seq")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise PresenceError("configured room has a malformed last_seq")
    return seq


def _load_state(path: Path) -> Dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PresenceError(f"could not load presence state: {error}") from error
    if not isinstance(state, dict) or state.get("schema") != STATE_SCHEMA:
        raise PresenceError("presence state is malformed")
    return state


def _save_state(path: Path, state: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _iso(now: datetime) -> str:
    return now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _note_value(config: PresenceConfig, seq: int, observed_at: str) -> str:
    return json.dumps({
        "schema": NOTE_SCHEMA,
        "mode": "DRY_RUN_ONLY",
        "observation": {"room": config.room, "last_seq": seq, "observed_at": observed_at},
        "capability": {"version": "v1", "status": "OBSERVED"},
        "collaboration": {"version": "v2", "status": "NOT_IMPLEMENTED"},
    }, sort_keys=True, separators=(",", ":"))


def observe(config: PresenceConfig, state_path: Path, *, reader: Callable[[str], Any] = read_official,
            now: datetime | None = None) -> Dict[str, Any]:
    """Read one room, save last-seen state, and maybe preview a note CAS."""
    if not config.enabled:
        return {"status": "KILL_SWITCHED", "mode": "DRY_RUN_ONLY", "write_performed": False, "payload": None}
    if not config.dry_run:
        raise DryRunOnly("Presence Adapter V0 requires dry_run=true")
    observed = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    observed_at = _iso(observed)
    latest_seq = _latest_seq(reader(ROOMS_PATH), config.room)
    previous = _load_state(state_path)
    previous_seq = previous.get("last_seen_seq") if previous else None
    if previous and previous.get("room") != config.room:
        raise PresenceError("presence state belongs to a different configured room")

    status, payload = ("BASELINE_ESTABLISHED" if previous is None else "UNCHANGED"), None
    last_prepared_at = previous.get("last_prepared_at") if previous else None
    if previous_seq is not None and latest_seq < previous_seq:
        status = "SEQUENCE_REGRESSION_REVIEW_REQUIRED"
    elif previous_seq is not None and latest_seq > previous_seq:
        prepared = _parse_time(last_prepared_at)
        elapsed = (observed - prepared).total_seconds() if prepared else None
        if elapsed is not None and elapsed < config.minimum_update_seconds:
            status = "RATE_LIMITED"
        else:
            value = _note_value(config, latest_seq, observed_at)
            payload = {"method": "POST", "path": config.note_path,
                       "body": conditional_note_payload(config.current_note_value, value)}
            status, last_prepared_at = "PAYLOAD_PREPARED", observed_at

    _save_state(state_path, {
        "schema": STATE_SCHEMA, "room": config.room, "last_seen_seq": latest_seq,
        "last_observed_at": observed_at, "last_prepared_at": last_prepared_at,
        "mode": "DRY_RUN_ONLY",
    })
    return {"status": status, "mode": "DRY_RUN_ONLY", "room": config.room,
            "previous_seq": previous_seq, "latest_seq": latest_seq,
            "state_path": str(state_path), "write_performed": False, "payload": payload}


def apply_payload(*_: Any, **__: Any) -> None:
    """V0 has no activation path, including with human confirmation."""
    raise DryRunOnly("Technocore presence writes are not implemented in V0")
