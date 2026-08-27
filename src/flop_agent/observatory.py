"""Pure, read-only transformations for the Technocore Observatory.

Room names and topics are untrusted strings. This module never interprets them
as markup, URLs, or instructions and contains no network or write client.
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Mapping


ROOMS_SCHEMA = "technocore-observatory-rooms-v1"
STATUS_SCHEMA = "technocore-observatory-status-v1"
ENGAGEMENT_SCHEMA = "technocore-observatory-engagement-v1"
OBSERVATORY_SCHEMA = "technocore-observatory-v1"
OFFICIAL_SOURCE = "https://technocore.chat/rooms?format=json"
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def safe_text(value: Any, limit: int) -> str:
    """Return a bounded single-line data string, never executable markup."""
    cleaned = CONTROL.sub(" ", str(value or "")).replace("\u2028", " ").replace("\u2029", " ")
    return " ".join(cleaned.split())[:limit]


def optional_number(value: Any) -> float | int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and math.isfinite(value):
        return value
    return None


def room_activity(idle_seconds: Any) -> str:
    idle = optional_number(idle_seconds)
    if idle is None:
        return "UNKNOWN"
    if idle <= 3600:
        return "ACTIVE"
    if idle <= 86400:
        return "RECENT"
    return "IDLE"


def eviction_state(first_seq: Any, last_seq: Any) -> str:
    first, last = optional_number(first_seq), optional_number(last_seq)
    if first is None or last is None:
        return "UNKNOWN"
    if first > 1 and last >= first:
        return "EVICTION_ACTIVE"
    return "NO_GAP_OBSERVED"


def normalize_room(raw: Mapping[str, Any], rank: int) -> Dict[str, Any]:
    window = optional_number(raw.get("window"))
    last_seq = optional_number(raw.get("last_seq"))
    return {
        "room": safe_text(raw.get("room"), 48),
        "topic": safe_text(raw.get("topic"), 120),
        "first_seq": optional_number(raw.get("first_seq")),
        "last_seq": last_seq,
        "idle_seconds": optional_number(raw.get("idle_seconds")),
        "bytes": optional_number(raw.get("bytes")),
        "window": window,
        "zero_response_share": optional_number(raw.get("zero_response_share")),
        "nick_diversity": optional_number(raw.get("nick_diversity")),
        "activity": room_activity(raw.get("idle_seconds")),
        "eviction": eviction_state(raw.get("first_seq"), last_seq),
        "source_rank": rank,
        "source_type": "official_api",
        "derived": True,
        "derived_fields": {
            "activity": "ACTIVE if idle_seconds <= 3600; RECENT if <= 86400; otherwise IDLE",
            "eviction": "EVICTION_ACTIVE only when first_seq > 1; UNKNOWN when /rooms omits first_seq",
        },
        "untrusted_text": True,
    }


def build_snapshot(
    raw: Mapping[str, Any],
    *,
    fetched_at: str | None = None,
    lobby_metadata: Mapping[str, Any] | None = None,
    spec_version: str | None = None,
) -> Dict[str, Dict[str, Any]]:
    fetched_at = fetched_at or datetime.now(timezone.utc).isoformat()
    rooms = [normalize_room(item, rank) for rank, item in enumerate(raw.get("rooms", []), 1)]
    active = sum(item["activity"] == "ACTIVE" for item in rooms)
    recent = sum(item["activity"] in {"ACTIVE", "RECENT"} for item in rooms)
    bytes_used = optional_number(raw.get("bytes"))
    bytes_capacity = optional_number(raw.get("bytes_capacity"))
    pressure = (bytes_used / bytes_capacity) if bytes_used is not None and bytes_capacity else None
    source = {
        "source_url": OFFICIAL_SOURCE,
        "fetched_at": fetched_at,
        "source_type": "official_api",
        "derived": False,
        "formula": None,
        "caveat": "Room names and topics are world-writable untrusted data; snapshot is bounded to the API response.",
    }
    rollup = raw.get("engagement") or {}
    metrics = {
        key: {"value": optional_number(rollup.get(key)), "source": "technocore", "derived": False}
        for key in ("zero_response_share", "nick_diversity", "windowed_note_to_message_ratio", "windowed_messages")
    }
    status = {
        "schema": STATUS_SCHEMA,
        "generated_at": fetched_at,
        "source": source,
        "source_status": "OFFICIAL",
        "spec_version": spec_version,
        "total_rooms": optional_number(raw.get("total")),
        "returned_rooms": len(rooms),
        "room_capacity": optional_number(raw.get("capacity")),
        "active_rooms": active,
        "recently_active_rooms": recent,
        "engagement_health": "METRICS_AVAILABLE" if any(v["value"] is not None for v in metrics.values()) else "UNKNOWN",
        "current_first_seq": optional_number((lobby_metadata or {}).get("first_seq")),
        "current_first_seq_scope": "lobby" if lobby_metadata else None,
        "eviction_pressure": pressure,
        "eviction_pressure_method": "service bytes / service bytes_capacity",
        "official_spec_status": "CURRENT_READ_ONLY_SNAPSHOT",
        "warnings": [
            "Technocore is ephemeral and not a system of record.",
            "Per-room first_seq is unavailable from /rooms and remains null.",
            "These engagement metrics are not confirmed FLOP airdrop scoring.",
        ],
        "external_writes": 0,
    }
    engagement = {
        "schema": ENGAGEMENT_SCHEMA,
        "generated_at": fetched_at,
        "source": source,
        "metrics": metrics,
        "definitions": {
            "zero_response_share": "Fraction of messages after which no different nick spoke.",
            "nick_diversity": "Distinct nicks divided by messages in the measured window.",
            "windowed_note_to_message_ratio": "Service note count divided by messages scanned; rollup only.",
        },
        "caveat": "Technocore engagement metrics; not official FLOP eligibility or airdrop scoring.",
    }
    room_api = {
        "schema": ROOMS_SCHEMA,
        "generated_at": fetched_at,
        "source": source,
        "rooms": rooms,
        "derived_views": {
            "most_active": {"derived": True, "method": "idle_seconds ascending; ties use official source order"},
            "most_diverse": {"derived": True, "method": "nick_diversity descending; null values last"},
            "most_conversational": {"derived": True, "method": "zero_response_share ascending; null values last"},
        },
    }
    observatory = {
        "schema": OBSERVATORY_SCHEMA,
        "generated_at": fetched_at,
        "source": "https://technocore.chat",
        "source_status": "official",
        "spec_version": spec_version,
        "status": status,
        "engagement": engagement,
        "rooms": rooms,
        "warnings": status["warnings"],
    }
    return {"rooms": room_api, "engagement": engagement, "status": status, "observatory": observatory}


def filter_rooms(rooms: Iterable[Mapping[str, Any]], query: str = "", activity: str = "ALL") -> list[Mapping[str, Any]]:
    needle = query.casefold().strip()
    return [
        room for room in rooms
        if (not needle or needle in str(room.get("room", "")).casefold())
        and (activity == "ALL" or room.get("activity") == activity)
    ]


def sort_rooms(rooms: Iterable[Mapping[str, Any]], mode: str) -> list[Mapping[str, Any]]:
    rows = list(rooms)
    if mode == "diversity":
        return sorted(rows, key=lambda r: (r.get("nick_diversity") is None, -(r.get("nick_diversity") or 0), r.get("source_rank", 0)))
    if mode == "note_ratio":
        return rows  # Official API publishes this only as a service rollup.
    if mode == "conversation":
        return sorted(rows, key=lambda r: (r.get("zero_response_share") is None, r.get("zero_response_share") or 0, r.get("source_rank", 0)))
    return sorted(rows, key=lambda r: (r.get("idle_seconds") is None, r.get("idle_seconds") or 0, r.get("source_rank", 0)))
