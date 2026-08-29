"""Pure transforms for bounded, observational Technocore engagement data."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

SOURCE_URL = "https://technocore.chat/rooms?format=json&limit=200"
CAVEATS = [
    "Low nick_diversity does not imply bot activity.",
    "High zero_response_share does not imply spam.",
    "These are observational engagement signals, not FLOP eligibility metrics.",
    "Unsigned nick values are self-asserted.",
    "Rollup values depend on request limit and observation window.",
]


def number(value: Any) -> int | float | None:
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def room_status(window: Any) -> str:
    value = number(window)
    return "INSUFFICIENT_WINDOW" if value is None or value < 20 else "OBSERVED"


def build_sample(raw: Mapping[str, Any], *, fetched_at: str, source_sha256: str,
                 collector_version: str, git_revision: str | None = None,
                 content_length: int | None = None) -> dict[str, Any]:
    rollup = raw.get("engagement") if isinstance(raw.get("engagement"), Mapping) else {}
    source_rooms = raw.get("rooms") if isinstance(raw.get("rooms"), list) else []
    per_room = []
    for candidate in source_rooms[:200]:
        item = candidate if isinstance(candidate, Mapping) else {}
        room = item.get("room")
        per_room.append({
            "room": room[:48] if isinstance(room, str) else "",
            "window": number(item.get("window")),
            "zero_response_share": number(item.get("zero_response_share")),
            "nick_diversity": number(item.get("nick_diversity")),
            "last_seq": number(item.get("last_seq")),
            "first_seq": number(item.get("first_seq")),
            "idle_seconds": number(item.get("idle_seconds")),
            "generation": number(item.get("generation")),
            "status": room_status(item.get("window")),
            "untrusted": True,
        })
    notes = raw.get("notes") if isinstance(raw.get("notes"), Mapping) else {}
    warnings = list(CAVEATS)
    warnings.append("BUDGET_METADATA_UNAVAILABLE")
    return {
        "schema": "engagement-sample-v1", "fetched_at": fetched_at,
        "source_url": SOURCE_URL, "source_sha256": source_sha256,
        "collector_version": collector_version, "git_revision": git_revision,
        "content_length": content_length, "http_status": 200,
        "evidence_level": "OFFICIAL_PUBLIC_ENDPOINT", "limit": 200,
        "returned_rooms": len(per_room), "rooms_total": number(raw.get("total")),
        "windowed_messages": number(rollup.get("windowed_messages")),
        "zero_response_share": number(rollup.get("zero_response_share")),
        "nick_diversity": number(rollup.get("nick_diversity")),
        "windowed_note_to_message_ratio": number(rollup.get("windowed_note_to_message_ratio")),
        "notes_total": number(notes.get("total")) if notes else number(raw.get("notes_total")),
        "notes_capacity": number(notes.get("capacity")) if notes else number(raw.get("notes_capacity")),
        "observed_spec_version": raw.get("version") if isinstance(raw.get("version"), str) else None,
        "coverage": {"scope": "OBSERVED_COVERAGE_ONLY", "returned_rooms": len(per_room),
                     "rooms_total": number(raw.get("total"))},
        "warnings": warnings, "per_room": per_room,
    }


def _delta(current: Any, previous: Any) -> int | float | None:
    return current - previous if number(current) is not None and number(previous) is not None else None


def diff(previous: Mapping[str, Any] | None, current: Mapping[str, Any]) -> dict[str, Any]:
    prior = previous or {}
    old = {r.get("room"): r for r in prior.get("per_room", []) if isinstance(r, Mapping)}
    new = {r.get("room"): r for r in current.get("per_room", []) if isinstance(r, Mapping)}
    return {
        "schema": "engagement-diff-v1", "generated_at": current["fetched_at"],
        "comparison": "OBSERVED_ENGAGEMENT_CHANGE" if previous else "NO_PREVIOUS_SAMPLE",
        "delta_zero_response_share": _delta(current.get("zero_response_share"), prior.get("zero_response_share")),
        "delta_nick_diversity": _delta(current.get("nick_diversity"), prior.get("nick_diversity")),
        "delta_notes_total": _delta(current.get("notes_total"), prior.get("notes_total")),
        "new_rooms": sorted(k for k in new.keys() - old.keys() if k),
        "not_observed_in_latest_snapshot": sorted(k for k in old.keys() - new.keys() if k),
        "changed_rooms": sorted(k for k in old.keys() & new.keys() if old[k] != new[k] and k),
        "evidence_level": "LOCAL_DERIVED", "warnings": list(CAVEATS),
    }


def series(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    fields = ("fetched_at", "zero_response_share", "nick_diversity", "notes_total",
              "windowed_messages", "returned_rooms", "rooms_total")
    return {"schema": "engagement-series-v1", "window_days": 7,
            "points": [{field: row.get(field) for field in fields} for row in rows][-672:],
            "interpretation": "NO_PERSISTENT_CHANGE_ESTABLISHED",
            "evidence_level": "LOCAL_DERIVED", "warnings": list(CAVEATS)}
