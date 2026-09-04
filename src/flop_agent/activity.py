from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from .technocore import permalink
from .remote_content_policy import (
    MAX_LOCAL_RAW_EVIDENCE_CHARS,
    LocalActionClass,
    ReviewedLocalIntent,
    RemoteOrigin,
    discovered_remote_value,
    require_local_intent,
)

_ROOT = Path(__file__).resolve().parents[2]
_PUBLIC_ACTIVITY_JSONL = (_ROOT / "data/activity.jsonl").resolve()
_PUBLIC_ACTIVITY_MARKDOWN = (_ROOT / "docs/ACTIVITY_LOG.md").resolve()


def append_activity(
    jsonl_path: Path, markdown_path: Path, room: str, message: Dict[str, Any],
    evidence: Dict[str, Any] | None = None,
    *, local_provenance: ReviewedLocalIntent | None = None,
    revision: str | None = None,
    config_version: str | None = None,
    context: str = "local-activity-record",
    output_scope: str = "PUBLIC",
) -> None:
    """Write only to the two repository-configured activity destinations."""
    if (jsonl_path.resolve() != _PUBLIC_ACTIVITY_JSONL
            or markdown_path.resolve() != _PUBLIC_ACTIVITY_MARKDOWN):
        raise PermissionError("activity output paths are fixed local configuration")
    _append_activity_at_configured_paths(
        jsonl_path, markdown_path, room, message, evidence,
        local_provenance=local_provenance, revision=revision,
        config_version=config_version, context=context, output_scope=output_scope)


def _append_activity_at_configured_paths(
    jsonl_path: Path, markdown_path: Path, room: str, message: Dict[str, Any],
    evidence: Dict[str, Any] | None = None, *,
    local_provenance: ReviewedLocalIntent | None = None,
    revision: str | None = None, config_version: str | None = None,
    context: str = "local-activity-record", output_scope: str = "PUBLIC",
) -> None:
    """Mechanism used by the fixed-path production wrapper and isolated tests."""
    evidence = evidence or {}
    raw_text = str(message.get("swept_text", message["text"]))
    raw_input = str(message.get("input_text", message["text"]))
    local_origin = False
    if local_provenance is not None:
        require_local_intent(
            local_provenance, LocalActionClass.LOCAL_ACTIVITY_RAW, raw_text,
            target=str(jsonl_path.resolve()), payload=raw_text, context=context,
            revision=revision, config_version=config_version)
        local_origin = True
    raw_allowed = local_origin and output_scope == "LOCAL_ONLY"
    message_origin = ("TYPED_LOCAL_RAW" if raw_allowed else
                      "TYPED_LOCAL_HASH_ONLY" if local_origin else "REMOTE_OR_UNKNOWN")
    if raw_allowed and (len(raw_text) > MAX_LOCAL_RAW_EVIDENCE_CHARS
                        or len(raw_input) > MAX_LOCAL_RAW_EVIDENCE_CHARS):
        raise ValueError("approved outbound evidence text exceeds the local bound")
    local_evidence = evidence if local_origin else {}
    note = local_evidence.get("note_value")
    remote_summary: Dict[str, Any] = {}
    if not raw_allowed:
        remote_summary = discovered_remote_value(
            raw_text, RemoteOrigin.TECHNOCORE_MESSAGE, "activity-message").evidence()
    record = {
        "activity_type": local_evidence.get("activity_type", "signed_message" if local_origin else "remote_observation"),
        "proof_type": "signed_message",
        "official_status": message.get("official_status", "OFFICIAL_RECOMMENDED") if local_origin else "UNVERIFIED",
        "source": "technocore.chat",
        "did": message["from"] if local_origin else None,
        "did_sha256": hashlib.sha256(str(message.get("from", "")).encode()).hexdigest(),
        "room": room if local_origin else None,
        "room_length": len(room.encode("utf-8")),
        "room_sha256": hashlib.sha256(room.encode("utf-8")).hexdigest(),
        "seq": message["seq"] if isinstance(message.get("seq"), int) else None,
        "timestamp": message["ts"] if local_origin else datetime.now(timezone.utc).isoformat(),
        "source_timestamp_sha256": hashlib.sha256(str(message.get("ts", "")).encode()).hexdigest(),
        "nonce": message.get("nonce") if local_origin else None,
        "content_origin": message_origin,
        "content_length": len(raw_text.encode("utf-8")),
        "content_sha256": hashlib.sha256(raw_text.encode("utf-8")).hexdigest(),
        "classifications": remote_summary.get("classifications", ["UNKNOWN"]),
        "source_id": remote_summary.get("source_id", "unknown"),
        "input_text": raw_input if raw_allowed else None,
        "text_after_sweep": raw_text if raw_allowed else None,
        "signature": message.get("signature") if local_origin else None,
        "contribution": local_evidence.get("contribution"),
        "repository": local_evidence.get("repository"),
        "git_commit_hash": local_evidence.get("git_commit_hash"),
        "receipt_fingerprint": local_evidence.get("receipt_fingerprint"),
        "approval_status": local_evidence.get("approval_status"),
        "mailbox": local_evidence.get("mailbox"),
        "note_path": local_evidence.get("note_path"),
        "note_length": len(str(note).encode("utf-8")) if note is not None else None,
        "note_hash": (local_evidence.get("note_hash")
                      or (hashlib.sha256(str(note).encode("utf-8")).hexdigest() if note is not None else None)),
        "x25519_public_key": local_evidence.get("x25519_public_key"),
        "verification_method": "Ed25519 over UTF-8 room|nonce|text_after_sweep; server-verified DID",
        "persistence": "Technocore room ring; local JSONL is the retained receipt",
        "permalink": permalink(room, message["seq"]) if local_origin else None,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    record = {key: value for key, value in record.items() if value is not None}
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    with jsonl_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    with markdown_path.open("a", encoding="utf-8") as handle:
        display = raw_text if raw_allowed else f"remote or unknown content SHA-256 {record['content_sha256']}"
        room_display = room if local_origin else f"room SHA-256 {record['room_sha256']}"
        link = f" — [permalink]({record['permalink']})" if record.get("permalink") else ""
        did_display = record.get("did") or f"DID SHA-256 {record['did_sha256']}"
        handle.write(f"\n- {record['timestamp']} — `{room_display}` seq {record.get('seq', 'unknown')} — {display}{link} — `{did_display}`\n")
