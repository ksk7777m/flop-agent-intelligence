from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from .technocore import permalink
from .remote_content_policy import MAX_LOCAL_RAW_EVIDENCE_CHARS


def append_activity(
    jsonl_path: Path, markdown_path: Path, room: str, message: Dict[str, Any],
    evidence: Dict[str, Any] | None = None,
) -> None:
    evidence = evidence or {}
    message_origin = evidence.get("content_origin", "LOCAL_APPROVED_OUTBOUND")
    raw_text = str(message.get("swept_text", message["text"]))
    raw_input = str(message.get("input_text", message["text"]))
    raw_allowed = message_origin == "LOCAL_APPROVED_OUTBOUND"
    if raw_allowed and (len(raw_text) > MAX_LOCAL_RAW_EVIDENCE_CHARS
                        or len(raw_input) > MAX_LOCAL_RAW_EVIDENCE_CHARS):
        raise ValueError("approved outbound evidence text exceeds the local bound")
    note = evidence.get("note_value")
    record = {
        "activity_type": evidence.get("activity_type", message.get("activity_type", "signed_message")),
        "proof_type": "signed_message",
        "official_status": message.get("official_status", "OFFICIAL_RECOMMENDED"),
        "source": "technocore.chat",
        "did": message["from"], "room": room, "seq": message["seq"], "timestamp": message["ts"],
        "nonce": message.get("nonce"),
        "content_origin": message_origin,
        "content_length": len(raw_text.encode("utf-8")),
        "content_sha256": hashlib.sha256(raw_text.encode("utf-8")).hexdigest(),
        "input_text": raw_input if raw_allowed else None,
        "text_after_sweep": raw_text if raw_allowed else None,
        "signature": message.get("signature"),
        "contribution": evidence.get("contribution"),
        "repository": evidence.get("repository"),
        "git_commit_hash": evidence.get("git_commit_hash"),
        "receipt_fingerprint": evidence.get("receipt_fingerprint"),
        "approval_status": evidence.get("approval_status"),
        "mailbox": evidence.get("mailbox"),
        "note_path": evidence.get("note_path"),
        "note_length": len(str(note).encode("utf-8")) if note is not None else None,
        "note_hash": (evidence.get("note_hash")
                      or (hashlib.sha256(str(note).encode("utf-8")).hexdigest() if note is not None else None)),
        "x25519_public_key": evidence.get("x25519_public_key"),
        "verification_method": "Ed25519 over UTF-8 room|nonce|text_after_sweep; server-verified DID",
        "persistence": "Technocore room ring; local JSONL is the retained receipt",
        "permalink": permalink(room, message["seq"]),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    record = {key: value for key, value in record.items() if value is not None}
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    with jsonl_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    with markdown_path.open("a", encoding="utf-8") as handle:
        display = raw_text if raw_allowed else f"remote content SHA-256 {record['content_sha256']}"
        handle.write(f"\n- {record['timestamp']} — `{room}` seq {record['seq']} — {display} — [permalink]({record['permalink']}) — DID `{record['did']}`\n")
