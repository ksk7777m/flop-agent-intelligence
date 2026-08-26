from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from .technocore import permalink


def append_activity(
    jsonl_path: Path, markdown_path: Path, room: str, message: Dict[str, Any],
    evidence: Dict[str, Any] | None = None,
) -> None:
    evidence = evidence or {}
    record = {
        "activity_type": evidence.get("activity_type", message.get("activity_type", "signed_message")),
        "proof_type": "signed_message",
        "official_status": message.get("official_status", "OFFICIAL_RECOMMENDED"),
        "source": "technocore.chat",
        "did": message["from"], "room": room, "seq": message["seq"], "timestamp": message["ts"],
        "nonce": message.get("nonce"),
        "input_text": message.get("input_text", message["text"]),
        "text_after_sweep": message.get("swept_text", message["text"]),
        "signature": message.get("signature"),
        "contribution": evidence.get("contribution"),
        "repository": evidence.get("repository"),
        "git_commit_hash": evidence.get("git_commit_hash"),
        "receipt_fingerprint": evidence.get("receipt_fingerprint"),
        "approval_status": evidence.get("approval_status"),
        "mailbox": evidence.get("mailbox"),
        "note_path": evidence.get("note_path"),
        "note_value": evidence.get("note_value"),
        "note_hash": evidence.get("note_hash"),
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
        handle.write(f"\n- {record['timestamp']} — `{room}` seq {record['seq']} — {record['text_after_sweep']} — [permalink]({record['permalink']}) — DID `{record['did']}`\n")
