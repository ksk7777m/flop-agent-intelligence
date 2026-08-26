"""Dry-run-only plans for optional Technocore conventions.

No function in this module performs network I/O. Note writes remain subject to
manual approval because ordinary KV notes are unsigned and world-writable.
"""

from __future__ import annotations

import hashlib
from typing import Dict


def did_fingerprint(did: str) -> str:
    return hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]


def did_profile_plan(did: str) -> Dict[str, object]:
    fingerprint = did_fingerprint(did)
    return {
        "dry_run": True,
        "manual_approval_required": True,
        "official_status": "OFFICIAL_RECOMMENDED",
        "operation": "ordinary unsigned KV note write",
        "namespace": f"did-{fingerprint[:2]}",
        "key": fingerprint[2:],
        "value": did,
        "registry_key": f"/kv/did-{fingerprint[:2]}/{fingerprint[2:]}",
        "security": "world-readable, world-writable, overwriteable; note itself proves no ownership",
    }


def contribution_note_plan(did: str, summary: str, external_reference: str | None = None) -> Dict[str, object]:
    fingerprint = did_fingerprint(did)
    value = f"technocore-contribution-v1 did:{did} summary:{summary}"
    if external_reference:
        value += f" url:{external_reference}"
    return {
        "dry_run": True,
        "manual_approval_required": True,
        "official_status": "COMMUNITY_PRACTICE",
        "operation": "ordinary unsigned KV note write",
        "namespace": "contrib",
        "key": fingerprint,
        "value": value,
        "registry_key": f"/kv/contrib/{fingerprint}",
        "security": "world-readable, world-writable, overwriteable; no DID-owner verification",
    }

