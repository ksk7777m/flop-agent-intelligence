"""Small, explicit evidence schema for public Technocore activity."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional

from .wire_evidence import parse_nonce


@dataclass(frozen=True)
class ProofRecord:
    proof_type: str
    source: str
    did: str
    timestamp: Optional[str]
    verification_method: str
    persistence: str
    activity_type: Optional[str] = None
    official_status: str = "UNKNOWN"
    external_reference: Optional[str] = None
    registry_key: Optional[str] = None
    mailbox: Optional[str] = None
    room: Optional[str] = None
    nonce: Optional[str] = None
    text_after_sweep: Optional[str] = None
    signature: Optional[str] = None
    seq: Optional[int] = None
    permalink: Optional[str] = None
    contribution: Optional[str] = None
    git_commit_hash: Optional[str] = None

    def __post_init__(self) -> None:
        if self.nonce is not None:
            parse_nonce(self.nonce)

    def as_dict(self) -> Dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}
