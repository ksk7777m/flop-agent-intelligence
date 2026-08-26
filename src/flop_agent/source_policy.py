"""Explicit source trust policy; discovered URLs never modify this allowlist."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import IntEnum
from typing import Dict


class SourceTier(IntEnum):
    AUTHORITATIVE = 1
    DIRECTLY_LINKED = 2
    COMMUNITY = 3


@dataclass(frozen=True)
class SourceAssessment:
    source_id: str
    tier: int
    authoritative: bool
    can_confirm_sensitive_claims: bool
    reason: str

    def as_dict(self) -> Dict[str, object]:
        return asdict(self)


TIER_1 = {
    "crypto_hayes_x",
    "flop_labs_x",
    "flop_finance",
    "flop_labs_github",
    "technocore_live",
    "technocore_github",
}


def assess_source(source_id: str, directly_linked_by_tier1: bool = False) -> SourceAssessment:
    if source_id in TIER_1:
        return SourceAssessment(source_id, 1, True, True, "configured first-party source")
    if directly_linked_by_tier1:
        return SourceAssessment(
            source_id, 2, False, True,
            "document directly linked by a configured first-party source; provenance must be retained",
        )
    return SourceAssessment(
        source_id, 3, False, False,
        "community, mirror, aggregator, or otherwise unverified source",
    )

