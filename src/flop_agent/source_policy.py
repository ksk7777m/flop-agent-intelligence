"""Explicit source trust policy; discovered URLs never modify this allowlist."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import IntEnum
from typing import Dict

from .remote_content_policy import ContractProvenance, SourceTrustTier


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


@dataclass(frozen=True)
class SourceAssessmentV2:
    source_id: str
    source_trust_tier: SourceTrustTier
    contract_provenance: ContractProvenance
    reason: str

    def as_dict(self) -> Dict[str, object]:
        value = asdict(self)
        value["source_trust_tier"] = self.source_trust_tier.value
        value["contract_provenance"] = self.contract_provenance.value
        return value


def assess_source_v2(source_id: str, *, signed_community: bool = False,
                     conflicting: bool = False) -> SourceAssessmentV2:
    """Classify source identity without granting contract authority."""
    if conflicting:
        tier = SourceTrustTier.TIER_3_SUSPICIOUS_CONFLICTING
        reason = "source evidence is suspicious or conflicting"
    elif source_id in TIER_1:
        tier = SourceTrustTier.TIER_0_OFFICIAL
        reason = "explicitly configured first-party source"
    elif signed_community:
        tier = SourceTrustTier.TIER_1_SIGNED_COMMUNITY
        reason = "DID signature authenticates a community signer, not official authority"
    else:
        tier = SourceTrustTier.TIER_2_UNSIGNED_COMMUNITY
        reason = "unsigned or otherwise unverified community source"
    return SourceAssessmentV2(
        source_id, tier,
        ContractProvenance.CONFLICTING if conflicting else ContractProvenance.UNVERIFIED,
        reason,
    )


def assess_source(source_id: str, directly_linked_by_tier1: bool = False) -> SourceAssessment:
    if source_id in TIER_1:
        return SourceAssessment(source_id, 1, True, True, "configured first-party source")
    if directly_linked_by_tier1:
        return SourceAssessment(
            source_id, 2, False, False,
            "linked targets do not inherit first-party trust; exact provenance review is required",
        )
    return SourceAssessment(
        source_id, 3, False, False,
        "community, mirror, aggregator, or otherwise unverified source",
    )
