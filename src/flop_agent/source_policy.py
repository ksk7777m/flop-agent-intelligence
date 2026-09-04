"""Explicit source trust policy; discovered URLs never modify this allowlist."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import IntEnum
from typing import Dict

from .remote_content_policy import ContractProvenance, ReviewedSourceId, SourceTrustTier


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


def assess_source_v2(source_id: ReviewedSourceId | str, *, signed_community: bool = False,
                     conflicting: bool = False) -> SourceAssessmentV2:
    """Classify source identity without granting contract authority."""
    if conflicting:
        tier = SourceTrustTier.TIER_3_SUSPICIOUS_CONFLICTING
        reason = "source evidence is suspicious or conflicting"
    elif isinstance(source_id, ReviewedSourceId):
        tier = SourceTrustTier.TIER_0_OFFICIAL
        reason = "explicitly configured first-party source"
    elif signed_community:
        tier = SourceTrustTier.TIER_1_SIGNED_COMMUNITY
        reason = "DID signature authenticates a community signer, not official authority"
    else:
        tier = SourceTrustTier.TIER_2_UNSIGNED_COMMUNITY
        reason = "unsigned or otherwise unverified community source"
    return SourceAssessmentV2(
        source_id.value if isinstance(source_id, ReviewedSourceId) else source_id, tier,
        ContractProvenance.CONFLICTING if conflicting else ContractProvenance.UNVERIFIED,
        reason,
    )


def assess_source(source_id: ReviewedSourceId | str, directly_linked_by_tier1: bool = False) -> SourceAssessment:
    if isinstance(source_id, ReviewedSourceId):
        return SourceAssessment(source_id.value, 1, True, True, "internally registered first-party source")
    source_name = str(source_id)
    if directly_linked_by_tier1:
        return SourceAssessment(
            source_name, 2, False, False,
            "linked targets do not inherit first-party trust; exact provenance review is required",
        )
    return SourceAssessment(
        source_name, 3, False, False,
        "community, mirror, aggregator, or otherwise unverified source",
    )
