"""Conservative, evidence-aware signal classification."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List

from .remote_content_policy import (
    RemoteContentClass,
    RemoteOrigin,
    ReviewedSourceId,
    SourceTrustTier,
    discovered_remote_value,
)

CRITICAL = ("testnet launch", "faucet", "airdrop snapshot", "claim", "deadline", "registration deadline", "wallet linking", "did registration", "eligibility", "contract address", "genesis")
ACTION = ("technocore task", "specific tasks", "official task", "challenge", "workflow integration", "integration", "testnet feature", "miner", "validator", "did requirement")
INFO = ("ama", "roadmap", "interview", "technical", "announcement")
IGNORE = ("price prediction", "price speculation", "referral", "guaranteed airdrop", "unofficial token")
SECURITY = ("seed phrase", "reveal your seed", "private key", "wallet key", "approve unlimited", "token transfer", "wallet connect", "claim now", "urgent snapshot", "send funds", "bridge assets", "unknown contract")


@dataclass(frozen=True)
class Classification:
    category: str
    security_review_required: bool
    reasons: List[str]
    official: bool

    def as_dict(self) -> Dict[str, object]:
        return asdict(self)


def _hits(text: str, phrases: Iterable[str]) -> List[str]:
    lowered = text.casefold()
    return [phrase for phrase in phrases if phrase in lowered]


def classify(text: str, source_id: ReviewedSourceId | None = None) -> Classification:
    official = isinstance(source_id, ReviewedSourceId)
    remote = discovered_remote_value(
        text,
        RemoteOrigin.FETCHED_CONTENT if official else RemoteOrigin.TECHNOCORE_MESSAGE,
        source_id.value if official else "untrusted-content",
        trust_tier=(SourceTrustTier.TIER_0_OFFICIAL if official
                    else SourceTrustTier.TIER_2_UNSIGNED_COMMUNITY),
    )
    policy_hits = [finding.content_class.value for finding in remote.findings
                   if finding.content_class not in {
                       RemoteContentClass.PLAIN_TEXT,
                       RemoteContentClass.URL,
                       RemoteContentClass.CONTRACT_ADDRESS_CANDIDATE,
                   }]
    if policy_hits:
        return Classification("SECURITY_REVIEW_REQUIRED", True, policy_hits, official)
    security_hits = _hits(text, SECURITY)
    ignore_hits = _hits(text, IGNORE)
    if security_hits:
        return Classification("SECURITY_REVIEW_REQUIRED", True, security_hits, official)
    if ignore_hits or (not official and _hits(text, CRITICAL)):
        return Classification("IGNORE", False, ignore_hits or ["critical claim lacks an official source"], official)
    for category, phrases in (("CRITICAL", CRITICAL), ("ACTION", ACTION), ("INFO", INFO)):
        hits = _hits(text, phrases)
        if hits:
            return Classification(category, False, hits, official)
    if re.search(r"https?://", text) and not official:
        return Classification("IGNORE", False, ["untrusted external URL"], official)
    return Classification("INFO", False, ["no actionable official keyword"], official)
