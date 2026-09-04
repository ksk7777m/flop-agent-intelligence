"""Mandatory fail-closed policy for remote content.

Remote values are evidence-bearing data.  They never acquire authority to
select a fetch, path, process, installer, signer, wallet, or payment target.
Configured read-only endpoints are created through a separate constructor so
that an identical URL discovered in remote text remains inert.
"""

from __future__ import annotations

import hashlib
import base64
import binascii
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Mapping, TypeVar
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


POLICY_VERSION = "technocore-untrusted-input-policy-v1"
MAX_CLASSIFICATION_CHARS = 64 * 1024
MAX_LOCAL_RAW_EVIDENCE_CHARS = 4096
DEFAULT_RESPONSE_LIMIT = 2 * 1024 * 1024
DEFAULT_HTTP_TIMEOUT_SECONDS = 20


class RemoteOrigin(str, Enum):
    CONFIGURED_OFFICIAL_ENDPOINT = "CONFIGURED_OFFICIAL_ENDPOINT"
    TECHNOCORE_ROOM = "TECHNOCORE_ROOM"
    TECHNOCORE_TOPIC = "TECHNOCORE_TOPIC"
    TECHNOCORE_MESSAGE = "TECHNOCORE_MESSAGE"
    TECHNOCORE_NICK = "TECHNOCORE_NICK"
    TECHNOCORE_KV_NAMESPACE = "TECHNOCORE_KV_NAMESPACE"
    TECHNOCORE_KV_KEY = "TECHNOCORE_KV_KEY"
    TECHNOCORE_KV_VALUE = "TECHNOCORE_KV_VALUE"
    TECHNOCORE_MAILBOX = "TECHNOCORE_MAILBOX"
    TECHNOCORE_DID_NOTE = "TECHNOCORE_DID_NOTE"
    FETCHED_CONTENT = "FETCHED_CONTENT"
    HTTP_ERROR_BODY = "HTTP_ERROR_BODY"
    REMOTE_DISCOVERED_URL = "REMOTE_DISCOVERED_URL"
    REMOTE_FIXTURE = "REMOTE_FIXTURE"


class RemoteContentClass(str, Enum):
    PLAIN_TEXT = "PLAIN_TEXT"
    URL = "URL"
    SHELL_COMMAND = "SHELL_COMMAND"
    CODE_SNIPPET = "CODE_SNIPPET"
    PACKAGE_INSTALL_INSTRUCTION = "PACKAGE_INSTALL_INSTRUCTION"
    REPOSITORY_INSTALL_INSTRUCTION = "REPOSITORY_INSTALL_INSTRUCTION"
    MCP_REFERENCE = "MCP_REFERENCE"
    MCP_INSTALL_INSTRUCTION = "MCP_INSTALL_INSTRUCTION"
    SECRET_REQUEST = "SECRET_REQUEST"
    SIGNING_REQUEST = "SIGNING_REQUEST"
    WALLET_CONNECT_REQUEST = "WALLET_CONNECT_REQUEST"
    CLAIM_REQUEST = "CLAIM_REQUEST"
    PAYMENT_REQUEST = "PAYMENT_REQUEST"
    CONTRACT_ADDRESS_CANDIDATE = "CONTRACT_ADDRESS_CANDIDATE"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    UNKNOWN_SENSITIVE_INSTRUCTION = "UNKNOWN_SENSITIVE_INSTRUCTION"


class SourceTrustTier(str, Enum):
    TIER_0_OFFICIAL = "TIER_0_OFFICIAL"
    TIER_1_SIGNED_COMMUNITY = "TIER_1_SIGNED_COMMUNITY"
    TIER_2_UNSIGNED_COMMUNITY = "TIER_2_UNSIGNED_COMMUNITY"
    TIER_3_SUSPICIOUS_CONFLICTING = "TIER_3_SUSPICIOUS_CONFLICTING"


class ContractProvenance(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    OFFICIAL_SOURCE_REFERENCED = "OFFICIAL_SOURCE_REFERENCED"
    MULTI_SOURCE_CONFIRMED = "MULTI_SOURCE_CONFIRMED"
    CONFLICTING = "CONFLICTING"
    VERIFIED_FOR_TESTNET_USE = "VERIFIED_FOR_TESTNET_USE"


class SinkClass(str, Enum):
    HTTP_READ_ONLY = "HTTP_READ_ONLY"
    PUBLIC_NAVIGATION = "PUBLIC_NAVIGATION"
    SUBPROCESS = "SUBPROCESS"
    SHELL = "SHELL"
    EVAL_EXEC = "EVAL_EXEC"
    FILESYSTEM_PATH = "FILESYSTEM_PATH"
    FILESYSTEM_WRITE = "FILESYSTEM_WRITE"
    REPOSITORY_INSTALLER = "REPOSITORY_INSTALLER"
    PACKAGE_INSTALLER = "PACKAGE_INSTALLER"
    MCP_INSTALLER = "MCP_INSTALLER"
    MCP_INVOCATION = "MCP_INVOCATION"
    SIGNER = "SIGNER"
    WALLET = "WALLET"
    CLAIM = "CLAIM"
    PAYMENT = "PAYMENT"
    SECRET_ACCESS = "SECRET_ACCESS"


class DecisionCode(str, Enum):
    ALLOW_CONFIGURED_READ_ONLY = "ALLOW_CONFIGURED_READ_ONLY"
    DENY_UNTRUSTED_INPUT = "DENY_UNTRUSTED_INPUT"
    DENY_DISCOVERED_URL = "DENY_DISCOVERED_URL"
    DENY_EXECUTION = "DENY_EXECUTION"
    DENY_SIGNING = "DENY_SIGNING"
    DENY_WALLET = "DENY_WALLET"
    DENY_MCP_CUSTODY = "DENY_MCP_CUSTODY"
    REQUIRE_HUMAN_APPROVAL = "REQUIRE_HUMAN_APPROVAL"
    REQUIRE_PROVENANCE_REVIEW = "REQUIRE_PROVENANCE_REVIEW"


class NavigationState(str, Enum):
    INERT = "INERT"
    REVIEWED_OFFICIAL = "REVIEWED_OFFICIAL"
    APPROVED_FOR_NAVIGATION = "APPROVED_FOR_NAVIGATION"


@dataclass(frozen=True)
class RemoteOriginMetadata:
    origin: RemoteOrigin
    source_id: str
    observed_at: str
    trust_tier: SourceTrustTier = SourceTrustTier.TIER_2_UNSIGNED_COMMUNITY
    freshness: str = "UNKNOWN"

    def __post_init__(self) -> None:
        if not self.source_id.strip() or not self.observed_at.strip():
            raise ValueError("remote origin requires source_id and observed_at")


@dataclass(frozen=True)
class SafetyFinding:
    content_class: RemoteContentClass
    reason: str


@dataclass(frozen=True)
class UntrustedRemoteValue:
    metadata: RemoteOriginMetadata
    length: int
    content_sha256: str
    findings: tuple[SafetyFinding, ...]
    _value: str = field(repr=False, compare=False)
    _authority: object | None = field(default=None, repr=False, compare=False)
    policy_version: str = POLICY_VERSION

    @property
    def value_for_classification_only(self) -> str:
        """Return bounded runtime data; callers must still pass a sink guard."""
        return self._value

    def evidence(self) -> dict[str, Any]:
        """A safe summary that deliberately omits raw remote content."""
        return {
            "policy_version": self.policy_version,
            "origin": self.metadata.origin.value,
            "source_id": self.metadata.source_id,
            "observed_at": self.metadata.observed_at,
            "trust_tier": self.metadata.trust_tier.value,
            "freshness": self.metadata.freshness,
            "length": self.length,
            "content_sha256": self.content_sha256,
            "classifications": [finding.content_class.value for finding in self.findings],
        }


@dataclass(frozen=True)
class HumanApprovalEvidence:
    """Non-authoritative display evidence retained for compatibility.

    Caller-provided fields are never accepted as a local capability.
    """
    reviewer: str
    approved_at: str
    purpose: str
    subject_sha256: str


class ReviewedSourceId(str, Enum):
    TECHNOCORE_README = "TECHNOCORE_README"
    TECHNOCORE_SECURITY = "TECHNOCORE_SECURITY"
    TECHNOCORE_PATTERNS = "TECHNOCORE_PATTERNS"
    TECHNOCORE_LLMS = "TECHNOCORE_LLMS"
    TECHNOCORE_SKILL = "TECHNOCORE_SKILL"
    TECHNOCORE_HEALTH = "TECHNOCORE_HEALTH"
    TECHNOCORE_DID_NOTE = "TECHNOCORE_DID_NOTE"
    TECHNOCORE_CONTRIBUTION = "TECHNOCORE_CONTRIBUTION"
    TECHNOCORE_AGENT_MANIFEST = "TECHNOCORE_AGENT_MANIFEST"
    TECHNOCORE_ROOMS_SUMMARY = "TECHNOCORE_ROOMS_SUMMARY"
    TECHNOCORE_ROOMS = "TECHNOCORE_ROOMS"
    TECHNOCORE_ROOMS_JSON = "TECHNOCORE_ROOMS_JSON"
    TECHNOCORE_LOBBY_JSON = "TECHNOCORE_LOBBY_JSON"
    TECHNOCORE_PATTERNS_HOSTED = "TECHNOCORE_PATTERNS_HOSTED"
    TECHNOCORE_CONFIG = "TECHNOCORE_CONFIG"
    PUBLIC_REPOSITORY_API = "PUBLIC_REPOSITORY_API"
    TECHNOCORE_REPOSITORY_API = "TECHNOCORE_REPOSITORY_API"
    ORIGINAL_COMMIT_API = "ORIGINAL_COMMIT_API"
    DASHBOARD_COMMIT_API = "DASHBOARD_COMMIT_API"
    PUBLIC_DASHBOARD = "PUBLIC_DASHBOARD"
    PUBLIC_EVIDENCE = "PUBLIC_EVIDENCE"
    FLOP_FINANCE = "FLOP_FINANCE"
    FLOP_FINANCE_TEASER = "FLOP_FINANCE_TEASER"
    FLOP_LABS_X = "FLOP_LABS_X"
    CONTRIBUTION_X = "CONTRIBUTION_X"


@dataclass(frozen=True)
class ReviewedSource:
    source_id: ReviewedSourceId
    url: str
    method: str = "GET"
    redirects: bool = False
    max_bytes: int = DEFAULT_RESPONSE_LIMIT
    timeout: int = DEFAULT_HTTP_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        parsed = urlparse(self.url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username
                or parsed.password or self.method != "GET"):
            raise ValueError("reviewed sources must be credential-free HTTPS GET endpoints")
        if (not isinstance(self.max_bytes, int) or isinstance(self.max_bytes, bool)
                or self.max_bytes <= 0):
            raise ValueError("reviewed source byte cap must be a positive integer")
        if (not isinstance(self.timeout, int) or isinstance(self.timeout, bool)
                or self.timeout <= 0):
            raise ValueError("reviewed source timeout must be a positive integer")


_REVIEWED_AUTHORITY = object()
_LOCAL_AUTHORITY = object()
_LOCAL_APPROVAL_AUTHORITY = object()
_REVIEWED_SOURCES: Mapping[ReviewedSourceId, ReviewedSource] = MappingProxyType({
    ReviewedSourceId.TECHNOCORE_README: ReviewedSource(ReviewedSourceId.TECHNOCORE_README, "https://raw.githubusercontent.com/flop-labs/technocore-chat/main/README.md"),
    ReviewedSourceId.TECHNOCORE_SECURITY: ReviewedSource(ReviewedSourceId.TECHNOCORE_SECURITY, "https://raw.githubusercontent.com/flop-labs/technocore-chat/main/SECURITY.md"),
    ReviewedSourceId.TECHNOCORE_PATTERNS: ReviewedSource(ReviewedSourceId.TECHNOCORE_PATTERNS, "https://raw.githubusercontent.com/flop-labs/technocore-chat/main/src/patterns.md"),
    ReviewedSourceId.TECHNOCORE_LLMS: ReviewedSource(ReviewedSourceId.TECHNOCORE_LLMS, "https://technocore.chat/llms.txt"),
    ReviewedSourceId.TECHNOCORE_SKILL: ReviewedSource(ReviewedSourceId.TECHNOCORE_SKILL, "https://technocore.chat/skill.md"),
    ReviewedSourceId.TECHNOCORE_HEALTH: ReviewedSource(ReviewedSourceId.TECHNOCORE_HEALTH, "https://technocore.chat/healthz"),
    ReviewedSourceId.TECHNOCORE_DID_NOTE: ReviewedSource(ReviewedSourceId.TECHNOCORE_DID_NOTE, "https://technocore.chat/kv/did-4e/1df29904c79a56"),
    ReviewedSourceId.TECHNOCORE_CONTRIBUTION: ReviewedSource(ReviewedSourceId.TECHNOCORE_CONTRIBUTION, "https://technocore.chat/r/lobby?since=929749&limit=1&format=json"),
    ReviewedSourceId.TECHNOCORE_AGENT_MANIFEST: ReviewedSource(ReviewedSourceId.TECHNOCORE_AGENT_MANIFEST, "https://technocore.chat/.well-known/agent.json"),
    ReviewedSourceId.TECHNOCORE_ROOMS_SUMMARY: ReviewedSource(ReviewedSourceId.TECHNOCORE_ROOMS_SUMMARY, "https://technocore.chat/rooms?limit=1&format=json"),
    ReviewedSourceId.TECHNOCORE_ROOMS: ReviewedSource(ReviewedSourceId.TECHNOCORE_ROOMS, "https://technocore.chat/rooms"),
    ReviewedSourceId.TECHNOCORE_ROOMS_JSON: ReviewedSource(ReviewedSourceId.TECHNOCORE_ROOMS_JSON, "https://technocore.chat/rooms?format=json"),
    ReviewedSourceId.TECHNOCORE_LOBBY_JSON: ReviewedSource(ReviewedSourceId.TECHNOCORE_LOBBY_JSON, "https://technocore.chat/r/lobby?format=json"),
    ReviewedSourceId.TECHNOCORE_PATTERNS_HOSTED: ReviewedSource(ReviewedSourceId.TECHNOCORE_PATTERNS_HOSTED, "https://technocore.chat/patterns.md"),
    ReviewedSourceId.TECHNOCORE_CONFIG: ReviewedSource(ReviewedSourceId.TECHNOCORE_CONFIG, "https://technocore.chat/config"),
    ReviewedSourceId.PUBLIC_REPOSITORY_API: ReviewedSource(ReviewedSourceId.PUBLIC_REPOSITORY_API, "https://api.github.com/repos/ksk7777m/flop-agent-intelligence"),
    ReviewedSourceId.TECHNOCORE_REPOSITORY_API: ReviewedSource(ReviewedSourceId.TECHNOCORE_REPOSITORY_API, "https://api.github.com/repos/flop-labs/technocore-chat"),
    ReviewedSourceId.ORIGINAL_COMMIT_API: ReviewedSource(ReviewedSourceId.ORIGINAL_COMMIT_API, "https://api.github.com/repos/ksk7777m/flop-agent-intelligence/commits/e388c6fd549de2931c40f1647dc1540a78b5c920"),
    ReviewedSourceId.DASHBOARD_COMMIT_API: ReviewedSource(ReviewedSourceId.DASHBOARD_COMMIT_API, "https://api.github.com/repos/ksk7777m/flop-agent-intelligence/commits/1fdc4b014a24bb7bcaf9ca0c0851959dcdef3bc7"),
    ReviewedSourceId.PUBLIC_DASHBOARD: ReviewedSource(ReviewedSourceId.PUBLIC_DASHBOARD, "https://ksk7777m.github.io/flop-agent-intelligence/"),
    ReviewedSourceId.PUBLIC_EVIDENCE: ReviewedSource(ReviewedSourceId.PUBLIC_EVIDENCE, "https://ksk7777m.github.io/flop-agent-intelligence/data/evidence.json"),
    ReviewedSourceId.FLOP_FINANCE: ReviewedSource(ReviewedSourceId.FLOP_FINANCE, "https://flop.finance/"),
    ReviewedSourceId.FLOP_FINANCE_TEASER: ReviewedSource(ReviewedSourceId.FLOP_FINANCE_TEASER, "https://flop.finance/teaser/"),
    ReviewedSourceId.FLOP_LABS_X: ReviewedSource(ReviewedSourceId.FLOP_LABS_X, "https://x.com/flop_labs"),
    ReviewedSourceId.CONTRIBUTION_X: ReviewedSource(ReviewedSourceId.CONTRIBUTION_X, "https://x.com/Giappone_Medici/status/2092613806434218126"),
})


class LocalActionClass(str, Enum):
    SIGNED_ROOM_POST = "SIGNED_ROOM_POST"
    SIGNED_RECORD_LOOKUP = "SIGNED_RECORD_LOOKUP"
    DID_NOTE_CAS = "DID_NOTE_CAS"
    PRESENCE_NOTE_READ = "PRESENCE_NOTE_READ"
    LOCAL_ACTIVITY_RAW = "LOCAL_ACTIVITY_RAW"


@dataclass(frozen=True)
class ReviewedLocalIntent:
    action: LocalActionClass
    subject_sha256: str
    target_sha256: str
    payload_sha256: str
    revision: str
    config_version: str
    approval_id: str
    purpose: str
    _authority: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._authority is not _LOCAL_AUTHORITY:
            raise PermissionError("local authority cannot be caller-constructed")
        if not re.fullmatch(r"[0-9a-f]{64}", self.subject_sha256):
            raise ValueError("local intent requires a SHA-256 subject binding")
        if (not re.fullmatch(r"[0-9a-f]{64}", self.target_sha256)
                or not re.fullmatch(r"[0-9a-f]{64}", self.payload_sha256)
                or not self.config_version or not self.approval_id):
            raise ValueError("local intent requires complete immutable bindings")
        if (self.action is not LocalActionClass.PRESENCE_NOTE_READ
                and not re.fullmatch(r"[0-9a-f]{40}", self.revision)):
            raise ValueError("sensitive local intent requires an exact revision")


@dataclass(frozen=True)
class _ValidatedLocalApproval:
    approval_id: str
    reviewer: str
    approved_at: str
    action: LocalActionClass
    subject_sha256: str
    target_sha256: str
    payload_sha256: str
    revision: str
    config_version: str
    purpose: str
    _authority: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._authority is not _LOCAL_APPROVAL_AUTHORITY:
            raise PermissionError("validated approval cannot be caller-constructed")


# Sensitive approvals are deliberately empty until a separately reviewed local
# approval store exists. JSON, CLI fields, and remote records cannot populate it.
_TRUSTED_LOCAL_REVIEWERS = frozenset()
_LOCAL_APPROVAL_RECORDS: Mapping[str, Mapping[str, str]] = MappingProxyType({})


def _parse_approval_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise PermissionError("approval timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise PermissionError("approval timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def trusted_local_intent(approval_id: str, action: LocalActionClass, subject: str, *,
                         target: str, payload: str, revision: str, config_version: str,
                         purpose: str) -> ReviewedLocalIntent:
    """Mint a sensitive capability only from the immutable local approval store."""
    record = _LOCAL_APPROVAL_RECORDS.get(approval_id)
    if record is None:
        raise PermissionError("approval is not present in the trusted local store")
    if not isinstance(action, LocalActionClass) or action is LocalActionClass.PRESENCE_NOTE_READ:
        raise PermissionError("sensitive action class required")
    if (not re.fullmatch(r"[0-9a-f]{40}", revision)
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", config_version)
            or not target or not payload or not purpose.strip()):
        raise PermissionError("approval binding inputs are malformed")
    approved_at = _parse_approval_time(record.get("approved_at", ""))
    current = _parse_approval_time(utc_now())
    age = (current - approved_at).total_seconds()
    if age < 0 or age > 900:
        raise PermissionError("approval is stale or future-dated")
    bindings = {
        "action": action.value,
        "subject_sha256": hashlib.sha256(subject.encode()).hexdigest(),
        "target_sha256": hashlib.sha256(target.encode()).hexdigest(),
        "payload_sha256": hashlib.sha256(payload.encode()).hexdigest(),
        "revision": revision,
        "config_version": config_version,
        "purpose": purpose,
    }
    if record.get("reviewer") not in _TRUSTED_LOCAL_REVIEWERS:
        raise PermissionError("approval reviewer is not trusted local configuration")
    if any(record.get(key) != value for key, value in bindings.items()):
        raise PermissionError("approval does not exactly bind this action")
    validated = _ValidatedLocalApproval(
        approval_id, record["reviewer"], record["approved_at"], action,
        bindings["subject_sha256"], bindings["target_sha256"], bindings["payload_sha256"],
        revision, config_version, purpose, _LOCAL_APPROVAL_AUTHORITY,
    )
    return ReviewedLocalIntent(
        action, validated.subject_sha256, validated.target_sha256,
        validated.payload_sha256, revision, config_version, approval_id, purpose,
        _LOCAL_AUTHORITY,
    )


def reviewed_local_intent(action: LocalActionClass, subject: str, purpose: str, *,
                          approval: HumanApprovalEvidence | None = None) -> ReviewedLocalIntent:
    """Create the sole public low-risk intent: a bounded Presence note read."""
    if not isinstance(action, LocalActionClass) or not purpose.strip():
        raise ValueError("reviewed local intent requires a known action and purpose")
    subject_sha256 = hashlib.sha256(subject.encode()).hexdigest()
    if action is not LocalActionClass.PRESENCE_NOTE_READ or approval is not None:
        raise PermissionError("sensitive intents require trusted stored local approval")
    return ReviewedLocalIntent(
        action, subject_sha256, subject_sha256, hashlib.sha256(b"").hexdigest(),
        "STATIC_READ", POLICY_VERSION, "STATIC_PRESENCE_READ", purpose, _LOCAL_AUTHORITY)


def require_local_intent(intent: ReviewedLocalIntent, action: LocalActionClass, subject: str) -> None:
    if not isinstance(intent, ReviewedLocalIntent) or intent._authority is not _LOCAL_AUTHORITY:
        raise PermissionError("typed local intent required")
    if intent.action is not action or intent.subject_sha256 != hashlib.sha256(subject.encode()).hexdigest():
        raise PermissionError("local intent does not match action subject")


@dataclass(frozen=True)
class ActionDecision:
    allowed: bool
    decision: DecisionCode
    sink: SinkClass
    reason: str


class SafeRemoteError(RuntimeError):
    """Remote failure whose message contains metadata but never response text."""

    def __init__(self, error_class: str, *, status: int | None = None,
                 response_length: int | None = None, content_sha256: str | None = None,
                 truncated: bool = False):
        self.error_class = error_class
        self.status = status
        self.response_length = response_length
        self.content_sha256 = content_sha256
        self.truncated = truncated
        fields = [f"class={error_class}"]
        if status is not None:
            fields.append(f"status={status}")
        if response_length is not None:
            fields.append(f"response_length={response_length}")
        if content_sha256 is not None:
            fields.append(f"content_sha256={content_sha256}")
        if truncated:
            fields.append("truncated=true")
        super().__init__("remote request failed (" + ", ".join(fields) + ")")


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        del req, fp, code, msg, headers, newurl
        return None


_PATTERNS: tuple[tuple[RemoteContentClass, re.Pattern[str]], ...] = (
    (RemoteContentClass.PROMPT_INJECTION, re.compile(
        r"ignore\s+(?:all\s+)?previous\s+instructions|system\s+prompt\s+override|"
        r"act\s+as\s+(?:the\s+)?(?:system|developer)", re.I)),
    (RemoteContentClass.SHELL_COMMAND, re.compile(
        r"(?:run|execute)\s+(?:this\s+)?(?:command|shell)|(?:^|\s)(?:curl|wget)\s+", re.I)),
    (RemoteContentClass.CODE_SNIPPET, re.compile(
        r"(?:run|execute)\s+(?:this\s+)?code|```|\beval\s*\(|\bexec\s*\(", re.I)),
    (RemoteContentClass.PACKAGE_INSTALL_INSTRUCTION, re.compile(
        r"\b(?:pip|pip3|npm|pnpm|yarn|brew|apt(?:-get)?)\s+install\b", re.I)),
    (RemoteContentClass.REPOSITORY_INSTALL_INSTRUCTION, re.compile(
        r"\b(?:git\s+clone|clone\s+(?:and\s+)?install|install\s+this\s+(?:repo|repository))\b", re.I)),
    (RemoteContentClass.MCP_REFERENCE, re.compile(r"\bMCP\b", re.I)),
    (RemoteContentClass.MCP_INSTALL_INSTRUCTION, re.compile(
        r"\b(?:install|add|connect|invoke|enable)\s+(?:this\s+)?MCP\b", re.I)),
    (RemoteContentClass.SECRET_REQUEST, re.compile(
        r"\b(?:paste|provide|reveal|import|send|upload)\b.{0,40}\b(?:seed(?: phrase)?|mnemonic|"
        r"private key|signing key|wallet key|API key|SSH key)\b|"
        r"\b(?:dump|print|show|reveal)\b.{0,24}\b(?:environment|env(?:ironment)? variables?)\b", re.I)),
    (RemoteContentClass.SIGNING_REQUEST, re.compile(
        r"\b(?:sign|approve)\s+(?:this\s+)?(?:arbitrary\s+)?(?:payload|message|transaction)\b", re.I)),
    (RemoteContentClass.WALLET_CONNECT_REQUEST, re.compile(
        r"\b(?:connect|link|import)\s+(?:your\s+)?wallet\b|\bwallet\s+connect\b", re.I)),
    (RemoteContentClass.CLAIM_REQUEST, re.compile(
        r"\bclaim\s+(?:the\s+|this\s+)?(?:faucet|airdrop|tokens?)\b|\bclaim\s+here\b", re.I)),
    (RemoteContentClass.PAYMENT_REQUEST, re.compile(
        r"\b(?:send|make|release)\s+(?:funds|payment|crypto|tokens?)\b|\bpay\s+(?:me|now)\b", re.I)),
    (RemoteContentClass.CONTRACT_ADDRESS_CANDIDATE, re.compile(r"(?<![0-9A-Fa-f])0x[0-9A-Fa-f]{40}(?![0-9A-Fa-f])")),
    (RemoteContentClass.UNKNOWN_SENSITIVE_INSTRUCTION, re.compile(
        r"\b(?:escrow|locked|unlock|bridge|approve unlimited|urgent deadline)\b", re.I)),
)
_URL_RE = re.compile(r"(?:https?://|file://|javascript:|data:)[^\s<>'\"]+", re.I)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def evaluate_remote_content(value: Any, metadata: RemoteOriginMetadata) -> UntrustedRemoteValue:
    text = str(value)
    bounded = text[:MAX_CLASSIFICATION_CHARS]
    findings: list[SafetyFinding] = []
    if _URL_RE.search(bounded):
        findings.append(SafetyFinding(RemoteContentClass.URL, "URL-like remote data remains inert"))
    for content_class, pattern in _PATTERNS:
        if pattern.search(bounded):
            findings.append(SafetyFinding(content_class, f"matched {content_class.value.lower()} policy"))
    if not findings:
        findings.append(SafetyFinding(RemoteContentClass.PLAIN_TEXT, "no sensitive pattern matched"))
    return UntrustedRemoteValue(
        metadata=metadata,
        length=len(text.encode("utf-8")),
        content_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        findings=tuple(findings),
        _value=bounded,
    )


def resolve_reviewed_source(source_id: ReviewedSourceId) -> ReviewedSource:
    if not isinstance(source_id, ReviewedSourceId):
        raise PermissionError("reviewed source ID must be an internal enum value")
    return _REVIEWED_SOURCES[source_id]


def configured_official_value(source_id: ReviewedSourceId, *, observed_at: str | None = None) -> UntrustedRemoteValue:
    source = resolve_reviewed_source(source_id)
    metadata = RemoteOriginMetadata(
        RemoteOrigin.CONFIGURED_OFFICIAL_ENDPOINT,
        source.source_id.value,
        observed_at or utc_now(),
        SourceTrustTier.TIER_0_OFFICIAL,
        "CONFIGURED",
    )
    value = evaluate_remote_content(source.url, metadata)
    return UntrustedRemoteValue(**{**value.__dict__, "_authority": _REVIEWED_AUTHORITY})


def discovered_remote_value(value: Any, origin: RemoteOrigin, source_id: str,
                            *, observed_at: str | None = None,
                            trust_tier: SourceTrustTier = SourceTrustTier.TIER_2_UNSIGNED_COMMUNITY) -> UntrustedRemoteValue:
    if origin is RemoteOrigin.CONFIGURED_OFFICIAL_ENDPOINT:
        raise ValueError("use configured_official_value for reviewed configuration")
    return evaluate_remote_content(value, RemoteOriginMetadata(
        origin, source_id, observed_at or utc_now(), trust_tier, "UNKNOWN"))


def authorize_sink(value: UntrustedRemoteValue, sink: SinkClass, *,
                   approval: HumanApprovalEvidence | None = None,
                   contract_provenance: ContractProvenance = ContractProvenance.UNVERIFIED) -> ActionDecision:
    del approval  # Sensitive sinks remain disabled in this package even with evidence.
    if sink in {SinkClass.HTTP_READ_ONLY, SinkClass.PUBLIC_NAVIGATION}:
        if (value.metadata.origin is not RemoteOrigin.CONFIGURED_OFFICIAL_ENDPOINT
                or value._authority is not _REVIEWED_AUTHORITY):
            decision = DecisionCode.DENY_DISCOVERED_URL if any(
                item.content_class is RemoteContentClass.URL for item in value.findings
            ) else DecisionCode.DENY_UNTRUSTED_INPUT
            return ActionDecision(False, decision, sink, "remote-discovered targets are inert")
        source = resolve_reviewed_source(ReviewedSourceId(value.metadata.source_id))
        parsed = urlparse(value.value_for_classification_only)
        if (value.value_for_classification_only != source.url or parsed.scheme != "https"
                or parsed.username or parsed.password or not parsed.hostname
                or value.metadata.trust_tier is not SourceTrustTier.TIER_0_OFFICIAL):
            return ActionDecision(False, DecisionCode.REQUIRE_PROVENANCE_REVIEW, sink,
                                  "target is not an exact reviewed HTTPS endpoint")
        return ActionDecision(True, DecisionCode.ALLOW_CONFIGURED_READ_ONLY, sink,
                              "exact configured official endpoint")

    if sink in {SinkClass.SIGNER}:
        return ActionDecision(False, DecisionCode.DENY_SIGNING, sink, "remote-directed signing is disabled")
    if sink in {SinkClass.WALLET, SinkClass.CLAIM, SinkClass.PAYMENT}:
        return ActionDecision(False, DecisionCode.DENY_WALLET, sink,
                              "wallet, claim, and payment sinks are disabled")
    if sink in {SinkClass.MCP_INSTALLER, SinkClass.MCP_INVOCATION}:
        return ActionDecision(False, DecisionCode.DENY_MCP_CUSTODY, sink,
                              "remote MCP installation/invocation is disabled")
    del contract_provenance
    return ActionDecision(False, DecisionCode.DENY_EXECUTION, sink,
                          "remote values cannot authorize execution or filesystem sinks")


def navigation_state(value: UntrustedRemoteValue) -> NavigationState:
    decision = authorize_sink(value, SinkClass.PUBLIC_NAVIGATION)
    return NavigationState.REVIEWED_OFFICIAL if decision.allowed else NavigationState.INERT


_SECRET_FIELD_RE = re.compile(
    r"(?:private[_-]?key|secret[_-]?key|seed(?:[_-]?phrase)?|mnemonic|signing[_-]?key|"
    r"wallet[_-]?key|x25519[_-]?private|api[_-]?key|ssh[_-]?key|password|token[_-]?secret)", re.I)
MCP_MAX_KEYS = 24


def _decode_base64url(value: str, expected_length: int) -> bytes | None:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        return None
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        return None
    return decoded if len(decoded) == expected_length else None


def _decode_base58btc(value: str) -> bytes | None:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    if not value.startswith("z") or any(char not in alphabet for char in value[1:]):
        return None
    number = 0
    for char in value[1:]:
        number = number * 58 + alphabet.index(char)
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading = len(value[1:]) - len(value[1:].lstrip("1"))
    return b"\0" * leading + decoded


def _did_ed25519_key(value: str) -> bytes | None:
    if not isinstance(value, str) or not value.startswith("did:key:z"):
        return None
    decoded = _decode_base58btc(value[len("did:key:"):])
    if decoded is None or len(decoded) != 34 or decoded[:2] != b"\xed\x01":
        return None
    return decoded[2:]


def _valid_public_key(value: Any, did_key: bytes) -> bool:
    return (isinstance(value, Mapping)
            and set(value) == {"type", "encoding", "value"}
            and value.get("type") == "Ed25519VerificationKey2020"
            and value.get("encoding") == "base64url"
            and _decode_base64url(value.get("value", ""), 32) == did_key)


def _valid_signature(value: Any) -> bool:
    return (isinstance(value, Mapping)
            and set(value) == {"algorithm", "encoding", "value"}
            and value.get("algorithm") == "Ed25519"
            and value.get("encoding") == "base64url"
            and _decode_base64url(value.get("value", ""), 64) is not None)


def _valid_signed_envelope(value: Any) -> bool:
    if not isinstance(value, Mapping) or set(value) != {
        "schema", "context", "public_did", "public_key", "payload_sha256", "signature"
    }:
        return False
    public_key = _did_ed25519_key(value.get("public_did", ""))
    if (value.get("schema") != "flop-public-signed-evidence-v1"
            or value.get("context") != "FLOP_PUBLIC_EVIDENCE"
            or public_key is None
            or not _valid_public_key(value.get("public_key"), public_key)
            or not isinstance(value.get("payload_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", value["payload_sha256"])
            or not _valid_signature(value.get("signature"))):
        return False
    signature = _decode_base64url(value["signature"]["value"], 64)
    signed = b"FLOP_PUBLIC_EVIDENCE\0" + value["payload_sha256"].encode("ascii")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, signed)
    except (InvalidSignature, ValueError):
        return False
    return True


def authorize_remote_mcp_payload(payload: Mapping[str, Any]) -> ActionDecision:
    """Validate exact public-material schemas; never infer custody from a field name."""
    if not isinstance(payload, Mapping) or not payload or len(payload) > MCP_MAX_KEYS:
        valid = False
    else:
        allowed = {"public_did", "public_key", "content_sha256", "evidence_sha256",
                   "public_receipt_id", "status", "signed_envelope", "evidence"}
        valid = set(payload) <= allowed and not any(_SECRET_FIELD_RE.search(str(k)) for k in payload)
        for key in ("content_sha256", "evidence_sha256"):
            if key in payload:
                valid = valid and isinstance(payload[key], str) and bool(re.fullmatch(r"[0-9a-f]{64}", payload[key]))
        if "public_receipt_id" in payload:
            valid = valid and isinstance(payload["public_receipt_id"], str) and bool(re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", payload["public_receipt_id"]))
        if "status" in payload:
            valid = valid and payload["status"] in {"OBSERVED", "VERIFIED", "REJECTED", "UNKNOWN"}
        did_key = _did_ed25519_key(payload.get("public_did", "")) if "public_did" in payload else None
        if "public_did" in payload:
            valid = valid and did_key is not None
        if "public_key" in payload:
            valid = valid and did_key is not None and _valid_public_key(payload["public_key"], did_key)
        if "signed_envelope" in payload:
            envelope = payload["signed_envelope"]
            valid = valid and _valid_signed_envelope(envelope)
        if "evidence" in payload:
            evidence = payload["evidence"]
            valid = valid and isinstance(evidence, Mapping) and set(evidence) <= {
                "schema", "content_sha256", "evidence_sha256", "public_did",
                "public_receipt_id", "status"
            } and evidence.get("schema") == "flop-public-evidence-v1"
            if valid:
                nested = dict(evidence)
                nested.pop("schema")
                nested_decision = authorize_remote_mcp_payload(nested)
                valid = nested_decision.decision is DecisionCode.REQUIRE_HUMAN_APPROVAL
    if not valid:
        return ActionDecision(False, DecisionCode.DENY_MCP_CUSTODY, SinkClass.MCP_INVOCATION,
                              "payload contains secret, oversized, malformed, or unrecognized material")
    return ActionDecision(False, DecisionCode.REQUIRE_HUMAN_APPROVAL, SinkClass.MCP_INVOCATION,
                          "payload is public-only; MCP invocation still requires a future approved integration")


@dataclass(frozen=True)
class ContractEvidenceRecord:
    contract: str
    source_id: ReviewedSourceId
    artifact_sha256: str
    observed_at: str
    exact_artifact_verified: bool

    def __post_init__(self) -> None:
        if not re.fullmatch(r"0x[0-9a-fA-F]{40}", self.contract):
            raise ValueError("contract evidence requires an exact address candidate")
        if not isinstance(self.source_id, ReviewedSourceId):
            raise ValueError("contract evidence requires an internal reviewed source ID")
        if not re.fullmatch(r"[0-9a-f]{64}", self.artifact_sha256):
            raise ValueError("contract evidence requires an exact artifact hash")
        _parse_approval_time(self.observed_at)


@dataclass(frozen=True)
class ContractEvidenceBundle:
    bundle_id: str
    records: tuple[ContractEvidenceRecord, ...]
    approved_for_testnet_use: bool = False


_CONTRACT_EVIDENCE_BUNDLES: Mapping[str, ContractEvidenceBundle] = MappingProxyType({})
_SOURCE_PROVENANCE_ROOTS: Mapping[ReviewedSourceId, str] = MappingProxyType({
    source_id: (
        "TECHNOCORE_PROJECT" if source_id.name.startswith("TECHNOCORE_") else
        "FLOP_AGENT_PROJECT" if source_id in {
            ReviewedSourceId.PUBLIC_REPOSITORY_API, ReviewedSourceId.ORIGINAL_COMMIT_API,
            ReviewedSourceId.DASHBOARD_COMMIT_API, ReviewedSourceId.PUBLIC_DASHBOARD,
            ReviewedSourceId.PUBLIC_EVIDENCE,
        } else
        "FLOP_FINANCE" if source_id in {
            ReviewedSourceId.FLOP_FINANCE, ReviewedSourceId.FLOP_FINANCE_TEASER,
        } else
        source_id.value
    ) for source_id in ReviewedSourceId
})


def _derive_contract_records(records: tuple[ContractEvidenceRecord, ...], contract: str,
                             *, approved_for_testnet_use: bool = False) -> ContractProvenance:
    exact = [record for record in records if record.contract == contract and record.exact_artifact_verified]
    if any(record.contract != contract for record in records):
        return ContractProvenance.CONFLICTING
    if not exact:
        return ContractProvenance.UNVERIFIED
    official = [record for record in exact if record.source_id in _REVIEWED_SOURCES]
    if not official:
        return ContractProvenance.UNVERIFIED
    # Independence is derived solely from immutable reviewed-source provenance
    # and canonical artifact hashes. Caller labels cannot affect the count.
    provenance_roots = {_SOURCE_PROVENANCE_ROOTS[record.source_id] for record in official}
    artifact_hashes = {record.artifact_sha256 for record in official}
    if len(provenance_roots) < 2 or len(artifact_hashes) < 2:
        return ContractProvenance.OFFICIAL_SOURCE_REFERENCED
    if not approved_for_testnet_use:
        return ContractProvenance.MULTI_SOURCE_CONFIRMED
    return ContractProvenance.VERIFIED_FOR_TESTNET_USE


def evaluate_contract_provenance(bundle_id: str | None, contract: str) -> ContractProvenance:
    if not bundle_id or bundle_id not in _CONTRACT_EVIDENCE_BUNDLES:
        return ContractProvenance.UNVERIFIED
    bundle = _CONTRACT_EVIDENCE_BUNDLES[bundle_id]
    return _derive_contract_records(
        bundle.records, contract, approved_for_testnet_use=bundle.approved_for_testnet_use)


def minimized_remote_evidence(value: UntrustedRemoteValue) -> dict[str, Any]:
    return value.evidence()


def _bounded_error_metadata(error: urllib.error.HTTPError, limit: int) -> SafeRemoteError:
    body = error.read(limit + 1)
    truncated = len(body) > limit
    bounded = body[:limit]
    return SafeRemoteError(
        "HTTP_ERROR",
        status=error.code,
        response_length=len(body),
        content_sha256=hashlib.sha256(bounded).hexdigest(),
        truncated=truncated,
    )


def read_configured_endpoint(source_id: ReviewedSourceId, *,
                             opener: Any = None,
                             timeout: int | None = None,
                             max_bytes: int | None = None) -> bytes:
    """GET an exact configured endpoint with no redirects and bounded bytes."""
    source = resolve_reviewed_source(source_id)
    timeout = source.timeout if timeout is None else timeout
    max_bytes = source.max_bytes if max_bytes is None else max_bytes
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout <= 0:
        raise ValueError("timeout must be a positive integer")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    if timeout > source.timeout or max_bytes > source.max_bytes:
        raise ValueError("caller cannot expand a reviewed source resource bound")
    remote = configured_official_value(source_id)
    decision = authorize_sink(remote, SinkClass.HTTP_READ_ONLY)
    if not decision.allowed:
        raise PermissionError(decision.decision.value)
    request = urllib.request.Request(source.url, method=source.method, headers={"User-Agent": POLICY_VERSION})
    open_request = opener or urllib.request.build_opener(RejectRedirects()).open
    try:
        with open_request(request, timeout=timeout) as response:
            final_url = response.geturl()
            if final_url != source.url:
                raise SafeRemoteError("FINAL_ORIGIN_MISMATCH")
            declared = response.headers.get("Content-Length")
            if declared is not None:
                try:
                    if int(declared) > max_bytes:
                        raise SafeRemoteError("RESPONSE_TOO_LARGE", response_length=int(declared))
                except ValueError as error:
                    raise SafeRemoteError("INVALID_CONTENT_LENGTH") from error
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise SafeRemoteError(
                    "RESPONSE_TOO_LARGE", response_length=len(body),
                    content_sha256=hashlib.sha256(body[:max_bytes]).hexdigest(), truncated=True)
            return body
    except urllib.error.HTTPError as error:
        raise _bounded_error_metadata(error, max_bytes) from error
    except urllib.error.URLError as error:
        raise SafeRemoteError("TRANSPORT_ERROR") from error


T = TypeVar("T")


def invoke_remote_sink(value: UntrustedRemoteValue, sink: SinkClass,
                       operation: Callable[[], T]) -> T:
    """Single production guard used before a remote value can reach any sink."""
    decision = authorize_sink(value, sink)
    if not decision.allowed:
        raise PermissionError(decision.decision.value)
    return operation()
