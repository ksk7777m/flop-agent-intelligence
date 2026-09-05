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
import dataclasses
import re
import threading
import urllib.error
import urllib.request
import weakref
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
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
    PRESENCE_WRITE = "PRESENCE_WRITE"
    RECEIPT_SIGN = "RECEIPT_SIGN"
    IDENTITY_SIGN = "IDENTITY_SIGN"
    SUBPROCESS = "SUBPROCESS"
    FILESYSTEM_WRITE = "FILESYSTEM_WRITE"
    SECRET_ACCESS = "SECRET_ACCESS"
    MCP_INVOKE = "MCP_INVOKE"
    WALLET = "WALLET"
    CLAIM = "CLAIM"
    PAYMENT = "PAYMENT"


class ReviewedLocalIntent:
    """Opaque process-local capability; its public constructor never issues authority."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: Any, **_kwargs: Any) -> "ReviewedLocalIntent":
        raise PermissionError("local authority is issued only by the internal capability store")

    def __copy__(self) -> "ReviewedLocalIntent":
        raise TypeError("capabilities cannot be copied")

    def __deepcopy__(self, _memo: dict[int, Any]) -> "ReviewedLocalIntent":
        raise TypeError("capabilities cannot be copied")

    def __reduce__(self) -> Any:
        raise TypeError("capabilities cannot be serialized")


@dataclass(frozen=True)
class _CapabilityRecord:
    approval_id: str
    action: LocalActionClass
    subject_sha256: str
    target_sha256: str
    payload_sha256: str
    context_sha256: str
    revision: str
    config_version: str
    issued_at: datetime
    expires_at: datetime
    one_shot: bool
    used: bool = False


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


def _new_capability_store(
    approvals: Mapping[str, Mapping[str, str]], reviewers: frozenset[str],
    clock: Callable[[], datetime],
) -> tuple[Callable[..., ReviewedLocalIntent], Callable[..., None]]:
    """Return issuer/validator closures over a registry callers cannot replace."""
    configured = MappingProxyType({key: MappingProxyType(dict(value)) for key, value in approvals.items()})
    trusted_reviewers = frozenset(reviewers)
    registry: weakref.WeakKeyDictionary[ReviewedLocalIntent, _CapabilityRecord] = weakref.WeakKeyDictionary()
    registry_lock = threading.Lock()
    sha256 = hashlib.sha256
    digest = lambda value: sha256(value.encode()).hexdigest()
    fullmatch = re.fullmatch
    parse_time = _parse_approval_time
    intent_type, action_type = ReviewedLocalIntent, LocalActionClass
    record_type, replace_record = _CapabilityRecord, dataclasses.replace
    presence_read = LocalActionClass.PRESENCE_NOTE_READ
    utc, duration = timezone.utc, timedelta

    def issue(approval_id: str, action: LocalActionClass, subject: str, *, target: str,
              payload: str, context: str, revision: str, config_version: str,
              ttl_seconds: int = 900, one_shot: bool = True) -> ReviewedLocalIntent:
        record = configured.get(approval_id)
        if record is None or record.get("reviewer") not in trusted_reviewers:
            raise PermissionError("approval is not present in the trusted local store")
        now = clock().astimezone(utc)
        approved_at = parse_time(record.get("approved_at", ""))
        if (now - approved_at).total_seconds() < 0 or (now - approved_at).total_seconds() > 900:
            raise PermissionError("approval is stale or future-dated")
        if (not isinstance(action, action_type)
                or action is presence_read
                or not fullmatch(r"[0-9a-f]{40}", revision)
                or not fullmatch(r"[A-Za-z0-9._-]{1,64}", config_version)
                or not subject or not target or not payload or not context
                or not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool)
                or not 1 <= ttl_seconds <= 900):
            raise PermissionError("capability binding inputs are malformed")
        bindings = {
            "action": action.value,
            "subject_sha256": digest(subject),
            "target_sha256": digest(target),
            "payload_sha256": digest(payload),
            "context_sha256": digest(context),
            "revision": revision, "config_version": config_version,
        }
        if any(record.get(key) != value for key, value in bindings.items()):
            raise PermissionError("approval does not exactly bind this action")
        capability = object.__new__(intent_type)
        with registry_lock:
            registry[capability] = record_type(
                approval_id, action, bindings["subject_sha256"], bindings["target_sha256"],
                bindings["payload_sha256"], bindings["context_sha256"], revision,
                config_version, now, now + duration(seconds=ttl_seconds), one_shot)
        return capability

    def require(capability: ReviewedLocalIntent, action: LocalActionClass, subject: str, *,
                target: str, payload: str, context: str, revision: str,
                config_version: str, consume: bool = True) -> None:
        now = clock().astimezone(utc)
        expected = (
            action, digest(subject), digest(target), digest(payload), digest(context),
            revision, config_version,
        )
        with registry_lock:
            record = registry.get(capability) if isinstance(capability, intent_type) else None
            actual = None if record is None else (
                record.action, record.subject_sha256, record.target_sha256, record.payload_sha256,
                record.context_sha256, record.revision, record.config_version,
            )
            if record is None or actual != expected or now < record.issued_at or now > record.expires_at:
                raise PermissionError("capability is absent, expired, or does not match the action")
            if record.one_shot and record.used:
                raise PermissionError("one-shot capability has already been consumed")
            if consume and record.one_shot:
                registry[capability] = replace_record(record, used=True)

    return issue, require


def _new_static_read_store() -> tuple[
    Callable[[str, str], ReviewedLocalIntent], Callable[[ReviewedLocalIntent, str], None]
]:
    registry: weakref.WeakKeyDictionary[ReviewedLocalIntent, tuple[str, str]] = weakref.WeakKeyDictionary()
    intent_type, digest = ReviewedLocalIntent, hashlib.sha256

    def issue(subject: str, purpose: str) -> ReviewedLocalIntent:
        capability = object.__new__(intent_type)
        registry[capability] = (digest(subject.encode()).hexdigest(), purpose)
        return capability

    def require(capability: ReviewedLocalIntent, subject: str) -> None:
        expected = registry.get(capability) if isinstance(capability, intent_type) else None
        if expected is None or expected[0] != digest(subject.encode()).hexdigest():
            raise PermissionError("Presence read capability is absent or has the wrong binding")

    return issue, require


def _build_capability_api(
    approvals: Mapping[str, Mapping[str, str]], reviewers: frozenset[str],
    clock: Callable[[], datetime],
) -> tuple[Callable[..., ReviewedLocalIntent], Callable[..., ReviewedLocalIntent], Callable[..., None]]:
    """Build one sealed authority domain whose dependencies are closure-captured."""
    issue_sensitive, require_sensitive = _new_capability_store(approvals, reviewers, clock)
    issue_static, require_static = _new_static_read_store()
    action_type, presence_read = LocalActionClass, LocalActionClass.PRESENCE_NOTE_READ

    def trusted(approval_id: str, action: LocalActionClass, subject: str, *,
                target: str, payload: str, revision: str, config_version: str,
                purpose: str) -> ReviewedLocalIntent:
        return issue_sensitive(
            approval_id, action, subject, target=target, payload=payload, context=purpose,
            revision=revision, config_version=config_version)

    def reviewed(action: LocalActionClass, subject: str, purpose: str, *,
                 approval: HumanApprovalEvidence | None = None) -> ReviewedLocalIntent:
        if not isinstance(action, action_type) or not purpose.strip():
            raise ValueError("reviewed local intent requires a known action and purpose")
        if action is not presence_read or approval is not None:
            raise PermissionError("sensitive intents require trusted stored local approval")
        return issue_static(subject, purpose)

    def require(intent: ReviewedLocalIntent, action: LocalActionClass, subject: str, *,
                target: str | None = None, payload: str | None = None,
                context: str | None = None, revision: str | None = None,
                config_version: str | None = None, consume: bool = True) -> None:
        if action is presence_read:
            require_static(intent, subject)
            return
        if None in (target, payload, context, revision, config_version):
            raise PermissionError("sensitive intent validation requires all exact bindings")
        require_sensitive(
            intent, action, subject, target=target, payload=payload, context=context,
            revision=revision, config_version=config_version, consume=consume)

    return trusted, reviewed, require


trusted_local_intent, reviewed_local_intent, require_local_intent = _build_capability_api(
    _LOCAL_APPROVAL_RECORDS, _TRUSTED_LOCAL_REVIEWERS,
    lambda _now=datetime.now, _utc=timezone.utc: _now(_utc))


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


def _build_reviewed_source_service(
    configured_sources: Mapping[ReviewedSourceId, ReviewedSource],
) -> tuple[Callable[[ReviewedSourceId], ReviewedSource], Callable[..., UntrustedRemoteValue],
           Callable[..., ActionDecision], Callable[[ReviewedSourceId], NavigationState]]:
    """Capture reviewed source policy; descriptive values never carry authority."""
    sources = MappingProxyType(dict(configured_sources))
    source_id_type, remote_metadata_type = ReviewedSourceId, RemoteOriginMetadata
    configured_origin = RemoteOrigin.CONFIGURED_OFFICIAL_ENDPOINT
    official_tier = SourceTrustTier.TIER_0_OFFICIAL
    evaluate, clock = evaluate_remote_content, utc_now
    sink_http, sink_navigation = SinkClass.HTTP_READ_ONLY, SinkClass.PUBLIC_NAVIGATION
    sink_signer = SinkClass.SIGNER
    wallet_sinks = frozenset({SinkClass.WALLET, SinkClass.CLAIM, SinkClass.PAYMENT})
    mcp_sinks = frozenset({SinkClass.MCP_INSTALLER, SinkClass.MCP_INVOCATION})
    url_class = RemoteContentClass.URL
    deny_url, deny_untrusted = DecisionCode.DENY_DISCOVERED_URL, DecisionCode.DENY_UNTRUSTED_INPUT
    deny_signing, deny_wallet = DecisionCode.DENY_SIGNING, DecisionCode.DENY_WALLET
    deny_mcp, deny_execution = DecisionCode.DENY_MCP_CUSTODY, DecisionCode.DENY_EXECUTION
    decision_type, parse_url = ActionDecision, urlparse
    inert, reviewed = NavigationState.INERT, NavigationState.REVIEWED_OFFICIAL

    def resolve(source_id: ReviewedSourceId) -> ReviewedSource:
        if not isinstance(source_id, source_id_type):
            raise PermissionError("reviewed source ID must be an internal enum value")
        return sources[source_id]

    def describe(source_id: ReviewedSourceId, *, observed_at: str | None = None) -> UntrustedRemoteValue:
        source = resolve(source_id)
        return evaluate(source.url, remote_metadata_type(
            configured_origin, source.source_id.value,
            observed_at or clock(), official_tier, "CONFIGURED"))

    def authorize(value: UntrustedRemoteValue, sink: SinkClass, *,
                  approval: HumanApprovalEvidence | None = None,
                  contract_provenance: ContractProvenance = ContractProvenance.UNVERIFIED) -> ActionDecision:
        del approval, contract_provenance
        # Remote/descriptive values are never capabilities, including descriptions
        # of exact configured sources. Official reads and navigation take source IDs
        # through the sealed service instead.
        if sink in {sink_http, sink_navigation}:
            decision = deny_url if any(
                item.content_class is url_class for item in value.findings
            ) else deny_untrusted
            return decision_type(False, decision, sink, "descriptive remote values are inert")
        if sink is sink_signer:
            return decision_type(False, deny_signing, sink,
                                  "remote-directed signing is disabled")
        if sink in wallet_sinks:
            return decision_type(False, deny_wallet, sink,
                                  "wallet, claim, and payment sinks are disabled")
        if sink in mcp_sinks:
            return decision_type(False, deny_mcp, sink,
                                  "remote MCP installation/invocation is disabled")
        return decision_type(False, deny_execution, sink,
                              "remote values cannot authorize execution or filesystem sinks")

    def navigation(source_id: ReviewedSourceId) -> NavigationState:
        source = resolve(source_id)
        parsed = parse_url(source.url)
        if (parsed.scheme != "https" or parsed.username or parsed.password
                or not parsed.hostname):
            return inert
        return reviewed

    return resolve, describe, authorize, navigation


resolve_reviewed_source, configured_official_value, authorize_sink, resolve_navigation = (
    _build_reviewed_source_service(_REVIEWED_SOURCES))


def discovered_remote_value(value: Any, origin: RemoteOrigin, source_id: str,
                            *, observed_at: str | None = None,
                            trust_tier: SourceTrustTier = SourceTrustTier.TIER_2_UNSIGNED_COMMUNITY) -> UntrustedRemoteValue:
    if origin is RemoteOrigin.CONFIGURED_OFFICIAL_ENDPOINT:
        raise ValueError("use configured_official_value for reviewed configuration")
    return evaluate_remote_content(value, RemoteOriginMetadata(
        origin, source_id, observed_at or utc_now(), trust_tier, "UNKNOWN"))


def _build_navigation_classifier(authorize: Callable[..., ActionDecision]) -> Any:
    def classify(value: UntrustedRemoteValue) -> NavigationState:
        decision = authorize(value, SinkClass.PUBLIC_NAVIGATION)
        return NavigationState.REVIEWED_OFFICIAL if decision.allowed else NavigationState.INERT
    return classify


navigation_state = _build_navigation_classifier(authorize_sink)


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
    """Untrusted evidence proposal.  This object never conveys reviewed status."""
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
    records: tuple["ReviewedContractEvidence", ...]


class ReviewedContractEvidence:
    """Opaque reference to evidence resolved in a private reviewed registry."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: Any, **_kwargs: Any) -> "ReviewedContractEvidence":
        raise PermissionError("reviewed contract evidence cannot be caller-constructed")

    def __copy__(self) -> "ReviewedContractEvidence":
        raise TypeError("reviewed evidence cannot be copied")

    def __deepcopy__(self, _memo: dict[int, Any]) -> "ReviewedContractEvidence":
        raise TypeError("reviewed evidence cannot be copied")

    def __reduce__(self) -> Any:
        raise TypeError("reviewed evidence cannot be serialized")


@dataclass(frozen=True)
class _ReviewedEvidenceRecord:
    source_id: ReviewedSourceId
    canonical_artifact_id: str
    contract: str
    artifact_sha256: str
    observed_at: str
    reviewed_at: str
    provenance_root: str
    reviewer: str
    policy_version: str


_CONTRACT_EVIDENCE_BUNDLES: Mapping[str, ContractEvidenceBundle] = MappingProxyType({})
_REVIEWED_EVIDENCE_RECORDS: Mapping[str, Mapping[str, str]] = MappingProxyType({})
_TESTNET_CONTRACT_APPROVALS: Mapping[str, Mapping[str, str]] = MappingProxyType({})
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


def _new_evidence_store(
    configured_records: Mapping[str, Mapping[str, str]],
    configured_approvals: Mapping[str, Mapping[str, str]],
) -> tuple[Callable[[str, ContractEvidenceRecord], ReviewedContractEvidence], Callable[..., ContractProvenance]]:
    configured = MappingProxyType({key: MappingProxyType(dict(value))
                                   for key, value in configured_records.items()})
    approvals = MappingProxyType({key: MappingProxyType(dict(value))
                                  for key, value in configured_approvals.items()})
    reviewed_sources = frozenset(_REVIEWED_SOURCES)
    provenance_roots = MappingProxyType(dict(_SOURCE_PROVENANCE_ROOTS))
    registry: weakref.WeakKeyDictionary[ReviewedContractEvidence, _ReviewedEvidenceRecord] = weakref.WeakKeyDictionary()
    proposal_type, reviewed_type = ContractEvidenceRecord, ReviewedContractEvidence
    resolved_record_type = _ReviewedEvidenceRecord
    parse_time, policy_version = _parse_approval_time, POLICY_VERSION
    unverified = ContractProvenance.UNVERIFIED
    conflicting = ContractProvenance.CONFLICTING
    official_referenced = ContractProvenance.OFFICIAL_SOURCE_REFERENCED
    multi_source = ContractProvenance.MULTI_SOURCE_CONFIRMED
    verified = ContractProvenance.VERIFIED_FOR_TESTNET_USE

    def issue(record_id: str, proposal: ContractEvidenceRecord) -> ReviewedContractEvidence:
        source = configured.get(record_id)
        if source is None or not isinstance(proposal, proposal_type):
            raise PermissionError("evidence is not present in the reviewed source registry")
        expected = {
            "source_id": proposal.source_id.value, "contract": proposal.contract,
            "artifact_sha256": proposal.artifact_sha256, "observed_at": proposal.observed_at,
        }
        if any(source.get(key) != value for key, value in expected.items()):
            raise PermissionError("evidence does not match the reviewed artifact record")
        if (proposal.source_id not in reviewed_sources
                or source.get("provenance_root") != provenance_roots[proposal.source_id]
                or not source.get("canonical_artifact_id") or not source.get("reviewer")
                or source.get("policy_version") != policy_version):
            raise PermissionError("reviewed evidence registry entry is incomplete")
        parse_time(source.get("reviewed_at", ""))
        capability = object.__new__(reviewed_type)
        registry[capability] = resolved_record_type(
            proposal.source_id, source["canonical_artifact_id"], proposal.contract,
            proposal.artifact_sha256, proposal.observed_at, source["reviewed_at"],
            source["provenance_root"], source["reviewer"], source["policy_version"])
        return capability

    def derive(records: tuple[ReviewedContractEvidence, ...], contract: str, *,
               approval_id: str | None = None) -> ContractProvenance:
        resolved = [registry.get(item) if isinstance(item, reviewed_type) else None
                    for item in records]
        if any(item is None for item in resolved) or not resolved:
            return unverified
        valid = [item for item in resolved if item is not None]
        if any(item.contract != contract for item in valid):
            return conflicting
        roots = {item.provenance_root for item in valid}
        artifacts = {(item.canonical_artifact_id, item.artifact_sha256) for item in valid}
        if len(roots) < 2 or len(artifacts) < 2:
            return official_referenced
        approval = approvals.get(approval_id or "")
        if approval is None:
            return multi_source
        if (approval.get("contract") != contract
                or approval.get("policy_version") != policy_version
                or approval.get("status") != "APPROVED_FOR_TESTNET_USE"):
            return multi_source
        return verified

    return issue, derive


def _build_contract_verifier(
    records: Mapping[str, Mapping[str, str]],
    approvals: Mapping[str, Mapping[str, str]],
    bundles: Mapping[str, ContractEvidenceBundle],
) -> tuple[Callable[[str, ContractEvidenceRecord], ReviewedContractEvidence],
           Callable[[tuple[object, ...], str], ContractProvenance],
           Callable[[str | None, str], ContractProvenance]]:
    """Build one sealed verifier; caller-created verifiers cannot alter production."""
    issue, derive = _new_evidence_store(records, approvals)
    configured_bundles = MappingProxyType(dict(bundles))
    unverified = ContractProvenance.UNVERIFIED

    def reviewed(record_id: str, proposal: ContractEvidenceRecord) -> ReviewedContractEvidence:
        return issue(record_id, proposal)

    def derive_records(items: tuple[object, ...], contract: str, *,
                       approval_id: str | None = None) -> ContractProvenance:
        return derive(items, contract, approval_id=approval_id)

    def evaluate(bundle_id: str | None, contract: str) -> ContractProvenance:
        if not bundle_id or bundle_id not in configured_bundles:
            return unverified
        bundle = configured_bundles[bundle_id]
        return derive(bundle.records, contract, approval_id=bundle.bundle_id)

    return reviewed, derive_records, evaluate


reviewed_contract_evidence, _derive_contract_records, evaluate_contract_provenance = (
    _build_contract_verifier(
        _REVIEWED_EVIDENCE_RECORDS, _TESTNET_CONTRACT_APPROVALS,
        _CONTRACT_EVIDENCE_BUNDLES))


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


def _build_configured_reader(
    source_resolver: Callable[[ReviewedSourceId], ReviewedSource],
    open_request: Callable[..., Any] | None = None,
) -> Callable[..., bytes]:
    """Build the sole configured HTTP reader with a captured source registry."""
    request_type = urllib.request.Request
    redirect_handler = RejectRedirects
    http_error_type, url_error_type = urllib.error.HTTPError, urllib.error.URLError
    bounded_error = _bounded_error_metadata
    user_agent = POLICY_VERSION
    configured_open = open_request or urllib.request.build_opener(redirect_handler()).open
    safe_error, digest = SafeRemoteError, hashlib.sha256

    def read(source_id: ReviewedSourceId, *, timeout: int | None = None,
             max_bytes: int | None = None) -> bytes:
        source = source_resolver(source_id)
        selected_timeout = source.timeout if timeout is None else timeout
        selected_max = source.max_bytes if max_bytes is None else max_bytes
        if (not isinstance(selected_timeout, int) or isinstance(selected_timeout, bool)
                or selected_timeout <= 0):
            raise ValueError("timeout must be a positive integer")
        if (not isinstance(selected_max, int) or isinstance(selected_max, bool)
                or selected_max <= 0):
            raise ValueError("max_bytes must be a positive integer")
        if selected_timeout > source.timeout or selected_max > source.max_bytes:
            raise ValueError("caller cannot expand a reviewed source resource bound")
        request = request_type(
            source.url, method=source.method, headers={"User-Agent": user_agent})
        try:
            with configured_open(request, timeout=selected_timeout) as response:
                final_url = response.geturl()
                if final_url != source.url:
                    raise safe_error("FINAL_ORIGIN_MISMATCH")
                declared = response.headers.get("Content-Length")
                if declared is not None:
                    try:
                        if int(declared) > selected_max:
                            raise safe_error(
                                "RESPONSE_TOO_LARGE", response_length=int(declared))
                    except ValueError as error:
                        raise safe_error("INVALID_CONTENT_LENGTH") from error
                body = response.read(selected_max + 1)
                if len(body) > selected_max:
                    raise safe_error(
                        "RESPONSE_TOO_LARGE", response_length=len(body),
                        content_sha256=digest(body[:selected_max]).hexdigest(),
                        truncated=True)
                return body
        except http_error_type as error:
            raise bounded_error(error, selected_max) from error
        except url_error_type as error:
            raise safe_error("TRANSPORT_ERROR") from error

    return read


read_configured_endpoint = _build_configured_reader(resolve_reviewed_source)


T = TypeVar("T")


def _build_remote_sink_guard(authorize: Callable[..., ActionDecision]) -> Any:
    def invoke(value: UntrustedRemoteValue, sink: SinkClass,
               operation: Callable[[], T]) -> T:
        decision = authorize(value, sink)
        if not decision.allowed:
            raise PermissionError(decision.decision.value)
        return operation()
    return invoke


invoke_remote_sink = _build_remote_sink_guard(authorize_sink)
