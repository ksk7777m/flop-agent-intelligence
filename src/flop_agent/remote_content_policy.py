"""Mandatory fail-closed policy for remote content.

Remote values are evidence-bearing data.  They never acquire authority to
select a fetch, path, process, installer, signer, wallet, or payment target.
Configured read-only endpoints are created through a separate constructor so
that an identical URL discovered in remote text remains inert.
"""

from __future__ import annotations

import hashlib
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse


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
    reviewer: str
    approved_at: str
    purpose: str
    subject_sha256: str


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
        r"private key|signing key|wallet key|API key|SSH key)\b", re.I)),
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


def configured_official_value(url: str, source_id: str, *, observed_at: str | None = None) -> UntrustedRemoteValue:
    metadata = RemoteOriginMetadata(
        RemoteOrigin.CONFIGURED_OFFICIAL_ENDPOINT,
        source_id,
        observed_at or utc_now(),
        SourceTrustTier.TIER_0_OFFICIAL,
        "CONFIGURED",
    )
    return evaluate_remote_content(url, metadata)


def discovered_remote_value(value: Any, origin: RemoteOrigin, source_id: str,
                            *, observed_at: str | None = None,
                            trust_tier: SourceTrustTier = SourceTrustTier.TIER_2_UNSIGNED_COMMUNITY) -> UntrustedRemoteValue:
    if origin is RemoteOrigin.CONFIGURED_OFFICIAL_ENDPOINT:
        raise ValueError("use configured_official_value for reviewed configuration")
    return evaluate_remote_content(value, RemoteOriginMetadata(
        origin, source_id, observed_at or utc_now(), trust_tier, "UNKNOWN"))


def authorize_sink(value: UntrustedRemoteValue, sink: SinkClass, *,
                   configured_urls: Iterable[str] = (),
                   approval: HumanApprovalEvidence | None = None,
                   contract_provenance: ContractProvenance = ContractProvenance.UNVERIFIED) -> ActionDecision:
    del approval  # Sensitive sinks remain disabled in this package even with evidence.
    configured = frozenset(configured_urls)
    if sink in {SinkClass.HTTP_READ_ONLY, SinkClass.PUBLIC_NAVIGATION}:
        if value.metadata.origin is not RemoteOrigin.CONFIGURED_OFFICIAL_ENDPOINT:
            decision = DecisionCode.DENY_DISCOVERED_URL if any(
                item.content_class is RemoteContentClass.URL for item in value.findings
            ) else DecisionCode.DENY_UNTRUSTED_INPUT
            return ActionDecision(False, decision, sink, "remote-discovered targets are inert")
        parsed = urlparse(value.value_for_classification_only)
        if (value.value_for_classification_only not in configured or parsed.scheme != "https"
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


def navigation_state(value: UntrustedRemoteValue, configured_urls: Iterable[str]) -> NavigationState:
    decision = authorize_sink(value, SinkClass.PUBLIC_NAVIGATION, configured_urls=configured_urls)
    return NavigationState.REVIEWED_OFFICIAL if decision.allowed else NavigationState.INERT


_SECRET_FIELD_RE = re.compile(
    r"(?:private|secret|seed|mnemonic|credential|password|token|api[_-]?key|ssh[_-]?key)", re.I)


def authorize_remote_mcp_payload(payload: Mapping[str, Any]) -> ActionDecision:
    """Permit only an explicitly small, public evidence vocabulary."""
    allowed = {"public_did", "public_key", "signature", "signed_envelope", "content_sha256", "evidence_sha256"}
    for key in payload:
        if key not in allowed or _SECRET_FIELD_RE.search(key):
            return ActionDecision(False, DecisionCode.DENY_MCP_CUSTODY, SinkClass.MCP_INVOCATION,
                                  "payload contains a non-public or unrecognized field")
    return ActionDecision(False, DecisionCode.REQUIRE_HUMAN_APPROVAL, SinkClass.MCP_INVOCATION,
                          "payload is public-only; MCP invocation still requires a future approved integration")


def evaluate_contract_provenance(source_tier: SourceTrustTier, *, independent_confirmations: int = 0,
                                 conflicting: bool = False,
                                 exact_artifact_verified: bool = False) -> ContractProvenance:
    if conflicting:
        return ContractProvenance.CONFLICTING
    if source_tier is not SourceTrustTier.TIER_0_OFFICIAL:
        return ContractProvenance.UNVERIFIED
    if independent_confirmations < 1:
        return ContractProvenance.OFFICIAL_SOURCE_REFERENCED
    if not exact_artifact_verified:
        return ContractProvenance.MULTI_SOURCE_CONFIRMED
    return ContractProvenance.VERIFIED_FOR_TESTNET_USE


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


def read_configured_endpoint(url: str, source_id: str, configured_urls: Iterable[str], *,
                             opener: Any = None,
                             timeout: int = DEFAULT_HTTP_TIMEOUT_SECONDS,
                             max_bytes: int = DEFAULT_RESPONSE_LIMIT) -> bytes:
    """GET an exact configured endpoint with no redirects and bounded bytes."""
    if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout <= 0:
        raise ValueError("timeout must be a positive integer")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    remote = configured_official_value(url, source_id)
    decision = authorize_sink(remote, SinkClass.HTTP_READ_ONLY, configured_urls=configured_urls)
    if not decision.allowed:
        raise PermissionError(decision.decision.value)
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": POLICY_VERSION})
    open_request = opener or urllib.request.build_opener(RejectRedirects()).open
    try:
        with open_request(request, timeout=timeout) as response:
            final_url = response.geturl()
            if final_url != url:
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
