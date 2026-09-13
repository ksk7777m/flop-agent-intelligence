"""Sealed one-shot boundary for the fixed sonnet-2 writer registration.

Production approval authority is deliberately empty.  This module therefore
cannot sign or post until a separately reviewed local approval is installed.
It does not relax the generic signer policy for ``mb-`` rooms.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import threading
import weakref
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .did_key import public_key_from_did
from .identity import sweep_text


ACTION_CLASS = "SONNET2_WRITER_REGISTRATION"
CONTEST_ID = "sonnet-2"
PROTOCOL_TYPE = "sonnet.register.v1"
ROLE = "writer"
PARTICIPANT_DID = "did:key:z6MkkTuFggpkYcZ61zGxej2Ae7Lf6MHk3AbsYASULYTqiqXy"
X_ACCOUNT_URL = "https://x.com/Giappone_Medici"
ROOM = "mb-sonnet-2-registration"
POST_URL = "https://technocore.chat/r/mb-sonnet-2-registration"
REQUEST_ID = "bf8de59d-6e06-48b3-914b-6ac75cf07f4a"
NONCE = "1789279012380"
REFEREE_DID = "did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte"
MANIFEST_COMMIT = "e1999094c359ef7390bdf07fe2a151393a5c2f51"
MANIFEST_SHA256 = "0c87c41b8b33bdd8641f77c9e481a12f2758a0e27d47b90452b1c0a2020a9547"
PACKET_TEXT = (
    '{"type":"sonnet.register.v1","contest_id":"sonnet-2","role":"writer",'
    '"x_account_url":"https://x.com/Giappone_Medici",'
    '"request_id":"bf8de59d-6e06-48b3-914b-6ac75cf07f4a"}'
)
PACKET_BYTES = PACKET_TEXT.encode("utf-8")
PACKET_BYTE_LENGTH = 169
PACKET_SHA256 = "d4f9c1ea2532bd267a800ac8a9ae8f10343d11cd12c93fa678c83792040a2f0c"
SIGNING_TARGET_BYTES = f"{ROOM}|{NONCE}|{PACKET_TEXT}".encode("utf-8")
SIGNING_TARGET_BYTE_LENGTH = 208
SIGNING_TARGET_SHA256 = "ace738f321cea3606f7bc4aa04d3ee86ae37b30c8f7426f5c5fdf65cba8658da"
POLICY_VERSION = "sonnet2-writer-registration-boundary-v1"
APPROVAL_TTL_SECONDS = 900
MAX_RECEIPT_TEXT_BYTES = 4096
MAX_RECEIPT_SIGNATURE_CHARS = 128

_PACKET_KEYS = ("type", "contest_id", "role", "x_account_url", "request_id")
_BINDING_KEYS = frozenset({
    "action_class", "contest_id", "protocol_type", "role", "participant_did",
    "x_account_url", "room", "request_id", "nonce", "packet_byte_length",
    "packet_sha256", "signing_target_byte_length", "signing_target_sha256",
    "referee_did", "manifest_commit", "manifest_sha256",
})
_APPROVAL_KEYS = _BINDING_KEYS | frozenset({"reviewer", "approved_at"})


class RegistrationBoundaryError(PermissionError):
    """Fixed-code rejection that never reflects remote or secret values."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class _RegistrationPermit:
    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: Any, **_kwargs: Any) -> "_RegistrationPermit":
        raise TypeError("registration permits are issued only by the sealed authority")

    def __reduce__(self) -> Any:
        raise TypeError("registration permits cannot be serialized")


@dataclass(frozen=True)
class _PermitRecord:
    binding_sha256: str
    issued_at: datetime
    expires_at: datetime
    used: bool = False


@dataclass(frozen=True)
class TransportObservation:
    """Bounded transport metadata; response bodies are intentionally absent."""

    status_code: int
    final_url: str
    redirected: bool = False


def fixed_binding() -> Mapping[str, Any]:
    return MappingProxyType({
        "action_class": ACTION_CLASS,
        "contest_id": CONTEST_ID,
        "protocol_type": PROTOCOL_TYPE,
        "role": ROLE,
        "participant_did": PARTICIPANT_DID,
        "x_account_url": X_ACCOUNT_URL,
        "room": ROOM,
        "request_id": REQUEST_ID,
        "nonce": NONCE,
        "packet_byte_length": PACKET_BYTE_LENGTH,
        "packet_sha256": PACKET_SHA256,
        "signing_target_byte_length": SIGNING_TARGET_BYTE_LENGTH,
        "signing_target_sha256": SIGNING_TARGET_SHA256,
        "referee_did": REFEREE_DID,
        "manifest_commit": MANIFEST_COMMIT,
        "manifest_sha256": MANIFEST_SHA256,
    })


def fixed_candidate() -> dict[str, Any]:
    """Return inert descriptive input; it is not an approval or capability."""
    return {**fixed_binding(), "packet": PACKET_TEXT}


def _binding_digest(binding: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        dict(binding), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _validate_fixed_constants() -> None:
    if (sweep_text(PACKET_TEXT) != PACKET_TEXT
            or len(PACKET_BYTES) != PACKET_BYTE_LENGTH
            or hashlib.sha256(PACKET_BYTES).hexdigest() != PACKET_SHA256
            or len(SIGNING_TARGET_BYTES) != SIGNING_TARGET_BYTE_LENGTH
            or hashlib.sha256(SIGNING_TARGET_BYTES).hexdigest() != SIGNING_TARGET_SHA256):
        raise RuntimeError("fixed sonnet registration constants are inconsistent")
    try:
        packet = json.loads(PACKET_TEXT)
    except json.JSONDecodeError as error:
        raise RuntimeError("fixed sonnet registration packet is invalid") from error
    if tuple(packet) != _PACKET_KEYS or packet != {
        "type": PROTOCOL_TYPE, "contest_id": CONTEST_ID, "role": ROLE,
        "x_account_url": X_ACCOUNT_URL, "request_id": REQUEST_ID,
    }:
        raise RuntimeError("fixed sonnet registration packet fields are inconsistent")


_validate_fixed_constants()
_FIXED_BINDING = MappingProxyType(dict(fixed_binding()))
_FIXED_BINDING_SHA256 = _binding_digest(_FIXED_BINDING)


def validate_candidate(candidate: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate every public binding before any permit or key access."""
    if not isinstance(candidate, Mapping):
        raise RegistrationBoundaryError("CANDIDATE_INVALID")
    if set(candidate) != _BINDING_KEYS | {"packet"}:
        raise RegistrationBoundaryError("CANDIDATE_FIELDS_INVALID")
    if candidate.get("packet") != PACKET_TEXT:
        raise RegistrationBoundaryError("PACKET_BYTES_MISMATCH")
    for key, expected in _FIXED_BINDING.items():
        if type(candidate.get(key)) is not type(expected) or candidate.get(key) != expected:
            raise RegistrationBoundaryError("BINDING_MISMATCH")
    try:
        packet = json.loads(candidate["packet"])
    except (TypeError, json.JSONDecodeError):
        raise RegistrationBoundaryError("PACKET_JSON_INVALID") from None
    if tuple(packet) != _PACKET_KEYS:
        raise RegistrationBoundaryError("PACKET_FIELDS_INVALID")
    if (len(candidate["packet"].encode("utf-8")) != PACKET_BYTE_LENGTH
            or hashlib.sha256(candidate["packet"].encode("utf-8")).hexdigest()
            != PACKET_SHA256):
        raise RegistrationBoundaryError("PACKET_HASH_MISMATCH")
    canonical = f"{candidate['room']}|{candidate['nonce']}|{candidate['packet']}".encode("utf-8")
    if (len(canonical) != SIGNING_TARGET_BYTE_LENGTH
            or hashlib.sha256(canonical).hexdigest() != SIGNING_TARGET_SHA256
            or canonical != SIGNING_TARGET_BYTES):
        raise RegistrationBoundaryError("SIGNING_TARGET_MISMATCH")
    return MappingProxyType(dict(candidate))


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise RegistrationBoundaryError("APPROVAL_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise RegistrationBoundaryError("APPROVAL_INVALID") from None
    if parsed.tzinfo is None:
        raise RegistrationBoundaryError("APPROVAL_INVALID")
    return parsed.astimezone(timezone.utc)


def _verify_ed25519(did: str, signature: str, canonical: bytes) -> None:
    try:
        raw = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        if len(raw) != 64:
            raise ValueError
        Ed25519PublicKey.from_public_bytes(public_key_from_did(did)).verify(raw, canonical)
    except (ValueError, TypeError, binascii.Error, InvalidSignature):
        raise RegistrationBoundaryError("RECEIPT_SIGNATURE_INVALID") from None


class _RegistrationService:
    __slots__ = ("_preflight", "_execute", "_verify_receipt", "_classify_receipt")

    def __init__(self, token: object, preflight: Callable[..., Any],
                 execute: Callable[..., Any], verify_receipt: Callable[..., Any],
                 classify_receipt: Callable[..., Any]):
        if token is not _SERVICE_TOKEN:
            raise TypeError("registration service is sealed")
        object.__setattr__(self, "_preflight", preflight)
        object.__setattr__(self, "_execute", execute)
        object.__setattr__(self, "_verify_receipt", verify_receipt)
        object.__setattr__(self, "_classify_receipt", classify_receipt)

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise AttributeError("registration service is immutable")

    def preflight(self, candidate: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._preflight(candidate)

    def execute(self, candidate: Mapping[str, Any], permit: Any = None) -> Mapping[str, Any]:
        return self._execute(candidate, permit)

    def verify_receipt(self, record: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._verify_receipt(record)

    def classify_receipt(self, record: Mapping[str, Any]) -> Mapping[str, Any]:
        """Verify a terminal accepted/rejected receipt without granting write authority."""
        return self._classify_receipt(record)


_SERVICE_TOKEN = object()


def _build_registration_service(
    *, approvals: Mapping[str, Mapping[str, Any]], trusted_reviewers: frozenset[str],
    clock: Callable[[], datetime], key_loader: Callable[[], tuple[Any, str]],
    signer: Callable[[Any, bytes], str],
    transport: Callable[..., TransportObservation],
    signature_verifier: Callable[[str, str, bytes], None],
) -> tuple[_RegistrationService, Callable[[str], _RegistrationPermit]]:
    # Capture every authority-bearing dependency at construction.  Later
    # rebinding of module globals must not widen an already-created service.
    boundary_error = RegistrationBoundaryError
    permit_type = _RegistrationPermit
    permit_record_type = _PermitRecord
    transport_observation_type = TransportObservation
    service_type = _RegistrationService
    service_token = _SERVICE_TOKEN
    binding_keys = _BINDING_KEYS
    approval_keys = _APPROVAL_KEYS
    packet_keys = _PACKET_KEYS
    expected_binding = _FIXED_BINDING
    expected_binding_sha256 = _FIXED_BINDING_SHA256
    packet_text = PACKET_TEXT
    packet_byte_length = PACKET_BYTE_LENGTH
    packet_sha256 = PACKET_SHA256
    signing_target = SIGNING_TARGET_BYTES
    signing_target_byte_length = SIGNING_TARGET_BYTE_LENGTH
    signing_target_sha256 = SIGNING_TARGET_SHA256
    participant_did = PARTICIPANT_DID
    nonce = NONCE
    room = ROOM
    post_url = POST_URL
    referee_did = REFEREE_DID
    contest_id = CONTEST_ID
    request_id = REQUEST_ID
    role = ROLE
    x_account_url = X_ACCOUNT_URL
    approval_ttl_seconds = APPROVAL_TTL_SECONDS
    max_receipt_text_bytes = MAX_RECEIPT_TEXT_BYTES
    max_receipt_signature_chars = MAX_RECEIPT_SIGNATURE_CHARS
    json_loads = json.loads
    json_decode_error = json.JSONDecodeError
    sha256 = hashlib.sha256
    mapping_type = Mapping
    mapping_proxy = MappingProxyType
    utc = timezone.utc
    parse_iso_time = datetime.fromisoformat
    make_delta = timedelta
    replace_record = replace

    configured_approvals = MappingProxyType({
        key: MappingProxyType(dict(value)) for key, value in approvals.items()})
    reviewers = frozenset(trusted_reviewers)
    registry: weakref.WeakKeyDictionary[_RegistrationPermit, _PermitRecord] = weakref.WeakKeyDictionary()
    issued_approvals: set[str] = set()
    lock = threading.Lock()

    def validate_sealed(candidate: Mapping[str, Any]) -> Mapping[str, Any]:
        if not isinstance(candidate, mapping_type):
            raise boundary_error("CANDIDATE_INVALID")
        if set(candidate) != binding_keys | {"packet"}:
            raise boundary_error("CANDIDATE_FIELDS_INVALID")
        if candidate.get("packet") != packet_text:
            raise boundary_error("PACKET_BYTES_MISMATCH")
        for key, expected in expected_binding.items():
            if type(candidate.get(key)) is not type(expected) or candidate.get(key) != expected:
                raise boundary_error("BINDING_MISMATCH")
        try:
            packet = json_loads(candidate["packet"])
        except (TypeError, json_decode_error):
            raise boundary_error("PACKET_JSON_INVALID") from None
        if tuple(packet) != packet_keys:
            raise boundary_error("PACKET_FIELDS_INVALID")
        encoded_packet = candidate["packet"].encode("utf-8")
        if (len(encoded_packet) != packet_byte_length
                or sha256(encoded_packet).hexdigest() != packet_sha256):
            raise boundary_error("PACKET_HASH_MISMATCH")
        canonical = (
            f"{candidate['room']}|{candidate['nonce']}|{candidate['packet']}"
            .encode("utf-8"))
        if (len(canonical) != signing_target_byte_length
                or sha256(canonical).hexdigest() != signing_target_sha256
                or canonical != signing_target):
            raise boundary_error("SIGNING_TARGET_MISMATCH")
        return mapping_proxy(dict(candidate))

    def parse_time_sealed(value: Any) -> datetime:
        if not isinstance(value, str):
            raise boundary_error("APPROVAL_INVALID")
        try:
            parsed = parse_iso_time(value.replace("Z", "+00:00"))
        except ValueError:
            raise boundary_error("APPROVAL_INVALID") from None
        if parsed.tzinfo is None:
            raise boundary_error("APPROVAL_INVALID")
        return parsed.astimezone(utc)

    def preflight(candidate: Mapping[str, Any]) -> Mapping[str, Any]:
        validate_sealed(candidate)
        return mapping_proxy({
            "status": "REGISTRATION_WRITE_APPROVAL_REQUIRED",
            "ready_to_sign": False,
            "authorized_to_write": False,
            "packet_sha256": packet_sha256,
            "signing_target_sha256": signing_target_sha256,
            "external_writes": 0,
        })

    def issue(approval_id: str) -> _RegistrationPermit:
        approval = configured_approvals.get(approval_id)
        if approval is None or set(approval) != approval_keys:
            raise boundary_error("APPROVAL_NOT_ISSUED")
        if approval.get("reviewer") not in reviewers:
            raise boundary_error("APPROVAL_REVIEWER_UNTRUSTED")
        for key, expected in expected_binding.items():
            if type(approval.get(key)) is not type(expected) or approval.get(key) != expected:
                raise boundary_error("APPROVAL_BINDING_MISMATCH")
        now = clock().astimezone(utc)
        approved_at = parse_time_sealed(approval.get("approved_at"))
        age = (now - approved_at).total_seconds()
        if age < 0 or age > approval_ttl_seconds:
            raise boundary_error("APPROVAL_EXPIRED")
        permit = object.__new__(permit_type)
        with lock:
            if approval_id in issued_approvals:
                raise boundary_error("APPROVAL_ALREADY_USED")
            registry[permit] = permit_record_type(
                expected_binding_sha256, now,
                now + make_delta(seconds=approval_ttl_seconds))
            issued_approvals.add(approval_id)
        return permit

    def require_and_consume(permit: Any) -> None:
        now = clock().astimezone(utc)
        with lock:
            record = registry.get(permit) if isinstance(permit, permit_type) else None
            if (record is None or record.binding_sha256 != expected_binding_sha256
                    or now < record.issued_at or now > record.expires_at):
                raise boundary_error("PERMIT_INVALID")
            if record.used:
                raise boundary_error("PERMIT_ALREADY_USED")
            registry[permit] = replace_record(record, used=True)

    def execute(candidate: Mapping[str, Any], permit: Any) -> Mapping[str, Any]:
        checked = validate_sealed(candidate)
        require_and_consume(permit)
        key, did = key_loader()
        if did != participant_did:
            raise boundary_error("IDENTITY_DID_MISMATCH")
        signature = signer(key, signing_target)
        if not isinstance(signature, str) or not signature:
            raise boundary_error("SIGNATURE_INVALID")
        payload = mapping_proxy({
            "did": did, "sig": signature, "nonce": nonce, "text": checked["packet"],
        })
        try:
            response = transport(
                post_url, payload, timeout_seconds=20, allow_redirects=False)
        except (TimeoutError, ConnectionError, OSError):
            return mapping_proxy({
                "status": "WRITE_OUTCOME_UNKNOWN", "writes_attempted": 1,
                "automatic_retry": False, "permit_consumed": True,
                "receipt_required": True,
            })
        if (not isinstance(response, transport_observation_type)
                or response.redirected or response.final_url != post_url
                or not isinstance(response.status_code, int)
                or isinstance(response.status_code, bool)
                or not 200 <= response.status_code < 300):
            return mapping_proxy({
                "status": "WRITE_OUTCOME_UNKNOWN", "writes_attempted": 1,
                "automatic_retry": False, "permit_consumed": True,
                "receipt_required": True,
            })
        return mapping_proxy({
            "status": "POST_OBSERVED_RECEIPT_REQUIRED",
            "http_status": response.status_code, "writes_attempted": 1,
            "automatic_retry": False, "permit_consumed": True,
            "receipt_required": True,
        })

    def classify_receipt(record: Mapping[str, Any]) -> Mapping[str, Any]:
        if not isinstance(record, mapping_type):
            raise boundary_error("RECEIPT_INVALID")
        for key in ("from", "sig", "nonce", "text"):
            if not isinstance(record.get(key), str) or not record.get(key):
                raise boundary_error("RECEIPT_FIELDS_INVALID")
        if record["from"] != referee_did:
            raise boundary_error("RECEIPT_REFEREE_MISMATCH")
        if (len(record["sig"]) > max_receipt_signature_chars
                or len(record["text"].encode("utf-8")) > max_receipt_text_bytes):
            raise boundary_error("RECEIPT_SIZE_INVALID")
        if (len(record["nonce"]) > 19 or not record["nonce"].isdigit()
                or record["nonce"].startswith("0")):
            raise boundary_error("RECEIPT_NONCE_INVALID")
        canonical = f"{room}|{record['nonce']}|{record['text']}".encode("utf-8")
        signature_verifier(referee_did, record["sig"], canonical)

        def reject_duplicate_pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in items:
                if key in result:
                    raise boundary_error("RECEIPT_JSON_INVALID")
                result[key] = value
            return result

        try:
            receipt = json_loads(
                record["text"], object_pairs_hook=reject_duplicate_pairs)
        except (TypeError, json_decode_error):
            raise boundary_error("RECEIPT_JSON_INVALID") from None
        if not isinstance(receipt, dict):
            raise boundary_error("RECEIPT_JSON_INVALID")
        required = {
            "type": "sonnet.receipt.v1", "contest_id": contest_id,
            "request_id": request_id, "participant_did": participant_did,
            "role": role, "x_account_url": x_account_url,
        }
        if (any(receipt.get(key) != value for key, value in required.items())
                or receipt.get("status") not in {"accepted", "rejected"}):
            raise boundary_error("RECEIPT_BINDING_MISMATCH")
        accepted = receipt["status"] == "accepted"
        return mapping_proxy({
            "status": "ACCEPTED_VERIFIED" if accepted else "REJECTED_VERIFIED",
            "referee_signature": "VALID",
            "contest_id": contest_id,
            "request_id": request_id,
            "participant_did": participant_did,
            "role": role,
            "x_account_url": x_account_url,
            "transport_metadata": "UNSIGNED_NOT_PROJECTED",
        })

    def verify_receipt(record: Mapping[str, Any]) -> Mapping[str, Any]:
        result = classify_receipt(record)
        if result["status"] != "ACCEPTED_VERIFIED":
            raise boundary_error("RECEIPT_BINDING_MISMATCH")
        return result

    return service_type(
        service_token, preflight, execute, verify_receipt, classify_receipt), issue


def _disabled_key_loader() -> tuple[Any, str]:
    raise RegistrationBoundaryError("REGISTRATION_WRITE_APPROVAL_REQUIRED")


def _disabled_signer(_key: Any, _target: bytes) -> str:
    raise RegistrationBoundaryError("REGISTRATION_WRITE_APPROVAL_REQUIRED")


def _disabled_transport(*_args: Any, **_kwargs: Any) -> TransportObservation:
    raise RegistrationBoundaryError("REGISTRATION_WRITE_APPROVAL_REQUIRED")


def _build_registration_service_for_test(
    *, approvals: Mapping[str, Mapping[str, Any]], trusted_reviewers: frozenset[str],
    clock: Callable[[], datetime], key_loader: Callable[[], tuple[Any, str]],
    signer: Callable[[Any, bytes], str],
    transport: Callable[..., TransportObservation],
    signature_verifier: Callable[[str, str, bytes], None] = _verify_ed25519,
) -> tuple[_RegistrationService, Callable[[str], _RegistrationPermit]]:
    """Private fixture seam; production callers have no permit issuer."""
    return _build_registration_service(
        approvals=approvals, trusted_reviewers=trusted_reviewers, clock=clock,
        key_loader=key_loader, signer=signer, transport=transport,
        signature_verifier=signature_verifier)


production_registration_service, _production_issue = _build_registration_service(
    approvals=MappingProxyType({}), trusted_reviewers=frozenset(),
    clock=lambda: datetime.now(timezone.utc), key_loader=_disabled_key_loader,
    signer=_disabled_signer, transport=_disabled_transport,
    signature_verifier=_verify_ed25519)
del _production_issue
