"""Fail-closed production adapters for the fixed sonnet-2 registration.

The production objects in this module have no approval authority and are not
invoked at import time.  Remote bytes are data only.  No response body or
identity material is retained by an adapter.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import ssl
import stat
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import sonnet_registration as registration
from .did_key import did_from_public_key
from .identity import verify_message


PRESTART_EVIDENCE_LOCALLY_VERIFIED = "PRESTART_EVIDENCE_LOCALLY_VERIFIED"
OFFICIAL_ARCHIVE_ELIGIBILITY_UNCONFIRMED = (
    "OFFICIAL_ARCHIVE_ELIGIBILITY_UNCONFIRMED")
NO_CONFLICT_IN_OBSERVED_WINDOW = "NO_CONFLICT_IN_OBSERVED_WINDOW"
ALREADY_REGISTERED_IDENTICALLY = "ALREADY_REGISTERED_IDENTICALLY"
REGISTRATION_CONFLICT = "REGISTRATION_CONFLICT"
REQUEST_OBSERVED_RECEIPT_UNCONFIRMED = (
    "REQUEST_OBSERVED_RECEIPT_UNCONFIRMED")
AWAITING_REFEREE_RECEIPT = "AWAITING_REFEREE_RECEIPT"

OFFICIAL_ORIGIN = "https://technocore.chat"
REGISTRATION_GET_URL = (
    "https://technocore.chat/r/mb-sonnet-2-registration?limit=200&format=json")
RULES_VERSION = "0.5"
IDENTITY_CUTOFF = datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc)
DEADLINE = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
HTTP_TIMEOUT_SECONDS = 20
MAX_RESPONSE_BYTES = 262_144
REQUEST_BODY_BYTE_LENGTH = 384
MAX_READ_ATTEMPTS = 3
_PRODUCTION_IDENTITY_PATH = (
    Path(__file__).resolve().parents[2] / "secrets" / "agent_identity.json")


class AdapterError(PermissionError):
    """A fixed-code error which never includes remote or secret content."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AdapterError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _decode_object(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except AdapterError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise AdapterError("REMOTE_JSON_INVALID") from None
    if type(value) is not dict:
        raise AdapterError("REMOTE_JSON_INVALID")
    return value


def _read_bounded(response: Any, limit: int = MAX_RESPONSE_BYTES) -> bytes:
    lengths = response.headers.get_all("Content-Length") or []
    if len(lengths) > 1:
        raise AdapterError("RESPONSE_LENGTH_INVALID")
    if lengths:
        try:
            declared = int(lengths[0])
        except (TypeError, ValueError):
            raise AdapterError("RESPONSE_LENGTH_INVALID") from None
        if declared < 0 or declared > limit:
            raise AdapterError("RESPONSE_TOO_LARGE")
    encoding = response.headers.get("Content-Encoding")
    if encoding not in (None, "", "identity"):
        raise AdapterError("RESPONSE_ENCODING_REJECTED")
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(8192, limit - total + 1))
        if not chunk:
            break
        if type(chunk) is not bytes:
            raise AdapterError("RESPONSE_STREAM_INVALID")
        total += len(chunk)
        if total > limit:
            raise AdapterError("RESPONSE_TOO_LARGE")
        chunks.append(chunk)
    body = b"".join(chunks)
    if lengths and len(body) != int(lengths[0]):
        raise AdapterError("RESPONSE_TRUNCATED")
    return body


def _production_opener() -> Any:
    context = ssl.create_default_context()
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect(),
        urllib.request.HTTPSHandler(context=context))


def _secure_identity_signer(
    identity_path: Path, *, opener: Callable[..., int] = os.open,
    fstat: Callable[[int], os.stat_result] = os.fstat,
    reader: Callable[[int, int], bytes] = os.read,
    closer: Callable[[int], None] = os.close,
    expected_did: str = registration.PARTICIPANT_DID,
) -> Callable[[bytes], tuple[str, str]]:
    """Capture a fixed identity path; return only DID and exact-target signature."""
    configured = Path(os.path.abspath(identity_path))
    used = False

    def sign_exact(target: bytes) -> tuple[str, str]:
        nonlocal used
        if used:
            raise AdapterError("SIGNER_ALREADY_USED")
        if (type(target) is not bytes
                or target != registration.SIGNING_TARGET_BYTES
                or hashlib.sha256(target).hexdigest()
                != registration.SIGNING_TARGET_SHA256):
            raise AdapterError("SIGNING_TARGET_MISMATCH")
        used = True
        no_follow = getattr(os, "O_NOFOLLOW", None)
        if no_follow is None:
            raise AdapterError("IDENTITY_NOFOLLOW_UNAVAILABLE")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow
        try:
            fd = opener(str(configured), flags)
        except OSError:
            raise AdapterError("IDENTITY_OPEN_REJECTED") from None
        try:
            info = fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != os.getuid() or info.st_nlink != 1):
                raise AdapterError("IDENTITY_FILE_UNSAFE")
            pieces: list[bytes] = []
            size = 0
            while True:
                piece = reader(fd, min(4096, 16_385 - size))
                if not piece:
                    break
                size += len(piece)
                if size > 16_384:
                    raise AdapterError("IDENTITY_FILE_UNSAFE")
                pieces.append(piece)
        finally:
            closer(fd)
        payload = _decode_object(b"".join(pieces))
        if set(payload) != {"type", "did", "seed_b64"} or payload.get("type") != "Ed25519":
            raise AdapterError("IDENTITY_FORMAT_INVALID")
        try:
            encoded = payload["seed_b64"]
            if (type(encoded) is not str or len(encoded) != 43
                    or any(character not in
                           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                           for character in encoded)):
                raise ValueError
            seed = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            if (len(seed) != 32
                    or base64.urlsafe_b64encode(seed).decode("ascii").rstrip("=")
                    != encoded):
                raise ValueError
            key = Ed25519PrivateKey.from_private_bytes(seed)
            did = did_from_public_key(key.public_key().public_bytes_raw())
        except Exception:
            raise AdapterError("IDENTITY_FORMAT_INVALID") from None
        if did != expected_did or payload.get("did") != did:
            raise AdapterError("IDENTITY_DID_MISMATCH")
        signature = base64.urlsafe_b64encode(key.sign(target)).decode("ascii").rstrip("=")
        if (len(signature) != 86 or "=" in signature
                or base64.urlsafe_b64encode(base64.urlsafe_b64decode(
                    signature + "==")).decode("ascii").rstrip("=") != signature):
            raise AdapterError("SIGNATURE_INVALID")
        return did, signature

    return sign_exact


def _build_post_transport(
    *, opener_factory: Callable[[], Any], observation_factory: Callable[..., Any],
    signature_verifier: Callable[[str, str, str, str, str], None] = verify_message,
) -> Callable[..., Any]:
    used = False

    def post(url: str, body: bytes, **options: Any) -> Any:
        nonlocal used
        if used:
            raise AdapterError("TRANSPORT_ALREADY_USED")
        used = True
        if (url != registration.POST_URL or options != {
                "method": "POST", "timeout_seconds": HTTP_TIMEOUT_SECONDS,
                "allow_redirects": False, "allow_proxy": False,
                "credential_forwarding": False}):
            raise AdapterError("TRANSPORT_TARGET_REJECTED")
        if type(body) is not bytes or len(body) != REQUEST_BODY_BYTE_LENGTH:
            raise AdapterError("REQUEST_BODY_INVALID")
        body_hash = hashlib.sha256(body).digest()
        parsed = _decode_object(body)
        if (tuple(parsed) != ("did", "nonce", "sig", "text")
                or set(parsed) != {"did", "sig", "nonce", "text"}
                or parsed.get("did") != registration.PARTICIPANT_DID
                or parsed.get("nonce") != registration.NONCE
                or parsed.get("text") != registration.PACKET_TEXT
                or type(parsed.get("sig")) is not str
                or len(parsed["sig"]) != 86
                or json.dumps(parsed, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=True).encode("utf-8") != body):
            raise AdapterError("REQUEST_BODY_INVALID")
        try:
            signature_verifier(parsed["did"], parsed["sig"], registration.ROOM,
                               parsed["nonce"], parsed["text"])
        except Exception:
            raise AdapterError("REQUEST_SIGNATURE_INVALID") from None
        request = urllib.request.Request(
            registration.POST_URL, data=body, method="POST", headers={
                "Accept": "application/json", "Accept-Encoding": "identity",
                "Content-Type": "application/json", "Content-Length": str(len(body)),
            })
        if hashlib.sha256(bytes(request.data)).digest() != body_hash:
            raise AdapterError("REQUEST_BODY_CHANGED")
        opener = opener_factory()
        try:
            with opener.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
                final_url = response.geturl()
                raw = _read_bounded(response)
                if final_url != registration.POST_URL:
                    raise AdapterError("REDIRECT_REJECTED")
                _decode_object(raw)
                return observation_factory(
                    int(response.status), final_url, raw, redirected=False,
                    tls_valid=True, complete=True)
        except urllib.error.HTTPError as error:
            # HTTP bodies are deliberately discarded; retry authority is never created.
            return observation_factory(
                int(error.code), registration.POST_URL, b"", redirected=False,
                tls_valid=True, complete=False)

    return post


@dataclass(frozen=True)
class RegistrationObservation:
    official_origin: str
    room: str
    room_generation: str
    first_observed_seq: int | None
    last_observed_seq: int | None
    record_count: int
    fetched_at: str
    response_sha256: str
    did_exact_match_count: int
    x_exact_match_count: int
    x_casefold_match_count: int
    conflict_classification: str


def classify_registration_export(
    raw: bytes, *, generation: str, fetched_at: datetime,
    receipt_classifier: Callable[[Mapping[str, Any]], Mapping[str, Any]],
) -> RegistrationObservation:
    if (type(generation) is not str or not generation or fetched_at.tzinfo is None
            or fetched_at.utcoffset() != timezone.utc.utcoffset(fetched_at)):
        raise AdapterError("OBSERVATION_METADATA_INVALID")
    decoded = _decode_object(raw)
    if set(decoded) != {"messages"} or type(decoded["messages"]) is not list:
        raise AdapterError("REGISTRATION_EXPORT_INVALID")
    records = decoded["messages"]
    if len(records) > 10_000:
        raise AdapterError("REGISTRATION_EXPORT_INVALID")
    seqs: list[int] = []
    did_count = x_count = x_fold_count = 0
    own_request_observed = False
    accepted_identical = False
    conflict = False
    for record in records:
        if type(record) is not dict or type(record.get("seq")) is not int:
            raise AdapterError("REGISTRATION_EXPORT_INVALID")
        seqs.append(record["seq"])
        text = record.get("text")
        if type(text) is not str or len(text.encode("utf-8")) > 4096:
            continue
        try:
            packet = json.loads(text, object_pairs_hook=_no_duplicates)
        except (json.JSONDecodeError, AdapterError):
            continue
        if type(packet) is not dict:
            continue
        did_match = record.get("from") == registration.PARTICIPANT_DID
        x_value = packet.get("x_account_url")
        exact_x = x_value == registration.X_ACCOUNT_URL
        folded_x = (type(x_value) is str
                    and x_value.casefold() == registration.X_ACCOUNT_URL.casefold())
        did_count += int(did_match)
        x_count += int(exact_x)
        x_fold_count += int(folded_x)
        if packet.get("type") == registration.PROTOCOL_TYPE:
            if (did_match and packet.get("role") == registration.ROLE
                    and exact_x and type(packet.get("request_id")) is str
                    and bool(packet["request_id"])):
                own_request_observed = True
            if ((did_match and (packet.get("role") != registration.ROLE
                                or not exact_x))
                    or (folded_x and not did_match)):
                conflict = True
        if packet.get("type") == "sonnet.receipt.v1":
            try:
                status = receipt_classifier(record).get("status")
            except Exception:
                continue
            if status == "ACCEPTED_VERIFIED":
                accepted_identical = True
    if accepted_identical:
        classification = ALREADY_REGISTERED_IDENTICALLY
    elif conflict:
        classification = REGISTRATION_CONFLICT
    elif own_request_observed:
        classification = REQUEST_OBSERVED_RECEIPT_UNCONFIRMED
    else:
        classification = NO_CONFLICT_IN_OBSERVED_WINDOW
    return RegistrationObservation(
        OFFICIAL_ORIGIN, registration.ROOM, generation,
        min(seqs) if seqs else None, max(seqs) if seqs else None, len(records),
        fetched_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        hashlib.sha256(raw).hexdigest(), did_count, x_count, x_fold_count,
        classification)


def _build_readonly_registration_adapter(
    *, opener_factory: Callable[[], Any], clock: Callable[[], datetime],
    receipt_classifier: Callable[[Mapping[str, Any]], Mapping[str, Any]],
) -> Callable[[], RegistrationObservation]:
    def read_once() -> RegistrationObservation:
        request = urllib.request.Request(REGISTRATION_GET_URL, method="GET", headers={
            "Accept": "application/json", "Accept-Encoding": "identity"})
        with opener_factory().open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            if response.geturl() != REGISTRATION_GET_URL:
                raise AdapterError("REDIRECT_REJECTED")
            generations = response.headers.get_all("X-Room-Generation") or []
            if (len(generations) != 1 or type(generations[0]) is not str
                    or not generations[0].isdigit()):
                raise AdapterError("ROOM_GENERATION_INVALID")
            generation = generations[0]
            raw = _read_bounded(response)
        return classify_registration_export(
            raw, generation=generation, fetched_at=clock(),
            receipt_classifier=receipt_classifier)
    return read_once


def bounded_readonly_reconciliation(
    read_once: Callable[[], RegistrationObservation], *, max_attempts: int,
) -> Mapping[str, Any]:
    if type(max_attempts) is not int or not 1 <= max_attempts <= MAX_READ_ATTEMPTS:
        raise AdapterError("RECONCILIATION_BOUND_INVALID")
    last: RegistrationObservation | None = None
    attempts = 0
    for _ in range(max_attempts):
        attempts += 1
        last = read_once()
        if last.conflict_classification in {
                ALREADY_REGISTERED_IDENTICALLY, REGISTRATION_CONFLICT}:
            break
    assert last is not None
    return MappingProxyType({
        "status": (last.conflict_classification
                   if last.conflict_classification != NO_CONFLICT_IN_OBSERVED_WINDOW
                   else AWAITING_REFEREE_RECEIPT),
        "read_attempts": attempts,
        "transport_invocations": 0,
        "retry_count": 0,
    })


def verify_local_prestart_evidence(
    record: Mapping[str, Any], *, verifier: Callable[[str, str, str, str, str], None],
) -> Mapping[str, str]:
    if (type(record) is not dict
            or set(record) != {"from", "sig", "room", "nonce", "text"}
            or record.get("from") != registration.PARTICIPANT_DID
            or type(record.get("nonce")) is not str
            or not record["nonce"].isdigit()):
        raise AdapterError("PRESTART_EVIDENCE_INVALID")
    observed = datetime.fromtimestamp(int(record["nonce"]) / 1000, tz=timezone.utc)
    if observed >= IDENTITY_CUTOFF:
        raise AdapterError("PRESTART_EVIDENCE_AFTER_CUTOFF")
    try:
        verifier(record["from"], record["sig"], record["room"],
                 record["nonce"], record["text"])
    except Exception:
        raise AdapterError("PRESTART_EVIDENCE_SIGNATURE_INVALID") from None
    return MappingProxyType({
        "local_prestart_evidence": PRESTART_EVIDENCE_LOCALLY_VERIFIED,
        "official_archive_eligibility": OFFICIAL_ARCHIVE_ELIGIBILITY_UNCONFIRMED,
    })


def _classify_observed_receipt(
    record: Mapping[str, Any], *,
    signature_verifier: Callable[[str, str, str, str, str], None] = verify_message,
) -> Mapping[str, str]:
    if (type(record) is not dict
            or any(type(record.get(key)) is not str or not record.get(key)
                   for key in ("from", "sig", "nonce", "text"))
            or record.get("from") != registration.REFEREE_DID
            or not record["nonce"].isdigit() or len(record["nonce"]) > 19
            or len(record["text"].encode("utf-8")) > 4096):
        raise AdapterError("RECEIPT_CANDIDATE_INVALID")
    try:
        signature_verifier(record["from"], record["sig"], registration.ROOM,
                           record["nonce"], record["text"])
    except Exception:
        raise AdapterError("RECEIPT_SIGNATURE_INVALID") from None
    receipt = _decode_object(record["text"].encode("utf-8"))
    if (set(receipt) != {"type", "contest_id", "request_id", "participant_did",
                         "role", "x_account_url", "status"}
            or receipt.get("type") != "sonnet.receipt.v1"
            or receipt.get("contest_id") != registration.CONTEST_ID
            or receipt.get("participant_did") != registration.PARTICIPANT_DID
            or receipt.get("role") != registration.ROLE
            or receipt.get("x_account_url") != registration.X_ACCOUNT_URL
            or type(receipt.get("request_id")) is not str
            or not receipt["request_id"]
            or receipt.get("status") not in {"accepted", "rejected"}):
        raise AdapterError("RECEIPT_BINDING_MISMATCH")
    return MappingProxyType({
        "status": ("ACCEPTED_VERIFIED" if receipt["status"] == "accepted"
                   else "REJECTED_VERIFIED")})


def evaluate_freshness(
    *, now: datetime, launch: Mapping[str, Any], observation: RegistrationObservation,
    prestart: Mapping[str, str], nonce_unused: bool, journal_state: str,
    approval_status: str, expected_generation: str,
) -> str:
    if (now.tzinfo is None or now.utcoffset() != timezone.utc.utcoffset(now)
            or now >= DEADLINE):
        raise AdapterError("REGISTRATION_DEADLINE_CLOSED")
    expected_launch = {
        "status": "open", "contest_id": registration.CONTEST_ID,
        "rules_version": RULES_VERSION, "referee_did": registration.REFEREE_DID,
        "manifest_commit": registration.MANIFEST_COMMIT,
        "manifest_sha256": registration.MANIFEST_SHA256,
    }
    if dict(launch) != expected_launch:
        raise AdapterError("LAUNCH_BINDING_MISMATCH")
    if dict(prestart) != {
            "local_prestart_evidence": PRESTART_EVIDENCE_LOCALLY_VERIFIED,
            "official_archive_eligibility": OFFICIAL_ARCHIVE_ELIGIBILITY_UNCONFIRMED}:
        raise AdapterError("PRESTART_EVIDENCE_UNRESOLVED")
    if (observation.official_origin != OFFICIAL_ORIGIN
            or observation.room != registration.ROOM
            or type(expected_generation) is not str or not expected_generation
            or observation.room_generation != expected_generation
            or len(observation.response_sha256) != 64
            or any(character not in "0123456789abcdef"
                   for character in observation.response_sha256)):
        raise AdapterError("OBSERVATION_BINDING_MISMATCH")
    try:
        fetched_at = datetime.fromisoformat(
            observation.fetched_at.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise AdapterError("OBSERVATION_BINDING_MISMATCH") from None
    if (fetched_at.tzinfo is None
            or fetched_at.utcoffset() != timezone.utc.utcoffset(fetched_at)):
        raise AdapterError("OBSERVATION_BINDING_MISMATCH")
    if (type(observation.record_count) is not int
            or observation.record_count < 0
            or any(type(count) is not int or not 0 <= count <= observation.record_count
                   for count in (observation.did_exact_match_count,
                                 observation.x_exact_match_count,
                                 observation.x_casefold_match_count))
            or ((observation.record_count == 0)
                != (observation.first_observed_seq is None
                    and observation.last_observed_seq is None))
            or (observation.record_count > 0
                and (type(observation.first_observed_seq) is not int
                     or type(observation.last_observed_seq) is not int
                     or observation.first_observed_seq < 0
                     or observation.first_observed_seq > observation.last_observed_seq))):
        raise AdapterError("OBSERVATION_BINDING_MISMATCH")
    age = now.astimezone(timezone.utc) - fetched_at.astimezone(timezone.utc)
    if age.total_seconds() < 0 or age.total_seconds() > 300:
        raise AdapterError("OBSERVATION_STALE")
    if observation.conflict_classification == ALREADY_REGISTERED_IDENTICALLY:
        return ALREADY_REGISTERED_IDENTICALLY
    if observation.conflict_classification == REGISTRATION_CONFLICT:
        raise AdapterError(REGISTRATION_CONFLICT)
    if observation.conflict_classification == REQUEST_OBSERVED_RECEIPT_UNCONFIRMED:
        return REQUEST_OBSERVED_RECEIPT_UNCONFIRMED
    if (observation.conflict_classification != NO_CONFLICT_IN_OBSERVED_WINDOW
            or nonce_unused is not True or journal_state != "NOT_STARTED"):
        raise AdapterError("FRESHNESS_GATE_REJECTED")
    if approval_status == "ABSENT":
        return "REGISTRATION_WRITE_APPROVAL_REQUIRED"
    if approval_status != "VALID":
        raise AdapterError("APPROVAL_INVALID_OR_EXPIRED")
    return "READY_FOR_REGISTRATION_EXECUTION"


production_identity_signer = _secure_identity_signer(_PRODUCTION_IDENTITY_PATH)
production_readonly_registration = _build_readonly_registration_adapter(
    opener_factory=_production_opener, clock=lambda: datetime.now(timezone.utc),
    receipt_classifier=_classify_observed_receipt)
