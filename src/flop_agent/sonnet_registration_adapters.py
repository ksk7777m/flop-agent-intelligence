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
SAFE_INTEGER_MAX = 9_007_199_254_740_991
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


def _no_duplicates(
    pairs: list[tuple[str, Any]], _error: type[AdapterError] = AdapterError,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _error("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _decode_object(
    raw: bytes, _loads: Callable[..., Any] = json.loads,
    _error: type[AdapterError] = AdapterError,
) -> dict[str, Any]:
    try:
        value = _loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except _error:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _error("REMOTE_JSON_INVALID") from None
    if type(value) is not dict:
        raise _error("REMOTE_JSON_INVALID")
    return value


def _read_bounded(
    response: Any, limit: int = MAX_RESPONSE_BYTES,
    _error: type[AdapterError] = AdapterError,
) -> bytes:
    lengths = response.headers.get_all("Content-Length") or []
    if len(lengths) > 1:
        raise _error("RESPONSE_LENGTH_INVALID")
    if lengths:
        try:
            declared = int(lengths[0])
        except (TypeError, ValueError):
            raise _error("RESPONSE_LENGTH_INVALID") from None
        if declared < 0 or declared > limit:
            raise _error("RESPONSE_TOO_LARGE")
    encoding = response.headers.get("Content-Encoding")
    if encoding not in (None, "", "identity"):
        raise _error("RESPONSE_ENCODING_REJECTED")
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(8192, limit - total + 1))
        if not chunk:
            break
        if type(chunk) is not bytes:
            raise _error("RESPONSE_STREAM_INVALID")
        total += len(chunk)
        if total > limit:
            raise _error("RESPONSE_TOO_LARGE")
        chunks.append(chunk)
    body = b"".join(chunks)
    if lengths and len(body) != int(lengths[0]):
        raise _error("RESPONSE_TRUNCATED")
    return body


def _production_opener(
    _create_context: Callable[[], ssl.SSLContext] = ssl.create_default_context,
    _build_opener: Callable[..., Any] = urllib.request.build_opener,
    _proxy_type: Callable[..., Any] = urllib.request.ProxyHandler,
    _https_type: Callable[..., Any] = urllib.request.HTTPSHandler,
    _redirect_type: type[_NoRedirect] = _NoRedirect,
) -> Any:
    context = _create_context()
    return _build_opener(
        _proxy_type({}), _redirect_type(), _https_type(context=context))


def _secure_identity_signer(
    identity_path: Path, *, opener: Callable[..., int] = os.open,
    fstat: Callable[[int], os.stat_result] = os.fstat,
    reader: Callable[[int, int], bytes] = os.read,
    closer: Callable[[int], None] = os.close,
    path_stat: Callable[..., os.stat_result] = os.stat,
    expected_did: str = registration.PARTICIPANT_DID,
) -> Callable[[bytes], tuple[str, str]]:
    """Capture a fixed identity path; return only DID and exact-target signature."""
    configured = Path(os.path.abspath(identity_path))
    used = False
    expected_target = bytes(registration.SIGNING_TARGET_BYTES)
    expected_target_sha256 = str(registration.SIGNING_TARGET_SHA256)
    sha256 = hashlib.sha256
    error_type = AdapterError
    b64decode = base64.urlsafe_b64decode
    b64encode = base64.urlsafe_b64encode
    key_type = Ed25519PrivateKey
    did_builder = did_from_public_key
    mode_of = stat.S_IMODE
    is_regular = stat.S_ISREG
    current_uid = os.getuid
    decode_object = _decode_object
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise error_type("IDENTITY_NOFOLLOW_UNAVAILABLE")
    open_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow

    def sign_exact(target: bytes) -> tuple[str, str]:
        nonlocal used
        if used:
            raise error_type("SIGNER_ALREADY_USED")
        if (type(target) is not bytes
                or target != expected_target
                or sha256(target).hexdigest() != expected_target_sha256):
            raise error_type("SIGNING_TARGET_MISMATCH")
        used = True
        try:
            fd = opener(str(configured), open_flags)
        except OSError:
            raise error_type("IDENTITY_OPEN_REJECTED") from None
        try:
            info = fstat(fd)
            try:
                path_info = path_stat(str(configured), follow_symlinks=False)
            except OSError:
                raise error_type("IDENTITY_PATH_CHANGED") from None
            if (not is_regular(path_info.st_mode)
                    or path_info.st_dev != info.st_dev
                    or path_info.st_ino != info.st_ino):
                raise error_type("IDENTITY_PATH_CHANGED")
            if (not is_regular(info.st_mode) or mode_of(info.st_mode) != 0o600
                    or info.st_uid != current_uid() or info.st_nlink != 1):
                raise error_type("IDENTITY_FILE_UNSAFE")
            pieces: list[bytes] = []
            size = 0
            while True:
                piece = reader(fd, min(4096, 16_385 - size))
                if not piece:
                    break
                size += len(piece)
                if size > 16_384:
                    raise error_type("IDENTITY_FILE_UNSAFE")
                pieces.append(piece)
        finally:
            closer(fd)
        payload = decode_object(b"".join(pieces))
        if set(payload) != {"type", "did", "seed_b64"} or payload.get("type") != "Ed25519":
            raise error_type("IDENTITY_FORMAT_INVALID")
        try:
            encoded = payload["seed_b64"]
            if (type(encoded) is not str or len(encoded) != 43
                    or any(character not in
                           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                           for character in encoded)):
                raise ValueError
            seed = b64decode(encoded + "=" * (-len(encoded) % 4))
            if (len(seed) != 32
                    or b64encode(seed).decode("ascii").rstrip("=")
                    != encoded):
                raise ValueError
            key = key_type.from_private_bytes(seed)
            did = did_builder(key.public_key().public_bytes_raw())
        except Exception:
            raise error_type("IDENTITY_FORMAT_INVALID") from None
        if did != expected_did or payload.get("did") != did:
            raise error_type("IDENTITY_DID_MISMATCH")
        signature = b64encode(key.sign(target)).decode("ascii").rstrip("=")
        if (len(signature) != 86 or "=" in signature
                or b64encode(b64decode(signature + "==")).decode(
                    "ascii").rstrip("=") != signature):
            raise error_type("SIGNATURE_INVALID")
        return did, signature

    return sign_exact


def _build_post_transport(
    *, opener_factory: Callable[[], Any], observation_factory: Callable[..., Any],
    signature_verifier: Callable[[str, str, str, str, str], None] = verify_message,
) -> Callable[..., Any]:
    used = False
    post_url = str(registration.POST_URL)
    participant_did = str(registration.PARTICIPANT_DID)
    nonce = str(registration.NONCE)
    packet_text = str(registration.PACKET_TEXT)
    room = str(registration.ROOM)
    timeout = HTTP_TIMEOUT_SECONDS
    request_length = REQUEST_BODY_BYTE_LENGTH
    decode_object = _decode_object
    read_bounded = _read_bounded
    request_type = urllib.request.Request
    http_error_type = urllib.error.HTTPError
    sha256 = hashlib.sha256
    json_dumps = json.dumps
    error_type = AdapterError

    def post(url: str, body: bytes, **options: Any) -> Any:
        nonlocal used
        if used:
            raise error_type("TRANSPORT_ALREADY_USED")
        used = True
        if (url != post_url or options != {
                "method": "POST", "timeout_seconds": timeout,
                "allow_redirects": False, "allow_proxy": False,
                "credential_forwarding": False}):
            raise error_type("TRANSPORT_TARGET_REJECTED")
        if type(body) is not bytes or len(body) != request_length:
            raise error_type("REQUEST_BODY_INVALID")
        body_hash = sha256(body).digest()
        parsed = decode_object(body)
        if (tuple(parsed) != ("did", "nonce", "sig", "text")
                or set(parsed) != {"did", "sig", "nonce", "text"}
                or parsed.get("did") != participant_did
                or parsed.get("nonce") != nonce
                or parsed.get("text") != packet_text
                or type(parsed.get("sig")) is not str
                or len(parsed["sig"]) != 86
                or json_dumps(parsed, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=True).encode("utf-8") != body):
            raise error_type("REQUEST_BODY_INVALID")
        try:
            signature_verifier(parsed["did"], parsed["sig"], room,
                               parsed["nonce"], parsed["text"])
        except Exception:
            raise error_type("REQUEST_SIGNATURE_INVALID") from None
        request = request_type(
            post_url, data=body, method="POST", headers={
                "Accept": "application/json", "Accept-Encoding": "identity",
                "Content-Type": "application/json", "Content-Length": str(len(body)),
            })
        if sha256(bytes(request.data)).digest() != body_hash:
            raise error_type("REQUEST_BODY_CHANGED")
        opener = opener_factory()
        try:
            with opener.open(request, timeout=timeout) as response:
                final_url = response.geturl()
                raw = read_bounded(response)
                if final_url != post_url:
                    raise error_type("REDIRECT_REJECTED")
                decode_object(raw)
                return observation_factory(
                    int(response.status), final_url, raw, redirected=False,
                    tls_valid=True, complete=True)
        except http_error_type as error:
            # HTTP bodies are deliberately discarded; retry authority is never created.
            return observation_factory(
                int(error.code), post_url, b"", redirected=False,
                tls_valid=True, complete=False)

    return post


@dataclass(frozen=True)
class RegistrationObservation:
    official_origin: str
    room: str
    room_generation: int
    generation_trust: str
    first_observed_seq: int | None
    last_observed_seq: int | None
    record_count: int
    fetched_at: str
    response_sha256: str
    response_byte_length: int
    did_exact_match_count: int
    x_exact_match_count: int
    x_casefold_match_count: int
    conflict_classification: str


def classify_registration_export(
    raw: bytes, *, fetched_at: datetime,
    receipt_classifier: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    _room: str = registration.ROOM,
    _participant_did: str = registration.PARTICIPANT_DID,
    _x_url: str = registration.X_ACCOUNT_URL,
    _role: str = registration.ROLE,
    _protocol: str = registration.PROTOCOL_TYPE,
    _origin: str = OFFICIAL_ORIGIN,
    _safe_integer_max: int = SAFE_INTEGER_MAX,
    _decode: Callable[[bytes], dict[str, Any]] = _decode_object,
    _sha256: Callable[[bytes], Any] = hashlib.sha256,
) -> RegistrationObservation:
    if (fetched_at.tzinfo is None
            or fetched_at.utcoffset() != timezone.utc.utcoffset(fetched_at)):
        raise AdapterError("OBSERVATION_METADATA_INVALID")
    decoded = _decode(raw)
    if (set(decoded) != {"room", "count", "first_seq", "last_seq",
                         "generation", "messages"}
            or decoded.get("room") != _room
            or type(decoded.get("generation")) is not int
            or not 1 <= decoded["generation"] <= _safe_integer_max
            or type(decoded.get("count")) is not int
            or not 0 <= decoded["count"] <= 10_000
            or type(decoded.get("messages")) is not list
            or decoded["count"] != len(decoded["messages"])):
        raise AdapterError("REGISTRATION_EXPORT_INVALID")
    records = decoded["messages"]
    seqs: list[int] = []
    did_count = x_count = x_fold_count = 0
    own_request_observed = False
    accepted_identical = False
    conflict = False
    for record in records:
        if (type(record) is not dict or type(record.get("seq")) is not int
                or not 0 <= record["seq"] <= _safe_integer_max):
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
        did_match = record.get("from") == _participant_did
        x_value = packet.get("x_account_url")
        exact_x = x_value == _x_url
        folded_x = (type(x_value) is str
                    and x_value.casefold() == _x_url.casefold())
        did_count += int(did_match)
        x_count += int(exact_x)
        x_fold_count += int(folded_x)
        if packet.get("type") == _protocol:
            if (did_match and packet.get("role") == _role
                    and exact_x and type(packet.get("request_id")) is str
                    and bool(packet["request_id"])):
                own_request_observed = True
            if ((did_match and (packet.get("role") != _role
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
    if records:
        if (type(decoded.get("first_seq")) is not int
                or type(decoded.get("last_seq")) is not int
                or decoded["first_seq"] != min(seqs)
                or decoded["last_seq"] != max(seqs)):
            raise AdapterError("REGISTRATION_EXPORT_INVALID")
    elif decoded.get("first_seq") is not None or decoded.get("last_seq") is not None:
        raise AdapterError("REGISTRATION_EXPORT_INVALID")
    if accepted_identical:
        classification = ALREADY_REGISTERED_IDENTICALLY
    elif conflict:
        classification = REGISTRATION_CONFLICT
    elif own_request_observed:
        classification = REQUEST_OBSERVED_RECEIPT_UNCONFIRMED
    else:
        classification = NO_CONFLICT_IN_OBSERVED_WINDOW
    return RegistrationObservation(
        _origin, _room, decoded["generation"],
        "OBSERVED_DEPLOYMENT_FIELD",
        min(seqs) if seqs else None, max(seqs) if seqs else None, len(records),
        fetched_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        _sha256(raw).hexdigest(), len(raw), did_count, x_count, x_fold_count,
        classification)


def _build_readonly_registration_adapter(
    *, opener_factory: Callable[[], Any], clock: Callable[[], datetime],
    receipt_classifier: Callable[[Mapping[str, Any]], Mapping[str, Any]],
) -> Callable[[], RegistrationObservation]:
    get_url = REGISTRATION_GET_URL
    timeout = HTTP_TIMEOUT_SECONDS
    request_type = urllib.request.Request
    read_bounded = _read_bounded
    classify = classify_registration_export
    error_type = AdapterError

    def read_once() -> RegistrationObservation:
        request = request_type(get_url, method="GET", headers={
            "Accept": "application/json", "Accept-Encoding": "identity"})
        with opener_factory().open(request, timeout=timeout) as response:
            if response.geturl() != get_url:
                raise error_type("REDIRECT_REJECTED")
            raw = read_bounded(response)
        return classify(
            raw, fetched_at=clock(),
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
    _referee_did: str = registration.REFEREE_DID,
    _room: str = registration.ROOM,
    _contest_id: str = registration.CONTEST_ID,
    _participant_did: str = registration.PARTICIPANT_DID,
    _role: str = registration.ROLE,
    _x_url: str = registration.X_ACCOUNT_URL,
) -> Mapping[str, str]:
    if (type(record) is not dict
            or any(type(record.get(key)) is not str or not record.get(key)
                   for key in ("from", "sig", "nonce", "text"))
            or record.get("from") != _referee_did
            or not record["nonce"].isdigit() or len(record["nonce"]) > 19
            or len(record["text"].encode("utf-8")) > 4096):
        raise AdapterError("RECEIPT_CANDIDATE_INVALID")
    try:
        signature_verifier(record["from"], record["sig"], _room,
                           record["nonce"], record["text"])
    except Exception:
        raise AdapterError("RECEIPT_SIGNATURE_INVALID") from None
    receipt = _decode_object(record["text"].encode("utf-8"))
    required_fields = {"type", "contest_id", "request_id", "participant_did",
                       "role", "x_account_url", "status"}
    if (not required_fields <= set(receipt)
            or not set(receipt) <= required_fields | {"reason"}
            or receipt.get("type") != "sonnet.receipt.v1"
            or receipt.get("contest_id") != _contest_id
            or receipt.get("participant_did") != _participant_did
            or receipt.get("role") != _role
            or receipt.get("x_account_url") != _x_url
            or type(receipt.get("request_id")) is not str
            or not receipt["request_id"]
            or ("reason" in receipt and type(receipt["reason"]) is not str)
            or receipt.get("status") not in {"accepted", "rejected"}):
        raise AdapterError("RECEIPT_BINDING_MISMATCH")
    return MappingProxyType({
        "status": ("ACCEPTED_VERIFIED" if receipt["status"] == "accepted"
                   else "REJECTED_VERIFIED")})


def evaluate_freshness(
    *, now: datetime, launch: Mapping[str, Any], observation: RegistrationObservation,
    prestart: Mapping[str, str], nonce_unused: bool, journal_state: str,
    approval_status: str, expected_generation: int,
    _deadline: datetime = DEADLINE,
    _origin: str = OFFICIAL_ORIGIN,
    _room: str = registration.ROOM,
    _contest_id: str = registration.CONTEST_ID,
    _rules_version: str = RULES_VERSION,
    _referee_did: str = registration.REFEREE_DID,
    _manifest_commit: str = registration.MANIFEST_COMMIT,
    _manifest_sha256: str = registration.MANIFEST_SHA256,
) -> str:
    if (now.tzinfo is None or now.utcoffset() != timezone.utc.utcoffset(now)
            or now >= _deadline):
        raise AdapterError("REGISTRATION_DEADLINE_CLOSED")
    expected_launch = {
        "status": "open", "contest_id": _contest_id,
        "rules_version": _rules_version, "referee_did": _referee_did,
        "manifest_commit": _manifest_commit,
        "manifest_sha256": _manifest_sha256,
    }
    if dict(launch) != expected_launch:
        raise AdapterError("LAUNCH_BINDING_MISMATCH")
    if dict(prestart) != {
            "local_prestart_evidence": PRESTART_EVIDENCE_LOCALLY_VERIFIED,
            "official_archive_eligibility": OFFICIAL_ARCHIVE_ELIGIBILITY_UNCONFIRMED}:
        raise AdapterError("PRESTART_EVIDENCE_UNRESOLVED")
    if (observation.official_origin != _origin
            or observation.room != _room
            or type(expected_generation) is not int or expected_generation < 1
            or observation.room_generation != expected_generation
            or observation.generation_trust != "OBSERVED_DEPLOYMENT_FIELD"
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
            or type(observation.response_byte_length) is not int
            or not 0 <= observation.response_byte_length <= MAX_RESPONSE_BYTES
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
