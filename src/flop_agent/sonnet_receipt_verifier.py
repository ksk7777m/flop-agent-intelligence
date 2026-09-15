"""Signature-verification-only boundary for the fixed Sonnet receipt.

This module deliberately contains no signer, identity loader, nonce allocator,
HTTP transport, or registration writer.  Production receipt observation can
therefore verify referee evidence without importing the registration adapter.
"""

from __future__ import annotations

import json
from types import MappingProxyType
from typing import Any, Callable, Mapping

from . import sonnet_registration as registration
from .message_verification import verify_message


class AdapterError(PermissionError):
    """A fixed-code error which never includes remote or secret content."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AdapterError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _decode_object(
    raw: bytes, *, _loads: Callable[..., Any] = json.loads,
    _pairs_hook: Callable[[list[tuple[str, Any]]], dict[str, Any]] = _no_duplicates,
    _error: type[AdapterError] = AdapterError,
) -> dict[str, Any]:
    try:
        value = _loads(raw.decode("utf-8"), object_pairs_hook=_pairs_hook)
    except _error:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _error("REMOTE_JSON_INVALID") from None
    if type(value) is not dict:
        raise _error("REMOTE_JSON_INVALID")
    return value


def _classify_observed_receipt_core(
    record: Mapping[str, Any], *,
    signature_verifier: Callable[[str, str, str, str, str], None],
    referee_did: str, room: str, contest_id: str, participant_did: str,
    role: str, x_url: str, request_id: str,
    _decoder: Callable[[bytes], dict[str, Any]] = _decode_object,
) -> Mapping[str, str]:
    if (type(record) is not dict
            or any(type(record.get(key)) is not str or not record.get(key)
                   for key in ("from", "sig", "nonce", "text"))
            or record.get("from") != referee_did
            or not record["nonce"].isdigit() or len(record["nonce"]) > 19
            or len(record["text"].encode("utf-8")) > 4096):
        raise AdapterError("RECEIPT_CANDIDATE_INVALID")
    try:
        signature_verifier(record["from"], record["sig"], room,
                           record["nonce"], record["text"])
    except Exception:
        raise AdapterError("RECEIPT_SIGNATURE_INVALID") from None
    receipt = _decoder(record["text"].encode("utf-8"))
    required_fields = {"type", "contest_id", "request_id", "participant_did",
                       "role", "x_account_url", "status"}
    if (not required_fields <= set(receipt)
            or not set(receipt) <= required_fields | {"reason"}
            or receipt.get("type") != "sonnet.receipt.v1"
            or receipt.get("contest_id") != contest_id
            or receipt.get("participant_did") != participant_did
            or receipt.get("role") != role
            or receipt.get("x_account_url") != x_url
            or ("reason" in receipt and type(receipt["reason"]) is not str)
            or receipt.get("status") not in {"accepted", "rejected"}):
        raise AdapterError("RECEIPT_BINDING_MISMATCH")
    if (type(receipt.get("request_id")) is not str
            or receipt["request_id"] != request_id):
        raise AdapterError("RECEIPT_REQUEST_ID_MISMATCH")
    if ("request_id" in record
            and (type(record["request_id"]) is not str
                 or record["request_id"] != receipt["request_id"])):
        raise AdapterError("RECEIPT_OUTER_METADATA_MISMATCH")
    return MappingProxyType({
        "status": ("ACCEPTED_VERIFIED" if receipt["status"] == "accepted"
                   else "REJECTED_VERIFIED")})


def _seal_receipt_classifier_factory() -> Callable[..., Any]:
    """Expose only verifier substitution; all registration bindings stay sealed."""
    core = _classify_observed_receipt_core
    referee_did = registration.REFEREE_DID
    room = registration.ROOM
    contest_id = registration.CONTEST_ID
    participant_did = registration.PARTICIPANT_DID
    role = registration.ROLE
    x_url = registration.X_ACCOUNT_URL
    request_id = registration.REQUEST_ID

    def build(
        signature_verifier: Callable[[str, str, str, str, str], None],
    ) -> Callable[[Mapping[str, Any]], Mapping[str, str]]:
        def classify(record: Mapping[str, Any]) -> Mapping[str, str]:
            return core(
                record, signature_verifier=signature_verifier,
                referee_did=referee_did, room=room, contest_id=contest_id,
                participant_did=participant_did, role=role, x_url=x_url,
                request_id=request_id)

        return classify

    return build


_build_fixed_receipt_classifier_for_test = _seal_receipt_classifier_factory()
del _seal_receipt_classifier_factory
del _classify_observed_receipt_core
_classify_observed_receipt = _build_fixed_receipt_classifier_for_test(
    verify_message)
