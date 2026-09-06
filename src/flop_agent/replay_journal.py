"""Fail-closed local replay ledger and side-effect journal.

The production service has no effect adapter and no authority issuer.  Its
SQLite location and all security policy are captured at module construction.
Private builders exist solely for isolated boundary tests and future reviewed
composition with an independent action-authority service.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import weakref
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import Any, Callable, Mapping


POLICY_VERSION = "local-replay-side-effect-policy-v1"
SCHEMA_VERSION = "replay-journal-v1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,511}$")
DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)$")


class ReplaySafetyError(ValueError):
    """Secret-safe denial with stable machine-readable code."""

    def __init__(self, code: str, field: str, reason: str):
        super().__init__(f"{code}: {field}: {reason}")
        self.code = code
        self.metadata = MappingProxyType({"field": field, "reason": reason})


class ReplayState(str, Enum):
    OBSERVED = "OBSERVED"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"
    REPLAY_IDENTITY_CONFLICT = "REPLAY_IDENTITY_CONFLICT"
    EFFECT_RESERVED = "EFFECT_RESERVED"
    EFFECT_ATTEMPTED = "EFFECT_ATTEMPTED"
    EFFECT_CONFIRMED = "EFFECT_CONFIRMED"
    EFFECT_FAILED_SAFE = "EFFECT_FAILED_SAFE"
    EFFECT_OUTCOME_UNKNOWN = "EFFECT_OUTCOME_UNKNOWN"


class RetryClassification(str, Enum):
    SAFE_TO_RETRY = "SAFE_TO_RETRY"
    DO_NOT_RETRY = "DO_NOT_RETRY"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"


class EffectClass(str, Enum):
    FAUCET_CLAIM = "FAUCET_CLAIM"
    INFERENCE_SPEND = "INFERENCE_SPEND"
    PAYMENT = "PAYMENT"
    AGENT_TASK = "AGENT_TASK"
    REPUTATION_CREDIT = "REPUTATION_CREDIT"


@dataclass(frozen=True)
class CanonicalAction:
    actor_did: str
    action_class: str
    context: str
    nonce: str
    signed_payload_sha256: str
    signing_bytes_sha256: str
    target: str
    schema_version: str

    def __post_init__(self) -> None:
        for field in ("actor_did", "action_class", "context", "target", "schema_version"):
            value = getattr(self, field)
            if not isinstance(value, str) or SAFE_TEXT.fullmatch(value) is None:
                raise ReplaySafetyError("IDENTIFIER_INVALID", field, "bounded exact text required")
        if not isinstance(self.nonce, str) or DECIMAL.fullmatch(self.nonce) is None:
            raise ReplaySafetyError("NONCE_INVALID", "nonce", "exact canonical decimal string required")
        for field in ("signed_payload_sha256", "signing_bytes_sha256"):
            value = getattr(self, field)
            if not isinstance(value, str) or HEX64.fullmatch(value) is None:
                raise ReplaySafetyError("HASH_INVALID", field, "lowercase SHA-256 hex required")


class ValidationAuthority:
    __slots__ = ("__weakref__",)
    def __new__(cls, *_args: Any, **_kwargs: Any) -> "ValidationAuthority":
        raise PermissionError("validation authority is issued only by a sealed validator")
    def __reduce__(self) -> Any:
        raise TypeError("validation authority cannot be serialized")
    def __copy__(self) -> "ValidationAuthority":
        raise TypeError("validation authority cannot be copied")
    __deepcopy__ = lambda self, _memo: self.__copy__()


class EffectAuthority:
    __slots__ = ("__weakref__",)
    def __new__(cls, *_args: Any, **_kwargs: Any) -> "EffectAuthority":
        raise PermissionError("effect authority is issued only by an independent sealed service")
    def __reduce__(self) -> Any:
        raise TypeError("effect authority cannot be serialized")
    def __copy__(self) -> "EffectAuthority":
        raise TypeError("effect authority cannot be copied")
    __deepcopy__ = lambda self, _memo: self.__copy__()


class Reservation:
    __slots__ = ("__weakref__",)
    def __new__(cls, *_args: Any, **_kwargs: Any) -> "Reservation":
        raise PermissionError("reservations are issued only by the sealed journal")
    def __reduce__(self) -> Any:
        raise TypeError("reservations cannot be serialized")
    def __copy__(self) -> "Reservation":
        raise TypeError("reservations cannot be copied")
    __deepcopy__ = lambda self, _memo: self.__copy__()


class ReconciliationAuthority:
    __slots__ = ("__weakref__",)
    def __new__(cls, *_args: Any, **_kwargs: Any) -> "ReconciliationAuthority":
        raise PermissionError("reconciliation authority is issued only after independent review")
    def __reduce__(self) -> Any:
        raise TypeError("reconciliation authority cannot be serialized")


def _build_replay_journal_service(db_path: Path, clock: Callable[[], datetime]) -> SimpleNamespace:
    """Build an isolated service; private dependency injection is test-only."""
    requested_path = db_path
    path = db_path.resolve(strict=False)
    parent = path.parent
    sha256, json_module, sqlite, os_module, close_connection = (
        hashlib.sha256, json, sqlite3, os, closing)
    datetime_type, utc = datetime, timezone.utc
    state_type, effect_type = ReplayState, EffectClass
    action_type, retry_type, error_type = CanonicalAction, RetryClassification, ReplaySafetyError
    proxy = MappingProxyType
    validation_type, authority_type = ValidationAuthority, EffectAuthority
    reservation_type, reconciliation_type = Reservation, ReconciliationAuthority
    policy, schema = POLICY_VERSION, SCHEMA_VERSION
    lock = threading.RLock()
    validations: weakref.WeakKeyDictionary[ValidationAuthority, str] = weakref.WeakKeyDictionary()
    authorities: weakref.WeakKeyDictionary[EffectAuthority, tuple[str, str]] = weakref.WeakKeyDictionary()
    reservations: weakref.WeakKeyDictionary[Reservation, tuple[str, str]] = weakref.WeakKeyDictionary()
    reconciliations: weakref.WeakKeyDictionary[ReconciliationAuthority, tuple[str, bool, str]] = weakref.WeakKeyDictionary()
    transitions = MappingProxyType({
        state_type.OBSERVED: frozenset({state_type.VALIDATED, state_type.REJECTED, state_type.REPLAY_IDENTITY_CONFLICT}),
        state_type.VALIDATED: frozenset({state_type.EFFECT_RESERVED, state_type.REJECTED, state_type.REPLAY_IDENTITY_CONFLICT}),
        state_type.EFFECT_RESERVED: frozenset({state_type.EFFECT_ATTEMPTED, state_type.EFFECT_FAILED_SAFE}),
        state_type.EFFECT_ATTEMPTED: frozenset({state_type.EFFECT_CONFIRMED, state_type.EFFECT_FAILED_SAFE, state_type.EFFECT_OUTCOME_UNKNOWN}),
        state_type.EFFECT_OUTCOME_UNKNOWN: frozenset({state_type.EFFECT_CONFIRMED, state_type.EFFECT_FAILED_SAFE}),
        state_type.EFFECT_FAILED_SAFE: frozenset({state_type.EFFECT_RESERVED}),
        state_type.REJECTED: frozenset(), state_type.REPLAY_IDENTITY_CONFLICT: frozenset(),
        state_type.EFFECT_CONFIRMED: frozenset(),
    })
    retry_policy = MappingProxyType({
        state_type.OBSERVED: RetryClassification.HUMAN_REVIEW_REQUIRED,
        state_type.VALIDATED: RetryClassification.SAFE_TO_RETRY,
        state_type.REJECTED: RetryClassification.DO_NOT_RETRY,
        state_type.REPLAY_IDENTITY_CONFLICT: RetryClassification.HUMAN_REVIEW_REQUIRED,
        state_type.EFFECT_RESERVED: RetryClassification.SAFE_TO_RETRY,
        state_type.EFFECT_ATTEMPTED: RetryClassification.RECONCILIATION_REQUIRED,
        state_type.EFFECT_CONFIRMED: RetryClassification.DO_NOT_RETRY,
        state_type.EFFECT_FAILED_SAFE: RetryClassification.SAFE_TO_RETRY,
        state_type.EFFECT_OUTCOME_UNKNOWN: RetryClassification.RECONCILIATION_REQUIRED,
    })
    effect_unknown_policy = MappingProxyType({
        effect_type.FAUCET_CLAIM: RetryClassification.RECONCILIATION_REQUIRED,
        effect_type.INFERENCE_SPEND: RetryClassification.RECONCILIATION_REQUIRED,
        effect_type.PAYMENT: RetryClassification.RECONCILIATION_REQUIRED,
        effect_type.AGENT_TASK: RetryClassification.HUMAN_REVIEW_REQUIRED,
        effect_type.REPUTATION_CREDIT: RetryClassification.HUMAN_REVIEW_REQUIRED,
    })

    def now_text() -> str:
        value = clock()
        if not isinstance(value, datetime_type) or value.tzinfo is None or value.utcoffset() is None:
            raise error_type("CLOCK_INVALID", "clock", "aware datetime required")
        return value.astimezone(utc).isoformat()

    def action_material(action: CanonicalAction) -> bytes:
        if type(action) is not action_type:
            raise error_type("ACTION_INVALID", "action", "canonical action required")
        return json_module.dumps({
            "actor_did": action.actor_did, "action_class": action.action_class,
            "context": action.context, "nonce": action.nonce,
            "signed_payload_sha256": action.signed_payload_sha256,
            "signing_bytes_sha256": action.signing_bytes_sha256,
            "target": action.target, "schema_version": action.schema_version,
            "policy_version": policy,
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

    def replay_id(action: CanonicalAction) -> str:
        return sha256(b"FLOP-REPLAY-ID\0" + action_material(action)).hexdigest()

    def nonce_scope(action: CanonicalAction) -> str:
        material = json_module.dumps({"actor_did": action.actor_did, "context": action.context,
            "nonce": action.nonce, "schema_version": action.schema_version},
            sort_keys=True, separators=(",", ":")).encode()
        return sha256(b"FLOP-NONCE-SCOPE\0" + material).hexdigest()

    def ensure_storage() -> None:
        if requested_path.is_symlink():
            raise error_type("STORAGE_UNSAFE", "storage", "symlinks are forbidden")
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if parent.is_symlink() or path.is_symlink():
            raise error_type("STORAGE_UNSAFE", "storage", "symlinks are forbidden")
        os_module.chmod(parent, 0o700)

    def connect() -> sqlite3.Connection:
        ensure_storage()
        connection = sqlite.connect(str(path), timeout=10, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.executescript("""
        CREATE TABLE IF NOT EXISTS replay_records (
          replay_id TEXT PRIMARY KEY, nonce_scope TEXT NOT NULL UNIQUE,
          actor_did TEXT NOT NULL, action_class TEXT NOT NULL, context TEXT NOT NULL,
          nonce TEXT NOT NULL, payload_hash TEXT NOT NULL, signing_hash TEXT NOT NULL,
          target TEXT NOT NULL, schema_version TEXT NOT NULL, state TEXT NOT NULL,
          observation_count INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS replay_events (
          event_id INTEGER PRIMARY KEY AUTOINCREMENT, replay_id TEXT NOT NULL,
          from_state TEXT, to_state TEXT NOT NULL, occurred_at TEXT NOT NULL,
          event_hash TEXT NOT NULL UNIQUE, FOREIGN KEY(replay_id) REFERENCES replay_records(replay_id));
        CREATE TABLE IF NOT EXISTS effects (
          reservation_id TEXT PRIMARY KEY, replay_id TEXT NOT NULL,
          authority_ref_hash TEXT NOT NULL, effect_class TEXT NOT NULL, target TEXT NOT NULL,
          request_hash TEXT NOT NULL, attempt_number TEXT NOT NULL, started_at TEXT,
          result_state TEXT NOT NULL, confirmation_evidence_hash TEXT,
          FOREIGN KEY(replay_id) REFERENCES replay_records(replay_id));
        """)
        os_module.chmod(path, 0o600)
        return connection

    def append_event(connection: sqlite3.Connection, rid: str, old: str | None,
                     new: str, when: str) -> None:
        count = connection.execute("SELECT COUNT(*) FROM replay_events WHERE replay_id=?", (rid,)).fetchone()[0]
        digest = sha256(f"{rid}|{count}|{old}|{new}|{when}".encode()).hexdigest()
        connection.execute("INSERT INTO replay_events(replay_id,from_state,to_state,occurred_at,event_hash) VALUES(?,?,?,?,?)",
                           (rid, old, new, when, digest))

    def transition(connection: sqlite3.Connection, rid: str, new: ReplayState, when: str) -> None:
        row = connection.execute("SELECT state FROM replay_records WHERE replay_id=?", (rid,)).fetchone()
        if row is None:
            raise error_type("REPLAY_NOT_FOUND", "replay_id", "record not found")
        old = state_type(row[0])
        if new not in transitions[old]:
            raise error_type("TRANSITION_INVALID", "state", "transition denied")
        connection.execute("UPDATE replay_records SET state=?,updated_at=? WHERE replay_id=?", (new.value, when, rid))
        append_event(connection, rid, old.value, new.value, when)

    def observe(action: CanonicalAction) -> Mapping[str, Any]:
        rid, scope, when = replay_id(action), nonce_scope(action), now_text()
        with lock, close_connection(connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute("SELECT replay_id,payload_hash,signing_hash,state,observation_count FROM replay_records WHERE nonce_scope=?", (scope,)).fetchone()
            if prior is not None and prior[0] != rid:
                connection.execute("UPDATE replay_records SET state=?,updated_at=? WHERE replay_id=?", (state_type.REPLAY_IDENTITY_CONFLICT.value, when, prior[0]))
                append_event(connection, prior[0], prior[3], state_type.REPLAY_IDENTITY_CONFLICT.value, when)
                connection.commit()
                return proxy({"status": "DESCRIPTIVE_ONLY", "decision": "REPLAY_IDENTITY_CONFLICT",
                    "replay_id": rid, "state": state_type.REPLAY_IDENTITY_CONFLICT.value,
                    "retry_classification": retry_type.HUMAN_REVIEW_REQUIRED.value})
            if prior is None:
                connection.execute("INSERT INTO replay_records VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (rid, scope, action.actor_did, action.action_class, action.context, action.nonce,
                     action.signed_payload_sha256, action.signing_bytes_sha256, action.target,
                     action.schema_version, state_type.OBSERVED.value, 1, when, when))
                append_event(connection, rid, None, state_type.OBSERVED.value, when)
                decision, count, current = "FIRST_OBSERVATION", 1, state_type.OBSERVED
            else:
                count, current = prior[4] + 1, state_type(prior[3])
                connection.execute("UPDATE replay_records SET observation_count=?,updated_at=? WHERE replay_id=?", (count, when, rid))
                decision = "DUPLICATE_OBSERVATION"
            connection.commit()
        return proxy({"status": "DESCRIPTIVE_ONLY", "decision": decision,
            "replay_id": rid, "state": current.value, "observation_count": count,
            "retry_classification": retry_policy[current].value})

    def issue_validation(action: CanonicalAction) -> ValidationAuthority:
        token = object.__new__(validation_type)
        validations[token] = replay_id(action)
        return token

    def validate(action: CanonicalAction, proof: ValidationAuthority) -> Mapping[str, Any]:
        rid, when = replay_id(action), now_text()
        if type(proof) is not validation_type or validations.get(proof) != rid:
            raise PermissionError("validation authority invalid or belongs to another service")
        with lock, close_connection(connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            transition(connection, rid, state_type.VALIDATED, when)
            connection.commit()
        return inspect(action)

    def issue_effect_authority(action: CanonicalAction, authority_reference: str) -> EffectAuthority:
        if not isinstance(authority_reference, str) or SAFE_TEXT.fullmatch(authority_reference) is None:
            raise error_type("AUTHORITY_REFERENCE_INVALID", "authority_reference", "safe reference required")
        token = object.__new__(authority_type)
        authorities[token] = (replay_id(action), sha256(authority_reference.encode()).hexdigest())
        return token

    def reserve(action: CanonicalAction, authorization: EffectAuthority, effect_class: EffectClass,
                target: str, request_hash: str) -> Reservation:
        rid, when = replay_id(action), now_text()
        if type(authorization) is not authority_type or authorization not in authorities or authorities[authorization][0] != rid:
            raise PermissionError("independent action authority invalid or belongs to another service")
        if type(effect_class) is not effect_type:
            raise error_type("EFFECT_CLASS_INVALID", "effect_class", "reviewed effect class required")
        if not isinstance(target, str) or SAFE_TEXT.fullmatch(target) is None or not isinstance(request_hash, str) or HEX64.fullmatch(request_hash) is None:
            raise error_type("EFFECT_IDENTITY_INVALID", "effect", "safe target and request hash required")
        with lock, close_connection(connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT state FROM replay_records WHERE replay_id=?", (rid,)).fetchone()
            if row is None or state_type(row[0]) not in {state_type.VALIDATED, state_type.EFFECT_FAILED_SAFE}:
                connection.rollback()
                raise error_type("EFFECT_RESERVATION_DENIED", "state", "validated safe state required")
            prior_attempts = connection.execute("SELECT COUNT(*) FROM effects WHERE replay_id=?", (rid,)).fetchone()[0]
            identity = sha256(f"{rid}|{effect_class.value}|{target}|{request_hash}".encode()).hexdigest()
            reservation_id = sha256(
                b"FLOP-RESERVATION\0" + identity.encode() + b"\0" + str(prior_attempts + 1).encode()
            ).hexdigest()
            try:
                connection.execute("INSERT INTO effects VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (reservation_id, rid, authorities[authorization][1], effect_class.value, target,
                     request_hash, str(prior_attempts + 1), None, state_type.EFFECT_RESERVED.value, None))
            except sqlite.IntegrityError as error:
                connection.rollback()
                raise error_type("DUPLICATE_EFFECT", "effect", "effect already reserved") from error
            transition(connection, rid, state_type.EFFECT_RESERVED, when)
            connection.commit()
        token = object.__new__(reservation_type)
        reservations[token] = (rid, reservation_id)
        return token

    def resolve_reservation(token: Reservation) -> tuple[str, str]:
        if type(token) is not reservation_type or token not in reservations:
            raise PermissionError("reservation invalid or belongs to another service")
        return reservations[token]

    def attempted(token: Reservation) -> Mapping[str, Any]:
        rid, reservation_id = resolve_reservation(token)
        when = now_text()
        with lock, close_connection(connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            transition(connection, rid, state_type.EFFECT_ATTEMPTED, when)
            connection.execute("UPDATE effects SET started_at=?,result_state=? WHERE reservation_id=?",
                               (when, state_type.EFFECT_ATTEMPTED.value, reservation_id))
            connection.commit()
        return inspect_id(rid)

    def confirm(token: Reservation, evidence_hash: str) -> Mapping[str, Any]:
        if not isinstance(evidence_hash, str) or HEX64.fullmatch(evidence_hash) is None:
            raise error_type("EVIDENCE_HASH_INVALID", "evidence_hash", "SHA-256 reference required")
        rid, reservation_id = resolve_reservation(token)
        when = now_text()
        with lock, close_connection(connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            transition(connection, rid, state_type.EFFECT_CONFIRMED, when)
            connection.execute("UPDATE effects SET result_state=?,confirmation_evidence_hash=? WHERE reservation_id=?",
                               (state_type.EFFECT_CONFIRMED.value, evidence_hash, reservation_id))
            connection.commit()
        return inspect_id(rid)

    def fail_safe(token: Reservation) -> Mapping[str, Any]:
        rid, reservation_id = resolve_reservation(token)
        when = now_text()
        with lock, close_connection(connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            transition(connection, rid, state_type.EFFECT_FAILED_SAFE, when)
            connection.execute("UPDATE effects SET result_state=? WHERE reservation_id=?",
                               (state_type.EFFECT_FAILED_SAFE.value, reservation_id))
            connection.commit()
        return inspect_id(rid)

    def recover() -> int:
        """Convert incomplete attempted operations to unknown, never to failed."""
        when = now_text()
        with lock, close_connection(connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute("SELECT replay_id FROM replay_records WHERE state=?", (state_type.EFFECT_ATTEMPTED.value,)).fetchall()
            for (rid,) in rows:
                transition(connection, rid, state_type.EFFECT_OUTCOME_UNKNOWN, when)
                connection.execute("UPDATE effects SET result_state=? WHERE replay_id=? AND result_state=?",
                    (state_type.EFFECT_OUTCOME_UNKNOWN.value, rid, state_type.EFFECT_ATTEMPTED.value))
            connection.commit()
        return len(rows)

    def issue_reconciliation(action: CanonicalAction, proved_no_effect: bool,
                             evidence_hash: str) -> ReconciliationAuthority:
        if type(proved_no_effect) is not bool or not isinstance(evidence_hash, str) or HEX64.fullmatch(evidence_hash) is None:
            raise error_type("RECONCILIATION_INVALID", "evidence", "explicit result and evidence hash required")
        token = object.__new__(reconciliation_type)
        reconciliations[token] = (replay_id(action), proved_no_effect, evidence_hash)
        return token

    def reconcile(action: CanonicalAction, proof: ReconciliationAuthority) -> Mapping[str, Any]:
        rid, when = replay_id(action), now_text()
        record = reconciliations.get(proof) if type(proof) is reconciliation_type else None
        if record is None or record[0] != rid:
            raise PermissionError("reconciliation authority invalid or belongs to another service")
        new = state_type.EFFECT_FAILED_SAFE if record[1] else state_type.EFFECT_CONFIRMED
        with lock, close_connection(connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            transition(connection, rid, new, when)
            connection.execute("UPDATE effects SET result_state=?,confirmation_evidence_hash=? WHERE replay_id=?",
                               (new.value, record[2], rid))
            connection.commit()
        return inspect_id(rid)

    def inspect_id(rid: str) -> Mapping[str, Any]:
        with close_connection(connect()) as connection:
            row = connection.execute("SELECT replay_id,action_class,state,created_at,updated_at,observation_count FROM replay_records WHERE replay_id=?", (rid,)).fetchone()
            if row is None:
                return proxy({"status": "DESCRIPTIVE_ONLY", "decision": "NOT_SEEN", "replay_id": rid})
            effect = connection.execute("SELECT effect_class,result_state,confirmation_evidence_hash FROM effects WHERE replay_id=? ORDER BY rowid DESC LIMIT 1", (rid,)).fetchone()
        current = state_type(row[2])
        classification = effect_unknown_policy[effect_type(effect[0])] if current is state_type.EFFECT_OUTCOME_UNKNOWN and effect else retry_policy[current]
        return proxy({"status": "DESCRIPTIVE_ONLY", "authority": "NOT_SERIALIZED",
            "replay_id": row[0], "action_class": row[1], "state": current.value,
            "created_at": row[3], "updated_at": row[4], "observation_count": row[5],
            "effect_class": effect[0] if effect else None,
            "confirmation_evidence_hash": effect[2] if effect else None,
            "retry_classification": classification.value})

    def inspect(action: CanonicalAction) -> Mapping[str, Any]:
        return inspect_id(replay_id(action))

    return SimpleNamespace(observe=observe, validate=validate, reserve=reserve,
        attempted=attempted, confirm=confirm, fail_safe=fail_safe, recover=recover,
        reconcile=reconcile, inspect=inspect, replay_id=replay_id,
        _issue_validation=issue_validation, _issue_effect_authority=issue_effect_authority,
        _issue_reconciliation=issue_reconciliation)


def _utc_now(_datetime: type[datetime] = datetime,
             _utc: timezone = timezone.utc) -> datetime:
    return _datetime.now(_utc)


_PRODUCTION_DB = Path(__file__).resolve().parents[2] / "secrets" / "replay-safety" / "ledger.sqlite3"
_PRODUCTION = _build_replay_journal_service(_PRODUCTION_DB, _utc_now)

# Production exposes observation and descriptive lookup only.  No validator,
# action-authority issuer, reservation, or effect adapter is configured here.
observe_action = _PRODUCTION.observe
inspect_action = _PRODUCTION.inspect
canonical_replay_id = _PRODUCTION.replay_id
recover_incomplete_attempts = _PRODUCTION.recover

__all__ = ("CanonicalAction", "EffectClass", "ReplaySafetyError", "ReplayState",
           "RetryClassification", "canonical_replay_id", "inspect_action",
           "observe_action", "recover_incomplete_attempts")
