"""Technocore Presence Adapter V0.1: live-ready, disabled by default.

Presence is a public, unsigned, mutable note. It proves neither identity nor
authorization. No production HTTP writer is wired into this module or the CLI.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Mapping

from .remote_content_policy import LocalActionClass, ReviewedLocalIntent, require_local_intent
from .technocore import read_official

ADAPTER_VERSION = "Presence V0.1"
CAPABILITY_CONFIG_VERSION = "presence-v0.1"
CONFIG_SCHEMA = "technocore-presence-config-v0.1"
STATE_SCHEMA = "technocore-presence-state-v0.1"
ROOMS_PATH = "/rooms?format=json"
AGENT_PATH = "/.well-known/agent.json"
CONFIG_PATH = "/config"
MINIMUM_LIVE_WRITE_SECONDS = 3600
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
SEMANTIC_CONTRACT_ANCHOR = "technocore-presence-semantic-v0.1-reviewed-2026-08-29"
SEMANTIC_CONTRACT_PATH = Path(__file__).resolve().parents[2] / "data" / "presence_semantic_contract.json"
STATES = {"LIVE", "UNKNOWN", "NEVER_OBSERVED", "DISABLED", "SPEC_CHANGED", "CONFLICT",
          "READBACK_MISMATCH", "REAPPROVAL_REQUIRED"}


class PresenceError(RuntimeError):
    """Fail-closed presence error."""


class LiveWriteDisabled(PermissionError):
    """Raised unless every live-write gate is satisfied."""


class ConflictError(RuntimeError):
    """A writer may raise this for an HTTP 409 response."""
    def __init__(self, current_value: str):
        super().__init__("Technocore note conflict")
        self.current_value = current_value


@dataclass(frozen=True)
class PresenceConfig:
    room: str
    nick: str
    semantic_spec_anchor: str
    approved_semantic_contract_sha256: str
    approved_agent_version: str
    approved_agent_manifest_sha256: str | None = None
    operator_enabled: bool = False
    live_write_enabled: bool = False
    semantic_spec_approved: bool = False
    minimum_update_seconds: int = MINIMUM_LIVE_WRITE_SECONDS

    def __post_init__(self) -> None:
        validate_public_room(self.room)
        validate_name(self.nick, "nick")
        if self.semantic_spec_anchor != SEMANTIC_CONTRACT_ANCHOR:
            raise PresenceError("semantic_spec_anchor is not the reviewed Presence contract")
        if (not isinstance(self.approved_semantic_contract_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", self.approved_semantic_contract_sha256) is None):
            raise PresenceError("approved_semantic_contract_sha256 must be a lowercase SHA-256")
        if not isinstance(self.approved_agent_version, str) or not self.approved_agent_version:
            raise PresenceError("approved_agent_version is required as a re-review detector")
        if self.approved_agent_manifest_sha256 is not None and re.fullmatch(
                r"[0-9a-f]{64}", self.approved_agent_manifest_sha256) is None:
            raise PresenceError("approved_agent_manifest_sha256 must be a lowercase SHA-256")
        if (isinstance(self.minimum_update_seconds, bool)
                or not isinstance(self.minimum_update_seconds, int)
                or self.minimum_update_seconds < MINIMUM_LIVE_WRITE_SECONDS):
            raise PresenceError("minimum_update_seconds cannot be below the one-hour safety floor")

    @property
    def note_path(self) -> str:
        return presence_path(self.room, self.nick)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "PresenceConfig":
        if raw.get("schema") != CONFIG_SCHEMA:
            raise PresenceError(f"config schema must be {CONFIG_SCHEMA}")
        room, nick = raw.get("room"), raw.get("nick")
        validate_public_room(room)
        validate_name(nick, "nick")
        anchor = raw.get("semantic_spec_anchor")
        contract_hash = raw.get("approved_semantic_contract_sha256")
        version = raw.get("approved_agent_version")
        if not isinstance(anchor, str) or not anchor:
            raise PresenceError("semantic_spec_anchor is required")
        if not isinstance(version, str) or not version:
            raise PresenceError("approved_agent_version is required")
        interval = raw.get("minimum_update_seconds", MINIMUM_LIVE_WRITE_SECONDS)
        if isinstance(interval, bool) or not isinstance(interval, int) or interval < MINIMUM_LIVE_WRITE_SECONDS:
            raise PresenceError("minimum_update_seconds cannot be below the one-hour safety floor")
        manifest_hash = raw.get("approved_agent_manifest_sha256")
        if manifest_hash is not None and (not isinstance(manifest_hash, str)
                                          or re.fullmatch(r"[0-9a-f]{64}", manifest_hash) is None):
            raise PresenceError("approved_agent_manifest_sha256 must be a lowercase SHA-256")
        return cls(room, nick, anchor, contract_hash, version, manifest_hash, raw.get("operator_enabled") is True,
                   raw.get("live_write_enabled") is True, raw.get("semantic_spec_approved") is True, interval)


def validate_name(value: Any, label: str) -> str:
    if not isinstance(value, str) or NAME_RE.fullmatch(value) is None:
        raise PresenceError(f"invalid {label}")
    return value


def validate_public_room(room: Any) -> str:
    validate_name(room, "room")
    parts = str(room).split("-")
    if parts[0] in {"p", "mb"} or "p" in parts[:-1]:
        raise PresenceError("private or unlisted rooms are not valid presence sources")
    return str(room)


def presence_path(room: str, nick: str) -> str:
    return f"/kv/{validate_public_room(room)}/hb-{validate_name(nick, 'nick')}"


def scalar_value(seq: int) -> str:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise PresenceError("observed sequence must be a non-negative integer")
    return str(seq)


def load_config(path: Path) -> PresenceConfig:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PresenceError(f"could not load presence config: {error}") from error
    if not isinstance(raw, dict):
        raise PresenceError("presence config must be a JSON object")
    return PresenceConfig.from_mapping(raw)


def _latest_seq(response: Any, room: str) -> int:
    if not isinstance(response, Mapping) or not isinstance(response.get("rooms"), list):
        raise PresenceError("malformed Technocore rooms response")
    matches = [x for x in response["rooms"] if isinstance(x, Mapping) and x.get("room") == room]
    if len(matches) != 1:
        raise PresenceError(f"configured public room is {'missing' if not matches else 'ambiguous'}")
    return int(scalar_value(matches[0].get("last_seq")))


def _load_state(path: Path) -> Dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PresenceError(f"could not load presence state: {error}") from error
    if not isinstance(state, dict) or state.get("schema") != STATE_SCHEMA:
        raise PresenceError("presence state is malformed")
    return state


def _save_state(path: Path, state: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _iso(now: datetime) -> str:
    return now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc) if isinstance(value, str) else None
    except ValueError:
        return None


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_sha256(value: Any) -> str:
    return _sha(json.dumps(value, sort_keys=True, separators=(",", ":")))


def load_semantic_contract(path: Path = SEMANTIC_CONTRACT_PATH,
                           expected_sha256: str | None = None) -> tuple[Dict[str, Any], str]:
    """Load, validate and canonically bind the one reviewed semantic source."""
    try:
        contract = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PresenceError(f"semantic contract unavailable or malformed: {error}") from error
    if not isinstance(contract, dict):
        raise PresenceError("semantic contract must be a JSON object")
    expected = {
        "schema": "technocore-presence-semantic-contract-v0.1",
        "classification": "LOCALLY_REVIEWED_OFFICIAL_SEMANTIC_CONTRACT",
        "semantic_contract_version": "0.1",
        "anchor": SEMANTIC_CONTRACT_ANCHOR,
        "path_template": "/kv/<room>/hb-<nick>",
        "value": "scalar_decimal_room_sequence",
        "conditional_create": "if_absent",
        "conditional_update": "exact_value_cas_if",
        "conflict": "http_409_returns_current_value",
        "authentication": "public_unsigned_unauthenticated_mutable_last_write_wins_note",
        "name_pattern": NAME_RE.pattern,
    }
    if not all(contract.get(key) == value for key, value in expected.items()):
        raise PresenceError("semantic contract contains unreviewed semantics")
    if not isinstance(contract.get("reviewed_at"), str) or not contract["reviewed_at"]:
        raise PresenceError("semantic contract reviewed_at is required")
    if not isinstance(contract.get("reviewed_source_version"), str) or not contract["reviewed_source_version"]:
        raise PresenceError("semantic contract reviewed_source_version is required")
    sources = contract.get("official_sources")
    if not isinstance(sources, list) or not sources or not all(
            isinstance(source, str) and source.startswith("https://") for source in sources):
        raise PresenceError("semantic contract official_sources are required")
    digest = canonical_sha256(contract)
    if expected_sha256 is not None and digest != expected_sha256:
        raise PresenceError("semantic contract SHA-256 does not match approved review")
    return contract, digest


def detect_server_spec_change(config: PresenceConfig, discovery: Any) -> bool:
    """Use server version/manifest identity only as fail-closed re-review triggers."""
    if not isinstance(discovery, Mapping) or discovery.get("name") != "technocore-chat":
        return True
    conventions = discovery.get("conventions")
    if not isinstance(conventions, Mapping) or conventions.get("name_pattern") != NAME_RE.pattern:
        return True
    if discovery.get("version") != config.approved_agent_version:
        return True
    return (config.approved_agent_manifest_sha256 is not None
            and canonical_sha256(discovery) != config.approved_agent_manifest_sha256)


def runtime_context(raw: Any) -> Dict[str, Any]:
    """Extract informational mutable deployment values without eligibility claims."""
    keys = ("read_rate_limit", "write_rate_limit", "retention", "room_capacity",
            "note_capacity", "deployment_version")
    if not isinstance(raw, Mapping):
        return {"classification": "RUNTIME_CONTEXT", "status": "UNKNOWN",
                **{key: "UNKNOWN" for key in keys},
                "warnings": ["/config unavailable or malformed; no values fabricated"]}
    limits = raw.get("limits") if isinstance(raw.get("limits"), Mapping) else {}
    retention = raw.get("retention") if isinstance(raw.get("retention"), Mapping) else {}
    values = {
        "read_rate_limit": limits.get("reads", raw.get("read_rate_limit", "UNKNOWN")),
        "write_rate_limit": limits.get("writes", raw.get("write_rate_limit", "UNKNOWN")),
        "retention": retention or raw.get("retention_seconds", "UNKNOWN"),
        "room_capacity": limits.get("rooms", raw.get("room_capacity", "UNKNOWN")),
        "note_capacity": limits.get("notes", raw.get("note_capacity", "UNKNOWN")),
        "deployment_version": raw.get("version", "UNKNOWN"),
    }
    missing = [key for key, value in values.items() if value == "UNKNOWN"]
    return {"classification": "RUNTIME_CONTEXT", "status": "PARTIAL" if missing else "AVAILABLE",
            **values, "warnings": [f"missing informational /config fields: {', '.join(missing)}"] if missing else []}


def classify_note(current_value: Any, last_successful_seq: int | None) -> str:
    if current_value is None:
        return "ABSENT"
    expected = scalar_value(last_successful_seq) if last_successful_seq is not None else None
    return "EXPECTED" if isinstance(current_value, str) and expected is not None and current_value == expected else "UNEXPECTED"


def _blank_state(config: PresenceConfig) -> Dict[str, Any]:
    return {"schema": STATE_SCHEMA, "adapter_version": ADAPTER_VERSION, "room": config.room,
            "path": config.note_path, "state": "NEVER_OBSERVED", "last_observed_seq": None,
            "last_successfully_published_seq": None, "last_observed_at": None,
            "last_successful_write_at": None, "last_attempted_write_at": None,
            "known_note_present": False, "writes": 0, "live_write_ready": False}


def observe(config: PresenceConfig, state_path: Path, *, reader: Callable[[str], Any] = read_official,
            now: datetime | None = None) -> Dict[str, Any]:
    """Observe aggregate room metadata only; no message body is read or retained."""
    observed = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    state = _load_state(state_path) or _blank_state(config)
    if state.get("room") != config.room or state.get("path") != config.note_path:
        raise PresenceError("presence state belongs to a different configuration")
    if not config.operator_enabled:
        state.update({"state": "DISABLED", "live_write_ready": False})
        _save_state(state_path, state)
        return {"status": "DISABLED", "write_performed": False, "payload": None, "state": state}
    latest_seq = _latest_seq(reader(ROOMS_PATH), config.room)
    previous_seq = state.get("last_observed_seq")
    state.update({"last_observed_seq": latest_seq, "last_observed_at": _iso(observed)})
    if previous_seq is None:
        status = "UNKNOWN"
    elif latest_seq < previous_seq or (state.get("last_successfully_published_seq") is not None
                                       and latest_seq < state["last_successfully_published_seq"]):
        status = "CONFLICT"
    else:
        status = "LIVE" if latest_seq > previous_seq else "UNKNOWN"
    state.update({"state": status, "live_write_ready": False})
    _save_state(state_path, state)
    return {"status": status, "write_performed": False, "payload": None, "state": state}


def _note_request(config: PresenceConfig, seq: int, note_state: str, previous_seq: int | None) -> Dict[str, Any]:
    body: Dict[str, Any] = {"value": scalar_value(seq)}
    if note_state == "ABSENT":
        body["if_absent"] = True
    elif note_state == "EXPECTED" and previous_seq is not None:
        body["if"] = scalar_value(previous_seq)
    else:
        raise PresenceError("unexpected note state cannot produce a request")
    return {"method": "POST", "path": config.note_path, "body": body}


def approval_metadata(config: PresenceConfig, request: Mapping[str, Any], observed_seq: int,
                      observed_at: str, note_state: str, application_commit: str,
                      semantic_contract_sha256: str) -> Dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{40}", application_commit) is None:
        raise PresenceError("application_commit must be an exact lowercase Git commit")
    body = json.dumps(request["body"], sort_keys=True, separators=(",", ":"))
    return {"room": config.room, "path": config.note_path, "method": request["method"],
            "body": request["body"], "observed_seq": observed_seq, "observed_at": observed_at,
            "expected_note_state": note_state, "payload_sha256": _sha(body),
            "application_commit": application_commit, "adapter_version": ADAPTER_VERSION,
            "semantic_spec_anchor": config.semantic_spec_anchor,
            "semantic_contract_sha256": semantic_contract_sha256}


def approval_digest(metadata: Mapping[str, Any]) -> str:
    return _sha(json.dumps(metadata, sort_keys=True, separators=(",", ":")))


def validate_approval(metadata: Mapping[str, Any], approval: Mapping[str, Any]) -> bool:
    return approval.get("binding_sha256") == approval_digest(metadata) and approval.get("metadata") == metadata


def preview_first_write(config: PresenceConfig, state_path: Path, *, reader: Callable[[str], Any],
                        application_commit: str, now: datetime | None = None,
                        semantic_contract_path: Path = SEMANTIC_CONTRACT_PATH) -> Dict[str, Any]:
    """Fresh reads, exact request and approval binding; guaranteed zero-write."""
    observed = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    state = _load_state(state_path) or _blank_state(config)
    discovery = reader(AGENT_PATH)
    try:
        contract, contract_digest = load_semantic_contract(
            semantic_contract_path, config.approved_semantic_contract_sha256)
    except PresenceError:
        state.update({"state": "SPEC_CHANGED", "live_write_ready": False}); _save_state(state_path, state)
        return {"status": "SPEC_CHANGED", "write_performed": False, "request": None}
    if config.semantic_spec_anchor != contract["anchor"] or detect_server_spec_change(config, discovery):
        state.update({"state": "SPEC_CHANGED", "live_write_ready": False}); _save_state(state_path, state)
        return {"status": "SPEC_CHANGED", "write_performed": False, "request": None}
    try:
        deployment = runtime_context(reader(CONFIG_PATH))
    except Exception:
        deployment = runtime_context(None)
    latest_seq, observed_at = _latest_seq(reader(ROOMS_PATH), config.room), _iso(observed)
    previous_observed = state.get("last_observed_seq")
    state.update({"last_observed_seq": latest_seq, "last_observed_at": observed_at})
    if previous_observed is not None and latest_seq < previous_observed:
        state.update({"state": "CONFLICT", "live_write_ready": False}); _save_state(state_path, state)
        return {"status": "CONFLICT", "write_performed": False, "request": None}
    current = reader(config.note_path)
    note_state = classify_note(current, state.get("last_successfully_published_seq"))
    if current is None and state.get("known_note_present"):
        state.update({"state": "REAPPROVAL_REQUIRED", "live_write_ready": False}); _save_state(state_path, state)
        return {"status": "REAPPROVAL_REQUIRED", "note_state": "ABSENT", "write_performed": False, "request": None}
    if note_state == "UNEXPECTED":
        state.update({"state": "CONFLICT", "unexpected_value_sha256": _sha(str(current)), "live_write_ready": False})
        _save_state(state_path, state)
        return {"status": "CONFLICT", "note_state": note_state, "write_performed": False, "request": None}
    previous_success = state.get("last_successfully_published_seq")
    if previous_success is not None and latest_seq <= previous_success:
        state.update({"state": "UNKNOWN", "live_write_ready": False}); _save_state(state_path, state)
        return {"status": "NO_SEQUENCE_ADVANCE", "note_state": note_state, "write_performed": False, "request": None}
    last_write = _parse_time(state.get("last_successful_write_at"))
    if last_write and (observed - last_write).total_seconds() < config.minimum_update_seconds:
        state.update({"state": "LIVE" if previous_observed is not None and latest_seq > previous_observed else "UNKNOWN",
                      "live_write_ready": False}); _save_state(state_path, state)
        return {"status": "RATE_LIMITED", "note_state": note_state, "write_performed": False, "request": None}
    request = _note_request(config, latest_seq, note_state, previous_success)
    metadata = approval_metadata(config, request, latest_seq, observed_at, note_state,
                                 application_commit, contract_digest)
    state.update({"state": "LIVE" if previous_observed is not None and latest_seq > previous_observed else "UNKNOWN",
                  "live_write_ready": True}); _save_state(state_path, state)
    return {"status": "PREVIEW_READY", "mode": "ZERO_WRITE", "write_performed": False,
            "note_state": note_state, "request": request, "approval_metadata": metadata,
            "approval_binding_sha256": approval_digest(metadata),
            "semantic_contract": {"classification": contract["classification"],
                                  "version": contract["semantic_contract_version"],
                                  "semantic_contract_sha256": contract_digest},
            "server_advertised": {"classification": "SERVER_ADVERTISED",
                                  "agent_version": discovery.get("version")},
            "runtime_context": deployment, "runtime_context_required_for_write": False}


def _append_audit(path: Path, entry: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")


def execute_approved_write(config: PresenceConfig, state_path: Path, audit_path: Path, *,
                           preview: Mapping[str, Any], approval: Mapping[str, Any],
                           intent: ReviewedLocalIntent,
                           writer: Callable[[str, Mapping[str, Any]], Any],
                           reader: Callable[[str], Any], now: datetime | None = None,
                           semantic_contract_path: Path = SEMANTIC_CONTRACT_PATH) -> Dict[str, Any]:
    """Deprecated caller-injected writer surface; production Presence stays disabled."""
    del config, state_path, audit_path, preview, approval, intent, writer, reader, now
    del semantic_contract_path
    raise LiveWriteDisabled("Presence writer requires a sealed preconfigured service")


def _execute_approved_write_after_capability(
    config: PresenceConfig, state_path: Path, audit_path: Path, *,
    preview: Mapping[str, Any], approval: Mapping[str, Any],
    writer: Callable[[str, Mapping[str, Any]], Any], reader: Callable[[str], Any],
    now: datetime | None = None,
    semantic_contract_path: Path = SEMANTIC_CONTRACT_PATH,
    _load: Any = _load_state, _save: Any = _save_state,
    _contract: Any = load_semantic_contract, _validate: Any = validate_approval,
    _classify: Any = classify_note, _audit: Any = _append_audit,
    _blank: Any = _blank_state, _parse: Any = _parse_time,
    _sha_fn: Any = _sha, _iso_fn: Any = _iso,
) -> Dict[str, Any]:
    """Mechanism-only implementation; callers must use execute_approved_write."""
    metadata, request = preview.get("approval_metadata"), preview.get("request")
    attempted = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    state = _load(state_path) or _blank(config)
    try:
        _, current_contract_digest = _contract(
            semantic_contract_path, config.approved_semantic_contract_sha256)
    except PresenceError:
        current_contract_digest = None
    gates = {"operator_enabled": config.operator_enabled, "live_write_enabled": config.live_write_enabled,
             "semantic_spec_approved": config.semantic_spec_approved, "source_data_valid": preview.get("status") == "PREVIEW_READY",
             "semantic_contract_current": current_contract_digest is not None
                 and current_contract_digest == (metadata or {}).get("semantic_contract_sha256"),
             "frequency_guard_healthy": True, "note_reconciled": preview.get("note_state") in {"ABSENT", "EXPECTED"},
             "no_conflict": state.get("state") not in {"CONFLICT", "READBACK_MISMATCH", "REAPPROVAL_REQUIRED", "SPEC_CHANGED"},
             "no_sequence_regression": state.get("last_observed_seq") == (metadata or {}).get("observed_seq"),
             "explicit_human_approval": isinstance(metadata, Mapping) and _validate(metadata, approval)}
    last_attempt = _parse(state.get("last_attempted_write_at"))
    if last_attempt and (attempted - last_attempt).total_seconds() < MINIMUM_LIVE_WRITE_SECONDS:
        gates["frequency_guard_healthy"] = False
    if not all(gates.values()) or not isinstance(request, Mapping) or not isinstance(metadata, Mapping):
        if not gates["frequency_guard_healthy"]:
            state.update({"state": "DISABLED", "live_write_ready": False,
                          "frequency_guard_status": "FREQUENCY_GUARD_TRIPPED"})
            _save(state_path, state)
        raise LiveWriteDisabled("live presence write gates are not all satisfied")
    current = reader(str(request["path"]))
    actual_note_state = _classify(current, state.get("last_successfully_published_seq"))
    if actual_note_state != metadata["expected_note_state"]:
        state.update({"state": "CONFLICT", "unexpected_value_sha256": _sha_fn(str(current)),
                      "live_write_ready": False})
        _save(state_path, state)
        return {"status": "CONFLICT", "write_performed": False, "state": state}
    state["last_attempted_write_at"] = _iso_fn(attempted); _save(state_path, state)
    response_status, response_body, result = None, "", "ERROR"
    try:
        response = writer(str(request["path"]), request["body"])
        response_status = int(response.get("status")) if isinstance(response, Mapping) and isinstance(response.get("status"), int) else None
        response_body = str(response.get("body", "")) if isinstance(response, Mapping) else ""
        if response_status == 409:
            raise ConflictError(response_body)
        if response_status is None or not 200 <= response_status <= 299:
            result = "RATE_LIMITED" if response_status == 429 else "HTTP_ERROR"
            state.update({"state": "DISABLED", "last_http_result": result, "live_write_ready": False})
        elif reader(str(request["path"])) != request["body"]["value"]:
            state.update({"state": "READBACK_MISMATCH", "live_write_ready": False}); result = "READBACK_MISMATCH"
        else:
            state.update({"state": "LIVE", "last_successfully_published_seq": metadata["observed_seq"],
                          "last_successful_write_at": _iso_fn(attempted), "known_note_present": True,
                          "writes": int(state.get("writes", 0)) + 1, "live_write_ready": False}); result = "SUCCESS"
    except ConflictError as error:
        response_status, response_body, result = 409, error.current_value, "CONFLICT"
        state.update({"state": "CONFLICT", "unexpected_value_sha256": _sha_fn(error.current_value), "live_write_ready": False})
    finally:
        _save(state_path, state)
        _audit(audit_path, {"attempted_at": _iso_fn(attempted), "observed_at": metadata["observed_at"],
            "room": config.room, "observed_seq": metadata["observed_seq"],
            "previous_successful_seq": request["body"].get("if"), "expected_note_state": metadata["expected_note_state"],
            "payload_sha256": metadata["payload_sha256"], "http_status": response_status,
            "response_body_sha256": _sha_fn(response_body), "adapter_version": ADAPTER_VERSION,
            "semantic_spec_anchor": config.semantic_spec_anchor,
            "semantic_contract_sha256": metadata["semantic_contract_sha256"],
            "application_commit": metadata["application_commit"],
            "decision": "ATTEMPTED", "result": result})
    return {"status": result, "write_performed": result == "SUCCESS", "state": state}


def _build_presence_write_service(
    config: PresenceConfig, state_path: Path, audit_path: Path, *,
    writer: Callable[[str, Mapping[str, Any]], Any], reader: Callable[[str], Any],
    semantic_contract_path: Path = SEMANTIC_CONTRACT_PATH,
    capability_validator: Any = require_local_intent,
    _mechanism: Any = _execute_approved_write_after_capability,
) -> Any:
    """Capture all Presence state, I/O, and authority dependencies at construction."""
    captured_config = config
    captured_state = state_path.resolve()
    captured_audit = audit_path.resolve()
    captured_contract = semantic_contract_path.resolve()
    captured_writer, captured_reader = writer, reader
    captured_version = CAPABILITY_CONFIG_VERSION
    digest_approval = approval_digest
    mapping_type, disabled_error = Mapping, LiveWriteDisabled
    json_dumps = json.dumps
    action = LocalActionClass.PRESENCE_WRITE

    def execute(*, preview: Mapping[str, Any], approval: Mapping[str, Any],
                intent: ReviewedLocalIntent | None, now: datetime | None = None) -> Dict[str, Any]:
        metadata, request = preview.get("approval_metadata"), preview.get("request")
        if not isinstance(metadata, mapping_type) or not isinstance(request, mapping_type):
            raise disabled_error("live presence write lacks an exact preview")
        canonical_body = json_dumps(
            request.get("body"), sort_keys=True, separators=(",", ":"))
        context = json_dumps({
            "action": "technocore-presence-write",
            "state_path": str(captured_state), "audit_path": str(captured_audit),
        }, sort_keys=True, separators=(",", ":"))
        capability_validator(
            intent, action, digest_approval(metadata),
            target=str(request.get("path", "")), payload=canonical_body,
            context=context, revision=str(metadata.get("application_commit", "")),
            config_version=captured_version, consume=True)
        return _mechanism(
            captured_config, captured_state, captured_audit, preview=preview,
            approval=approval, writer=captured_writer, reader=captured_reader,
            now=now, semantic_contract_path=captured_contract)

    return execute


def _sealed_presence_mechanism(*_args: Any, **_kwargs: Any) -> Dict[str, Any]:
    raise LiveWriteDisabled("direct Presence write mechanism is sealed")


_execute_approved_write_after_capability = _sealed_presence_mechanism


def apply_payload(*_: Any, **__: Any) -> None:
    raise LiveWriteDisabled("generic apply/confirm is disabled; use exact bound approval")
