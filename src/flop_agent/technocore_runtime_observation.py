"""Sealed, one-shot, read-only Technocore runtime observation.

Remote documents are bounded untrusted data.  This module has no writer, retry,
scheduler, signer, MCP, wallet, action-capability, or persistence interface.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .remote_content_policy import ReviewedSourceId, resolve_reviewed_source

SCHEMA_VERSION = "technocore-runtime-observation-v1"
POLICY_VERSION = "technocore-runtime-readonly-observation-v1"
CURRENT_PREDICATE_POLICY_REVISION = "technocore-runtime-predicates-v2"
DOCUMENTED_REVISION = "45921c3e3699e01a55cde391674815367e0cff6b"
DOCUMENTED_VERSION = "0.13.0"
MAX_AGE_SECONDS = (1 << 31) - 1
_TIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


class ObservationError(RuntimeError):
    def __init__(self, code: str, field_name: str = "observation",
                 *, status: int | None = None, redirect_detected: bool = False):
        super().__init__(f"{code}: {field_name}")
        self.code = code
        self.status = status
        self.redirect_detected = redirect_detected


class SourceClass(str, Enum):
    TEXT_DOCUMENT = "TEXT_DOCUMENT"
    OPENAPI_DOCUMENT = "OPENAPI_DOCUMENT"
    AGENT_MANIFEST = "AGENT_MANIFEST"
    CONFIG_DOCUMENT = "CONFIG_DOCUMENT"


class CapabilityState(str, Enum):
    OBSERVED_IN_LIVE_DOCUMENT = "OBSERVED_IN_LIVE_DOCUMENT"
    NOT_OBSERVED = "NOT_OBSERVED"
    OBSERVATION_INCOMPLETE = "OBSERVATION_INCOMPLETE"
    CONFLICTING = "CONFLICTING"
    UNKNOWN = "UNKNOWN"


class VersionEvidence(str, Enum):
    VERSION_EXPLICITLY_OBSERVED = "VERSION_EXPLICITLY_OBSERVED"
    VERSION_NOT_EXPOSED = "VERSION_NOT_EXPOSED"
    VERSION_EVIDENCE_CONFLICTING = "VERSION_EVIDENCE_CONFLICTING"
    VERSION_UNKNOWN = "VERSION_UNKNOWN"


class Freshness(str, Enum):
    FRESHNESS_UNKNOWN = "FRESHNESS_UNKNOWN"
    POTENTIALLY_STALE = "POTENTIALLY_STALE"
    CONFLICTING_CACHE_EVIDENCE = "CONFLICTING_CACHE_EVIDENCE"


class CacheControlClass(str, Enum):
    ABSENT = "ABSENT"
    NO_STORE = "NO_STORE"
    REVALIDATION_REQUIRED = "REVALIDATION_REQUIRED"
    CACHEABLE = "CACHEABLE"
    UNCLASSIFIED = "UNCLASSIFIED"


@dataclass(frozen=True)
class _SourceSpec:
    source_id: ReviewedSourceId
    source_class: SourceClass
    accepted_content_types: tuple[str, ...]


_SPECS = (
    _SourceSpec(ReviewedSourceId.TECHNOCORE_LLMS, SourceClass.TEXT_DOCUMENT,
                ("text/plain",)),
    _SourceSpec(ReviewedSourceId.TECHNOCORE_OPENAPI, SourceClass.OPENAPI_DOCUMENT,
                ("application/json", "application/openapi+json")),
    _SourceSpec(ReviewedSourceId.TECHNOCORE_AGENT_MANIFEST, SourceClass.AGENT_MANIFEST,
                ("application/json",)),
    _SourceSpec(ReviewedSourceId.TECHNOCORE_CONFIG, SourceClass.CONFIG_DOCUMENT,
                ("application/json",)),
)
_SPEC_BY_ID = MappingProxyType({item.source_id: item for item in _SPECS})


@dataclass(frozen=True)
class _Fetched:
    source_id: ReviewedSourceId
    status: int
    final_url_matched: bool
    redirect_detected: bool
    content_type: str
    age: str | None = field(repr=False)
    cache_control: str | None = field(repr=False)
    validator_present: bool
    body: bytes = field(repr=False)


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _req: Any, _fp: Any, _code: int, _msg: str,
                         _headers: Any, _newurl: str) -> None:
        return None


def _build_collector(source_resolver: Callable[[ReviewedSourceId], Any],
                     opener: Callable[..., Any] | None = None,
                     monotonic: Callable[[], float] = time.monotonic
                     ) -> Callable[[ReviewedSourceId], _Fetched]:
    """Private fixture seam; production captures the reviewed registry and opener."""
    request_type = urllib.request.Request
    configured_open = opener or urllib.request.build_opener(_RejectRedirects()).open
    specs = _SPEC_BY_ID

    def header_values(headers: Any, name: str) -> tuple[str, ...]:
        if hasattr(headers, "get_all"):
            values = headers.get_all(name) or []
        else:
            values = [value for key, value in headers.items() if key.lower() == name.lower()]
        return tuple(value for value in values if isinstance(value, str))

    def collect(source_id: ReviewedSourceId) -> _Fetched:
        if type(source_id) is not ReviewedSourceId or source_id not in specs:
            raise PermissionError("reviewed runtime observation source required")
        source, spec = source_resolver(source_id), specs[source_id]
        request = request_type(source.url, method="GET", headers={
            "User-Agent": POLICY_VERSION, "Accept-Encoding": "identity"})
        deadline = monotonic() + source.timeout
        try:
            with configured_open(request, timeout=source.timeout) as response:
                if monotonic() > deadline:
                    raise ObservationError("TRANSPORT_TIMEOUT")
                final_url = response.geturl()
                if final_url != source.url:
                    raise ObservationError("FINAL_URL_MISMATCH", redirect_detected=True)
                status = response.getcode()
                if status != 200:
                    raise ObservationError("HTTP_STATUS_REJECTED", status=status)
                content_types = header_values(response.headers, "Content-Type")
                if len(content_types) != 1:
                    raise ObservationError("CONTENT_TYPE_AMBIGUOUS")
                content_parts = [part.strip() for part in content_types[0].split(";")]
                media_type = content_parts[0].lower()
                parameters: dict[str, str] = {}
                for parameter in content_parts[1:]:
                    if "=" not in parameter:
                        raise ObservationError("CONTENT_TYPE_PARAMETER_INVALID")
                    name, parameter_value = (part.strip().lower() for part in parameter.split("=", 1))
                    if (not name or not parameter_value or name in parameters
                            or name != "charset" or parameter_value.strip('"') != "utf-8"):
                        raise ObservationError("CONTENT_TYPE_PARAMETER_INVALID")
                    parameters[name] = parameter_value
                if media_type not in spec.accepted_content_types:
                    raise ObservationError("CONTENT_TYPE_REJECTED")
                encodings = header_values(response.headers, "Content-Encoding")
                if len(encodings) > 1 or (encodings and encodings[0].strip().lower() != "identity"):
                    raise ObservationError("CONTENT_ENCODING_REJECTED")
                lengths = header_values(response.headers, "Content-Length")
                if len(lengths) > 1:
                    raise ObservationError("CONTENT_LENGTH_AMBIGUOUS")
                declared = lengths[0] if lengths else None
                if declared is not None:
                    if re.fullmatch(r"0|[1-9][0-9]{0,9}", declared) is None:
                        raise ObservationError("CONTENT_LENGTH_INVALID")
                    if int(declared) > source.max_bytes:
                        raise ObservationError("RESPONSE_TOO_LARGE")
                body = response.read(source.max_bytes + 1)
                if monotonic() > deadline:
                    raise ObservationError("TRANSPORT_TIMEOUT")
                if len(body) > source.max_bytes:
                    raise ObservationError("RESPONSE_TOO_LARGE")
                ages = header_values(response.headers, "Age")
                controls = header_values(response.headers, "Cache-Control")
                age = ages[0] if len(ages) == 1 else "INVALID" if ages else None
                control = controls[0] if len(controls) == 1 else "INVALID" if controls else None
                age = age if age is None or len(age) <= 32 else "INVALID"
                control = control if control is None or len(control) <= 1024 else "INVALID"
                return _Fetched(source_id, status, True, False, media_type,
                    age, control,
                    bool(header_values(response.headers, "ETag")
                         or header_values(response.headers, "Last-Modified")), body)
        except urllib.error.HTTPError as error:
            redirected = 300 <= error.code <= 399
            raise ObservationError("REDIRECT_REJECTED" if redirected else "HTTP_ERROR",
                                   status=error.code, redirect_detected=redirected) from None
        except urllib.error.URLError:
            raise ObservationError("TRANSPORT_ERROR") from None
        except TimeoutError:
            raise ObservationError("TRANSPORT_TIMEOUT") from None
    return collect


_collect_reviewed_source = _build_collector(resolve_reviewed_source)


def _cache(age_raw: str | None, control_raw: str | None,
           validator_present: bool) -> tuple[str, CacheControlClass, Freshness]:
    age_state = "ABSENT"
    age: int | None = None
    if age_raw is not None:
        if not re.fullmatch(r"0|[1-9][0-9]{0,9}", age_raw):
            age_state = "INVALID"
        else:
            age = int(age_raw)
            age_state = "VALID" if age <= MAX_AGE_SECONDS else "INVALID"
    control = CacheControlClass.ABSENT
    cache_conflict = False
    if control_raw is not None:
        raw_tokens = [part.strip().lower() for part in control_raw.split(",")]
        names = [part.split("=", 1)[0] for part in raw_tokens]
        cache_conflict = (not all(raw_tokens) or len(names) != len(set(names))
                          or ("no-store" in names and any(name in names for name in
                              ("public", "max-age", "s-maxage", "stale-while-revalidate"))))
        tokens = set(raw_tokens)
        if "no-store" in tokens:
            control = CacheControlClass.NO_STORE
        elif tokens.intersection({"no-cache", "must-revalidate", "proxy-revalidate"}):
            control = CacheControlClass.REVALIDATION_REQUIRED
        elif any(token == "public" or token.startswith("max-age=") for token in tokens):
            control = CacheControlClass.CACHEABLE
        else:
            control = CacheControlClass.UNCLASSIFIED
    if age_state == "INVALID" or cache_conflict:
        freshness = Freshness.CONFLICTING_CACHE_EVIDENCE
    elif age is not None and age > 0:
        freshness = Freshness.POTENTIALLY_STALE
    else:
        freshness = Freshness.FRESHNESS_UNKNOWN
    return age_state, control, freshness


def _semantic(spec: _SourceSpec, body: bytes) -> tuple[CapabilityState, VersionEvidence, str]:
    digest = hashlib.sha256(body).hexdigest()
    if spec.source_class is SourceClass.TEXT_DOCUMENT:
        try:
            text = body.decode("utf-8", "strict")
        except UnicodeDecodeError:
            return CapabilityState.OBSERVATION_INCOMPLETE, VersionEvidence.VERSION_UNKNOWN, digest
        lines = text.splitlines()
        valid = (len(lines) >= 20
                 and lines[0].startswith("# agent-chat — HTTP-native chat and notes for agents.")
                 and any(line.startswith("READ    GET /r/<room>") for line in lines[:20])
                 and any(line.startswith("META    GET /openapi.json") for line in lines[:30]))
        state = CapabilityState.OBSERVED_IN_LIVE_DOCUMENT if valid else CapabilityState.NOT_OBSERVED
        return state, VersionEvidence.VERSION_NOT_EXPOSED, digest
    try:
        def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError("duplicate JSON field")
                result[key] = item
            return result
        value = json.loads(body, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return CapabilityState.OBSERVATION_INCOMPLETE, VersionEvidence.VERSION_UNKNOWN, digest
    if not isinstance(value, dict):
        return CapabilityState.CONFLICTING, VersionEvidence.VERSION_UNKNOWN, digest
    version = value.get("version")
    version_state = VersionEvidence.VERSION_NOT_EXPOSED
    if version is not None:
        version_state = (VersionEvidence.VERSION_EXPLICITLY_OBSERVED
                         if version == DOCUMENTED_VERSION else VersionEvidence.VERSION_EVIDENCE_CONFLICTING)
    if spec.source_class is SourceClass.OPENAPI_DOCUMENT:
        paths = value.get("paths")
        room = paths.get("/r/{room}") if isinstance(paths, dict) else None
        export = paths.get("/r/{room}/export") if isinstance(paths, dict) else None
        valid = (value.get("openapi") == "3.1.0" and isinstance(room, dict)
                 and isinstance(export, dict) and isinstance(room.get("get"), dict)
                 and isinstance(export.get("get"), dict)
                 and isinstance(room["get"].get("responses"), dict)
                 and isinstance(export["get"].get("responses"), dict))
    elif spec.source_class is SourceClass.AGENT_MANIFEST:
        capabilities = value.get("capabilities")
        valid = (value.get("name") == "technocore-chat" and isinstance(value.get("limits"), dict)
                 and isinstance(capabilities, list)
                 and any(isinstance(item, dict) and item.get("name") == "read_room"
                         and item.get("method") == "GET" and item.get("path") == "/r/{room}"
                         for item in capabilities))
    else:
        settings = value.get("settings")
        valid = (value.get("service") == "technocore-chat" and isinstance(settings, dict)
                 and isinstance(settings.get("max_wait"), (int, float))
                 and not isinstance(settings.get("max_wait"), bool)
                 and all(isinstance(settings.get(key), (int, float))
                         and not isinstance(settings.get(key), bool) and settings[key] >= 0
                         for key in ("rooms_cache_seconds", "note_stats_cache_seconds"))
                 and isinstance(settings.get("fsync"), bool))
    return (CapabilityState.OBSERVED_IN_LIVE_DOCUMENT if valid else CapabilityState.NOT_OBSERVED,
            version_state, digest)


@dataclass(frozen=True)
class _SourceObservation:
    source_id: ReviewedSourceId
    source_class: SourceClass
    request_attempted: bool
    request_completed: bool
    http_status: int | None
    final_url_matched: bool
    redirect_detected: bool
    response_size_accepted: bool
    content_type_accepted: bool
    schema_validation: str
    capability_state: CapabilityState
    version_evidence: VersionEvidence
    cache_policy_observed: bool
    age_state: str
    cache_control_class: CacheControlClass
    validator_present: bool
    freshness: Freshness
    body_sha256: str | None
    body_bytes: int | None
    observed_at: str
    predicate_policy_revision: str

    def public_projection(self) -> Mapping[str, Any]:
        return MappingProxyType({
            "source_id": self.source_id.value, "source_class": self.source_class.value,
            "request_attempted": self.request_attempted, "request_completed": self.request_completed,
            "http_status": self.http_status, "final_url_matched": self.final_url_matched,
            "redirect_detected": self.redirect_detected,
            "response_size_accepted": self.response_size_accepted,
            "content_type_accepted": self.content_type_accepted,
            "schema_validation": self.schema_validation,
            "capability_state": self.capability_state.value,
            "version_evidence": self.version_evidence.value,
            "cache_policy_observed": self.cache_policy_observed,
            "age_state": self.age_state,
            "cache_control_class": self.cache_control_class.value,
            "validator_present": self.validator_present, "freshness": self.freshness.value,
            "body_sha256": self.body_sha256, "body_bytes": self.body_bytes,
            "observed_at": self.observed_at,
            "predicate_policy_revision": self.predicate_policy_revision,
        })


def _public_observation(observations: tuple[_SourceObservation, ...], observed_at: str) -> Mapping[str, Any]:
    expected = tuple(spec.source_id for spec in _SPECS)
    ids = tuple(item.source_id for item in observations)
    complete = (ids == expected and all(item.request_completed for item in observations)
                and all(item.capability_state is CapabilityState.OBSERVED_IN_LIVE_DOCUMENT
                        for item in observations))
    version_states = {item.version_evidence for item in observations}
    overall_version = (VersionEvidence.VERSION_EVIDENCE_CONFLICTING
                       if VersionEvidence.VERSION_EVIDENCE_CONFLICTING in version_states
                       else VersionEvidence.VERSION_EXPLICITLY_OBSERVED
                       if VersionEvidence.VERSION_EXPLICITLY_OBSERVED in version_states
                       else VersionEvidence.VERSION_UNKNOWN
                       if VersionEvidence.VERSION_UNKNOWN in version_states
                       else VersionEvidence.VERSION_NOT_EXPOSED if complete
                       else VersionEvidence.VERSION_UNKNOWN)
    drift = ("CONFLICTING" if any(item.capability_state is CapabilityState.CONFLICTING
                                  or item.version_evidence is VersionEvidence.VERSION_EVIDENCE_CONFLICTING
                                  for item in observations)
             else "COVERAGE_GAP" if not complete
             else "SEMANTIC_GAP" if any(item.capability_state is not CapabilityState.OBSERVED_IN_LIVE_DOCUMENT
                                        for item in observations)
             else "DRIFT_NOT_ESTABLISHED")
    projection = {
        "schema": SCHEMA_VERSION, "status": "DESCRIPTIVE_ONLY",
        "documented_version": DOCUMENTED_VERSION,
        "documented_revision": DOCUMENTED_REVISION,
        "observation_policy_version": POLICY_VERSION,
        "predicate_policy_revision": CURRENT_PREDICATE_POLICY_REVISION,
        "observed_at": observed_at, "source_set_complete": complete,
        "sources": [dict(item.public_projection()) for item in observations],
        "deployment_version_evidence": overall_version.value,
        "compatibility": "COMPATIBILITY_REVIEW_REQUIRED",
        "runtime_nonce_status": "BLOCKED_BY_LIVE_SIGNED_WRITE",
        "drift_status": drift,
        "ready_to_act": False, "authorized_to_act": False,
        "live_action_enabled": False,
    }
    if validate_public_observation(projection):
        raise ObservationError("PUBLIC_OBSERVATION_INVALID")
    return MappingProxyType(projection)


def validate_public_observation(value: Mapping[str, Any]) -> tuple[str, ...]:
    top = {"schema", "status", "documented_version", "documented_revision",
           "observation_policy_version", "predicate_policy_revision", "observed_at", "source_set_complete", "sources",
           "deployment_version_evidence", "compatibility", "runtime_nonce_status",
           "drift_status", "ready_to_act", "authorized_to_act", "live_action_enabled"}
    source = {"source_id", "source_class", "request_attempted", "request_completed",
              "http_status", "final_url_matched", "redirect_detected",
              "response_size_accepted", "content_type_accepted", "schema_validation",
              "capability_state", "version_evidence", "cache_policy_observed", "age_state",
              "cache_control_class", "validator_present", "freshness", "body_sha256",
              "body_bytes", "observed_at", "predicate_policy_revision"}
    errors = []
    if not isinstance(value, Mapping) or set(value) != top:
        return ("CLOSED_TOP_LEVEL_FIELDS_REQUIRED",)
    items = value.get("sources")
    if (not isinstance(items, list) or len(items) != len(_SPECS)
            or any(not isinstance(item, Mapping) or set(item) != source for item in items)):
        errors.append("CLOSED_SOURCE_FIELDS_REQUIRED")
    if value.get("compatibility") != "COMPATIBILITY_REVIEW_REQUIRED":
        errors.append("COMPATIBILITY_REVIEW_REQUIRED")
    for name in ("ready_to_act", "authorized_to_act", "live_action_enabled"):
        if value.get(name) is not False:
            errors.append("LIVE_ACTION_PROHIBITED")
    if value.get("predicate_policy_revision") != CURRENT_PREDICATE_POLICY_REVISION:
        errors.append("PREDICATE_POLICY_REVISION_INVALID")
    if not isinstance(value.get("observed_at"), str) or _TIME.fullmatch(value["observed_at"]) is None:
        errors.append("OBSERVATION_TIME_INVALID")
    if type(value.get("source_set_complete")) is not bool:
        errors.append("SOURCE_COMPLETENESS_TYPE_INVALID")
    if isinstance(items, list) and len(items) == len(_SPECS):
        expected_ids = [spec.source_id.value for spec in _SPECS]
        if [item.get("source_id") for item in items if isinstance(item, Mapping)] != expected_ids:
            errors.append("SOURCE_ORDER_OR_ID_INVALID")
        for item in items:
            if isinstance(item, Mapping):
                if item.get("predicate_policy_revision") != CURRENT_PREDICATE_POLICY_REVISION:
                    errors.append("SOURCE_POLICY_REVISION_INVALID")
                if item.get("observed_at") != value.get("observed_at"):
                    errors.append("SOURCE_TIME_MISMATCH")
                for field_name in ("request_attempted", "request_completed", "final_url_matched",
                                   "redirect_detected", "response_size_accepted",
                                   "content_type_accepted", "cache_policy_observed",
                                   "validator_present"):
                    if type(item.get(field_name)) is not bool:
                        errors.append("SOURCE_BOOLEAN_INVALID")
                status = item.get("http_status")
                if status is not None and (type(status) is not int or not 100 <= status <= 599):
                    errors.append("HTTP_STATUS_INVALID")
                digest, length = item.get("body_sha256"), item.get("body_bytes")
                if digest is not None and (not isinstance(digest, str)
                        or re.fullmatch(r"[0-9a-f]{64}", digest) is None):
                    errors.append("BODY_HASH_INVALID")
                if length is not None and (type(length) is not int or not 0 <= length <= 2 * 1024 * 1024):
                    errors.append("BODY_LENGTH_INVALID")
                if item.get("request_completed") is True:
                    if (status != 200 or item.get("final_url_matched") is not True
                            or item.get("redirect_detected") is not False
                            or item.get("response_size_accepted") is not True
                            or item.get("content_type_accepted") is not True
                            or digest is None or length is None):
                        errors.append("COMPLETED_SOURCE_STATE_INVALID")
                elif digest is not None or length is not None:
                    errors.append("FAILED_SOURCE_BODY_EVIDENCE_PROHIBITED")
        semantic_complete = all(isinstance(item, Mapping)
            and item.get("request_completed") is True
            and item.get("capability_state") == "OBSERVED_IN_LIVE_DOCUMENT" for item in items)
        if value.get("source_set_complete") is not semantic_complete:
            errors.append("SOURCE_COMPLETENESS_INVALID")
    return tuple(sorted(set(errors)))


def _build_observer(collector: Callable[[ReviewedSourceId], _Fetched]
                    ) -> tuple[Callable[[ReviewedSourceId, str], _SourceObservation],
                               Callable[[str], Mapping[str, Any]]]:
    specs, time_pattern = _SPEC_BY_ID, _TIME

    def observe_source(source_id: ReviewedSourceId, observed_at: str) -> _SourceObservation:
        if type(source_id) is not ReviewedSourceId or source_id not in specs:
            raise PermissionError("reviewed runtime observation source required")
        if not isinstance(observed_at, str) or time_pattern.fullmatch(observed_at) is None:
            raise ObservationError("OBSERVATION_TIME_INVALID")
        fetched = collector(source_id)
        spec = specs[source_id]
        capability, version, digest = _semantic(spec, fetched.body)
        age_state, control, freshness = _cache(fetched.age, fetched.cache_control,
                                               fetched.validator_present)
        return _SourceObservation(source_id, spec.source_class, True, True, fetched.status,
            fetched.final_url_matched, fetched.redirect_detected, True, True,
            "VALIDATED" if capability is CapabilityState.OBSERVED_IN_LIVE_DOCUMENT else "NOT_VALIDATED",
            capability, version, fetched.cache_control is not None, age_state, control,
            fetched.validator_present, freshness, digest, len(fetched.body), observed_at,
            CURRENT_PREDICATE_POLICY_REVISION)

    def observe_once(observed_at: str) -> Mapping[str, Any]:
        """One request per fixed source, no retry; failures remain explicit gaps."""
        if not isinstance(observed_at, str) or time_pattern.fullmatch(observed_at) is None:
            raise ObservationError("OBSERVATION_TIME_INVALID")
        observations = []
        for spec in _SPECS:
            try:
                observations.append(observe_source(spec.source_id, observed_at))
            except ObservationError as error:
                observations.append(_SourceObservation(spec.source_id, spec.source_class,
                    True, False, error.status, False, error.redirect_detected, False, False, "NOT_VALIDATED",
                    CapabilityState.OBSERVATION_INCOMPLETE, VersionEvidence.VERSION_UNKNOWN,
                    False, "ABSENT", CacheControlClass.ABSENT, False,
                    Freshness.FRESHNESS_UNKNOWN, None, None, observed_at,
                    CURRENT_PREDICATE_POLICY_REVISION))
        return _public_observation(tuple(observations), observed_at)

    return observe_source, observe_once


observe_source, observe_once = _build_observer(_collect_reviewed_source)


__all__ = ("CapabilityState", "Freshness", "ObservationError", "VersionEvidence",
           "observe_once", "observe_source", "validate_public_observation")
