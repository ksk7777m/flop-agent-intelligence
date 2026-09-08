"""Sealed, one-shot, read-only Technocore runtime observation.

Remote documents are bounded untrusted data.  This module has no writer, retry,
scheduler, signer, MCP, wallet, action-capability, or persistence interface.
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .remote_content_policy import ReviewedSourceId, resolve_reviewed_source

SCHEMA_VERSION = "technocore-runtime-observation-v1"
POLICY_VERSION = "technocore-runtime-readonly-observation-v1"
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
    age: str | None
    cache_control: str | None
    validator_present: bool
    body: bytes = field(repr=False)


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _req: Any, _fp: Any, _code: int, _msg: str,
                         _headers: Any, _newurl: str) -> None:
        return None


def _build_collector(source_resolver: Callable[[ReviewedSourceId], Any],
                     opener: Callable[..., Any] | None = None) -> Callable[[ReviewedSourceId], _Fetched]:
    """Private fixture seam; production captures the reviewed registry and opener."""
    request_type = urllib.request.Request
    configured_open = opener or urllib.request.build_opener(_RejectRedirects()).open
    specs = _SPEC_BY_ID

    def collect(source_id: ReviewedSourceId) -> _Fetched:
        if type(source_id) is not ReviewedSourceId or source_id not in specs:
            raise PermissionError("reviewed runtime observation source required")
        source, spec = source_resolver(source_id), specs[source_id]
        request = request_type(source.url, method="GET", headers={"User-Agent": POLICY_VERSION})
        try:
            with configured_open(request, timeout=source.timeout) as response:
                final_url = response.geturl()
                if final_url != source.url:
                    raise ObservationError("FINAL_URL_MISMATCH", redirect_detected=True)
                status = response.getcode()
                if status != 200:
                    raise ObservationError("HTTP_STATUS_REJECTED", status=status)
                media_type = (response.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
                if media_type not in spec.accepted_content_types:
                    raise ObservationError("CONTENT_TYPE_REJECTED")
                declared = response.headers.get("Content-Length")
                if declared is not None:
                    if re.fullmatch(r"0|[1-9][0-9]{0,9}", declared) is None:
                        raise ObservationError("CONTENT_LENGTH_INVALID")
                    if int(declared) > source.max_bytes:
                        raise ObservationError("RESPONSE_TOO_LARGE")
                body = response.read(source.max_bytes + 1)
                if len(body) > source.max_bytes:
                    raise ObservationError("RESPONSE_TOO_LARGE")
                age = response.headers.get("Age")
                control = response.headers.get("Cache-Control")
                age = age if age is None or len(age) <= 32 else "INVALID"
                control = control if control is None or len(control) <= 1024 else "INVALID"
                return _Fetched(source_id, status, True, False, media_type,
                    age, control,
                    bool(response.headers.get("ETag") or response.headers.get("Last-Modified")), body)
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
    if control_raw is not None:
        tokens = {part.strip().lower() for part in control_raw.split(",")}
        if "no-store" in tokens:
            control = CacheControlClass.NO_STORE
        elif tokens.intersection({"no-cache", "must-revalidate", "proxy-revalidate"}):
            control = CacheControlClass.REVALIDATION_REQUIRED
        elif any(token == "public" or token.startswith("max-age=") for token in tokens):
            control = CacheControlClass.CACHEABLE
        else:
            control = CacheControlClass.UNCLASSIFIED
    if age_state == "INVALID":
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
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
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
        valid = (value.get("openapi") == "3.1.0" and isinstance(paths, dict)
                 and isinstance(paths.get("/r/{room}/export"), dict)
                 and isinstance(paths.get("/r/{room}"), dict))
    elif spec.source_class is SourceClass.AGENT_MANIFEST:
        valid = isinstance(value.get("limits"), dict) and isinstance(value.get("capabilities"), (dict, list))
    else:
        settings = value.get("settings")
        valid = (value.get("service") == "technocore-chat" and isinstance(settings, dict)
                 and all(key in settings for key in ("max_wait", "rooms_cache_seconds",
                                                      "note_stats_cache_seconds", "fsync")))
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
        })


def _public_observation(observations: tuple[_SourceObservation, ...], observed_at: str) -> Mapping[str, Any]:
    expected = tuple(spec.source_id for spec in _SPECS)
    ids = tuple(item.source_id for item in observations)
    complete = ids == expected and all(item.request_completed for item in observations)
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
           "observation_policy_version", "observed_at", "source_set_complete", "sources",
           "deployment_version_evidence", "compatibility", "runtime_nonce_status",
           "drift_status", "ready_to_act", "authorized_to_act", "live_action_enabled"}
    source = {"source_id", "source_class", "request_attempted", "request_completed",
              "http_status", "final_url_matched", "redirect_detected",
              "response_size_accepted", "content_type_accepted", "schema_validation",
              "capability_state", "version_evidence", "cache_policy_observed", "age_state",
              "cache_control_class", "validator_present", "freshness", "body_sha256",
              "body_bytes", "observed_at"}
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
            fetched.validator_present, freshness, digest, len(fetched.body), observed_at)

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
                    Freshness.FRESHNESS_UNKNOWN, None, None, observed_at))
        return _public_observation(tuple(observations), observed_at)

    return observe_source, observe_once


observe_source, observe_once = _build_observer(_collect_reviewed_source)


__all__ = ("CapabilityState", "Freshness", "ObservationError", "VersionEvidence",
           "observe_once", "observe_source", "validate_public_observation")
