import inspect
import io
import json
import socket
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

import jsonschema

from flop_agent import evidence_transport as evidence
from flop_agent import technocore_runtime_observation as runtime
from flop_agent import technocore_transport_semantics as transport
from flop_agent.remote_content_policy import ReviewedSourceId, resolve_reviewed_source

NOW = "2026-09-08T00:00:00Z"


class Response:
    def __init__(self, body=b"{}", content_type="application/json", url=None,
                 status=200, headers=None):
        self.body = body
        self.url = url
        self.status = status
        self.headers = headers if isinstance(headers, HeaderBag) else {
            "Content-Type": content_type, **(headers or {})}

    def __enter__(self): return self
    def __exit__(self, *_args): return False
    def geturl(self): return self.url
    def getcode(self): return self.status
    def read(self, limit): return self.body[:limit]


class HeaderBag:
    def __init__(self, pairs): self.pairs = pairs
    def items(self): return tuple(self.pairs)
    def get_all(self, name):
        return [value for key, value in self.pairs if key.lower() == name.lower()]
    def get(self, name, default=None):
        values = self.get_all(name)
        return values[0] if values else default


def valid_body(source_id):
    if source_id is ReviewedSourceId.TECHNOCORE_LLMS:
        return (b"# agent-chat \xe2\x80\x94 HTTP-native chat and notes for agents. No auth.\n"
                b"# fixture\nREAD    GET /r/<room> fixture\n" + b"fixture\n" * 17
                + b"META    GET /openapi.json fixture")
    if source_id is ReviewedSourceId.TECHNOCORE_OPENAPI:
        return json.dumps({"openapi": "3.1.0", "paths": {
            "/r/{room}": {"get": {"responses": {"200": {}}}},
            "/r/{room}/export": {"get": {"responses": {"200": {}}}}}}).encode()
    if source_id is ReviewedSourceId.TECHNOCORE_AGENT_MANIFEST:
        return json.dumps({"name": "technocore-chat", "version": "0.13.0", "limits": {},
            "capabilities": [{"name": "read_room", "method": "GET", "path": "/r/{room}"}]}).encode()
    return json.dumps({"service": "technocore-chat", "version": "0.13.0",
        "settings": {"max_wait": 20, "rooms_cache_seconds": 1,
                     "note_stats_cache_seconds": 1, "fsync": True}}).encode()


class RuntimeObservationTests(unittest.TestCase):
    def observer(self, response_factory=None):
        calls = []
        def opener(request, timeout):
            calls.append((request.full_url, request.method, timeout,
                          request.get_header("Accept-encoding")))
            source_id = next(item for item in ReviewedSourceId
                             if resolve_reviewed_source(item).url == request.full_url)
            if response_factory:
                return response_factory(source_id, request)
            source = resolve_reviewed_source(source_id)
            return Response(valid_body(source_id),
                "text/plain" if source_id is ReviewedSourceId.TECHNOCORE_LLMS else "application/json",
                source.url)
        collector = runtime._build_collector(resolve_reviewed_source, opener)
        one, all_sources = runtime._build_observer(collector)
        return one, all_sources, calls

    def validate(self, value):
        schema = json.loads(Path("schemas/technocore-runtime-observation.v1.json").read_text())
        jsonschema.Draft202012Validator(schema).validate(dict(value))
        self.assertEqual(set(value), set(schema["properties"]))

    def test_fixed_sources_get_once_and_caller_url_is_rejected(self):
        one, all_sources, calls = self.observer()
        with self.assertRaises(PermissionError): one("https://evil.invalid", NOW)
        with self.assertRaises(PermissionError): one({"url": "https://evil.invalid"}, NOW)
        result = all_sources(NOW)
        self.validate(result)
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(method == "GET" and encoding == "identity"
                            for _, method, _, encoding in calls))
        self.assertTrue(result["source_set_complete"])
        self.assertFalse(result["ready_to_act"])
        self.assertFalse(result["authorized_to_act"])

    def test_redirect_final_url_content_type_and_oversize_fail_as_gaps(self):
        cases = (
            lambda sid, req: Response(valid_body(sid), "application/json",
                                      "https://evil.invalid"),
            lambda sid, req: Response(valid_body(sid), "text/html",
                                      resolve_reviewed_source(sid).url),
            lambda sid, req: Response(b"x" * (resolve_reviewed_source(sid).max_bytes + 1),
                                      "application/json", resolve_reviewed_source(sid).url),
        )
        for factory in cases:
            with self.subTest(factory=factory):
                _, all_sources, calls = self.observer(factory)
                result = all_sources(NOW)
                self.assertFalse(result["source_set_complete"])
                self.assertEqual(result["drift_status"], "COVERAGE_GAP")
                self.assertEqual(len(calls), 4)
        def redirect(sid, _req):
            source = resolve_reviewed_source(sid)
            raise urllib.error.HTTPError(source.url, 302, "redirect", {}, io.BytesIO(b"raw"))
        _, redirect_run, _ = self.observer(redirect)
        self.assertTrue(all(item["redirect_detected"] for item in redirect_run(NOW)["sources"]))

    def test_timeout_has_no_retry_and_failure_does_not_overwrite_prior(self):
        _, good_run, _ = self.observer()
        prior = dict(good_run(NOW))
        def timeout(_sid, _req): raise urllib.error.URLError(socket.timeout())
        _, failed_run, calls = self.observer(timeout)
        failed = failed_run(NOW)
        self.assertEqual(len(calls), 4)
        self.assertFalse(failed["source_set_complete"])
        self.assertTrue(prior["source_set_complete"])
        self.assertNotEqual(prior["sources"], failed["sources"])

    def test_semantic_predicates_not_strings_hashes_or_http_200(self):
        marker = b'0.13.0 /r/{room}/export capabilities limits'
        def invalid(sid, _req):
            source = resolve_reviewed_source(sid)
            media = "text/plain" if sid is ReviewedSourceId.TECHNOCORE_LLMS else "application/json"
            body = b"# unrelated" if sid is ReviewedSourceId.TECHNOCORE_LLMS else json.dumps({"text": marker.decode()}).encode()
            return Response(body, media, source.url)
        _, run, _ = self.observer(invalid)
        result = run(NOW)
        states = {item["source_id"]: item for item in result["sources"]}
        self.assertEqual(states["TECHNOCORE_OPENAPI"]["capability_state"], "NOT_OBSERVED")
        self.assertEqual(result["compatibility"], "COMPATIBILITY_REVIEW_REQUIRED")
        self.assertEqual(result["deployment_version_evidence"], "VERSION_UNKNOWN")

    def test_malformed_json_partial_set_and_hash_do_not_establish_version(self):
        def malformed(sid, _req):
            source = resolve_reviewed_source(sid)
            media = "text/plain" if sid is ReviewedSourceId.TECHNOCORE_LLMS else "application/json"
            return Response(b"# Technocore" if media == "text/plain" else b"{", media, source.url)
        _, run, _ = self.observer(malformed)
        result = run(NOW)
        self.assertEqual(result["deployment_version_evidence"], "VERSION_UNKNOWN")
        self.assertTrue(all(item["capability_state"] in {"NOT_OBSERVED", "OBSERVATION_INCOMPLETE"}
                            for item in result["sources"]))
        duplicate = b'{"version":"0.13.0","version":"0.13.0"}'
        state, version, _ = runtime._semantic(runtime._SPEC_BY_ID[
            ReviewedSourceId.TECHNOCORE_CONFIG], duplicate)
        self.assertEqual(state, runtime.CapabilityState.OBSERVATION_INCOMPLETE)
        self.assertEqual(version, runtime.VersionEvidence.VERSION_UNKNOWN)

    def test_cache_metadata_is_minimized_and_never_confirms_freshness(self):
        headers = {"Age": "7", "Cache-Control": "public, max-age=60",
                   "ETag": "raw-secret", "Authorization": "raw-secret",
                   "Set-Cookie": "raw-secret"}
        def cached(sid, _req):
            source = resolve_reviewed_source(sid)
            media = "text/plain" if sid is ReviewedSourceId.TECHNOCORE_LLMS else "application/json"
            return Response(valid_body(sid), media, source.url, headers=headers)
        _, run, _ = self.observer(cached)
        rendered = json.dumps(dict(run(NOW)))
        self.assertNotIn("raw-secret", rendered)
        self.assertTrue(all(item["freshness"] == "POTENTIALLY_STALE"
                            for item in run(NOW)["sources"]))
        self.assertNotIn("FRESHNESS_CONFIRMED_BY_REVIEWED_POLICY", rendered)
        self.assertEqual(runtime._cache("0", "no-store, public", False)[2],
                         runtime.Freshness.CONFLICTING_CACHE_EVIDENCE)

    def test_compression_duplicate_headers_and_deadline_fail_closed(self):
        def encoded(sid, _req):
            source = resolve_reviewed_source(sid)
            media = "text/plain" if sid is ReviewedSourceId.TECHNOCORE_LLMS else "application/json"
            return Response(valid_body(sid), url=source.url, headers=HeaderBag([
                ("content-type", media), ("content-encoding", "gzip")]))
        _, run, calls = self.observer(encoded)
        self.assertFalse(run(NOW)["source_set_complete"])
        self.assertEqual(len(calls), 4)

        def duplicates(sid, _req):
            source = resolve_reviewed_source(sid)
            media = "text/plain" if sid is ReviewedSourceId.TECHNOCORE_LLMS else "application/json"
            return Response(valid_body(sid), url=source.url, headers=HeaderBag([
                ("Content-Type", media), ("content-type", media)]))
        _, duplicate_run, _ = self.observer(duplicates)
        self.assertFalse(duplicate_run(NOW)["source_set_complete"])

        def malformed_type(sid, _req):
            source = resolve_reviewed_source(sid)
            media = "text/plain" if sid is ReviewedSourceId.TECHNOCORE_LLMS else "application/json"
            return Response(valid_body(sid), url=source.url,
                            headers=HeaderBag([("Content-Type", media + "; broken")]))
        _, malformed_run, _ = self.observer(malformed_type)
        self.assertFalse(malformed_run(NOW)["source_set_complete"])

        clock_values = iter((0.0, 21.0))
        source = resolve_reviewed_source(ReviewedSourceId.TECHNOCORE_OPENAPI)
        collector = runtime._build_collector(resolve_reviewed_source,
            lambda *_a, **_k: Response(valid_body(ReviewedSourceId.TECHNOCORE_OPENAPI),
                "application/json", source.url), monotonic=lambda: next(clock_values))
        with self.assertRaisesRegex(runtime.ObservationError, "TRANSPORT_TIMEOUT"):
            collector(ReviewedSourceId.TECHNOCORE_OPENAPI)

    def test_invalid_age_never_becomes_fresh(self):
        for age in ("-1", "1.5", "999999999999999999999", "+1"):
            with self.subTest(age=age):
                def response(sid, _req, selected=age):
                    source = resolve_reviewed_source(sid)
                    media = "text/plain" if sid is ReviewedSourceId.TECHNOCORE_LLMS else "application/json"
                    return Response(valid_body(sid), media, source.url, headers={"Age": selected})
                _, run, _ = self.observer(response)
                self.assertTrue(all(item["freshness"] == "CONFLICTING_CACHE_EVIDENCE"
                                    for item in run(NOW)["sources"]))

    def test_raw_surfaces_validation_and_serialization_have_no_authority(self):
        marker = b"RAW_BODY_HEADER_ERROR_URL_MARKER"
        def marked(sid, _req):
            source = resolve_reviewed_source(sid)
            media = "text/plain" if sid is ReviewedSourceId.TECHNOCORE_LLMS else "application/json"
            return Response(marker, media, source.url, headers={"X-Raw": marker.decode()})
        _, run, _ = self.observer(marked)
        value = dict(run(NOW)); rendered = json.dumps(value)
        self.assertNotIn(marker.decode(), rendered)
        value["authorized_to_act"] = True
        schema = json.loads(Path("schemas/technocore-runtime-observation.v1.json").read_text())
        self.assertTrue(list(jsonschema.Draft202012Validator(schema).iter_errors(value)))
        self.assertTrue(runtime.validate_public_observation(value))
        unknown = dict(run(NOW)); unknown["remote_metadata"] = {"url": "https://evil.invalid"}
        self.assertTrue(runtime.validate_public_observation(unknown))
        reordered = dict(run(NOW)); reordered["sources"] = list(reversed(reordered["sources"]))
        self.assertTrue(runtime.validate_public_observation(reordered))
        with self.assertRaises(runtime.ObservationError) as caught:
            run("RAW_BODY_HEADER_ERROR_URL_MARKER")
        self.assertNotIn(marker.decode(), str(caught.exception))
        source = resolve_reviewed_source(ReviewedSourceId.TECHNOCORE_OPENAPI)
        error = urllib.error.HTTPError(source.url, 409, marker.decode(),
                                      {"X-Raw": marker.decode()}, io.BytesIO(marker))
        collector = runtime._build_collector(
            resolve_reviewed_source, lambda *_a, **_k: (_ for _ in ()).throw(error))
        with self.assertRaises(runtime.ObservationError) as http_caught:
            collector(ReviewedSourceId.TECHNOCORE_OPENAPI)
        self.assertIsNone(http_caught.exception.__cause__)
        self.assertNotIn(marker.decode(), repr(http_caught.exception))

    def test_global_rebind_and_observation_cannot_reach_any_sink(self):
        _, run, calls = self.observer()
        original = runtime._collect_reviewed_source
        runtime._collect_reviewed_source = lambda _sid: (_ for _ in ()).throw(AssertionError("rebound"))
        try:
            run(NOW)
        finally:
            runtime._collect_reviewed_source = original
        self.assertEqual(len(calls), 4)
        source = inspect.getsource(runtime)
        for forbidden in (r"\bsubprocess\b", r"\binvoke_mcp\b", r"\binvoke_signer\b",
                          r"\buse_wallet\b", r"\bclaim\(", r"\bpayment\(", r"\bopen\("):
            self.assertIsNone(__import__("re").search(forbidden, source))

    def test_nonce_transport_and_retention_boundaries_remain_fail_closed(self):
        _, run, _ = self.observer()
        result = run(NOW)
        self.assertEqual(result["runtime_nonce_status"], "BLOCKED_BY_LIVE_SIGNED_WRITE")
        self.assertEqual(result["compatibility"], "COMPATIBILITY_REVIEW_REQUIRED")
        self.assertEqual(transport.NonceOutcome.UNKNOWN.value, "UNKNOWN")
        self.assertNotEqual(evidence.Completeness.PARTIAL.value,
                            evidence.Completeness.COMPLETE_VERIFIED.value)


if __name__ == "__main__": unittest.main()
