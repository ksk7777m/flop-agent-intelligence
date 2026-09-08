import copy
import inspect
import json
import os
import pickle
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import jsonschema

from flop_agent import durable_observation_journal as journal
from flop_agent import manual_reobservation_runner as runner
from flop_agent import technocore_runtime_observation as runtime
from flop_agent.observation_retention import FIXED_SOURCES
from flop_agent.remote_content_policy import ReviewedSourceId, resolve_reviewed_source


class Response:
    def __init__(self, body, media_type, url):
        self.body = body; self.url = url; self.status = 200
        self.headers = {"Content-Type": media_type}
    def __enter__(self): return self
    def __exit__(self, *_args): return False
    def geturl(self): return self.url
    def getcode(self): return self.status
    def read(self, limit): return self.body[:limit]


def valid_body(source_id):
    if source_id is ReviewedSourceId.TECHNOCORE_LLMS:
        return (b"# agent-chat \xe2\x80\x94 HTTP-native chat and notes for agents. No auth.\n"
                b"READ    GET /r/<room> fixture\n" + b"fixture\n" * 18
                + b"META    GET /openapi.json fixture")
    if source_id is ReviewedSourceId.TECHNOCORE_OPENAPI:
        return json.dumps({"openapi": "3.1.0", "paths": {
            "/r/{room}": {"get": {"responses": {"200": {}}}},
            "/r/{room}/export": {"get": {"responses": {"200": {}}}}}}).encode()
    if source_id is ReviewedSourceId.TECHNOCORE_AGENT_MANIFEST:
        return json.dumps({"name": "technocore-chat", "version": "0.13.0", "limits": {},
            "capabilities": [{"name": "read_room", "method": "GET",
                              "path": "/r/{room}"}]}).encode()
    return json.dumps({"service": "technocore-chat", "version": "0.13.0",
        "settings": {"max_wait": 20, "rooms_cache_seconds": 1,
                     "note_stats_cache_seconds": 1, "fsync": True}}).encode()


class ManualReobservationRunnerTests(unittest.TestCase):
    def service(self, root, observer=None, fault=None, pid=os.getpid):
        calls = []
        if observer is None:
            def opener(request, timeout):
                source_id = next(item for item in ReviewedSourceId
                    if resolve_reviewed_source(item).url == request.full_url)
                calls.append(source_id.value)
                source = resolve_reviewed_source(source_id)
                media = "text/plain" if source_id is ReviewedSourceId.TECHNOCORE_LLMS else "application/json"
                return Response(valid_body(source_id), media, source.url)
            collector = runtime._build_collector(resolve_reviewed_source, opener)
            observer = runtime._build_observer(collector)[0]
        api = journal._build_store(Path(root), fault=fault, fixture_issuers=True)
        return runner._build_fixture_runner(api, observer, pid=pid), calls, api

    def test_public_plan_and_status_are_closed_disabled_and_schema_valid(self):
        plan = dict(runner.fixed_plan_projection()); status = dict(runner.runner_status())
        self.assertEqual(runner.validate_plan(plan), ())
        self.assertEqual(runner.validate_status(status), ())
        schema = json.loads(Path("schemas/manual-readonly-reobservation-runner.v1.json").read_text())
        jsonschema.Draft202012Validator(schema).validate(plan)
        jsonschema.Draft202012Validator(schema).validate(status)
        for value in (plan, status):
            forged = dict(value); forged["metadata"] = {"raw": "secret"}
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.Draft202012Validator(schema).validate(forged)
        self.assertFalse(plan["execution_enabled"])
        self.assertEqual(status["production_permit_issuer"], "ABSENT")
        self.assertEqual(status["live_get_count"], 0)
        forged = dict(plan); forged["sources"] = [dict(item) for item in plan["sources"]]
        forged["sources"][0]["ordinal"] = False
        self.assertEqual(runner.validate_plan(forged), ("FIXED_SOURCES_INVALID",))

    def test_production_surface_has_no_issuer_execute_cli_or_scheduler(self):
        self.assertNotIn("_build_fixture_runner", runner.__all__)
        for name in ("issue_permit", "execute", "run", "schedule", "resume"):
            self.assertFalse(hasattr(runner, name))
        source = inspect.getsource(runner)
        for forbidden in ("import urllib", "import requests", "import httpx", "--confirm",
                          "wallet", "sign_transaction", "invoke_mcp("):
            self.assertNotIn(forbidden, source.lower())
        cli = Path("src/flop_agent/cli.py").read_text()
        self.assertNotIn("manual-reobservation", cli)
        with tempfile.TemporaryDirectory() as folder:
            production_api = journal._build_store(Path(folder))
            with self.assertRaisesRegex(runner.RunnerError, "FIXTURE_JOURNAL_REQUIRED"):
                runner._build_fixture_runner(production_api, lambda *_args: None)

    def test_exact_four_gets_fixed_order_and_finalized_journal(self):
        with tempfile.TemporaryDirectory() as folder:
            (issue, execute, _recover), calls, api = self.service(folder)
            result = execute(issue())
            self.assertEqual(calls, [item.value for item in FIXED_SOURCES])
            self.assertEqual(result["state"], "FINALIZED")
            self.assertFalse(result["ready_to_act"]); self.assertFalse(result["authorized_to_act"])
            state = api[7](); self.assertEqual(state["record_count"], 17)
            self.assertTrue(state["evidence_committed"]); self.assertTrue(state["finalized"])

    def test_no_permit_forged_copied_reused_and_foreign_service_rejected(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            (issue, execute, _), calls, _api = self.service(first)
            with self.assertRaises(runner.RunnerError): execute(object())
            permit = issue()
            with self.assertRaises(TypeError): copy.copy(permit)
            with self.assertRaises(TypeError): copy.deepcopy(permit)
            with self.assertRaises(TypeError): pickle.dumps(permit)
            other = self.service(second)[0][1]
            with self.assertRaises(runner.RunnerError): other(permit)
            execute(permit)
            with self.assertRaisesRegex(runner.RunnerError, "EXISTING_ATTEMPT_BLOCKS_EXECUTION"):
                execute(permit)
            self.assertEqual(len(calls), 4)

    def test_foreign_pid_rejected_before_journal_or_network(self):
        current = [10]
        with tempfile.TemporaryDirectory() as folder:
            (issue, execute, _), calls, api = self.service(folder, pid=lambda: current[0])
            permit = issue(); current[0] = 11
            with self.assertRaisesRegex(runner.RunnerError, "FOREIGN_PROCESS_PERMIT"):
                execute(permit)
            self.assertEqual(calls, []); self.assertFalse(api[7]()["durable_state_found"])

    def test_arbitrary_or_unsealed_observer_result_is_rejected_and_not_persisted(self):
        for observed in ({"source_id": "TECHNOCORE_LLMS", "raw": {"secret": "value"}},
                         RuntimeError("secret value")):
            with self.subTest(kind=type(observed).__name__), tempfile.TemporaryDirectory() as folder:
                calls = []
                def fake(*_args):
                    calls.append(1)
                    if isinstance(observed, Exception): raise observed
                    return observed
                (issue, execute, _), _, api = self.service(folder, observer=fake)
                with self.assertRaises(runner.RunnerError): execute(issue())
                self.assertEqual(len(calls), 1)
                encoded = json.dumps(dict(api[7]())).lower()
                self.assertNotIn("secret", encoded); self.assertNotIn("\"raw\"", encoded)

    def test_semantic_gap_stops_without_retry_commit_or_remaining_sources(self):
        calls = []
        def opener(request, timeout):
            source_id = next(item for item in ReviewedSourceId
                if resolve_reviewed_source(item).url == request.full_url)
            calls.append(source_id.value); source = resolve_reviewed_source(source_id)
            return Response(b"# invalid", "text/plain", source.url)
        observer = runtime._build_observer(runtime._build_collector(
            resolve_reviewed_source, opener))[0]
        with tempfile.TemporaryDirectory() as folder:
            (issue, execute, _), _, api = self.service(folder, observer=observer)
            with self.assertRaisesRegex(runner.RunnerError, "SEMANTIC_OR_TRANSPORT_GAP"):
                execute(issue())
            self.assertEqual(len(calls), 1)
            state = api[7](); self.assertFalse(state["evidence_committed"])
            self.assertFalse(state["automatic_retry_allowed"])

    def test_crash_after_request_boundary_is_inspection_only(self):
        calls = []
        def crashing(*_args): calls.append(1); raise OSError("private raw content")
        with tempfile.TemporaryDirectory() as folder:
            (issue, execute, recover), _, _api = self.service(folder, observer=crashing)
            with self.assertRaisesRegex(runner.RunnerError, "SOURCE_OUTCOME_UNKNOWN"):
                execute(issue())
            state = recover()
            self.assertEqual(calls, [1]); self.assertEqual(state["network_invocations"], 0)
            self.assertFalse(state["automatic_resume_allowed"])
            self.assertFalse(state["automatic_retry_allowed"])
            self.assertTrue(state["reconciliation_required"])

    def test_write_ahead_faults_never_reach_get_and_response_gap_is_unknown(self):
        before_get = ("BEFORE_CREATE", "PERMIT_CONSUMED_DURABLE",
                      "ATTEMPT_INTENT_DURABLE", "SOURCE_INTENT_DURABLE",
                      "REQUEST_MAY_HAVE_STARTED")
        for point in before_get:
            with self.subTest(point=point), tempfile.TemporaryDirectory() as folder:
                def fault(current):
                    if current == point: raise OSError("sensitive fault detail")
                (issue, execute, recover), calls, _api = self.service(folder, fault=fault)
                with self.assertRaises(runner.RunnerError) as caught: execute(issue())
                self.assertNotIn("sensitive", str(caught.exception)); self.assertEqual(calls, [])
                self.assertEqual(recover()["network_invocations"], 0)
        with tempfile.TemporaryDirectory() as folder:
            def after_response(current):
                if current == "RESPONSE_RECEIVED_BEFORE_RESULT":
                    raise OSError("sensitive response detail")
            (issue, execute, recover), calls, _api = self.service(folder, fault=after_response)
            with self.assertRaisesRegex(runner.RunnerError, "SOURCE_OUTCOME_UNKNOWN"):
                execute(issue())
            self.assertEqual(len(calls), 1)
            state = recover(); self.assertTrue(state["reconciliation_required"])
            self.assertFalse(state["automatic_retry_allowed"])

    def test_journal_plan_attempt_and_boundary_receipt_mismatch_fail_closed(self):
        for position, field in ((8, "plan_id"), (1, "attempt_id"), (3, "attempt_generation")):
            with self.subTest(position=position, field=field), tempfile.TemporaryDirectory() as folder:
                calls = []
                api = list(journal._build_store(Path(folder), fixture_issuers=True))
                original = api[position]
                def forged(*args, _original=original, _field=field):
                    value = dict(_original(*args)); value[_field] = "f" * 64 if _field != "attempt_generation" else 1
                    return value
                api[position] = forged
                def observer(*_args): calls.append(1); raise AssertionError("must not run")
                issue, execute, _recover = runner._build_fixture_runner(tuple(api), observer)
                with self.assertRaises(runner.RunnerError): execute(issue())
                self.assertEqual(calls, [])

    def test_permit_candidate_and_fsync_crashes_block_before_get(self):
        for point in ("WRITE_PARTIAL", "FILE_FSYNCED", "RENAMED",
                      "PERMIT_CONSUMED_DURABLE"):
            with self.subTest(point=point), tempfile.TemporaryDirectory() as folder:
                armed = False
                def fault(current):
                    nonlocal armed
                    if current == "PLAN_DURABLE": armed = True
                    elif armed and current == point: raise OSError("private detail")
                (issue, execute, recover), calls, _api = self.service(folder, fault=fault)
                permit = issue()
                with self.assertRaises(runner.RunnerError): execute(permit)
                self.assertEqual(calls, [])
                state = recover(); self.assertTrue(state["execution_blocked"])
                self.assertFalse(state["automatic_retry_allowed"])
                if point == "RENAMED": self.assertEqual(state["durability"], "UNKNOWN")

    def test_post_result_commit_and_finalize_faults_never_repeat_gets(self):
        for point, expected_calls in (("SOURCE_RESULT_DURABLE", 1),
                                      ("ALL_RESULTS_DURABLE", 4),
                                      ("EVIDENCE_COMMITTED", 4),
                                      ("BEFORE_FINALIZE", 4), ("FINALIZED", 4)):
            with self.subTest(point=point), tempfile.TemporaryDirectory() as folder:
                def fault(current):
                    if current == point: raise OSError("private detail")
                (issue, execute, recover), calls, _api = self.service(folder, fault=fault)
                with self.assertRaises(runner.RunnerError): execute(issue())
                self.assertEqual(len(calls), expected_calls)
                before = len(calls)
                with self.assertRaises(runner.RunnerError): execute(issue())
                self.assertEqual(len(calls), before)
                self.assertFalse(recover()["automatic_resume_allowed"])

    def test_result_and_evidence_identities_bind_attempt_boundary_and_ordered_results(self):
        with tempfile.TemporaryDirectory() as folder:
            (issue, execute, _recover), _calls, _api = self.service(folder)
            real_hash = runner._hash; captured = []
            def recording(value, domain):
                captured.append((dict(value), domain)); return real_hash(value, domain)
            with mock.patch.object(runner, "_hash", side_effect=recording):
                execute(issue())
            results = [value for value, domain in captured
                       if domain == "MINIMIZED_SOURCE_RESULT"]
            evidence = next(value for value, domain in captured
                            if domain == "SEALED_V2_EVIDENCE")
            self.assertEqual(len(results), 4)
            result_ids = [real_hash(value, "MINIMIZED_SOURCE_RESULT") for value in results]
            for ordinal, value in enumerate(results):
                self.assertEqual(value["plan_id"], runner.PLAN_ID)
                self.assertEqual(value["attempt_generation"], 0)
                self.assertEqual(value["source_ordinal"], ordinal)
                self.assertRegex(value["attempt_id"], r"^[0-9a-f]{64}$")
                self.assertRegex(value["request_boundary_id"], r"^[0-9a-f]{64}$")
                self.assertEqual(value["predicate_policy"], "technocore-runtime-predicates-v2")
            self.assertEqual([item["result_id"] for item in evidence["sources"]], result_ids)
            self.assertEqual([item["source_ordinal"] for item in evidence["sources"]], list(range(4)))
            self.assertRegex(evidence["journal_precommit_head"], r"^[0-9a-f]{64}$")
            self.assertEqual(evidence["attempt_id"], results[0]["attempt_id"])


if __name__ == "__main__": unittest.main()
