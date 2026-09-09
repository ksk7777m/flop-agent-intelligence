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
from flop_agent import production_reobservation_handoff as handoff


class ProductionReobservationHandoffTests(unittest.TestCase):
    def schema(self):
        return json.loads(Path("schemas/production-reobservation-handoff.v1.json").read_text())

    def test_public_projections_are_closed_schema_valid_and_disabled(self):
        schema = self.schema(); validator = jsonschema.Draft202012Validator(schema)
        values = (dict(handoff.review_record()), dict(handoff.activation_checklist()),
                  dict(handoff.handoff_status()))
        for value in values: validator.validate(value)
        self.assertEqual(handoff.validate_review_record(values[0]), ())
        self.assertEqual(handoff.validate_activation_checklist(values[1]), ())
        self.assertEqual(handoff.validate_handoff_status(values[2]), ())
        self.assertEqual(values[1]["activation_status"], "BLOCKED")
        self.assertGreater(values[1]["unsatisfied_count"], 0)
        self.assertEqual(values[2]["production_permit_issuer"], "ABSENT")
        self.assertEqual(values[2]["production_execute_api"], "ABSENT")
        self.assertEqual(values[2]["live_get_count"], 0)
        self.assertFalse(values[2]["ready_to_act"])
        self.assertFalse(values[2]["authorized_to_act"])

    def test_review_exact_identity_and_every_one_field_mutation_rejected(self):
        value = dict(handoff.review_record())
        self.assertEqual(value["reviewed_main_sha"], handoff.REVIEWED_MAIN_SHA)
        self.assertEqual(value["plan_id"], runner.PLAN_ID)
        self.assertEqual(value["journal_id"], journal.JOURNAL_ID)
        self.assertEqual(value["predicate_policy"], "technocore-runtime-predicates-v2")
        for key in value:
            with self.subTest(key=key):
                forged = dict(value)
                item = forged[key]
                forged[key] = (not item if type(item) is bool else item + 1
                               if type(item) is int else "f" * 64)
                self.assertTrue(handoff.validate_review_record(forged))

    def test_stale_generation_predicate_source_order_and_nested_fields_rejected(self):
        review = dict(handoff.review_record())
        for key, replacement in (("reviewed_main_sha", "0" * 40),
                                 ("expected_generation", 1),
                                 ("predicate_policy", "technocore-runtime-predicates-v1"),
                                 ("source_order_hash", "0" * 64),
                                 ("plan_id", "0" * 64),
                                 ("journal_id", "0" * 64)):
            forged = dict(review); forged[key] = replacement
            self.assertTrue(handoff.validate_review_record(forged))
        forged = dict(review); forged["metadata"] = {"secret": "not retained"}
        self.assertEqual(handoff.validate_review_record(forged), ("CLOSED_FIELDS_REQUIRED",))
        checklist = dict(handoff.activation_checklist())
        checklist["items"] = [dict(item) for item in checklist["items"]]
        checklist["items"][0]["ordinal"] = False
        self.assertTrue(handoff.validate_activation_checklist(checklist))

    def test_checklist_cannot_be_promoted_by_claimed_results(self):
        value = dict(handoff.activation_checklist())
        for mutation in (
            lambda item: item.update({"activation_status": "READY"}),
            lambda item: item.update({"ready_to_act": True}),
            lambda item: item.update({"authorized_to_act": True}),
            lambda item: item.update({"production_permit_issuer": "PRESENT"}),
            lambda item: item.update({"unsatisfied_count": 0}),
            lambda item: item.update({"extra": {}}),
        ):
            forged = copy.deepcopy(value); mutation(forged)
            self.assertTrue(handoff.validate_activation_checklist(forged))

    def test_fixture_review_state_is_one_shot_non_capability_and_replay_safe(self):
        issue, transition = handoff._build_fixture_handoff_service()
        token = issue()
        with self.assertRaises(TypeError): copy.copy(token)
        with self.assertRaises(TypeError): copy.deepcopy(token)
        with self.assertRaises(TypeError): pickle.dumps(token)
        first = transition(token, handoff.HandoffState.REVIEW_REQUIRED)
        second = transition(token, handoff.HandoffState.REVIEWED_DESCRIPTIVE_ONLY)
        final = transition(token, handoff.HandoffState.ACTIVATION_REVIEW_REQUIRED)
        self.assertEqual(first["network_invocations"], 0)
        self.assertFalse(second["permit_issued"]); self.assertFalse(final["authorized_to_act"])
        with self.assertRaisesRegex(handoff.HandoffError, "REVIEW_REPLAYED"):
            transition(token, handoff.HandoffState.HANDOFF_INCOMPLETE)
        other_transition = handoff._build_fixture_handoff_service()[1]
        with self.assertRaisesRegex(handoff.HandoffError, "SEALED_FIXTURE_REVIEW_REQUIRED"):
            other_transition(token, handoff.HandoffState.REVOKED)
        issue2, transition2 = handoff._build_fixture_handoff_service(); first_token = issue2(); second_token = issue2()
        for state in (handoff.HandoffState.REVIEW_REQUIRED,
                      handoff.HandoffState.REVIEWED_DESCRIPTIVE_ONLY,
                      handoff.HandoffState.ACTIVATION_REVIEW_REQUIRED):
            transition2(first_token, state)
        with self.assertRaisesRegex(handoff.HandoffError, "REVIEW_REPLAYED"):
            transition2(second_token, handoff.HandoffState.REVIEW_REQUIRED)

    def test_revoked_superseded_expired_and_incomplete_never_authorize(self):
        paths = (
            (handoff.HandoffState.REVIEW_REQUIRED, handoff.HandoffState.REVOKED),
            (handoff.HandoffState.REVIEW_REQUIRED, handoff.HandoffState.POLICY_BLOCKED),
            (handoff.HandoffState.REVIEW_REQUIRED, handoff.HandoffState.EXPIRED_OR_CURRENTNESS_UNKNOWN),
            (handoff.HandoffState.REVIEWED_DESCRIPTIVE_ONLY, handoff.HandoffState.SUPERSEDED),
            (handoff.HandoffState.REVIEWED_DESCRIPTIVE_ONLY, handoff.HandoffState.HANDOFF_INCOMPLETE),
        )
        for intermediate, terminal in paths:
            with self.subTest(terminal=terminal):
                issue, transition = handoff._build_fixture_handoff_service(); token = issue()
                transition(token, handoff.HandoffState.REVIEW_REQUIRED)
                if intermediate is handoff.HandoffState.REVIEWED_DESCRIPTIVE_ONLY:
                    transition(token, intermediate)
                result = transition(token, terminal)
                self.assertEqual(result["activation_status"], "BLOCKED")
                self.assertFalse(result["permit_issued"]); self.assertFalse(result["ready_to_act"])

    def test_review_artifact_cannot_become_runner_permit_or_network_call(self):
        calls = []
        with tempfile.TemporaryDirectory() as folder:
            api = journal._build_store(Path(folder), fixture_issuers=True)
            def observer(*_args): calls.append(1); raise AssertionError("unreachable")
            _issue, execute, _recover = runner._build_fixture_runner(api, observer)
            with self.assertRaises(runner.RunnerError): execute(handoff.review_record())
        self.assertEqual(calls, [])

    def test_production_surface_has_no_fixture_issuer_execute_cli_or_dependencies(self):
        self.assertNotIn("_build_fixture_handoff_service", handoff.__all__)
        for name in ("issue", "issue_permit", "execute", "activate", "schedule", "poll"):
            self.assertFalse(hasattr(handoff, name))
        source = inspect.getsource(handoff).lower()
        for forbidden in ("import urllib", "import requests", "import httpx", "import socket",
                          "invoke_mcp(", "sign_transaction", "wallet", "--confirm"):
            self.assertNotIn(forbidden, source)
        cli = Path("src/flop_agent/cli.py").read_text().lower()
        self.assertNotIn("reobservation-handoff", cli)
        self.assertNotIn("production-reobservation", cli)
        self.assertEqual(tuple(inspect.signature(handoff._build_production_projection_service).parameters), ())
        production = handoff._build_production_projection_service()
        self.assertEqual(len(production), 3)
        self.assertTrue(all(not hasattr(item, "issue") and not hasattr(item, "execute")
                            for item in production))
        before = dict(handoff.handoff_status())
        with mock.patch.object(handoff, "_build_fixture_handoff_service", return_value=(object(), object())):
            self.assertEqual(dict(handoff.handoff_status()), before)

    def test_import_projection_and_validation_make_zero_network_calls_and_hide_private_data(self):
        with mock.patch("socket.socket", side_effect=AssertionError("network")):
            review = dict(handoff.review_record())
            checklist = dict(handoff.activation_checklist())
            status = dict(handoff.handoff_status())
            self.assertEqual(handoff.validate_review_record(review), ())
            self.assertEqual(handoff.validate_activation_checklist(checklist), ())
            self.assertEqual(handoff.validate_handoff_status(status), ())
        encoded = json.dumps((review, checklist, status)).lower()
        for forbidden in ('"raw_body"', '"headers"', '"error_body"', '"url"', '"path"',
                          '"pid"', '"uid"', '"hostname"', '"username"', '"email"',
                          '"cookie"', '"authorization"', '"secret"', '"writer_token"',
                          '"permit_token"', '"metadata"', "http://", "https://"):
            self.assertNotIn(forbidden, encoded)

    def test_validation_errors_are_fixed_codes_without_input_or_cause(self):
        forged = dict(handoff.review_record()); forged["reviewed_main_sha"] = "private-value"
        errors = handoff.validate_review_record(forged)
        self.assertEqual(errors, ("REVIEW_BINDING_INVALID",))
        self.assertNotIn("private-value", repr(errors))


if __name__ == "__main__": unittest.main()
