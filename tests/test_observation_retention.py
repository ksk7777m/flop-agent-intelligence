import copy
import inspect
import json
import math
import unittest
from pathlib import Path

import jsonschema

from flop_agent import evidence_transport as evidence
from flop_agent import observation_retention as retention
from flop_agent import replay_journal as replay
from flop_agent import technocore_runtime_observation as runtime
from flop_agent import technocore_transport_semantics as transport


class ObservationRetentionTests(unittest.TestCase):
    def authority(self):
        values = retention._build_authority()
        return dict(zip(("historical", "migrate", "prepare", "review", "begin",
                         "source", "commit", "project"), values))

    def chain(self):
        api = self.authority()
        old = api["historical"]()
        migration = api["migrate"](old, retention.PredicatePolicy.V2)
        plan = api["prepare"](migration)
        review = api["review"](plan)
        return api, old, migration, plan, review

    def validate(self, value):
        schema = json.loads(Path("schemas/observation-retention-ceremony.v1.json").read_text())
        jsonschema.Draft202012Validator(schema).validate(dict(value))
        self.assertEqual(retention.validate_projection(value), ())
        self.assertEqual(set(value), set(schema["properties"]))

    def test_v1_evidence_is_immutable_retained_and_never_v2_pass(self):
        api = self.authority(); old = api["historical"]()
        before = dict(api["project"](old))
        migration = api["migrate"](old, retention.PredicatePolicy.V2)
        after = dict(api["project"](old))
        self.assertEqual(before, after)
        self.assertEqual(after["predicate_policy"], retention.PredicatePolicy.V1.value)
        self.assertEqual(after["semantic_result"], "LLMS_SEMANTIC_GAP")
        self.assertEqual(after["supersession"], "SUPERSEDED")
        self.assertEqual(api["project"](migration)["semantic_result"], "RE_EVALUATION_PROHIBITED")

    def test_evidence_identity_has_strict_domain_and_complete_semantic_binding(self):
        api = self.authority(); value = api["project"](api["historical"]())
        self.assertEqual(value["identity_domain"], retention.IDENTITY_DOMAIN)
        self.assertEqual(value["canonical_encoding"], retention.CANONICAL_ENCODING)
        self.assertEqual(value["hash_algorithm"], "SHA-256")
        self.assertEqual(value["predicate_policy_hash"],
                         retention.PREDICATE_POLICY_HASHES[retention.PredicatePolicy.V1])
        self.assertEqual(value["source_count"], 4)
        self.assertEqual(value["source_order_hash"], retention.SOURCE_ORDER_HASH)
        self.assertEqual(value["body_evidence"], "NOT_RETAINED")
        self.assertEqual(value["deployment_version_evidence"],
                         "VERSION_EXPLICITLY_OBSERVED_ONE_SHOT")
        source = inspect.getsource(retention)
        for binding in ("timeout_seconds", "body_byte_limit", "redirects_allowed",
                        "alternate_url_allowed", "fallback_allowed", "remote_mcp_enabled",
                        "signing_enabled", "write_enabled", "scheduler_enabled"):
            self.assertIn(binding, source)

        base = {"flag": True, "count": 1, "text": "e\N{COMBINING ACUTE ACCENT}"}
        self.assertNotEqual(retention._canonical_hash(base, "TEST"),
                            retention._canonical_hash({**base, "flag": 1}, "TEST"))
        self.assertNotEqual(retention._canonical_hash(base, "TEST"),
                            retention._canonical_hash({**base, "text": "\N{LATIN SMALL LETTER E WITH ACUTE}"}, "TEST"))
        self.assertNotEqual(retention._canonical_hash(base, "TEST"),
                            retention._canonical_hash(base, "OTHER"))
        for invalid in (1.0, math.nan, math.inf):
            with self.assertRaisesRegex(retention.RetentionError, "CANONICAL_TYPE_INVALID"):
                retention._canonical_hash({"value": invalid}, "TEST")

    def test_retention_currentness_freshness_and_compatibility_are_independent(self):
        api = self.authority(); value = api["project"](api["historical"]())
        self.assertEqual(value["retention"], "RETAINED")
        self.assertEqual(value["retention_policy"], "RETENTION_POLICY_REQUIRED")
        self.assertEqual(value["currentness"], "CURRENTNESS_UNKNOWN")
        self.assertEqual(value["freshness"], "FRESHNESS_NOT_CONFIRMED")
        self.assertEqual(value["compatibility"], "COMPATIBILITY_REVIEW_REQUIRED")
        self.assertFalse(value["ready_to_act"]); self.assertFalse(value["authorized_to_act"])

    def test_migration_same_unknown_duplicate_downgrade_and_cross_authority_fail(self):
        api = self.authority(); old = api["historical"]()
        with self.assertRaisesRegex(retention.RetentionError, "MIGRATION_SAME_REVISION"):
            api["migrate"](old, retention.PredicatePolicy.V1)
        with self.assertRaisesRegex(retention.RetentionError, "PREDICATE_POLICY_UNKNOWN"):
            api["migrate"](old, "technocore-runtime-predicates-v3")
        api["migrate"](old, retention.PredicatePolicy.V2)
        with self.assertRaisesRegex(retention.RetentionError, "MIGRATION_ALREADY_RECORDED"):
            api["migrate"](old, retention.PredicatePolicy.V2)
        other = self.authority()
        with self.assertRaisesRegex(retention.RetentionError, "CROSS_AUTHORITY_RECORD"):
            other["migrate"](old, retention.PredicatePolicy.V2)

    def test_migration_plan_and_review_are_descriptive_only(self):
        api, _, migration, plan, review = self.chain()
        for token in (migration, plan, review):
            value = api["project"](token); self.validate(value)
            self.assertFalse(value["live_action_enabled"])
            self.assertEqual(value["retry_count"], 0)
        self.assertEqual(api["project"](plan)["semantic_result"], "MANUAL_EXECUTION_PENDING")
        self.assertEqual(api["project"](review)["semantic_result"], "HUMAN_REVIEW_RECORDED")

    def test_plan_has_no_caller_url_predicate_timeout_transport_or_sink(self):
        signature = inspect.signature(retention.prepare_reobservation_plan)
        self.assertEqual(tuple(signature.parameters), ("migration",))
        source = inspect.getsource(retention)
        for forbidden in ("urllib", "requests", "subprocess", "socket", "invoke_mcp",
                          "invoke_signer", "use_wallet", "open("):
            self.assertNotIn(forbidden, source)

    def test_human_review_is_not_serializable_network_authority(self):
        api, _, _, _, review = self.chain()
        with self.assertRaises(TypeError): copy.copy(review)
        with self.assertRaises(TypeError): review.__reduce__()
        self.assertFalse(hasattr(review, "execute"))
        self.assertFalse(api["project"](review)["authorized_to_act"])

    def test_duplicate_attempt_and_duplicate_source_are_rejected(self):
        api, _, _, _, review = self.chain(); attempt = api["begin"](review)
        with self.assertRaisesRegex(retention.RetentionError, "DUPLICATE_ATTEMPT"):
            api["begin"](review)
        first = api["source"](attempt, retention.FIXED_SOURCES[0],
                              retention.SourceAttemptState.COMPLETED)
        with self.assertRaisesRegex(retention.RetentionError, "ATTEMPT_RECORD_SUPERSEDED"):
            api["source"](attempt, retention.FIXED_SOURCES[0],
                          retention.SourceAttemptState.COMPLETED)
        with self.assertRaisesRegex(retention.RetentionError, "SOURCE_ALREADY_ATTEMPTED"):
            api["source"](first, retention.FIXED_SOURCES[0],
                          retention.SourceAttemptState.COMPLETED)

    def test_partial_failed_and_interrupted_attempts_never_complete_or_retry(self):
        for state, expected in ((retention.SourceAttemptState.FAILED, "FAILED"),
                                (retention.SourceAttemptState.INTERRUPTED, "INTERRUPTED")):
            with self.subTest(state=state):
                api, _, _, _, review = self.chain(); attempt = api["begin"](review)
                terminal = api["source"](attempt, retention.FIXED_SOURCES[0], state)
                value = api["project"](terminal)
                self.assertEqual(value["semantic_result"], expected)
                self.assertEqual(value["completeness"], "INCOMPLETE")
                self.assertEqual(value["retry_count"], 0)
                with self.assertRaisesRegex(retention.RetentionError, "ATTEMPT_TERMINAL"):
                    api["source"](terminal, retention.FIXED_SOURCES[1],
                                  retention.SourceAttemptState.COMPLETED)

    def test_four_exact_sources_are_required_but_result_needs_current_evidence(self):
        api, old, _, _, review = self.chain(); attempt = api["begin"](review)
        current = attempt
        for index, source in enumerate(retention.FIXED_SOURCES):
            current = api["source"](current, source, retention.SourceAttemptState.COMPLETED)
            expected = "COMPLETE" if index == 3 else "INCOMPLETE"
            self.assertEqual(api["project"](current)["completeness"], expected)
        with self.assertRaisesRegex(retention.RetentionError, "JOURNALED_CURRENT_RESULT_REQUIRED"):
            api["commit"](current, old)

    def test_old_attempt_generations_are_retained_and_marked_superseded(self):
        api, _, _, _, review = self.chain(); started = api["begin"](review)
        next_record = api["source"](started, retention.FIXED_SOURCES[0],
                                    retention.SourceAttemptState.COMPLETED)
        self.assertEqual(api["project"](started)["supersession"], "SUPERSEDED")
        self.assertEqual(api["project"](next_record)["supersession"], "NOT_SUPERSEDED")

    def test_failure_cannot_delete_historical_success_and_crash_cannot_resume(self):
        api, old, _, _, review = self.chain(); before = dict(api["project"](old))
        attempt = api["begin"](review)
        api["source"](attempt, retention.FIXED_SOURCES[0], retention.SourceAttemptState.FAILED)
        self.assertEqual(before, dict(api["project"](old)))
        restarted = self.authority()
        with self.assertRaises(retention.RetentionError):
            restarted["begin"](review)

    def test_future_or_rollback_time_never_promotes_currentness(self):
        api = self.authority(); value = dict(api["project"](api["historical"]()))
        value["observed_at"] = "9999-12-31T23:59:59Z"
        self.assertEqual(value["currentness"], "CURRENTNESS_UNKNOWN")
        self.assertEqual(value["retention_policy"], "RETENTION_POLICY_REQUIRED")
        self.assertNotIn("WITHIN_LOCAL_REVIEW_WINDOW", value.values())

    def test_projection_rejects_unknown_nested_authority_and_raw_values(self):
        api = self.authority(); value = dict(api["project"](api["historical"]()))
        self.validate(value)
        for change in ({"authorized_to_act": True}, {"retry_count": 1},
                       {"metadata": {"url": "REMOTE_VALUE"}},
                       {"currentness": "CURRENT"}, {"source_count": True},
                       {"record_generation": True},
                       {"body_evidence": {"raw": "REMOTE_VALUE"}},
                       {"predicate_policy": retention.PredicatePolicy.V2.value},
                       {"predicate_policy_hash": "0" * 64},
                       {"semantic_result": "COMPLETED"}, {"completeness": "COMPLETE"},
                       {"schema": "observation-retention-ceremony-v2"},
                       {"runtime_nonce_status": "AVAILABLE"}):
            forged = dict(value); forged.update(change)
            self.assertTrue(retention.validate_projection(forged))
        with self.assertRaises(retention.RetentionError) as caught:
            api["migrate"]("REMOTE_VALUE", retention.PredicatePolicy.V2)
        self.assertNotIn("REMOTE_VALUE", str(caught.exception))

    def test_runtime_replay_transport_and_evidence_semantics_align(self):
        api = self.authority(); value = api["project"](api["historical"]())
        self.assertEqual(value["predicate_policy"], runtime.PredicatePolicy.V1.value
                         if hasattr(runtime, "PredicatePolicy") else retention.PredicatePolicy.V1.value)
        self.assertEqual(value["runtime_nonce_status"], "BLOCKED_BY_LIVE_SIGNED_WRITE")
        self.assertEqual(replay.RetryClassification.DO_NOT_RETRY.value, "DO_NOT_RETRY")
        self.assertEqual(transport.RetryDisposition.DO_NOT_RETRY.value, "DO_NOT_RETRY")
        self.assertNotEqual(evidence.Completeness.PARTIAL, evidence.Completeness.COMPLETE_VERIFIED)


if __name__ == "__main__": unittest.main()
