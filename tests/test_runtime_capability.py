import copy
import dataclasses
import inspect
import json
import pickle
import subprocess
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

from flop_agent import runtime_capability as rc
from flop_agent.remote_content_policy import resolve_reviewed_source


NOW = datetime(2026, 9, 6, 6, 0, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]


def issue(fixture_id):
    return rc.reviewed_runtime_observation(fixture_id)


def ready_definitions():
    state, domain, source = rc.CapabilityState, rc.Domain, rc.ReviewedSourceId
    offline, documented = state.IMPLEMENTED_OFFLINE, state.DOCUMENTED_ONLY
    return (
        rc.CapabilityDefinition("identity.architecture", domain.IDENTITY, offline, documented, source.TECHNOCORE_SECURITY, False, True, ()),
        rc.CapabilityDefinition("technocore.runtime", domain.TECHNOCORE, offline, documented, source.TECHNOCORE_HEALTH, True, True, ()),
        rc.CapabilityDefinition("export.runtime", domain.EXPORT_EVIDENCE, offline, documented, source.TECHNOCORE_ROOMS_JSON, True, True, ()),
        rc.CapabilityDefinition("faucet.runtime", domain.FAUCET, offline, documented, source.FLOP_FINANCE_TEASER, True, True, ()),
        rc.CapabilityDefinition("network.identity", domain.TESTNET_NETWORK, offline, documented, source.FLOP_FINANCE_TEASER, True, True, (), "fixture-chain-a", "fixture-rpc-a", "fixture-genesis-a"),
        rc.CapabilityDefinition("inference.runtime", domain.INFERENCE, offline, documented, source.FLOP_FINANCE_TEASER, True, True, ()),
        rc.CapabilityDefinition("rail.runtime", domain.SETTLEMENT_RAIL, offline, documented, source.FLOP_FINANCE_TEASER, True, True, (), rail_type="VERIFIED_TEST_RAIL", protocol_valid=True, rail_crypto_verified=True, economic_value_verified=True, finality_verified=True),
        rc.CapabilityDefinition("durability.readback", domain.EVIDENCE_DURABILITY, offline, documented, source.TECHNOCORE_ROOMS_JSON, True, True, ()),
        rc.CapabilityDefinition("delegation.verification", domain.DELEGATION_VERIFICATION, offline, documented, source.TECHNOCORE_SECURITY, False, False, ()),
        rc.CapabilityDefinition("tool.output_budget", domain.TOOL_OUTPUT_BUDGET, offline, state.REVIEW_REQUIRED, None, False, False, ()),
        rc.CapabilityDefinition("replay.safety", domain.REPLAY_SAFETY, offline, documented, None, False, False, (), replay_ledger_implemented=True, side_effect_journal_implemented=True),
        rc.CapabilityDefinition("activity.quality", domain.ACTIVITY_QUALITY, offline, state.REVIEW_REQUIRED, None, False, False, ()),
        rc.CapabilityDefinition("protocol.generic_models", domain.PROTOCOL_MODEL, offline, documented, source.TECHNOCORE_SECURITY, False, False, ()),
        rc.CapabilityDefinition("runtime.drift", domain.RUNTIME_DRIFT, offline, state.RUNTIME_NOT_OBSERVED, source.TECHNOCORE_CONFIG, False, False, ()),
    )


def private_service(definitions=None, clock=lambda: NOW, ttl=timedelta(hours=6)):
    return rc._build_readiness_service(
        ready_definitions() if definitions is None else definitions,
        rc._resolve_observation, clock, ttl)[0]


def private_manifest(action=rc.ReadinessAction.GENERAL_TESTNET):
    project = rc._build_readiness_service(
        ready_definitions(), rc._resolve_observation, lambda: NOW,
        timedelta(hours=6))[1]
    return project(all_observations(), action)


def all_observations(network=rc.ReviewedRuntimeFixtureId.NETWORK_MATCH):
    ids = (
        rc.ReviewedRuntimeFixtureId.TECHNOCORE_AVAILABLE,
        rc.ReviewedRuntimeFixtureId.EXPORT_AVAILABLE,
        rc.ReviewedRuntimeFixtureId.FAUCET_AVAILABLE,
        network,
        rc.ReviewedRuntimeFixtureId.INFERENCE_AVAILABLE,
        rc.ReviewedRuntimeFixtureId.RAIL_AVAILABLE,
        rc.ReviewedRuntimeFixtureId.DURABILITY_AVAILABLE,
    )
    return tuple(issue(item) for item in ids)


class RuntimeCapabilityTests(unittest.TestCase):
    def test_production_api_has_no_sensitive_policy_injection(self):
        forbidden = {"now", "ttl", "definitions", "resolver", "blocker_builder",
                     "state_type", "policy", "registry", "verifier", "issuer",
                     "fetcher", "reader", "opener", "url", "callback", "clock"}
        for function in (rc.assess_capabilities, rc.capability_manifest,
                         rc.reviewed_runtime_observation, rc.public_observation,
                         rc.transition_faucet):
            names = {name.lstrip("_").lower() for name in inspect.signature(function).parameters}
            self.assertFalse(names & forbidden, (function, names & forbidden))

    def test_empty_definitions_never_ready_or_authorized(self):
        assess = private_service(definitions=())
        result = assess()
        self.assertEqual(result["overall_state"], "INVALID_CONFIGURATION")
        self.assertFalse(result["ready_to_act"])
        self.assertFalse(result["authorized_to_act"])

    def test_missing_critical_domain_blocks(self):
        definitions = tuple(item for item in ready_definitions()
                            if item.domain is not rc.Domain.EVIDENCE_DURABILITY)
        assess = private_service(definitions=definitions)
        result = assess(all_observations())
        self.assertEqual(result["overall_state"], "INVALID_CONFIGURATION")
        self.assertIn("MISSING_CRITICAL_DOMAIN", result["blocking_reasons"])

    def test_arbitrary_fixture_mapping_and_raw_id_cannot_issue(self):
        with self.assertRaises((PermissionError, TypeError)):
            rc.reviewed_runtime_observation({"response_class": "AVAILABLE"})
        with self.assertRaises((PermissionError, TypeError)):
            rc.reviewed_runtime_observation("TECHNOCORE_AVAILABLE")

    def test_documented_and_implemented_do_not_imply_observed(self):
        result = private_service()()
        item = result["domains"]["TECHNOCORE"][0]
        self.assertEqual(item["implementation_status"], "IMPLEMENTED_OFFLINE")
        self.assertEqual(item["documented_status"], "DOCUMENTED_ONLY")
        self.assertEqual(item["runtime_status"], "RUNTIME_NOT_OBSERVED")
        self.assertFalse(result["ready_to_act"])

    def test_third_party_and_descriptive_records_cannot_promote(self):
        values = ({"status": "RUNTIME_OBSERVED", "provenance": "THIRD_PARTY_REPORT"},
                  {"status": "RUNTIME_OBSERVED", "provenance": "UNTRUSTED_CONTEXT"})
        for value in values:
            with self.assertRaises((PermissionError, TypeError)):
                rc.assess_capabilities((value,))

    def test_observation_construction_copy_replace_pickle_and_json_rejected(self):
        with self.assertRaises(PermissionError):
            rc.RuntimeCapabilityObservation()
        raw = object.__new__(rc.RuntimeCapabilityObservation)
        with self.assertRaises(PermissionError):
            rc.assess_capabilities((raw,))
        token = issue(rc.ReviewedRuntimeFixtureId.TECHNOCORE_AVAILABLE)
        with self.assertRaises(TypeError):
            dataclasses.replace(token)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with self.assertRaises(TypeError):
                operation(token)
        projection = json.loads(json.dumps(dict(rc.public_observation(token))))
        self.assertEqual(projection["status"], "DESCRIPTIVE_ONLY")
        with self.assertRaises((PermissionError, TypeError)):
            rc.assess_capabilities((projection,))

    def test_cross_authority_token_is_rejected(self):
        other_issue, _, _, _ = rc._build_runtime_authority(rc._PROBES, resolve_reviewed_source)
        token = other_issue(rc.ReviewedRuntimeFixtureId.TECHNOCORE_AVAILABLE)
        with self.assertRaises(PermissionError):
            rc.assess_capabilities((token,))

    def test_stale_observation_is_not_actionable(self):
        result = private_service()((issue(rc.ReviewedRuntimeFixtureId.TECHNOCORE_STALE),)
                                   + all_observations()[1:])
        item = result["domains"]["TECHNOCORE"][0]
        self.assertEqual(item["runtime_status"], "STALE_RUNTIME_OBSERVATION")
        self.assertFalse(item["ready_to_act"])
        self.assertFalse(result["ready_to_act"])

    def test_public_clock_and_ttl_injection_are_absent(self):
        signature = inspect.signature(rc.assess_capabilities)
        self.assertNotIn("now", signature.parameters)
        self.assertNotIn("ttl", signature.parameters)
        with self.assertRaises(TypeError):
            rc.assess_capabilities(now=NOW)
        with self.assertRaises(TypeError):
            rc.assess_capabilities(ttl=timedelta(days=365))

    def test_unavailable_conflict_survives_module_rebinding(self):
        token = issue(rc.ReviewedRuntimeFixtureId.TECHNOCORE_UNAVAILABLE)
        assess = private_service()
        originals = rc.ResponseClass, rc.CapabilityState, rc.OverallState
        rc.ResponseClass = type("FakeResponse", (), {"UNAVAILABLE": object()})
        rc.CapabilityState = object
        rc.OverallState = object
        try:
            item = assess((token,))["domains"]["TECHNOCORE"][0]
        finally:
            rc.ResponseClass, rc.CapabilityState, rc.OverallState = originals
        self.assertEqual(item["runtime_status"], "CONFLICTING_CAPABILITY_EVIDENCE")

    def test_faucet_progression_is_sealed_and_never_authorizes(self):
        transition = rc.transition_faucet
        rc._FAUCET_TRANSITIONS = {rc.FaucetState.NO_OFFICIAL_ENDPOINT: {
            "jump": "AUTHORIZED_TO_CLAIM"}}
        state = rc.FaucetState.NO_OFFICIAL_ENDPOINT
        for event in ("documented", "source_reviewed", "runtime_observed",
                      "requirements_verified", "request_approval"):
            state = transition(state, event)
        self.assertEqual(state.value, "READY_FOR_HUMAN_APPROVAL")
        with self.assertRaises(ValueError):
            transition(rc.FaucetState.NO_OFFICIAL_ENDPOINT, "jump")
        with self.assertRaises(ValueError):
            transition(state, "authorize")

    def test_faucet_runtime_still_requires_requirements_and_human(self):
        token = issue(rc.ReviewedRuntimeFixtureId.FAUCET_AVAILABLE)
        item = rc.assess_capabilities((token,), rc.ReadinessAction.FAUCET_CLAIM)["domains"]["FAUCET"][0]
        self.assertEqual(item["runtime_status"], "RUNTIME_OBSERVED")
        self.assertIn("CLAIM_REQUIREMENTS_UNVERIFIED", item["blocking_reasons"])
        self.assertIn("HUMAN_APPROVAL_REQUIRED", item["blocking_reasons"])
        self.assertFalse(item["authorized_to_act"])

    def test_every_prerequisite_ready_does_not_authorize(self):
        result = private_service()(all_observations())
        self.assertEqual(result["overall_state"], "ACTION_READY")
        self.assertTrue(result["ready_to_act"])
        self.assertFalse(result["authorized_to_act"])

    def test_action_authority_is_unconstructible_and_not_observation(self):
        with self.assertRaises(PermissionError):
            rc.ActionAuthorization()
        token = issue(rc.ReviewedRuntimeFixtureId.FAUCET_AVAILABLE)
        with self.assertRaises(PermissionError):
            rc.assess_capabilities((token,), authorization=token)

    def test_chain_rpc_and_genesis_mismatch_block_live(self):
        result = private_service()(all_observations(rc.ReviewedRuntimeFixtureId.NETWORK_MISMATCH))
        item = result["domains"]["TESTNET_NETWORK"][0]
        self.assertEqual(item["documented_chain_id"], "fixture-chain-a")
        self.assertEqual(item["observed_chain_id"], "fixture-chain-b")
        self.assertEqual(item["runtime_status"], "CONFLICTING_CAPABILITY_EVIDENCE")
        self.assertFalse(item["testnet_live"])
        self.assertFalse(result["ready_to_act"])

    def test_matching_network_identity_can_be_live_only_when_ready(self):
        result = private_service()(all_observations())
        item = result["domains"]["TESTNET_NETWORK"][0]
        self.assertTrue(item["testnet_live"])
        self.assertEqual(item["documented_rpc_identity"], item["observed_rpc_identity"])

    def test_inference_schema_auth_and_spend_are_canonical_blockers(self):
        item = rc.assess_capabilities((issue(rc.ReviewedRuntimeFixtureId.INFERENCE_AVAILABLE),),
            rc.ReadinessAction.INFERENCE_REQUEST)["domains"]["INFERENCE"][0]
        for blocker in ("REQUEST_SCHEMA_REVIEW_REQUIRED", "AUTHENTICATION_MODEL_REVIEW_REQUIRED",
                        "COST_SPEND_SEMANTICS_REVIEW_REQUIRED", "HUMAN_APPROVAL_REQUIRED"):
            self.assertIn(blocker, item["blocking_reasons"])
        self.assertFalse(item["ready_to_act"])

    def test_identity_backup_and_recovery_are_canonical_blockers(self):
        item = rc.assess_capabilities()["domains"]["IDENTITY"][0]
        self.assertIn("BACKUP_DRILL_REQUIRED", item["blocking_reasons"])
        self.assertIn("RECOVERY_DRILL_REQUIRED", item["blocking_reasons"])

    def test_rail_durability_and_paperrail_remain_fail_closed(self):
        manifest = rc.assess_capabilities()
        rail = manifest["domains"]["SETTLEMENT_RAIL"][0]
        durability = manifest["domains"]["EVIDENCE_DURABILITY"][0]
        self.assertIn("ECONOMIC_VALUE_UNVERIFIED", rail["blocking_reasons"])
        self.assertIn("RUNTIME_WRITE_NOT_AUTHORIZED", durability["blocking_reasons"])
        self.assertTrue(rc.domain_readiness()["SETTLEMENT_RAIL"]["paperrail_protocol_valid"])
        self.assertFalse(rc.domain_readiness()["SETTLEMENT_RAIL"]["economic_value_verified"])

    def test_future_probes_are_fixed_reviewed_and_inert(self):
        for probe in rc.probe_manifest():
            self.assertIsInstance(probe.source_id, rc.ReviewedSourceId)
            self.assertEqual(probe.method, "GET")
            self.assertFalse(probe.redirects)
            self.assertEqual(probe.retry_count, 0)
        config = [item for item in rc.probe_manifest() if item.capability_id == "technocore.config"][0]
        self.assertEqual(config.source_id, rc.ReviewedSourceId.TECHNOCORE_CONFIG)

    def test_delegation_budget_replay_drift_and_protocol_taxonomy(self):
        status = rc.domain_readiness()
        self.assertFalse(status["DELEGATION_VERIFICATION"]["delegation_ready"])
        self.assertTrue(status["DELEGATION_VERIFICATION"]["root_key_local_only"])
        self.assertEqual(status["TOOL_OUTPUT_BUDGET"]["framing"], "UNTRUSTED_CONTENT")
        self.assertFalse(status["TOOL_OUTPUT_BUDGET"]["auto_fetch"])
        self.assertFalse(status["TOOL_OUTPUT_BUDGET"]["auto_action"])
        self.assertFalse(status["REPLAY_SAFETY"]["replay_ledger_implemented"])
        self.assertEqual(status["RUNTIME_DRIFT"]["runtime"], "RUNTIME_NOT_OBSERVED")
        self.assertEqual(status["PROTOCOL_MODEL"]["ptlc"], "EXPERIMENTAL_UNEXERCISED")
        self.assertEqual(status["PROTOCOL_MODEL"]["owned_room_auth"], "INSUFFICIENT_AS_SOLE_AUTH_EVIDENCE")
        self.assertFalse(status["PROTOCOL_MODEL"]["remote_mcp_key_custody"])

    def test_security_sensitive_callables_have_no_module_global_reads(self):
        functions = (rc.reviewed_runtime_observation, rc._resolve_observation,
                     rc.public_observation, rc.assess_capabilities,
                     rc.transition_faucet, rc.capability_manifest,
                     rc.validate_capability_manifest)
        for function in functions:
            self.assertEqual(inspect.getclosurevars(function).globals, {}, function)

    def test_module_rebinding_cannot_change_production_projection(self):
        before = rc.capability_manifest()
        originals = rc.MANIFEST_SCHEMA, rc.DEFAULT_OBSERVATION_TTL, rc._PROBES
        rc.MANIFEST_SCHEMA, rc.DEFAULT_OBSERVATION_TTL, rc._PROBES = "forged", timedelta(days=999), ()
        try:
            after = rc.capability_manifest()
        finally:
            rc.MANIFEST_SCHEMA, rc.DEFAULT_OBSERVATION_TTL, rc._PROBES = originals
        self.assertEqual(before, after)

    def test_manifest_and_cli_validate_against_canonical_schema(self):
        schema = json.loads((ROOT / "schemas/runtime-capability.v1.json").read_text())
        validator = Draft202012Validator(schema)
        validator.validate(rc.capability_manifest())
        output = subprocess.check_output(
            ["python3", "-m", "flop_agent.cli", "testnet-readiness", "capabilities"],
            cwd=ROOT, env={"PYTHONPATH": str(ROOT / "src"), "PYTHONDONTWRITEBYTECODE": "1"})
        cli = json.loads(output)
        self.assertEqual(list(validator.iter_errors(cli)), [])
        self.assertEqual(rc.validate_capability_manifest(cli), ())

    def test_consistent_action_ready_manifest_passes_both_layers(self):
        schema = json.loads((ROOT / "schemas/runtime-capability.v1.json").read_text())
        value = private_manifest()
        Draft202012Validator(schema).validate(value)
        self.assertEqual(value["overall_state"], "ACTION_READY")
        self.assertTrue(value["ready_to_act"])
        self.assertFalse(value["authorized_to_act"])
        self.assertEqual(rc.validate_capability_manifest(value), ())

    def test_contract_rejects_action_ready_with_required_child_blocker(self):
        schema = json.loads((ROOT / "schemas/runtime-capability.v1.json").read_text())
        validator = Draft202012Validator(schema)
        value = private_manifest()
        child = value["domains"]["IDENTITY"][0]
        child["ready_to_act"] = False
        child["blocking_reasons"] = ["BACKUP_DRILL_REQUIRED"]
        errors = list(validator.iter_errors(value)) + list(rc.validate_capability_manifest(value))
        self.assertGreater(len(errors), 0)

    def test_schema_rejects_all_inconsistent_authorized_states(self):
        schema = json.loads((ROOT / "schemas/runtime-capability.v1.json").read_text())
        validator = Draft202012Validator(schema)
        mutations = (
            {"authorized_to_act": False},
            {"authorized_to_act": True, "ready_to_act": False},
            {"authorized_to_act": True, "blocking_reasons": ["HUMAN_APPROVAL_REQUIRED"]},
        )
        for mutation in mutations:
            value = private_manifest()
            value.update({"overall_state": "AUTHORIZED", "live_runtime_readiness": "AUTHORIZED"})
            value.update(mutation)
            errors = list(validator.iter_errors(value)) + list(rc.validate_capability_manifest(value))
            self.assertGreater(len(errors), 0, mutation)

    def test_contract_rejects_stale_required_child_with_action_ready(self):
        value = private_manifest()
        child = value["domains"]["TECHNOCORE"][0]
        child["runtime_status"], child["ready_to_act"] = "STALE_RUNTIME_OBSERVATION", True
        child["blocking_reasons"] = []
        self.assertTrue(rc.validate_capability_manifest(value))

    def test_all_required_domains_reject_non_actionable_runtime_states(self):
        actions = (rc.ReadinessAction.GENERAL_TESTNET, rc.ReadinessAction.FAUCET_CLAIM,
                   rc.ReadinessAction.INFERENCE_REQUEST, rc.ReadinessAction.SETTLEMENT)
        statuses = ("CONFLICTING_CAPABILITY_EVIDENCE", "RUNTIME_NOT_OBSERVED",
                    "RUNTIME_UNAVAILABLE", "STALE_RUNTIME_OBSERVATION")
        covered = set()
        for action in actions:
            for domain, rows in private_manifest(action)["domains"].items():
                if not rows[0]["required_for_action"]:
                    continue
                covered.add(domain)
                for status in statuses:
                    value = private_manifest(action)
                    child = value["domains"][domain][0]
                    child.update({"runtime_status": status, "ready_to_act": True,
                                  "blocking_reasons": []})
                    self.assertIn("REQUIRED_CHILD_RUNTIME_NOT_ACTIONABLE:" +
                                  child["capability_id"],
                                  rc.validate_capability_manifest(value),
                                  (action, domain, status))
        self.assertTrue({"IDENTITY", "TECHNOCORE", "FAUCET", "TESTNET_NETWORK",
                         "INFERENCE", "SETTLEMENT_RAIL", "EVIDENCE_DURABILITY",
                         "REPLAY_SAFETY"} <= covered)

    def test_authorized_reuses_required_child_runtime_validation(self):
        for status in ("CONFLICTING_CAPABILITY_EVIDENCE", "RUNTIME_NOT_OBSERVED",
                       "RUNTIME_UNAVAILABLE"):
            value = private_manifest()
            value.update({"overall_state": "AUTHORIZED",
                          "live_runtime_readiness": "AUTHORIZED",
                          "authorized_to_act": True})
            child = value["domains"]["TECHNOCORE"][0]
            child.update({"runtime_status": status, "ready_to_act": True,
                          "blocking_reasons": []})
            self.assertIn("REQUIRED_CHILD_RUNTIME_NOT_ACTIONABLE:" +
                          child["capability_id"],
                          rc.validate_capability_manifest(value))

    def test_unknown_required_child_runtime_state_fails_closed(self):
        schema = json.loads((ROOT / "schemas/runtime-capability.v1.json").read_text())
        value = private_manifest()
        value["domains"]["IDENTITY"][0]["runtime_status"] = "FUTURE_OPTIMISTIC_STATE"
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(value)))
        self.assertTrue(rc.validate_capability_manifest(value))

    def test_required_child_implementation_and_documentation_are_derived(self):
        mutations = (("implementation_status", "NOT_IMPLEMENTED",
                      "REQUIRED_CHILD_IMPLEMENTATION_INSUFFICIENT"),
                     ("documented_status", "REVIEW_REQUIRED",
                      "REQUIRED_CHILD_DOCUMENTATION_INSUFFICIENT"))
        for field, unsafe, error in mutations:
            value = private_manifest()
            child = value["domains"]["IDENTITY"][0]
            child[field] = unsafe
            self.assertIn(error + ":" + child["capability_id"],
                          rc.validate_capability_manifest(value))

    def test_paperrail_cannot_claim_economic_value_or_finality(self):
        schema = json.loads((ROOT / "schemas/runtime-capability.v1.json").read_text())
        value = rc.capability_manifest()
        rail = value["domains"]["SETTLEMENT_RAIL"][0]
        self.assertEqual(rail["rail_type"], "PAPER_RAIL")
        self.assertTrue(rail["protocol_valid"])
        self.assertFalse(rail["economic_value_verified"])
        self.assertFalse(rail["finality_verified"])
        rail["economic_value_verified"] = True
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(value)))
        self.assertIn("PAPER_RAIL_ECONOMIC_VALUE_INVALID",
                      rc.validate_capability_manifest(value))

    def test_faucet_and_settlement_require_first_class_replay_safety(self):
        for action in (rc.ReadinessAction.FAUCET_CLAIM, rc.ReadinessAction.SETTLEMENT):
            value = rc.capability_manifest(action=action)
            replay = value["domains"]["REPLAY_SAFETY"][0]
            self.assertTrue(replay["required_for_action"])
            self.assertFalse(replay["replay_ledger_implemented"])
            self.assertFalse(replay["side_effect_journal_implemented"])
            self.assertIn("REPLAY_LEDGER_REQUIRED", replay["blocking_reasons"])
            self.assertIn("SIDE_EFFECT_JOURNAL_REQUIRED", replay["blocking_reasons"])
            self.assertFalse(value["ready_to_act"])

    def test_contract_rejects_ready_without_replay_or_required_dependency(self):
        for action in (rc.ReadinessAction.FAUCET_CLAIM, rc.ReadinessAction.SETTLEMENT):
            value = private_manifest(action)
            replay = value["domains"]["REPLAY_SAFETY"][0]
            replay["replay_ledger_implemented"] = False
            self.assertIn("REPLAY_LEDGER_NOT_READY", rc.validate_capability_manifest(value))
            value = private_manifest(action)
            value["domains"]["REPLAY_SAFETY"] = []
            self.assertTrue(any("REPLAY_SAFETY" in error
                                for error in rc.validate_capability_manifest(value)))

    def test_settlement_has_exact_documented_dependency_graph(self):
        value = rc.capability_manifest(action=rc.ReadinessAction.SETTLEMENT)
        graph = value["action_dependencies"]["SETTLEMENT"]
        self.assertEqual({name for name, label in graph.items() if label == "REQUIRED"},
                         {"IDENTITY", "SETTLEMENT_RAIL", "EVIDENCE_DURABILITY", "REPLAY_SAFETY"})
        self.assertEqual(graph["TESTNET_NETWORK"], "NOT_APPLICABLE")

    def test_runtime_values_are_explicit_and_conflict_cannot_be_ready(self):
        value = rc.capability_manifest()
        self.assertEqual({item["value_id"] for item in value["runtime_values"]},
            {"stillborn_seconds", "idle_seconds", "room_capacity", "note_capacity", "rate_limit", "quota"})
        record = value["runtime_values"][0]
        record.update({"documented_value": 1, "runtime_observed_value": 2,
                       "status": "RUNTIME_OBSERVED_VALUE", "ready": True,
                       "observed_at": "2026-09-06T05:00:00+00:00",
                       "observation_hash": "a" * 64, "freshness": "FRESH"})
        self.assertIn("RUNTIME_VALUE_CONFLICT_UNMARKED:" + record["value_id"],
                      rc.validate_capability_manifest(value))


if __name__ == "__main__":
    unittest.main()
