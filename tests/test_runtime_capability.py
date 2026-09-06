import copy
import json
import pickle
import unittest
from datetime import datetime, timedelta, timezone

from flop_agent import runtime_capability as rc
from jsonschema import Draft202012Validator
from pathlib import Path


NOW = datetime(2026, 9, 6, 6, 0, tzinfo=timezone.utc)
HASH = "a" * 64


def observation(capability_id="technocore.runtime", response="AVAILABLE", observed_at="2026-09-06T05:00:00Z"):
    probe = {item.capability_id: item for item in rc.probe_manifest()}[capability_id]
    return rc.verify_runtime_fixture({
        "schema": "flop-runtime-observation-fixture-v1",
        "capability_id": capability_id,
        "domain": probe.domain.value,
        "source_id": probe.source_id.value,
        "endpoint_id": probe.endpoint_id,
        "method": probe.method,
        "response_class": response,
        "observed_at": observed_at,
        "source_hash": HASH,
    })


class RuntimeCapabilityTests(unittest.TestCase):
    def test_documented_is_not_observed(self):
        result = rc.assess_capabilities(now=NOW)
        item = result["domains"]["TECHNOCORE"][0]
        self.assertEqual(item["documented_status"], "DOCUMENTED_ONLY")
        self.assertEqual(item["runtime_status"], "RUNTIME_NOT_OBSERVED")

    def test_observed_is_not_authorized(self):
        item = rc.assess_capabilities((observation(),), now=NOW)["domains"]["TECHNOCORE"][0]
        self.assertEqual(item["runtime_status"], "RUNTIME_OBSERVED")
        self.assertFalse(item["authorized_to_act"])

    def test_third_party_report_cannot_promote_readiness(self):
        context = rc.CapabilityEvidence("faucet.runtime", rc.Provenance.THIRD_PARTY_REPORT, "social", "AVAILABLE")
        result = rc.assess_capabilities(now=NOW)
        self.assertEqual(context.provenance, rc.Provenance.THIRD_PARTY_REPORT)
        self.assertEqual(result["domains"]["FAUCET"][0]["runtime_status"], "RUNTIME_NOT_OBSERVED")

    def test_stale_runtime_observation(self):
        token = observation(observed_at="2026-09-05T00:00:00Z")
        item = rc.assess_capabilities((token,), now=NOW)["domains"]["TECHNOCORE"][0]
        self.assertEqual(item["runtime_status"], "STALE_RUNTIME_OBSERVATION")

    def test_conflicting_documentation_and_runtime(self):
        item = rc.assess_capabilities((observation(response="UNAVAILABLE"),), now=NOW)["domains"]["TECHNOCORE"][0]
        self.assertEqual(item["runtime_status"], "CONFLICTING_CAPABILITY_EVIDENCE")

    def test_faucet_documented_but_unobserved_and_unapproved(self):
        item = rc.assess_capabilities(now=NOW)["domains"]["FAUCET"][0]
        self.assertEqual(item["documented_status"], "DOCUMENTED_ONLY")
        self.assertIn("MISSING_RUNTIME_OBSERVATION", item["blocking_reasons"])
        self.assertIn("HUMAN_APPROVAL_REQUIRED", item["blocking_reasons"])

    def test_faucet_state_machine_is_ordered_and_cannot_authorize(self):
        state = rc.FaucetState.NO_OFFICIAL_ENDPOINT
        for event in ("documented", "source_reviewed", "runtime_observed",
                      "requirements_verified", "request_approval"):
            state = rc.transition_faucet(state, event)
        self.assertEqual(state, rc.FaucetState.READY_FOR_HUMAN_APPROVAL)
        with self.assertRaises(ValueError):
            rc.transition_faucet(state, "authorize")

    def test_no_official_endpoint_fails_closed(self):
        definition = rc.CapabilityDefinition("x", rc.Domain.FAUCET, rc.CapabilityState.IMPLEMENTED_OFFLINE, rc.CapabilityState.DOCUMENTED_ONLY, None)
        self.assertIn("OFFICIAL_ENDPOINT_UNVERIFIED", rc._blockers(definition, rc.CapabilityState.RUNTIME_NOT_OBSERVED))

    def test_chain_id_documented_does_not_make_it_observed(self):
        item = rc.assess_capabilities(now=NOW)["domains"]["TESTNET_NETWORK"][0]
        self.assertEqual(item["runtime_status"], "RUNTIME_NOT_OBSERVED")
        self.assertIn("CHAIN_ID_UNOBSERVED", item["blocking_reasons"])

    def test_inference_unavailable_remains_blocked(self):
        token = observation("inference.runtime", "UNAVAILABLE")
        item = rc.assess_capabilities((token,), now=NOW)["domains"]["INFERENCE"][0]
        self.assertFalse(item["ready_to_act"])

    def test_paperrail_is_not_economic_value(self):
        rail = rc.domain_readiness()["SETTLEMENT_RAIL"]
        self.assertTrue(rail["paperrail_protocol_valid"])
        self.assertFalse(rail["economic_value_verified"])

    def test_one_critical_domain_blocks_overall(self):
        result = rc.assess_capabilities((observation(),), now=NOW)
        self.assertEqual(result["overall_state"], "OBSERVATION_REQUIRED")
        self.assertFalse(result["ready_to_act"])

    def test_human_approval_is_separate_authority(self):
        with self.assertRaises(PermissionError):
            rc.ActionAuthorization("approved")
        self.assertFalse(rc.assess_capabilities(now=NOW)["authorized_to_act"])

    def test_serialized_evidence_cannot_become_authority(self):
        token = observation()
        public = dict(rc.public_observation(token))
        serialized = json.loads(json.dumps(public))
        with self.assertRaises((PermissionError, TypeError)):
            rc.assess_capabilities((serialized,), now=NOW)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with self.assertRaises(TypeError):
                operation(token)

    def test_caller_created_observation_rejected(self):
        with self.assertRaises(PermissionError):
            rc.RuntimeCapabilityObservation()

    def test_cross_authority_observation_rejected(self):
        issue, _ = rc._new_runtime_authority()
        probe = {item.capability_id: item for item in rc.probe_manifest()}["technocore.runtime"]
        token = issue({"schema": "flop-runtime-observation-fixture-v1", "capability_id": probe.capability_id, "domain": probe.domain.value, "source_id": probe.source_id.value, "endpoint_id": probe.endpoint_id, "method": "GET", "response_class": "AVAILABLE", "observed_at": "2026-09-06T05:00:00Z", "source_hash": HASH})
        with self.assertRaises(PermissionError):
            rc.assess_capabilities((token,), now=NOW)

    def test_probe_specs_are_inert_and_bounded(self):
        for probe in rc.probe_manifest():
            self.assertEqual(probe.method, "GET")
            self.assertFalse(probe.redirects)
            self.assertEqual(probe.retry_count, 0)

    def test_public_manifest_matches_canonical_schema(self):
        root = Path(__file__).resolve().parents[1]
        schema = json.loads((root / "schemas/runtime-capability.v1.json").read_text())
        Draft202012Validator(schema).validate(rc.capability_manifest(now=NOW))

    def test_production_assessor_ignores_authority_global_rebinding(self):
        token = observation()
        original = rc._resolve_observation
        rc._resolve_observation = lambda _token: (_ for _ in ()).throw(AssertionError("rebound"))
        try:
            item = rc.assess_capabilities((token,), now=NOW)["domains"]["TECHNOCORE"][0]
        finally:
            rc._resolve_observation = original
        self.assertEqual(item["runtime_status"], "RUNTIME_OBSERVED")


if __name__ == "__main__":
    unittest.main()
