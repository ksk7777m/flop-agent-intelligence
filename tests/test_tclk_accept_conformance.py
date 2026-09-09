import copy
import inspect
import json
import math
import unittest
from pathlib import Path
from unittest import mock

import jsonschema

from flop_agent import tclk_accept_conformance as tclk


class TclkAcceptConformanceTests(unittest.TestCase):
    def setUp(self):
        self.schema = json.loads(Path("schemas/tclk-accept-conformance.v1.json").read_text())
        self.package = json.loads(Path("data/tclk_accept_conformance.json").read_text())
        self.validator = jsonschema.Draft202012Validator(self.schema)

    def reidentify(self, value):
        body = {name: value[name] for name in tclk.PROJECTION_FIELDS if name != "observation_id"}
        value["observation_id"] = tclk._digest({"domain": tclk.DOMAIN,
            "schema": tclk.SCHEMA_VERSION, "canonical_encoding": tclk.CANONICAL_ENCODING,
            **body})
        return value

    @staticmethod
    def stages(value):
        return {stage["stage_id"]: stage["state"] for stage in value["validation_stages"]}

    def test_schema_package_and_observation_validate(self):
        jsonschema.Draft202012Validator.check_schema(self.schema)
        self.validator.validate(self.package); tclk.validate_package_status(self.package)
        for frame in (None, {"type": "offer"}, {"type": "accept"},
                      {"type": "accept", "contract": "fixture-contract"}):
            value = dict(tclk.classify_frame(frame))
            self.validator.validate(value); tclk.validate_projection(value)

    def test_local_profile_is_separate_from_official_conformance(self):
        value = tclk.classify_frame({"type": "accept", "contract": "c"})
        self.assertEqual(value["primary_classification"], "LOCAL_ACCEPT_SAFETY_PROFILE_PASS")
        self.assertEqual(value["local_safety_profile"]["status"], "PASS")
        self.assertFalse(value["local_safety_profile"]["official_schema_authority"])
        self.assertEqual(value["official_schema_conformance"], "OFFICIAL_SCHEMA_CONFORMANCE_UNKNOWN")
        self.assertEqual(self.stages(value)["ACCEPT_SCHEMA_VALID"], "EVIDENCE_REQUIRED")
        self.assertEqual(value["reputation_dimensions"]["protocol_conformance"], "UNKNOWN")

    def test_missing_and_contract_shape_are_reported_policy_failures(self):
        missing = tclk.classify_frame({"type": "accept"})
        self.assertEqual(missing["primary_classification"], "REPORTED_POLICY_MISSING_CONTRACT")
        self.assertFalse(missing["structural_facts"]["contract_field_present"])
        self.assertEqual(self.stages(missing)["CONTRACT_PRESENT"], "REJECTED")
        for contract in (None, "", 0, False, [], {}, "bad contract"):
            with self.subTest(contract_type=type(contract).__name__):
                value = tclk.classify_frame({"type": "accept", "contract": contract})
                self.assertEqual(value["primary_classification"], "REPORTED_POLICY_CONTRACT_TYPE_REJECTED")
                self.assertEqual(value["official_schema_conformance"], "OFFICIAL_SCHEMA_CONFORMANCE_UNKNOWN")

    def test_structural_facts_and_classification_priority(self):
        malformed = tclk.classify_frame("accept")
        self.assertEqual(malformed["primary_classification"], "MALFORMED_FRAME")
        self.assertFalse(malformed["structural_facts"]["frame_parsed"])
        other = tclk.classify_frame({"type": "offer", "contract": "ignored"})
        self.assertEqual(other["primary_classification"], "NOT_ACCEPT_FRAME")
        self.assertFalse(other["structural_facts"]["contract_field_present"])
        extra = tclk.classify_frame({"type": "accept", "contract": "c", "signature": "raw"})
        self.assertEqual(extra["primary_classification"], "LOCAL_PROFILE_UNKNOWN_FIELDS_REJECTED")
        self.assertTrue(extra["structural_facts"]["unknown_fields_observed"])

    def test_multiple_failures_are_preserved_in_fixed_order(self):
        value = tclk.classify_frame({"type": "accept", "extra": True})
        self.assertEqual(value["primary_classification"], "LOCAL_PROFILE_UNKNOWN_FIELDS_REJECTED")
        self.assertEqual(value["independent_failures"],
            ["LOCAL_PROFILE_UNKNOWN_FIELDS", "REPORTED_POLICY_MISSING_CONTRACT"])

    def test_stage_grammar_order_ids_duplicates_missing_unknown_and_bool(self):
        original = dict(tclk.classify_frame({"type": "accept", "contract": "c"}))
        mutations = []
        value = copy.deepcopy(original); value["validation_stages"][0], value["validation_stages"][1] = value["validation_stages"][1], value["validation_stages"][0]; mutations.append(value)
        value = copy.deepcopy(original); value["validation_stages"][0]["ordinal"] = 2; mutations.append(value)
        value = copy.deepcopy(original); value["validation_stages"][1]["stage_id"] = value["validation_stages"][0]["stage_id"]; mutations.append(value)
        value = copy.deepcopy(original); value["validation_stages"].pop(); mutations.append(value)
        value = copy.deepcopy(original); value["validation_stages"][0]["stage_id"] = "UNKNOWN_STAGE"; mutations.append(value)
        value = copy.deepcopy(original); value["validation_stages"][0]["ordinal"] = True; mutations.append(value)
        for value in mutations:
            self.reidentify(value)
            with self.assertRaisesRegex(tclk.ConformanceError, "STAGE_GRAMMAR_INVALID"):
                tclk.validate_projection(value)

    def test_unattested_and_sealed_stages_cannot_be_verified(self):
        original = dict(tclk.classify_frame({"type": "accept", "contract": "c"}))
        for stage_id in ("ACCEPT_SCHEMA_VALID", "SIGNATURE_VALID", "REPLAY_VALID",
                         "CONTRACT_DERIVATION_VERIFIED", "OFFER_GLOBAL_WINNER_VERIFIED",
                         "SETTLEMENT_VERIFIED"):
            value = copy.deepcopy(original)
            next(x for x in value["validation_stages"] if x["stage_id"] == stage_id)["state"] = "VERIFIED"
            self.reidentify(value)
            with self.assertRaises(tclk.ConformanceError): tclk.validate_projection(value)
            with self.assertRaises(jsonschema.ValidationError): self.validator.validate(value)

    def test_later_stage_cannot_be_verified_after_profile_failure(self):
        value = copy.deepcopy(dict(tclk.classify_frame({"type": "accept"})))
        next(x for x in value["validation_stages"] if x["stage_id"] == "SIGNATURE_VALID")["state"] = "EVIDENCE_REQUIRED"
        self.reidentify(value)
        with self.assertRaisesRegex(tclk.ConformanceError, "STAGE_CLASSIFICATION_CONTRADICTION"):
            tclk.validate_projection(value)

    def test_structural_fact_contradictions_and_caller_classification_fail(self):
        original = dict(tclk.classify_frame({"type": "accept", "contract": "c"}))
        value = copy.deepcopy(original); value["structural_facts"]["contract_field_present"] = False; self.reidentify(value)
        with self.assertRaises(tclk.ConformanceError): tclk.validate_projection(value)
        value = copy.deepcopy(original); value["primary_classification"] = "OFFICIAL_SCHEMA_CONFORMANT"; self.reidentify(value)
        with self.assertRaisesRegex(tclk.ConformanceError, "CLASSIFICATION_INVALID"):
            tclk.validate_projection(value)
        value = copy.deepcopy(original); value["structural_facts"]["contract_value_kind"] = "NULL"; value["structural_facts"]["contract_value_profile_shape"] = "NOT_EVALUATED"; self.reidentify(value)
        with self.assertRaisesRegex(tclk.ConformanceError, "STRUCTURAL_FACTS_CONTRADICTION"):
            tclk.validate_projection(value)

    def test_derivation_is_never_inferred_from_shape_or_report(self):
        value = tclk.classify_frame({"type": "accept", "contract": "a" * 64})
        self.assertEqual(self.stages(value)["CONTRACT_DERIVATION_VERIFIED"], "EVIDENCE_REQUIRED")
        self.assertEqual(self.package["policy_identity"]["contract_derivation_spec"], "SOURCE_EVIDENCE_REQUIRED")
        self.assertEqual(self.package["field_report"]["derivation_match_exact_ratio"], "55/56")

    def test_field_report_counts_exact_ratios_and_authority(self):
        report = self.package["field_report"]
        self.assertEqual((report["observation_runs"], report["accept_typed_frames"], report["missing_contract"]), (6, 1022, 922))
        self.assertEqual(report["missing_contract_exact_ratio"], "461/511")
        self.assertEqual(report["affected_exact_ratio"], "74/79")
        self.assertEqual(report["derivation_match_exact_ratio"], "55/56")
        self.assertFalse(report["evergreen"]); self.assertFalse(report["protocol_spec"]); self.assertFalse(report["current_runtime_proof"])
        for bad in (True, -1, 1.0, math.nan, math.inf, tclk.MAX_COUNT + 1):
            with self.assertRaises(tclk.ConformanceError): tclk.validate_count(bad, "count")
        for args in ((0, 0), (2, 1)):
            with self.assertRaises(tclk.ConformanceError): tclk.exact_ratio(*args)

    def test_field_report_mutation_and_ratio_mismatch_rejected(self):
        value = copy.deepcopy(self.package); value["field_report"]["missing_contract"] = 1023
        with self.assertRaisesRegex(tclk.ConformanceError, "COUNT_RELATION_INVALID"): tclk.validate_package_status(value)
        value = copy.deepcopy(self.package); value["field_report"]["derivation_match_exact_ratio"] = "1/1"
        with self.assertRaisesRegex(tclk.ConformanceError, "RATIO_MISMATCH"): tclk.validate_package_status(value)

    def test_historical_reclassification_and_reputation_are_fail_closed(self):
        historical = self.package["historical_reclassification"]
        self.assertEqual(historical["status"], "HISTORICAL_CLASSIFICATION_UNRESOLVED")
        self.assertNotIn("663", json.dumps(self.package)); self.assertNotIn("649", json.dumps(self.package))
        value = copy.deepcopy(self.package); value["historical_reclassification"]["automatic_migration"] = True
        with self.assertRaisesRegex(tclk.ConformanceError, "HISTORICAL_RECLASSIFICATION_BLOCKED"): tclk.validate_package_status(value)
        self.assertEqual(self.package["reputation_boundary"], "MALICIOUS_BEHAVIOR_NOT_ESTABLISHED")

    def test_identity_mutations_fail(self):
        original = dict(tclk.classify_frame({"type": "accept", "contract": "c"}))
        mutations = []
        for path, replacement in [
            (("policy_identity", "extraction_state"), "CHANGED"),
            (("policy_identity", "local_safety_profile_revision"), "CHANGED"),
            (("classification_basis",), "CHANGED"),
            (("structural_facts", "contract_field_present"), False),
            (("primary_classification",), "NOT_ACCEPT_FRAME"),
            (("reputation_dimensions", "malicious_behavior_evidence"), "PRESENT"),
            (("ready_to_act",), True)]:
            value = copy.deepcopy(original); target = value
            for key in path[:-1]: target = target[key]
            target[path[-1]] = replacement; mutations.append(value)
        value = copy.deepcopy(original); value["validation_stages"].reverse(); mutations.append(value)
        for value in mutations:
            with self.assertRaises(tclk.ConformanceError): tclk.validate_projection(value)
        for path, replacement in [(("field_report", "missing_contract"), 921), (("historical_reclassification", "status"), "CHANGED"), (("action_state", "authorized_to_act"), True)]:
            value = copy.deepcopy(self.package); target = value
            for key in path[:-1]: target = target[key]
            target[path[-1]] = replacement
            with self.assertRaises(tclk.ConformanceError): tclk.validate_package_status(value)

    def test_duplicate_unknown_nested_and_bool_fail_closed(self):
        with self.assertRaisesRegex(tclk.ConformanceError, "DUPLICATE_JSON_KEY"):
            tclk.parse_projection('{"schema":"a","schema":"b"}')
        value = copy.deepcopy(dict(tclk.classify_frame(None))); value["extra"] = {}
        with self.assertRaisesRegex(tclk.ConformanceError, "FIELD_SET_INVALID"): tclk.validate_projection(value)
        value = copy.deepcopy(self.package); value["field_report"]["observation_runs"] = False
        with self.assertRaisesRegex(tclk.ConformanceError, "COUNT_INVALID"): tclk.validate_package_status(value)

    def test_public_projection_privacy_and_fixed_reconstruction(self):
        values = (self.package, dict(tclk.classify_frame({"type": "accept", "contract": "private-input"})))
        encoded = json.dumps(values).lower(); self.assertNotIn("private-input", encoded)
        for forbidden in ('"raw_frame"', '"statement"', '"signature"', '"did"', '"nonce"',
                          '"room"', '"seq"', '"url"', '"header"', '"error_body"',
                          '"metadata"', '"token"', '"filesystem_path"'):
            self.assertNotIn(forbidden, encoded)

    def test_validation_errors_do_not_echo_input_or_exception_cause(self):
        marker = "rejected-sensitive-marker"
        value = copy.deepcopy(dict(tclk.classify_frame(None))); value["policy_identity"] = marker
        with self.assertRaises(tclk.ConformanceError) as raised: tclk.validate_projection(value)
        self.assertNotIn(marker, repr(raised.exception)); self.assertIsNone(raised.exception.__cause__)

    def test_no_network_signer_writer_wallet_or_reputation_action_surface(self):
        source = inspect.getsource(tclk).lower()
        for forbidden in ("import urllib", "import requests", "import httpx", "import socket",
                          "invoke_mcp", "sign_transaction", "private_key", "wallet", "--confirm"):
            self.assertNotIn(forbidden, source)
        for name in ("fetch", "post", "sign", "execute", "schedule", "poll", "rank_agent"):
            self.assertFalse(hasattr(tclk, name))
        with mock.patch("socket.socket", side_effect=AssertionError("network")):
            self.assertFalse(tclk.classify_frame({"type": "accept"})["ready_to_act"])

    def test_schema_index_compatibility_and_action_state(self):
        index = json.loads(Path("schemas/index.json").read_text())
        self.assertEqual(sum(x["path"] == "schemas/tclk-accept-conformance.v1.json" for x in index["schemas"]), 1)
        manifest = json.loads(Path("data/technocore_compatibility.json").read_text())
        manifest_schema = json.loads(Path("schemas/technocore-compatibility.v1.json").read_text())
        jsonschema.Draft202012Validator(manifest_schema).validate(manifest)
        self.assertEqual(manifest["tclk_accept_conformance"]["action"], "NO_LIVE_ACTION")
        self.assertEqual(manifest["tclk_accept_conformance"]["official_conformance"], "OFFICIAL_SCHEMA_CONFORMANCE_UNKNOWN")
        self.assertEqual(manifest["tclk_accept_conformance"]["local_safety_profile"], "TCLK_ACCEPT_LOCAL_SAFETY_PROFILE_V1")
        self.assertEqual(self.package["action_state"], {"mode": "NO_LIVE_ACTION", "ready_to_act": False, "authorized_to_act": False, "live_action_enabled": False})


if __name__ == "__main__": unittest.main()
