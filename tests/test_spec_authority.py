import copy
import inspect
import json
import math
import unittest
from pathlib import Path
from unittest import mock

import jsonschema

from flop_agent import spec_authority as spec


class SpecificationAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.value = json.loads(Path("data/spec_authority.json").read_text())
        self.schema = json.loads(Path("schemas/spec-authority.v1.json").read_text())

    def assertRejected(self, value, code=None):
        with self.assertRaises(spec.SpecAuthorityError) as raised:
            spec.validate_public_projection(value)
        if code is not None:
            self.assertEqual(raised.exception.code, code)

    def test_public_artifact_schema_runtime_and_draft_202012(self):
        jsonschema.Draft202012Validator.check_schema(self.schema)
        jsonschema.Draft202012Validator(self.schema).validate(self.value)
        validated = spec.validate_public_projection(self.value)
        self.assertEqual(validated["artifact_id"], spec.artifact_identity(self.value))
        self.assertFalse(validated["source_set_complete"])

    def test_authority_is_separate_from_parameter_ratification(self):
        teaser, yellow = self.value["sources"]
        self.assertEqual(teaser["authority"], "OFFICIAL_CONTEXT")
        self.assertEqual(yellow["authority"], "UNVERIFIED_SOURCE")
        self.assertFalse(yellow["identity_verified"])
        self.assertTrue(all(x["parameter_status"] != "RATIFIED" for x in self.value["claims"]))

    def test_conflicting_claims_are_preserved_without_single_value(self):
        by_category = {}
        for claim in self.value["claims"]:
            by_category.setdefault(claim["category"], []).append(claim["value"])
        self.assertEqual(by_category["AGENT_ALLOCATION"], ["1200000000", "596030000"])
        self.assertEqual(by_category["GENESIS_AIRDROP"], ["3500000000", "2483460000"])
        self.assertNotIn("current_value", self.value)
        self.assertTrue(all(not x["current_parameter_resolved"] for x in self.value["conflicts"]))
        forged = copy.deepcopy(self.value); forged["conflicts"][0]["claim_ids"] = forged["conflicts"][0]["claim_ids"][:1]
        forged["artifact_id"] = spec.artifact_identity(forged)
        self.assertRejected(forged, "CLAIM_SET_INVALID")

    def test_unverified_source_and_human_acknowledgement_cannot_ratify(self):
        forged = copy.deepcopy(self.value); claim = forged["claims"][1]
        claim["parameter_status"] = "RATIFIED"
        claim["claim_id"] = spec._claim_identity(claim)
        forged["conflicts"][0]["claim_ids"][1] = claim["claim_id"]
        forged["artifact_id"] = spec.artifact_identity(forged)
        self.assertRejected(forged, "RATIFICATION_EVIDENCE_REQUIRED")
        acknowledged = copy.deepcopy(self.value)
        acknowledged["conflicts"][0]["state"] = "CONFLICT_ACKNOWLEDGED"
        acknowledged["conflicts"][0]["current_parameter_resolved"] = True
        acknowledged["artifact_id"] = spec.artifact_identity(acknowledged)
        self.assertRejected(acknowledged, "RESOLUTION_CONTRADICTION")

    def test_exact_decimals_reject_float_bool_negative_and_malformed(self):
        for invalid in (1.2, True, -1, "-1", "1e9", "01", "NaN", "Infinity"):
            forged = copy.deepcopy(self.value); forged["claims"][0]["value"] = invalid
            forged["artifact_id"] = spec.artifact_identity(forged)
            self.assertRejected(forged, "DECIMAL_INVALID")
        self.assertEqual(self.value["claims"][0]["value"], "1200000000")

    def test_duplicate_source_claim_and_conflict_ids_rejected(self):
        source = copy.deepcopy(self.value); source["sources"].append(copy.deepcopy(source["sources"][0])); source["artifact_id"] = spec.artifact_identity(source)
        self.assertRejected(source, "DUPLICATE_SOURCE_ID")
        claim = copy.deepcopy(self.value); claim["claims"].append(copy.deepcopy(claim["claims"][0])); claim["artifact_id"] = spec.artifact_identity(claim)
        self.assertRejected(claim, "DUPLICATE_CLAIM_ID")
        conflict = copy.deepcopy(self.value); conflict["conflicts"].append(copy.deepcopy(conflict["conflicts"][0])); conflict["artifact_id"] = spec.artifact_identity(conflict)
        self.assertRejected(conflict, "DUPLICATE_CONFLICT_ID")

    def test_unknown_fields_enums_and_source_authority_contradictions_rejected(self):
        for path in ("top", "source", "claim", "conflict", "scoring", "action"):
            forged = copy.deepcopy(self.value)
            target = {"top": forged, "source": forged["sources"][0], "claim": forged["claims"][0],
                "conflict": forged["conflicts"][0], "scoring": forged["scoring_uncertainty"],
                "action": forged["action_state"]}[path]
            target["metadata"] = {"raw": "not retained"}; forged["artifact_id"] = spec.artifact_identity(forged)
            self.assertRejected(forged, "FIELD_SET_INVALID")
        forged = copy.deepcopy(self.value); forged["sources"][0]["authority"] = "AUTHORITATIVE_REFERENCE"; forged["artifact_id"] = spec.artifact_identity(forged)
        self.assertRejected(forged, "SOURCE_AUTHORITY_CONTRADICTION")
        forged = copy.deepcopy(self.value); forged["claims"][0]["parameter_status"] = "CURRENT"; forged["artifact_id"] = spec.artifact_identity(forged)
        self.assertRejected(forged, "CLAIM_STATUS_INVALID")

    def test_claim_and_artifact_identity_detect_mutation(self):
        claim = copy.deepcopy(self.value); claim["claims"][0]["value"] = "1200000001"; claim["artifact_id"] = spec.artifact_identity(claim)
        self.assertRejected(claim, "CLAIM_IDENTITY_MISMATCH")
        artifact = copy.deepcopy(self.value); artifact["scoring_uncertainty"]["scoring_cap"] = "FINAL"
        self.assertRejected(artifact, "SCORING_MUST_BE_UNRESOLVED")

    def test_all_scoring_items_are_unresolved_and_cannot_authorize(self):
        self.assertEqual(set(self.value["scoring_uncertainty"]), set(spec.SCORING_FIELDS))
        self.assertEqual(set(self.value["scoring_uncertainty"].values()), {"UNRESOLVED"})
        self.assertEqual(self.value["action_state"], {"mode": "NO_LIVE_ACTION",
            "ready_to_act": False, "authorized_to_act": False, "live_action_enabled": False})
        for name in ("spend_to_unlock", "airdrop_scoring", "final_agent_allocation"):
            forged = copy.deepcopy(self.value); forged["scoring_uncertainty"][name] = "RATIFIED"; forged["artifact_id"] = spec.artifact_identity(forged)
            self.assertRejected(forged, "SCORING_MUST_BE_UNRESOLVED")

    def test_duplicate_json_keys_nan_and_infinite_are_rejected(self):
        with self.assertRaisesRegex(spec.SpecAuthorityError, "DUPLICATE_JSON_KEY"):
            spec.parse_public_json('{"schema":"x","schema":"y"}')
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.assertRaisesRegex(spec.SpecAuthorityError, "NUMBER_INVALID"):
                spec.parse_public_json('{"value":' + constant + '}')

    def test_validation_error_omits_rejected_content_and_cause(self):
        marker = "sensitive-rejected-marker"
        forged = copy.deepcopy(self.value); forged["claims"][0]["value"] = marker
        with self.assertRaises(spec.SpecAuthorityError) as raised:
            spec.validate_public_projection(forged)
        self.assertNotIn(marker, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)

    def test_public_projection_has_no_raw_or_arbitrary_content(self):
        encoded = json.dumps(self.value).lower()
        for forbidden in ('"raw_body"', '"raw_document"', '"headers"', '"error_body"',
                          '"cookie"', '"authorization"', '"token"', '"secret"',
                          '"metadata"', '"filesystem_path"', '/users/', '/private/'):
            self.assertNotIn(forbidden, encoded)

    def test_import_validation_and_build_make_zero_network_calls(self):
        with mock.patch("socket.socket", side_effect=AssertionError("network")):
            spec.validate_public_projection(self.value)
        source = inspect.getsource(spec).lower()
        for forbidden in ("import urllib", "import requests", "import httpx", "import socket",
                          "invoke_mcp", "sign_transaction", "private_key", "wallet", "--confirm"):
            self.assertNotIn(forbidden, source)
        for name in ("fetch", "execute", "activate", "sign", "claim", "schedule", "poll"):
            self.assertFalse(hasattr(spec, name))

    def test_schema_index_and_compatibility_manifest(self):
        index = json.loads(Path("schemas/index.json").read_text())
        self.assertEqual(sum(x["path"] == "schemas/spec-authority.v1.json" for x in index["schemas"]), 1)
        compatibility = json.loads(Path("data/technocore_compatibility.json").read_text())
        compatibility_schema = json.loads(Path("schemas/technocore-compatibility.v1.json").read_text())
        jsonschema.Draft202012Validator(compatibility_schema).validate(compatibility)
        self.assertEqual(compatibility["flop_specification_authority"]["action"], "NO_LIVE_ACTION")
        self.assertEqual(compatibility["status"], "COMPATIBILITY_REVIEW_REQUIRED")


if __name__ == "__main__":
    unittest.main()
