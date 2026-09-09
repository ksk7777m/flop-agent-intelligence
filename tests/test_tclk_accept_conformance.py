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

    def test_schema_package_and_observation_validate(self):
        jsonschema.Draft202012Validator.check_schema(self.schema)
        self.validator.validate(self.package)
        tclk.validate_package_status(self.package)
        for value in (tclk.classify_frame(None), tclk.classify_frame({"type": "accept"}),
                      tclk.classify_frame({"type": "accept", "contract": "fixture-contract"})):
            self.validator.validate(dict(value)); tclk.validate_projection(value)

    def test_missing_null_empty_wrong_type_contract_are_separate_failures(self):
        missing = tclk.classify_frame({"type": "accept"})
        self.assertEqual(missing["primary_classification"], "INVALID_ACCEPT_MISSING_CONTRACT")
        self.assertEqual(missing["stages"]["contract_present"], "NOT_OBSERVED")
        for contract in (None, "", 0, False, [], {}, "bad contract"):
            with self.subTest(contract_type=type(contract).__name__):
                value = tclk.classify_frame({"type": "accept", "contract": contract})
                self.assertEqual(value["primary_classification"], "INVALID_ACCEPT_CONTRACT_TYPE")
                self.assertFalse(value["accepted_contract_count_eligible"])

    def test_malformed_unknown_field_and_non_accept_frame(self):
        self.assertEqual(tclk.classify_frame("accept")["primary_classification"], "MALFORMED")
        extra = tclk.classify_frame({"type": "accept", "contract": "c", "signature": "raw"})
        self.assertEqual(extra["primary_classification"], "INVALID_ACCEPT_SCHEMA")
        other = tclk.classify_frame({"type": "offer"})
        self.assertEqual(other["primary_classification"], "POLICY_REJECTED")
        self.assertEqual(other["stages"]["frame_type_accept"], "NOT_OBSERVED")

    def test_schema_signature_replay_and_contract_derivation_are_independent(self):
        value = tclk.classify_frame({"type": "accept", "contract": "c"})
        self.assertEqual(value["stages"]["accept_schema_valid"], "NOT_VERIFIED")
        self.assertEqual(value["stages"]["signature_valid"], "NOT_VERIFIED")
        self.assertEqual(value["stages"]["replay_valid"], "NOT_VERIFIED")
        self.assertEqual(value["stages"]["contract_present"], "OBSERVED")
        self.assertEqual(value["stages"]["contract_derivation_verified"], "NOT_VERIFIED")
        forged = copy.deepcopy(dict(value)); forged["stages"] = dict(forged["stages"])
        forged["stages"]["signature_valid"] = "VERIFIED"; self.reidentify(forged)
        with self.assertRaisesRegex(tclk.ConformanceError, "SEALED_EVIDENCE_REQUIRED"):
            tclk.validate_projection(forged)
        with self.assertRaises(jsonschema.ValidationError): self.validator.validate(forged)

    def test_candidate_shape_never_becomes_schema_valid_or_winner(self):
        value = tclk.classify_frame({"type": "accept", "contract": "c"})
        self.assertEqual(value["primary_classification"], "WINNER_UNRESOLVED")
        self.assertEqual(value["stages"]["offer_global_view_complete"], "INCOMPLETE")
        self.assertEqual(value["stages"]["offer_global_winner_verified"], "NOT_VERIFIED")
        forged = copy.deepcopy(dict(value)); forged["stages"] = dict(forged["stages"])
        forged["primary_classification"] = "ACCEPT_RACE_LOST"; self.reidentify(forged)
        with self.assertRaisesRegex(tclk.ConformanceError, "GLOBAL_VIEW_REQUIRED"):
            tclk.validate_projection(forged)

    def test_lock_absence_never_proves_payer_abandonment(self):
        for frame in ({"type": "accept"}, {"type": "accept", "contract": "c"}):
            value = tclk.classify_frame(frame)
            self.assertEqual(value["stages"]["lock_observed"], "UNKNOWN")
            self.assertEqual(value["payer_abandonment"], "PAYER_ABANDONMENT_UNPROVEN")
            self.assertNotIn("PAYER_ABANDONED", json.dumps(dict(value)))

    def test_missing_contract_is_not_malicious_replay_spam_or_race(self):
        value = tclk.classify_frame({"type": "accept"})
        self.assertEqual(value["reputation_dimensions"]["malicious_behavior_evidence"], "ABSENT")
        encoded = json.dumps(dict(value))
        for forbidden in ("MALICIOUS\"", "SPAMMER", "REPLAY_ATTACKER", "BAD_AGENT",
                          "NEGATIVE_REPUTATION", "ACCEPT_RACE_LOST"):
            self.assertNotIn(forbidden, encoded)

    def test_field_report_counts_and_exact_ratios(self):
        report = self.package["field_report"]
        self.assertEqual(report["missing_contract_exact_ratio"], "461/511")
        self.assertEqual(report["affected_exact_ratio"], "74/79")
        self.assertFalse(report["evergreen"]); self.assertFalse(report["protocol_spec"])
        for pair in ((922, 1022, "461/511"), (666, 711, "74/79")):
            self.assertEqual(tclk.exact_ratio(pair[0], pair[1]), pair[2])
        for bad in (True, -1, 1.0, math.nan, math.inf, tclk.MAX_COUNT + 1):
            with self.assertRaises(tclk.ConformanceError): tclk.validate_count(bad, "count")
        with self.assertRaises(tclk.ConformanceError): tclk.exact_ratio(0, 0)

    def test_field_report_count_mutation_and_ratio_mismatch_rejected(self):
        value = copy.deepcopy(self.package); value["field_report"]["missing_contract"] = 1023
        with self.assertRaisesRegex(tclk.ConformanceError, "COUNT_RELATION_INVALID"):
            tclk.validate_package_status(value)
        value = copy.deepcopy(self.package); value["field_report"]["missing_contract_exact_ratio"] = "922/1022"
        with self.assertRaisesRegex(tclk.ConformanceError, "RATIO_MISMATCH"):
            tclk.validate_package_status(value)

    def test_historical_reclassification_and_silent_migration_are_blocked(self):
        historical = self.package["historical_reclassification"]
        self.assertEqual(historical["status"], "HISTORICAL_CLASSIFICATION_UNRESOLVED")
        self.assertEqual(historical["evidence_requirement"], "RECLASSIFICATION_EVIDENCE_REQUIRED")
        self.assertTrue(all(value is False for key, value in historical.items()
            if key not in {"status", "evidence_requirement", "payer_abandonment"}))
        forged = copy.deepcopy(self.package); forged["historical_reclassification"]["automatic_migration"] = True
        with self.assertRaisesRegex(tclk.ConformanceError, "HISTORICAL_RECLASSIFICATION_BLOCKED"):
            tclk.validate_package_status(forged)
        legacy = copy.deepcopy(self.package); legacy["historical_reclassification"]["accepted_contracts"] = 663
        with self.assertRaisesRegex(tclk.ConformanceError, "HISTORICAL_FIELDS_INVALID"):
            tclk.validate_package_status(legacy)

    def test_schema_revision_source_and_issue_identity_remain_unverified(self):
        policy = self.package["policy_identity"]
        self.assertEqual(policy["source_revision"], "REVISION_UNVERIFIED")
        self.assertEqual(policy["document_hash"], "HASH_UNVERIFIED")
        self.assertEqual(policy["extraction_state"], "OFFICIAL_SCHEMA_REVISION_REQUIRED")
        self.assertEqual(self.package["issue_reference"]["canonical_object_type"],
                         "ISSUE_OR_PULL_REFERENCE_UNRESOLVED")
        forged = copy.deepcopy(self.package); forged["policy_identity"]["source_revision"] = "caller-revision"
        with self.assertRaisesRegex(tclk.ConformanceError, "POLICY_IDENTITY_INVALID"):
            tclk.validate_package_status(forged)

    def test_duplicate_json_unknown_enum_field_and_bool_fail_closed(self):
        with self.assertRaisesRegex(tclk.ConformanceError, "DUPLICATE_JSON_KEY"):
            tclk.parse_projection('{"schema":"a","schema":"b"}')
        value = copy.deepcopy(dict(tclk.classify_frame(None))); value["extra"] = {}
        with self.assertRaisesRegex(tclk.ConformanceError, "FIELD_SET_INVALID"):
            tclk.validate_projection(value)
        value = copy.deepcopy(self.package); value["field_report"]["observation_runs"] = False
        with self.assertRaisesRegex(tclk.ConformanceError, "COUNT_INVALID"):
            tclk.validate_package_status(value)

    def test_public_projection_privacy_and_fixed_reconstruction(self):
        values = (self.package, dict(tclk.classify_frame({"type": "accept", "contract": "private-input"})))
        encoded = json.dumps(values).lower()
        self.assertNotIn("private-input", encoded)
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
            self.assertEqual(tclk.classify_frame({"type": "accept"})["ready_to_act"], False)

    def test_schema_index_compatibility_and_action_state(self):
        index = json.loads(Path("schemas/index.json").read_text())
        self.assertEqual(sum(x["path"] == "schemas/tclk-accept-conformance.v1.json"
                             for x in index["schemas"]), 1)
        manifest = json.loads(Path("data/technocore_compatibility.json").read_text())
        manifest_schema = json.loads(Path("schemas/technocore-compatibility.v1.json").read_text())
        jsonschema.Draft202012Validator(manifest_schema).validate(manifest)
        self.assertEqual(manifest["tclk_accept_conformance"]["action"], "NO_LIVE_ACTION")
        self.assertEqual(self.package["action_state"], {"mode": "NO_LIVE_ACTION",
            "ready_to_act": False, "authorized_to_act": False, "live_action_enabled": False})


if __name__ == "__main__": unittest.main()
