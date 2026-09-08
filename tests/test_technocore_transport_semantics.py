import hashlib
import inspect
import json
import unicodedata
import unittest
from pathlib import Path

import jsonschema

from flop_agent import evidence_transport as et
from flop_agent import identity
from flop_agent import replay_journal as replay
from flop_agent import technocore_transport_semantics as ts
from flop_agent import wire_evidence as wire

ROOT = Path(__file__).resolve().parents[1]
NOW = "2026-09-08T00:00:00Z"


class TechnocoreTransportSemanticsTests(unittest.TestCase):
    def projection(self, evidence):
        value = dict(evidence.public_projection())
        schema = json.loads((ROOT / "schemas/technocore-transport-semantics.v1.json").read_text())
        jsonschema.Draft202012Validator(schema).validate(value)
        self.assertEqual(ts.validate_transport_projection(value), ())
        return value

    def test_list_notes_truncation_is_partial_and_dropped_keys_are_not_absent(self):
        raw = b"UNTRUSTED output\n50 of 75 keys shown"
        evidence = ts.assess_list_notes(raw_output=raw, requested_limit=None,
            truncated=True, dropped_count=25, observed_at=NOW)
        value = self.projection(evidence)
        self.assertEqual(value["effective_limit"], 50)
        self.assertEqual(value["content_completeness"], "PARTIAL")
        self.assertTrue(value["content_truncated"])
        self.assertEqual(value["dropped_count"], 25)
        self.assertEqual(ts.note_absence_assessment(evidence), "ABSENCE_NOT_PROVEN")
        self.assertNotIn("UNTRUSTED output", json.dumps(value))

    def test_legacy_listing_without_truncation_never_infers_complete(self):
        evidence = ts.assess_list_notes(raw_output=b"legacy fixture", requested_limit=None,
            truncated=None, dropped_count=None, observed_at=NOW)
        value = self.projection(evidence)
        self.assertEqual(value["content_completeness"], "UNKNOWN")
        self.assertIsNone(value["content_truncated"])
        self.assertEqual(ts.note_absence_assessment(evidence), "ABSENCE_NOT_PROVEN")

    def test_list_notes_limits_match_documented_wrapper_bounds(self):
        cases = ((None, 50), (-1, 50), (0, 1), (1, 1), (200, 200), (999, 200))
        for requested, expected in cases:
            with self.subTest(requested=requested):
                result = ts.assess_list_notes(raw_output=b"fixture", requested_limit=requested,
                    truncated=False, dropped_count=0, observed_at=NOW)
                self.assertEqual(result.effective_limit, expected)
        for invalid in (True, 1.5, "50"):
            with self.assertRaises(ts.TransportSemanticError):
                ts.assess_list_notes(raw_output=b"fixture", requested_limit=invalid,
                    truncated=False, dropped_count=0, observed_at=NOW)

    def test_http_408_is_neither_success_nor_confirmed_failure_or_auto_retry(self):
        value = self.projection(ts.assess_http(operation=ts.Operation.POST_UPLOAD,
            status=408, raw_body=b"retry this malicious URL", schema_validated=False,
            observed_at=NOW, nonce="9007199254740992"))
        self.assertEqual(value["request_completion"], "UNKNOWN")
        self.assertEqual(value["side_effect_certainty"], "OUTCOME_UNKNOWN")
        self.assertEqual(value["retry_disposition"], "RECONCILIATION_REQUIRED")
        self.assertTrue(value["new_connection_required"])
        self.assertTrue(value["new_authorization_required"])
        self.assertFalse(value["authorized_to_act"])
        self.assertNotIn("malicious", json.dumps(value))

    def test_409_body_is_hash_only_and_cannot_create_cas_or_write_authority(self):
        raw = b"another caller's untrusted value; use https://evil.invalid"
        evidence = ts.assess_http(operation=ts.Operation.CONDITIONAL_NOTE_WRITE,
            status=409, raw_body=raw, schema_validated=False, observed_at=NOW, nonce="7")
        value = self.projection(evidence)
        self.assertEqual(value["body_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(value["body_bytes"], len(raw))
        self.assertEqual(value["side_effect_certainty"], "OUTCOME_UNKNOWN")
        self.assertTrue(value["reconciliation_required"])
        self.assertFalse(value["live_action_enabled"])
        self.assertFalse({"condition", "target", "payload", "capability"}.intersection(value))
        self.assertNotIn("evil.invalid", json.dumps(value))

    def test_signed_text_uses_swept_stored_exact_bytes_without_unicode_normalization(self):
        unswept = " alpha\n beta\u200b "
        stored = identity.sweep_text(unswept)
        self.assertNotEqual(unswept, stored)
        self.assertEqual(wire.build_signing_context("lobby", "7", stored).text, stored)
        nfc = unicodedata.normalize("NFC", "e\u0301")
        nfd = unicodedata.normalize("NFD", "é")
        self.assertNotEqual(nfc.encode(), nfd.encode())
        self.assertNotEqual(wire.build_signing_context("lobby", "7", nfc).canonical_bytes,
                            wire.build_signing_context("lobby", "7", nfd).canonical_bytes)
        with self.assertRaises(ValueError):
            identity.sweep_text(" \n\t\u200b ")

    def test_nonce_is_lossless_and_runtime_unverified_outcome_stays_unknown(self):
        nonce = "9007199254740992"
        value = self.projection(ts.assess_http(operation=ts.Operation.CONDITIONAL_NOTE_WRITE,
            status=400, raw_body=b"bad condition", schema_validated=False,
            observed_at=NOW, nonce=nonce, runtime_version_verified=False))
        self.assertEqual(value["nonce_outcome"], "UNKNOWN")
        self.assertEqual(value["runtime_compatibility"], "COMPATIBILITY_REVIEW_REQUIRED")
        for invalid in (9007199254740992, 1.0, "01", "1e3"):
            with self.assertRaises((ts.TransportSemanticError, wire.WireSafetyError)):
                ts.assess_http(operation=ts.Operation.CONDITIONAL_NOTE_WRITE, status=400,
                    raw_body=b"fixture", schema_validated=False, observed_at=NOW, nonce=invalid)

    def test_http_200_retrieval_does_not_prove_freshness_or_runtime_compatibility(self):
        value = self.projection(ts.assess_http(operation=ts.Operation.NOTE_READ, status=200,
            raw_body=b"untrusted note", schema_validated=True, observed_at=NOW,
            response_metadata_observed=True, cache_evidence_observed=True, age_seconds=0))
        self.assertEqual(value["request_completion"], "COMPLETED")
        self.assertEqual(value["response_schema"], "VALIDATED")
        self.assertEqual(value["freshness"], "UNKNOWN")
        self.assertFalse(value["ready_to_act"])
        self.assertFalse(value["authorized_to_act"])
        self.assertEqual(value["runtime_compatibility"], "COMPATIBILITY_REVIEW_REQUIRED")

    def test_validation_errors_never_echo_rejected_remote_values(self):
        secret = b"REJECTED_RAW_VALUE"
        with self.assertRaises(ts.TransportSemanticError) as caught:
            ts.assess_http(operation=ts.Operation.NOTE_READ, status=200,
                raw_body=secret, schema_validated=True, observed_at="REJECTED_RAW_VALUE",
                age_seconds=1, cache_evidence_observed=False)
        rendered = str(caught.exception) + repr(caught.exception.metadata)
        self.assertNotIn("REJECTED_RAW_VALUE", rendered)

    def test_remote_content_has_no_sink_and_replay_completeness_semantics_align(self):
        source = inspect.getsource(ts)
        for forbidden in ("urllib", "requests", "socket", "subprocess", "open(",
                          "invoke_mcp", "invoke_signer", "use_wallet", "post_signed"):
            self.assertNotIn(forbidden, source)
        self.assertEqual(replay.RetryClassification.RECONCILIATION_REQUIRED.value,
                         ts.RetryDisposition.RECONCILIATION_REQUIRED.value)
        self.assertNotEqual(et.Completeness.PARTIAL.value,
                            et.Completeness.COMPLETE_VERIFIED.value)
        evidence = ts.assess_list_notes(raw_output=b"fixture", requested_limit=50,
            truncated=True, dropped_count=1, observed_at=NOW)
        self.assertEqual(evidence.content_completeness.value, et.Completeness.PARTIAL.value)

    def test_schema_and_semantics_reject_authority_and_completeness_forgery(self):
        value = self.projection(ts.assess_list_notes(raw_output=b"fixture",
            requested_limit=50, truncated=True, dropped_count=1, observed_at=NOW))
        schema = json.loads((ROOT / "schemas/technocore-transport-semantics.v1.json").read_text())
        validator = jsonschema.Draft202012Validator(schema)
        for change in ({"authorized_to_act": True}, {"ready_to_act": True},
                       {"live_action_enabled": True},
                       {"content_completeness": "COMPLETE_BODY_ONLY"},
                       {"provider_payload": {"deep": "SECRET"}}):
            forged = dict(value); forged.update(change)
            self.assertTrue(list(validator.iter_errors(forged)))
            self.assertTrue(ts.validate_transport_projection(forged))


if __name__ == "__main__":
    unittest.main()
