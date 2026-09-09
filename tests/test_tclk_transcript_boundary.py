import base64
import copy
import inspect
import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from jsonschema import Draft202012Validator

from flop_agent.identity import did_from_public_key
import flop_agent.tclk_transcript_boundary as boundary


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
DID = did_from_public_key(KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def signed_record(seq, ts, frame_type="heartbeat", transport_nonce=None, generation="gen-1"):
    nonce = transport_nonce or str(seq + 10)
    frame = {"type": frame_type, "from": DID, "contract": "0x" + "ab" * 32,
             "nonce": "00112233"}
    if frame_type == "refund": frame.pop("nonce")
    text = "tclk1 " + canonical(frame)
    payload = f"tclk-offers|{nonce}|{text}".encode()
    sig = base64.urlsafe_b64encode(KEY.sign(payload)).decode().rstrip("=")
    value = {"room": "tclk-offers", "seq": seq, "ts": ts, "from": DID,
             "nonce": nonce, "sig": sig, "text": text}
    if generation is not None: value["generation"] = generation
    return value


def transcript(records, final_newline=True):
    raw = "\n".join(canonical(record) for record in records).encode()
    return raw + (b"\n" if final_newline else b"")


def dimensions(result):
    return {item["dimension"]: item["state"] for item in result["dimensions"]}


class TclkTranscriptBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(Path("schemas/tclk-transcript-boundary.v1.json").read_text())
        Draft202012Validator.check_schema(cls.schema)
        cls.records = [signed_record(100, "2026-09-09T00:00:00Z"),
                       signed_record(101, "2026-09-09T00:00:01Z"),
                       signed_record(102, "2026-09-09T00:00:02Z")]

    def assert_closed(self, result):
        Draft202012Validator(self.schema).validate(result)
        encoded = json.dumps(result, sort_keys=True)
        for forbidden in (DID, "tclk-offers", "00112233", "abababab", self.records[0]["sig"], self.records[0]["ts"]):
            self.assertNotIn(forbidden, encoded)
        self.assertFalse(result["ready_to_act"]); self.assertFalse(result["authorized_to_act"])
        self.assertFalse(result["live_action_enabled"])

    def test_all_signatures_valid_but_completeness_replay_and_finality_unknown(self):
        result = boundary.assess_tclk_transcript(transcript(self.records))
        dims = dimensions(result)
        self.assertEqual(dims["SIGNATURE_VERIFICATION"], "VERIFIED")
        self.assertEqual(dims["SIGNED_PAYLOAD_BINDING"], "VERIFIED")
        self.assertEqual(dims["VENUE_METADATA_AUTHENTICITY"], "UNKNOWN")
        self.assertEqual(result["completeness"], "UNKNOWN")
        self.assertEqual(result["replay"], "REPLAY_EVIDENCE_REQUIRED")
        self.assertEqual(result["final_state"], "FINAL_STATE_DERIVATION_BLOCKED")
        self.assertEqual(result["winner"], "WINNER_UNRESOLVED")
        self.assertEqual(result["settlement"], "SETTLEMENT_UNVERIFIED")
        self.assert_closed(result)

    def test_seq_and_timestamp_mutation_preserve_signature_but_change_identity(self):
        original = boundary.assess_tclk_transcript(transcript(self.records))
        for field, value in (("seq", 201), ("ts", "2026-09-09T00:00:09Z")):
            records = copy.deepcopy(self.records); records[1][field] = value
            changed = boundary.assess_tclk_transcript(transcript(records))
            self.assertEqual(dimensions(changed)["SIGNATURE_VERIFICATION"], "VERIFIED")
            self.assertNotEqual(changed["artifact_id"], original["artifact_id"])
            self.assertNotEqual(changed["input_evidence"]["sha256"], original["input_evidence"]["sha256"])
            self.assertTrue(all(item["venue_metadata_binding"] == "UNKNOWN" for item in changed["frame_evidence"]))

    def test_middle_prefix_suffix_deletion_boundaries(self):
        middle = boundary.assess_tclk_transcript(transcript([self.records[0], self.records[2]]))
        self.assertEqual(middle["completeness"], "INCOMPLETE")
        self.assertEqual(middle["metadata_evidence"]["seq_state"], "INTERNAL_SEQ_GAP_DETECTED")
        for records in (self.records[1:], self.records[:-1]):
            result = boundary.assess_tclk_transcript(transcript(records))
            self.assertEqual(result["completeness"], "UNKNOWN")
            self.assertEqual(result["boundary_evidence"]["lower"], "LOWER_BOUNDARY_UNKNOWN")
            self.assertEqual(result["boundary_evidence"]["upper"], "UPPER_BOUNDARY_UNKNOWN")

    def test_truncated_duplicate_reordered_and_replay_indicators(self):
        truncated = boundary.assess_tclk_transcript(transcript(self.records, False))
        self.assertEqual(truncated["errors"], ["TRUNCATED_FINAL_RECORD"])
        self.assertEqual(truncated["completeness"], "INCOMPLETE")
        duplicate = boundary.assess_tclk_transcript(transcript([self.records[0], self.records[0]]))
        self.assertEqual(duplicate["metadata_evidence"]["duplicate_state"], "DUPLICATE_DETECTED")
        self.assertEqual(duplicate["replay_indicators"]["repeated_signed_payload_count"], 1)
        reordered = boundary.assess_tclk_transcript(transcript([self.records[1], self.records[0]]))
        self.assertEqual(reordered["metadata_evidence"]["seq_state"], "INTERNAL_SEQ_REGRESSION")
        self.assertTrue(reordered["replay_indicators"]["reordered_records"])
        self.assertEqual(reordered["replay"], "REPLAY_EVIDENCE_REQUIRED")

    def test_same_frame_different_metadata_and_same_metadata_different_frame(self):
        same_frame = copy.deepcopy(self.records[0]); same_frame["seq"] = 101; same_frame["ts"] = "2026-09-09T00:00:01Z"
        result = boundary.assess_tclk_transcript(transcript([self.records[0], same_frame]))
        self.assertEqual(result["replay_indicators"]["repeated_signed_payload_count"], 1)
        different = signed_record(100, self.records[0]["ts"], frame_type="refund", transport_nonce="12")
        result = boundary.assess_tclk_transcript(transcript([self.records[0], different]))
        self.assertEqual(result["metadata_evidence"]["duplicate_state"], "DUPLICATE_DETECTED")
        self.assertNotEqual(result["frame_evidence"][0]["signed_payload_sha256"], result["frame_evidence"][1]["signed_payload_sha256"])

    def test_seq_timestamp_generation_and_signature_fail_closed(self):
        cases = [("seq", True, "SEQ_INVALID"), ("seq", -1, "SEQ_INVALID"),
                 ("seq", 9007199254740992, "NUMERIC_REPRESENTATION_INVALID"),
                 ("ts", 1, "TIMESTAMP_INVALID"), ("ts", "2026-09-09", "TIMESTAMP_INVALID"),
                 ("ts", "1969-12-31T23:59:59Z", "TIMESTAMP_INVALID"),
                 ("generation", {}, "GENERATION_INVALID")]
        for field, value, code in cases:
            records = copy.deepcopy(self.records); records[0][field] = value
            self.assertEqual(boundary.assess_tclk_transcript(transcript(records))["errors"], [code])
        records = copy.deepcopy(self.records); records[0]["sig"] = "A" * 86
        result = boundary.assess_tclk_transcript(transcript(records))
        self.assertEqual(dimensions(result)["SIGNATURE_VERIFICATION"], "FAILED")
        self.assertEqual(result["completeness"], "UNKNOWN")
        records = copy.deepcopy(self.records); records[1]["generation"] = "gen-2"
        result = boundary.assess_tclk_transcript(transcript(records))
        self.assertEqual(result["metadata_evidence"]["generation_state"], "MULTIPLE_GENERATIONS_OBSERVED")
        self.assertEqual(result["completeness"], "INCOMPLETE")

    def test_timestamp_equal_future_and_currentness_are_descriptive(self):
        records = [signed_record(1, "9999-12-31T23:59:59Z"), signed_record(2, "9999-12-31T23:59:59Z")]
        result = boundary.assess_tclk_transcript(transcript(records))
        self.assertEqual(result["metadata_evidence"]["equal_timestamp_count"], 1)
        self.assertEqual(result["currentness"], "CURRENTNESS_NOT_EVALUATED")
        self.assertEqual(result["reference_time"], "REFERENCE_TIME_NOT_PROVIDED")

    def test_strict_parser_bounds_and_error_privacy(self):
        good = transcript(self.records)
        cases = [(b"", "EMPTY_TRANSCRIPT"), (b"\xef\xbb\xbf{}\n", "BOM_REJECTED"),
                 (b"{}\r\n", "CRLF_REJECTED"), (b"{}\n\n", "EMPTY_RECORD"),
                 (b'{"x":1.0}\n', "NUMERIC_REPRESENTATION_INVALID"),
                 (b'{"x":NaN}\n', "NUMERIC_REPRESENTATION_INVALID"),
                 (b'{"x":1,"x":2}\n', "DUPLICATE_JSON_KEY"),
                 (b'{"x":[' + b"0," * 32 + b"0]}\n", "ARRAY_LIMIT_EXCEEDED"),
                 (b'{"x":"' + b"a" * 5001 + b'"}\n', "STRING_INVALID"),
                 (b'{"x":' + b'{"x":' * 9 + b"0" + b"}" * 9 + b'}\n', "STRUCTURE_LIMIT_EXCEEDED"),
                 (b"[]\n", "RECORD_OBJECT_REQUIRED"), (b"\xff\n", "INVALID_UTF8"),
                 (b"x" * (boundary.MAX_TRANSCRIPT_BYTES + 1), "TRANSCRIPT_TOO_LARGE")]
        for raw, code in cases:
            result = boundary.assess_tclk_transcript(raw)
            self.assertEqual(result["errors"], [code]); self.assert_closed(result)
        for value in ("text", bytearray(good), memoryview(good), [], True):
            self.assertEqual(boundary.assess_tclk_transcript(value)["errors"], ["INPUT_TYPE_INVALID"])
        too_many = b"{}\n" * (boundary.MAX_RECORDS + 1)
        self.assertEqual(boundary.assess_tclk_transcript(too_many)["errors"], ["RECORD_COUNT_EXCEEDED"])
        too_large_record = b'{"x":"' + b"a" * boundary.MAX_RECORD_BYTES + b'"}\n'
        self.assertEqual(boundary.assess_tclk_transcript(too_large_record)["errors"], ["RECORD_TOO_LARGE"])

    def test_unknown_fields_sender_binding_and_frame_schema_rejected(self):
        for field in ("trusted", "complete", "expected_total", "venue_trusted", "final_state"):
            records = copy.deepcopy(self.records); records[0][field] = True
            self.assertEqual(boundary.assess_tclk_transcript(transcript(records))["errors"], ["RECORD_FIELD_SET_INVALID"])
        records = copy.deepcopy(self.records); records[0]["text"] = "tclk1 {}"
        self.assertEqual(boundary.assess_tclk_transcript(transcript(records))["errors"], ["FRAME_SCHEMA_OR_SENDER_BINDING_FAILED"])

    def test_production_surface_is_pure_sealed_and_has_no_trust_injection(self):
        signature = inspect.signature(boundary.assess_tclk_transcript)
        self.assertEqual(list(signature.parameters), ["transcript_bytes"])
        source = inspect.getsource(boundary)
        for forbidden in ("urlopen", "requests.", "subprocess.", "socket.", "cursor_path", "expected_total", "complete="):
            self.assertNotIn(forbidden, source)
        with self.assertRaises(AttributeError): boundary.SNAPSHOT = Path("replacement")
        first = boundary.assess_tclk_transcript(transcript(self.records))
        second = boundary.assess_tclk_transcript(transcript(self.records))
        self.assertEqual(first, second)

    def test_schema_index_compatibility_and_classification_inventory(self):
        index = json.loads(Path("schemas/index.json").read_text())
        self.assertIn("schemas/tclk-transcript-boundary.v1.json", {item["path"] for item in index["schemas"]})
        manifest = json.loads(Path("data/technocore_compatibility.json").read_text())
        item = manifest["tclk_transcript_boundary"]
        self.assertEqual(item["classification"], "SAFE_PURE_VALIDATOR")
        self.assertEqual(item["action"], "NO_LIVE_ACTION")
        forged = boundary.assess_tclk_transcript(transcript(self.records))
        forged["completeness"] = "COMPLETE"
        with self.assertRaises(Exception): Draft202012Validator(self.schema).validate(forged)


if __name__ == "__main__": unittest.main()
