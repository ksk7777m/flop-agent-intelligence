import copy
import hashlib
import inspect
import json
import socket
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator

import flop_agent.tclk_accept_preflight as preflight


PAYER = "did:key:z6Mk" + "f" * 44
PAYEE = "did:key:z6Mk" + "g" * 44
OFFER_ID = "0xd001fbbf4fa36d9ab8ea88df02a8b3303539e9d59f7ff9d9bfeb679318e9ce75"
CONTRACT_ID = "0x2768bf32b455317879796093ff2e5882371cbec238611ca71f555a7fcbe58e1c"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def vector():
    offer = {"type": "offer", "from": PAYER, "role": "payer", "amount": "1000000",
        "asset": "FLOP", "lock": "hash", "rails": ["flop-htlc", "x402"],
        "claimByMs": 1756703600000, "refundAfterMs": 1756707200000,
        "expiresMs": 1756700600000,
        "job": {"proto": "a2a", "id": "task-3f", "context": "ctx-1"},
        "nonce": "9f2c81d04c9e1f7a", "id": OFFER_ID}
    accept = {"type": "accept", "from": PAYEE, "ref": OFFER_ID,
        "statement": "0x" + "ab" * 32, "nonce": "0011223344556677",
        "contract": CONTRACT_ID}
    return offer, accept


def run(offer=None, accept=None, raw_offer=None, raw_accept=None):
    base_offer, base_accept = vector()
    offer = base_offer if offer is None else offer
    accept = base_accept if accept is None else accept
    return preflight.validate_tclk_accept_preflight(
        canonical(offer) if raw_offer is None else raw_offer,
        canonical(accept) if raw_accept is None else raw_accept)


class OfflineTclkAcceptPreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(Path("schemas/offline-tclk-accept-preflight.v1.json").read_text())
        Draft202012Validator.check_schema(cls.schema)

    def assert_closed(self, result):
        Draft202012Validator(self.schema).validate(result)
        encoded = json.dumps(result, sort_keys=True)
        for forbidden in (PAYER, PAYEE, CONTRACT_ID, "0011223344556677", "abababab"):
            self.assertNotIn(forbidden, encoded)
        self.assertFalse(result["ready_to_act"])
        self.assertFalse(result["authorized_to_act"])
        self.assertFalse(result["live_action_enabled"])
        self.assertEqual(result["deadline_evaluation"]["current_time_expiry"], "NOT_EVALUATED")
        self.assertEqual(result["deadline_evaluation"]["reference_time"], "REFERENCE_TIME_NOT_PROVIDED")
        self.assertEqual(result["deadline_evaluation"]["runtime_currentness"], "RUNTIME_CURRENTNESS_OUT_OF_SCOPE")

    def test_golden_vector_and_independent_recomputation_match(self):
        offer, accept = vector()
        fields = dict(offer); fields.pop("id")
        self.assertEqual("0x" + hashlib.sha256(b"FLOP::tclk::v1|offer|" + canonical(fields)).hexdigest(), OFFER_ID)
        core = {k: accept[k] for k in ("from", "ref", "statement", "nonce")}
        expected = "0x" + hashlib.sha256(b"FLOP::tclk::v1|contract|" + canonical({"offer": offer, "accept": core})).hexdigest()
        self.assertEqual(expected, CONTRACT_ID)
        result = run()
        self.assertEqual(result["overall_disposition"], "PREFLIGHT_PASS")
        self.assertEqual(result["contract_classification"], "ACCEPT_CONTRACT_MATCH")
        self.assert_closed(result)

    def test_contract_mismatch_and_classifications(self):
        offer, accept = vector()
        cases = [
            (lambda x: x.pop("contract"), "ACCEPT_CONTRACT_MISSING"),
            (lambda x: x.update(contract=None), "ACCEPT_CONTRACT_NULL"),
            (lambda x: x.update(contract=""), "ACCEPT_CONTRACT_EMPTY"),
            (lambda x: x.update(contract=7), "ACCEPT_CONTRACT_WRONG_TYPE"),
            (lambda x: x.update(contract="0xNO"), "ACCEPT_CONTRACT_PATTERN_INVALID"),
            (lambda x: x.update(contract="0x" + "00" * 32), "ACCEPT_CONTRACT_RECOMPUTATION_MISMATCH"),
        ]
        for mutate, code in cases:
            candidate = copy.deepcopy(accept); mutate(candidate)
            result = run(offer, candidate)
            self.assertEqual(result["errors"], [code])
            self.assert_closed(result)

    def test_every_required_accept_field_missing(self):
        offer, accept = vector()
        for field in ("type", "from", "ref", "statement", "contract", "nonce"):
            candidate = dict(accept); candidate.pop(field)
            self.assertEqual(run(offer, candidate)["overall_disposition"], "PREFLIGHT_FAIL")

    def test_every_required_offer_field_missing_and_empty_rails(self):
        offer, accept = vector()
        required = ("type", "from", "role", "amount", "asset", "lock", "rails", "claimByMs",
                    "refundAfterMs", "expiresMs", "nonce", "id")
        for field in required:
            candidate = dict(offer); candidate.pop(field)
            self.assertEqual(run(candidate, accept)["errors"], ["OFFER_SCHEMA_NONCONFORMANT"])
        offer["rails"] = []
        self.assertEqual(run(offer, accept)["errors"], ["OFFER_SCHEMA_NONCONFORMANT"])

    def test_optional_payment_key_is_bound_and_validated(self):
        offer, accept = vector()
        key = "0x" + "02" + "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        accept["paymentKey"] = key
        accept["contract"] = preflight._contract_id(offer, accept)
        self.assertEqual(run(offer, accept)["overall_disposition"], "PREFLIGHT_PASS")
        accept["paymentKey"] = "0x" + "02" + "ff" * 32
        self.assertEqual(run(offer, accept)["errors"], ["SECP256K1_POINT_INVALID"])

    def test_payment_key_encoding_and_point_lock_boundaries(self):
        offer, accept = vector()
        invalid_shapes = [(None, "ACCEPT_SCHEMA_NONCONFORMANT"),
                          ("0x" + "04" + "11" * 32, "SECP256K1_POINT_INVALID"),
                          ("0x04" + "11" * 64, "ACCEPT_SCHEMA_NONCONFORMANT"),
                          ("0x" + "02" + "11" * 31, "ACCEPT_SCHEMA_NONCONFORMANT"),
                          ("0X" + "02" + "11" * 32, "ACCEPT_SCHEMA_NONCONFORMANT"),
                          ("0x" + "02" + "AA" * 32, "ACCEPT_SCHEMA_NONCONFORMANT")]
        for value, code in invalid_shapes:
            candidate = copy.deepcopy(accept); candidate["paymentKey"] = value
            self.assertEqual(run(offer, candidate)["errors"], [code])

        point = "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        offer["lock"] = "point"; offer["paymentKey"] = point; offer["id"] = preflight._offer_id(offer)
        accept["ref"] = offer["id"]; accept["statement"] = point
        accept["contract"] = preflight._contract_id(offer, accept)
        self.assertEqual(run(offer, accept)["errors"], ["POINT_LOCK_PAYMENT_KEY_REQUIRED"])
        accept["paymentKey"] = point; accept["contract"] = preflight._contract_id(offer, accept)
        self.assertEqual(run(offer, accept)["overall_disposition"], "PREFLIGHT_PASS")
        accept["statement"] = "0x02" + "ff" * 32
        accept["contract"] = preflight._contract_id(offer, accept)
        self.assertEqual(run(offer, accept)["errors"], ["SECP256K1_POINT_INVALID"])

    def test_schema_type_additional_and_binding_failures(self):
        offer, accept = vector()
        for target, field, value, code in [
            (offer, "extra", {}, "OFFER_SCHEMA_NONCONFORMANT"),
            (accept, "extra", {}, "ACCEPT_SCHEMA_NONCONFORMANT"),
            (offer, "type", "accept", "OFFER_SCHEMA_NONCONFORMANT"),
            (accept, "type", "offer", "ACCEPT_SCHEMA_NONCONFORMANT"),
        ]:
            changed = copy.deepcopy(target); changed[field] = value
            result = run(changed, accept) if target is offer else run(offer, changed)
            self.assertEqual(result["errors"], [code])
        accept["ref"] = "0x" + "00" * 32
        self.assertEqual(run(offer, accept)["errors"], ["ACCEPT_REF_MISMATCH"])

    def test_strict_json_and_input_bounds(self):
        offer, accept = vector(); good = canonical(accept)
        cases = [
            (b'{"type":"offer","type":"offer"}', "DUPLICATE_JSON_KEY"),
            (b'{"type":"offer"} trailing', "MALFORMED_JSON"),
            (b'{}{}', "MALFORMED_JSON"),
            (b'{"x":"\\q"}', "MALFORMED_JSON"),
            (b'{"x":"\x01"}', "MALFORMED_JSON"),
            (b'{"x":"\\ud800"}', "INVALID_UNICODE_SCALAR"),
            (b"\xff", "INVALID_UTF8"),
            (b"\xef\xbb\xbf{}", "BOM_REJECTED"),
            (b"[1]", "TOP_LEVEL_OBJECT_REQUIRED"),
            (b'{"x":1.0}', "NUMERIC_REPRESENTATION_INVALID"),
            (b'{"x":1e2}', "NUMERIC_REPRESENTATION_INVALID"),
            (b'{"x":-0}', "NUMERIC_REPRESENTATION_INVALID"),
            (b'{"x":NaN}', "NUMERIC_REPRESENTATION_INVALID"),
            (b'{"x":Infinity}', "NUMERIC_REPRESENTATION_INVALID"),
            (b'{"x":9007199254740992}', "NUMERIC_REPRESENTATION_INVALID"),
            (b"{" + b'\"x\":' * 0 + b'\"' + b"a" * 1025 + b'\"}', "STRING_LIMIT_EXCEEDED"),
            (b"[" * 17 + b"]" * 17, "JSON_DEPTH_EXCEEDED"),
            (b" " * 4097, "INPUT_TOO_LARGE"),
        ]
        for raw, code in cases:
            result = preflight.validate_tclk_accept_preflight(raw, good)
            self.assertEqual(result["errors"], [code])
            self.assert_closed(result)
        for value in ("{}", bytearray(b"{}"), memoryview(b"{}"), [1], True):
            self.assertEqual(preflight.validate_tclk_accept_preflight(value, good)["errors"], ["INPUT_TYPE_INVALID"])
        self.assertEqual(preflight.validate_tclk_accept_preflight(b"", good)["errors"], ["MALFORMED_JSON"])

    def test_bool_is_not_integer_and_large_collections_rejected(self):
        offer, accept = vector(); offer["claimByMs"] = True
        self.assertEqual(run(offer, accept)["errors"], ["OFFER_SCHEMA_NONCONFORMANT"])
        raw = canonical({str(i): i for i in range(65)})
        self.assertEqual(preflight.validate_tclk_accept_preflight(raw, canonical(accept))["errors"], ["MEMBER_LIMIT_EXCEEDED"])
        raw = canonical({"x": list(range(33))})
        self.assertEqual(preflight.validate_tclk_accept_preflight(raw, canonical(accept))["errors"], ["ARRAY_LIMIT_EXCEEDED"])

    def test_unicode_normalization_array_order_and_raw_canonicality(self):
        offer, accept = vector()
        offer["job"]["id"] = "caf\u00e9"
        offer["id"] = preflight._offer_id(offer)
        accept["ref"] = offer["id"]; accept["contract"] = preflight._contract_id(offer, accept)
        self.assertEqual(run(offer, accept)["overall_disposition"], "PREFLIGHT_PASS")
        decomposed = copy.deepcopy(offer); decomposed["job"]["id"] = "cafe\u0301"
        self.assertNotEqual(preflight._offer_id(offer), preflight._offer_id(decomposed))
        base_offer, base_accept = vector()
        noncanonical = json.dumps(base_offer, ensure_ascii=True).encode()
        result = run(base_offer, base_accept, raw_offer=noncanonical)
        self.assertEqual(result["errors"], ["RAW_BYTES_NONCANONICAL"])
        reversed_offer = copy.deepcopy(base_offer); reversed_offer["rails"].reverse()
        reversed_offer["id"] = preflight._offer_id(reversed_offer)
        base_accept["ref"] = reversed_offer["id"]; base_accept["contract"] = preflight._contract_id(reversed_offer, base_accept)
        self.assertEqual(run(reversed_offer, base_accept)["errors"], ["RAIL_ORDER_NONCANONICAL"])

    def test_contract_mutations_exclusions_optional_and_boundary_nonce(self):
        offer, accept = vector()
        changed_offer = copy.deepcopy(offer)
        changed_offer["amount"] = "1000001"
        changed_offer["id"] = preflight._offer_id(changed_offer)
        changed_accept = copy.deepcopy(accept); changed_accept["ref"] = changed_offer["id"]
        self.assertEqual(run(changed_offer, changed_accept)["errors"], ["ACCEPT_CONTRACT_RECOMPUTATION_MISMATCH"])

        changed_accept = copy.deepcopy(accept); changed_accept["nonce"] = "0011223344556678"
        self.assertEqual(run(offer, changed_accept)["errors"], ["ACCEPT_CONTRACT_RECOMPUTATION_MISMATCH"])
        self.assertEqual(preflight._contract_id(offer, accept),
                         preflight._contract_id(offer, {**accept, "contract": "0x" + "00" * 32}))
        self.assertEqual(preflight._contract_id(offer, accept),
                         preflight._contract_id(offer, {**accept, "type": "excluded"}))

        key = "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        with_key = copy.deepcopy(accept); with_key["paymentKey"] = key
        self.assertNotEqual(preflight._contract_id(offer, accept), preflight._contract_id(offer, with_key))
        for nonce in ("00000000", "0" * 64):
            candidate = copy.deepcopy(accept); candidate["nonce"] = nonce
            candidate["contract"] = preflight._contract_id(offer, candidate)
            self.assertEqual(run(offer, candidate)["overall_disposition"], "PREFLIGHT_PASS")

    def test_all_rails_duplicate_unknown_and_mixed(self):
        for rails, code, disposition in [
            (["x402", "x402"], "DUPLICATE_RAIL", "PREFLIGHT_FAIL"),
            (["custom"], "UNKNOWN_RAIL", "PREFLIGHT_QUARANTINED"),
            (["flop-htlc", "custom"], "UNKNOWN_RAIL", "PREFLIGHT_QUARANTINED"),
            (["PaperRail"], "RAIL_NONCANONICAL", "PREFLIGHT_QUARANTINED"),
        ]:
            offer, accept = vector(); offer["rails"] = rails; offer["id"] = preflight._offer_id(offer)
            accept["ref"] = offer["id"]; accept["contract"] = preflight._contract_id(offer, accept)
            result = run(offer, accept)
            self.assertEqual(result["errors"], [code]); self.assertEqual(result["overall_disposition"], disposition)

    def test_policy_integrity_remote_refs_and_no_fallback(self):
        schema = json.loads(preflight.SNAPSHOT.read_text())
        refs = []
        def walk(value):
            if isinstance(value, dict):
                refs.extend(v for k, v in value.items() if k == "$ref")
                for v in value.values(): walk(v)
            elif isinstance(value, list):
                for v in value: walk(v)
        walk(schema)
        self.assertTrue(refs and all(ref.startswith("#/$defs/") for ref in refs))
        with mock.patch.object(Path, "read_bytes", return_value=b"{}"):
            result = run()
        self.assertEqual(result["errors"], ["PINNED_POLICY_INTEGRITY_FAILED"])
        self.assertEqual(result["overall_disposition"], "PREFLIGHT_NOT_PERFORMED")

    def test_deterministic_private_and_action_isolated(self):
        first, second = run(), run()
        self.assertEqual(first, second)
        self.assert_closed(first)
        signature = inspect.signature(preflight.validate_tclk_accept_preflight)
        self.assertEqual(list(signature.parameters), ["offer_bytes", "accept_bytes"])
        source = inspect.getsource(preflight)
        for forbidden in ("urlopen", "requests.", "subprocess.", "socket.", "--confirm", "sign(", "post("):
            self.assertNotIn(forbidden, source)
        self.assertFalse(first["production_api"]["corrected_frame_output"])
        with self.assertRaises(AttributeError):
            preflight.SNAPSHOT = Path("elsewhere")
        with self.assertRaises(AttributeError):
            preflight.CONTRACT_DOMAIN = b"replacement"
        with self.assertRaises(AttributeError):
            preflight.hashlib = object()

    def test_schema_index_and_compatibility_manifest(self):
        index = json.loads(Path("schemas/index.json").read_text())
        self.assertIn("schemas/offline-tclk-accept-preflight.v1.json", {x["path"] for x in index["schemas"]})
        manifest = json.loads(Path("data/technocore_compatibility.json").read_text())
        item = manifest["offline_tclk_accept_preflight"]
        self.assertEqual(item["classification"], "SAFE_PURE_VALIDATOR")
        self.assertEqual(item["action"], "NO_LIVE_ACTION")


if __name__ == "__main__":
    unittest.main()
