import base64
import ast
import copy
import inspect
import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from jsonschema import Draft202012Validator

from flop_agent.identity import did_from_public_key
import flop_agent.tclk_accept_preflight as preflight
import flop_agent.tclk_offer_global_winner as winner


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


PAYER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PAYEE_KEYS = (Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))),
              Ed25519PrivateKey.from_private_bytes(bytes(range(2, 34))))


def did(key):
    return did_from_public_key(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def vector():
    offer = {"type": "offer", "from": did(PAYER_KEY), "role": "payer", "amount": "1000000",
        "asset": "FLOP", "lock": "hash", "rails": ["flop-htlc", "x402"],
        "claimByMs": 1756703600000, "refundAfterMs": 1756707200000,
        "expiresMs": 1756700600000,
        "job": {"proto": "a2a", "id": "task-3f", "context": "ctx-1"},
        "nonce": "9f2c81d04c9e1f7a"}
    offer["id"] = preflight._offer_id(offer)
    accepts = []
    for index, key in enumerate(PAYEE_KEYS):
        accept = {"type": "accept", "from": did(key), "ref": offer["id"],
            "statement": "0x" + format(index + 1, "02x") * 32,
            "nonce": format(index + 1, "016x")}
        accept["contract"] = preflight._contract_id(offer, accept)
        accepts.append(accept)
    return offer, accepts


def record(frame, key, seq, ts=None, generation="gen-1", room="tclk-offers", transport_nonce=None):
    text = "tclk1 " + canonical(frame).decode("ascii")
    nonce = transport_nonce or str(seq + 10)
    payload = f"{room}|{nonce}|{text}".encode("utf-8")
    value = {"room": room, "seq": seq, "ts": ts or f"2026-09-09T00:00:{seq:02d}Z",
        "from": frame["from"], "nonce": nonce,
        "sig": base64.urlsafe_b64encode(key.sign(payload)).decode().rstrip("="), "text": text}
    if generation is not None: value["generation"] = generation
    return value


def transcript(records, final_newline=True):
    raw = b"\n".join(canonical(item) for item in records)
    return raw + (b"\n" if final_newline else b"")


def string_values(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values(): yield from string_values(child)
    elif isinstance(value, list):
        for child in value: yield from string_values(child)


class OfferGlobalWinnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(Path("schemas/tclk-offer-global-winner-boundary.v1.json").read_text())
        Draft202012Validator.check_schema(cls.schema)
        cls.offer, cls.accepts = vector()
        cls.records = [record(cls.accepts[0], PAYEE_KEYS[0], 1),
                       record(cls.accepts[1], PAYEE_KEYS[1], 2)]

    def assess(self, records=None, offer=None):
        return winner.assess_offer_global_winner(
            canonical(self.offer if offer is None else offer),
            transcript(self.records if records is None else records))

    def assert_closed(self, result):
        Draft202012Validator(self.schema).validate(result)
        winner._validate_result(result)
        projected = set(string_values(result))
        forbidden = [self.offer["id"], self.accepts[0]["contract"], self.accepts[0]["from"],
            self.records[0]["sig"], self.records[0]["nonce"], self.records[0]["room"],
            self.records[0]["ts"], self.accepts[0]["statement"]]
        for value in forbidden: self.assertNotIn(value, projected)
        self.assertEqual(result["winner"], "GLOBAL_WINNER_UNRESOLVED")
        self.assertFalse(result["ready_to_act"]); self.assertFalse(result["authorized_to_act"])
        self.assertFalse(result["live_action_enabled"])

    def test_single_valid_accept_does_not_prove_global_winner(self):
        result = self.assess(self.records[:1])
        self.assertEqual(result["candidates"][0]["eligibility"], "LOCAL_ACCEPT_ELIGIBLE")
        self.assertEqual(result["race"], "WINNER_UNRESOLVED")
        self.assert_closed(result)

    def test_multiple_local_valid_accepts_are_candidates_not_two_winners(self):
        result = self.assess()
        self.assertEqual(result["candidate_count"], 2)
        self.assertTrue(all(item["contract_local_view"] == "VALID" for item in result["candidates"]))
        self.assertTrue(all(item["race_classification"] == "RACE_LOSS_CANDIDATE" for item in result["candidates"]))
        self.assertEqual(result["race"], "RACE_LOSS_CANDIDATES_PRESENT")
        self.assert_closed(result)

    def test_unsigned_order_and_metadata_mutations_never_select_winner(self):
        cases = []
        for field, value in (("seq", 20), ("ts", "2026-09-09T00:00:00Z"),
                             ("generation", "gen-2")):
            changed = copy.deepcopy(self.records); changed[1][field] = value; cases.append(changed)
        cases.extend((list(reversed(self.records)), self.records[1:], self.records[:-1],
                      [self.records[0], self.records[0]],
                      [self.records[0], copy.deepcopy(self.records[1])]))
        cases[-1][1]["seq"] = 4
        for records in cases:
            result = self.assess(records)
            self.assertEqual(result["winner"], "GLOBAL_WINNER_UNRESOLVED")
            self.assertEqual(result["ordering"]["venue_authenticity"], "UNKNOWN")

    def test_equal_and_regressing_timestamps_do_not_establish_chronology(self):
        for ts in (self.records[0]["ts"], "2026-09-08T00:00:00Z"):
            records = copy.deepcopy(self.records); records[1]["ts"] = ts
            result = self.assess(records)
            self.assertEqual(result["ordering"]["chronology"], "NOT_VERIFIED")
            self.assertEqual(result["winner"], "GLOBAL_WINNER_UNRESOLVED")

    def test_missing_contract_signature_and_derivation_failures_are_not_race_loss(self):
        mutations = []
        missing = copy.deepcopy(self.accepts[0]); missing.pop("contract")
        mutations.append((record(missing, PAYEE_KEYS[0], 1), "MISSING_CONTRACT"))
        wrong_type = copy.deepcopy(self.accepts[0]); wrong_type["contract"] = 7
        mutations.append((record(wrong_type, PAYEE_KEYS[0], 1), "CONTRACT_TYPE_INVALID"))
        mismatch = copy.deepcopy(self.accepts[0]); mismatch["contract"] = "0x" + "00" * 32
        mutations.append((record(mismatch, PAYEE_KEYS[0], 1), "CONTRACT_DERIVATION_FAILED"))
        invalid = copy.deepcopy(self.records[0]); invalid["sig"] = "A" * 86
        mutations.append((invalid, "SIGNATURE_INVALID"))
        for candidate, classification in mutations:
            result = self.assess([candidate])
            self.assertEqual(result["candidates"][0]["eligibility"], classification)
            self.assertEqual(result["candidates"][0]["race_classification"], "WINNER_UNRESOLVED")
            self.assertEqual(result["maliciousness"], "NOT_ESTABLISHED")
            self.assertEqual(result["reputation"], "NO_IMPACT")

    def test_middle_deletion_changes_identity_without_resolving_boundaries(self):
        third = copy.deepcopy(self.records[1]); third["seq"] = 3
        complete_local = self.assess([self.records[0], self.records[1], third])
        deleted = self.assess([self.records[0], third])
        self.assertNotEqual(complete_local["artifact_id"], deleted["artifact_id"])
        self.assertEqual(deleted["winner"], "GLOBAL_WINNER_UNRESOLVED")
        self.assertEqual(deleted["evidence_boundary"]["source"], "EVIDENCE_REQUIRED")

    def test_replay_indicator_is_never_confirmed_replay(self):
        result = self.assess([self.records[0], self.records[0]])
        self.assertTrue(all(item["replay"] == "REPLAY_EVIDENCE_REQUIRED" for item in result["candidates"]))
        self.assertEqual(result["evidence_boundary"]["replay"], "EVIDENCE_REQUIRED")

    def test_identity_binds_order_count_metadata_and_candidate_evidence(self):
        original = self.assess()
        variants = [list(reversed(self.records)), self.records[:1], self.records + [self.records[0]]]
        for field, value in (("seq", 8), ("ts", "2026-09-09T01:00:00Z"), ("generation", "gen-2")):
            changed = copy.deepcopy(self.records); changed[0][field] = value; variants.append(changed)
        for records in variants:
            self.assertNotEqual(self.assess(records)["artifact_id"], original["artifact_id"])

    def test_schema_runtime_grammar_and_escalation_rejection_match(self):
        result = self.assess()
        for mutate in (
            lambda x: x["stages"].reverse(),
            lambda x: x["stages"][0].update(ordinal=True),
            lambda x: x["candidates"][0].update(ordinal=True),
            lambda x: x.update(winner="OFFER_GLOBAL_WINNER_VERIFIED"),
            lambda x: x["candidates"][0].update(extra=True)):
            forged = copy.deepcopy(result); mutate(forged)
            with self.assertRaises(Exception): Draft202012Validator(self.schema).validate(forged)
            with self.assertRaises(Exception): winner._validate_result(forged)

    def test_input_resource_error_privacy_and_determinism(self):
        for offer, raw, code in (("x", b"{}\n", "INPUT_TYPE_INVALID"),
                                 (b"{}", b"x", "TRANSCRIPT_PROFILE_INVALID"),
                                 (b"{}", b'{"secret":"do-not-leak"\n', "TRANSCRIPT_PARSE_FAILED")):
            result = winner.assess_offer_global_winner(offer, raw)
            self.assertEqual(result["errors"], [code]); self.assertNotIn("do-not-leak", json.dumps(result))
        result = winner.assess_offer_global_winner(b"x" * (winner.MAX_OFFER_BYTES + 1),
                                                   transcript(self.records[:1]))
        self.assertEqual(result["errors"], ["OFFER_LIMIT_EXCEEDED"])
        result = winner.assess_offer_global_winner(canonical(self.offer),
            b" " * winner.MAX_TRANSCRIPT_BYTES + b"\n")
        self.assertEqual(result["errors"], ["TRANSCRIPT_LIMIT_EXCEEDED"])
        first = self.assess(); second = self.assess(); self.assertEqual(first, second)
        unknown = copy.deepcopy(self.records[0]); unknown["extra"] = "untrusted"
        result = self.assess([unknown])
        self.assertEqual(result["errors"], ["TRANSCRIPT_PARSE_FAILED"])
        boolean = copy.deepcopy(self.records[0]); boolean["seq"] = True
        self.assertEqual(self.assess([boolean])["errors"], ["TRANSCRIPT_PARSE_FAILED"])
        result = self.assess([self.records[0]] * (winner.MAX_CANDIDATES + 1))
        self.assertEqual(result["errors"], ["CANDIDATE_LIMIT_EXCEEDED"])

    def test_field_report_correction_is_unattested_and_quantity_free(self):
        result = self.assess()
        state = result["field_report_currentness"]
        self.assertEqual(state["historical_state"], "POINT_IN_TIME_REPORTED_NOT_CURRENTLY_ATTESTED")
        self.assertEqual(state["correction_state"], "CORRECTION_REPORTED")
        self.assertEqual(state["source_evidence"], "SOURCE_EVIDENCE_REQUIRED")
        self.assertEqual(state["currentness"], "CURRENTNESS_NOT_CONFIRMED")
        self.assertEqual(state["supersession"], "SUPERSESSION_REVIEW_REQUIRED")
        self.assertEqual(state["conflict"], "NOT_ESTABLISHED")
        projected = set(string_values(result))
        for value in ("90.2%", "93.7%", "77%", "9 signed", "1022", "922", "711", "666"):
            self.assertNotIn(value, projected)

    def test_api_surface_action_isolation_and_sealing(self):
        self.assertEqual(list(inspect.signature(winner.assess_offer_global_winner).parameters),
                         ["offer_bytes", "transcript_bytes"])
        self.assertEqual(winner.__all__, ["assess_offer_global_winner"])
        source = inspect.getsource(winner)
        for forbidden in ("urlopen", "requests.", "socket.", "subprocess.", "winner_bool",
                          "completeness_bool", "callback", "filesystem_path"):
            self.assertNotIn(forbidden, source)
        with self.assertRaises(AttributeError): winner.DOMAIN = "changed"
        imports = {node.names[0].name.split(".")[0] for node in ast.walk(ast.parse(source))
                   if isinstance(node, ast.Import)}
        self.assertTrue(imports.isdisjoint({"socket", "subprocess", "urllib", "requests",
                                            "httpx", "aiohttp"}))

    def test_schema_index_compatibility_and_production_inventory(self):
        index = json.loads(Path("schemas/index.json").read_text())
        self.assertIn("schemas/tclk-offer-global-winner-boundary.v1.json",
                      {item["path"] for item in index["schemas"]})
        manifest = json.loads(Path("data/technocore_compatibility.json").read_text())
        item = manifest["tclk_offer_global_winner_boundary"]
        self.assertEqual(item["classification"], "SAFE_PURE_VALIDATOR")
        self.assertEqual(item["winner"], "GLOBAL_WINNER_UNRESOLVED")
        self.assertEqual(item["action"], "NO_LIVE_ACTION")


if __name__ == "__main__": unittest.main()
