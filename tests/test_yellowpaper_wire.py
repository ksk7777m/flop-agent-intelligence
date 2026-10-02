import json
import unittest
from pathlib import Path

from flop_agent import yellowpaper_wire as wire

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads((ROOT / "vendor/official_sources/2026-10-02/yellowpaper/evidence/wire-format-v1.json").read_text())


class YellowPaperWireTests(unittest.TestCase):
    def test_official_channel_and_replay_domain(self):
        vector = VECTORS["compute_channel_v1"]["channel_id"]
        v = vector["inputs"]
        args = [bytes.fromhex(v[k]) for k in ("genesis_hash_hex", "agent_account_id32_hex", "miner_account_id32_hex")]
        value = wire.channel_id(*args, int(v["nonce"]))
        self.assertEqual(value.hex(), vector["hash_hex"])
        args[0] = bytes(32)
        self.assertNotEqual(value, wire.channel_id(*args, int(v["nonce"])))
        with self.assertRaises(ValueError):
            wire.channel_id(*args, 1, profile="future")

    def test_official_all_leaf_versions_and_merkle(self):
        corpus = VECTORS["compute_channel_v1"]
        fields = {k.removesuffix("_hex"): bytes.fromhex(v) if k.endswith("_hex") else int(v)
                  for k, v in corpus["leaf_inputs"].items()}
        fields["ids_hash"] = fields.pop("h_ids")
        hashes = {}
        for vector in corpus["leaf_versions"]:
            name = vector["version"]
            hashes[name] = wire.leaf_hash(int(name[1:]), **fields)
            self.assertEqual(hashes[name].hex(), vector["hash_hex"])
        with self.assertRaises(ValueError):
            wire.leaf_hash(4, **fields)
        tree = corpus["merkle"]
        path = [(bytes.fromhex(p["sibling_hex"]), p["sibling_is_left"]) for p in tree["path_for_index_2"]]
        root = bytes.fromhex(tree["root_hex"])
        self.assertTrue(wire.check_merkle_path(hashes["V3"], path, root))
        path[-1] = (path[-1][0], not path[-1][1])
        with self.assertRaises(ValueError):
            wire.check_merkle_path(hashes["V3"], path, root)

    def test_official_fcc4_roundtrip_and_policy(self):
        corpus = VECTORS["compute_channel_v1"]
        raw = bytes.fromhex(corpus["fcc4_transcript_blob_hex"])
        channel = bytes.fromhex(corpus["channel_id"]["hash_hex"])
        policy = bytes.fromhex(corpus["leaf_inputs"]["decode_policy_hash_hex"])
        parsed_channel, turns = wire.decode_transcript(raw, expected_channel=channel, policy_hash=policy)
        self.assertEqual(wire.encode_transcript(parsed_channel, turns), raw)
        for wrong_channel, wrong_policy in ((bytes(32), policy), (channel, bytes(32)), (channel, None)):
            with self.assertRaises(ValueError):
                wire.decode_transcript(raw, expected_channel=wrong_channel, policy_hash=wrong_policy)
        for vector in VECTORS["negative_cases"]:
            if vector["site"] == "TranscriptBlob.decode":
                with self.subTest(vector=vector["id"]), self.assertRaises(ValueError):
                    wire.decode_transcript(bytes.fromhex(vector["bytes_hex"]), expected_channel=channel, policy_hash=policy)

    def test_official_receipt_and_payable_path_binding(self):
        vector = VECTORS["compute_channel_v1"]["receipt"]
        v = vector["inputs"]
        channel, root = bytes.fromhex(v["channel_id_hex"]), bytes.fromhex(v["final_root_hex"])
        self.assertEqual(wire.receipt_preimage(channel, root, v["aggregate_gn"], v["payable"]).hex(), vector["preimage_hex"])
        state = dict(path="settle", escrow=1000, turn_count=2, base_per_turn=1, rate_g=1)
        self.assertTrue(wire.check_receipt(bytes.fromhex(vector["preimage_hex"]), channel=channel,
            root=root, aggregate_gn=42, state=state)["bytes_conformant"])
        state["path"] = "force_settle"
        with self.assertRaises(ValueError):
            wire.check_receipt(bytes.fromhex(vector["preimage_hex"]), channel=channel, root=root,
                               aggregate_gn=42, state=state)
        self.assertEqual(wire.derive_payable(aggregate_gn=42, **state), 44)
        self.assertEqual(wire.derive_payable(aggregate_gn=42, contract_payment=50, **state), 50)
        for profile in (0, 2, True, None):
            with self.assertRaises(ValueError):
                wire.receipt_preimage(channel, root, 42, 1000, wire_profile=profile)
        with self.assertRaises(ValueError):
            wire.derive_payable(path="force_settle", escrow=1, turn_count=2, aggregate_gn=42,
                                base_per_turn=1, rate_g=1)

    def test_compact_official_boundaries_and_malformed(self):
        for v in VECTORS["codec"]["scale_compact_u32"]:
            raw = bytes.fromhex(v["bytes_hex"])
            self.assertEqual(wire.encode_compact(int(v["value"])), raw)
            self.assertEqual(wire.decode_compact(raw), int(v["value"]))
        for v in VECTORS["codec"]["malformed_compact"]:
            with self.subTest(v=v), self.assertRaises(ValueError):
                wire.decode_compact(bytes.fromhex(v["bytes_hex"]))
        for value in (-1, True, 1.1, 2**32):
            with self.assertRaises(ValueError):
                wire.encode_compact(value)
