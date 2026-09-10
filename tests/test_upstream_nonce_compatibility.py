import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from flop_agent import kol_referral_readiness as kol
from flop_agent import replay_journal as replay
from flop_agent import tclk_authenticated_winner as winner
from flop_agent import tclk_source_attestation as source
from flop_agent import testnet_readiness as readiness
from flop_agent import wire_evidence as wire


class UpstreamNonceCompatibilityTests(unittest.TestCase):
    INVALID = (True, False, 1.0, 9007199254740993, "1e3", "0x10", "+1",
               " 1", "\N{ARABIC-INDIC DIGIT ONE}", "01", "1" * 20)
    BOUNDARIES = ("9007199254740991", "9007199254740992",
                  "9007199254740993", "9999999999999999999")

    def test_decimal_boundary_matrix_is_consistent(self):
        validators = (source._valid_decimal, winner._decimal, readiness._decimal,
                      kol._decimal)
        for validate in validators:
            for value in self.INVALID:
                with self.subTest(validator=validate.__module__, value=value):
                    self.assertFalse(validate(value))
            for value in self.BOUNDARIES:
                self.assertTrue(validate(value))

    def test_json_bool_and_unsafe_number_never_enter_wire_identity(self):
        for raw in (b'{"nonce":true}', b'{"nonce":false}',
                    b'{"nonce":9007199254740993}'):
            with self.subTest(raw=raw), self.assertRaises(wire.WireSafetyError):
                wire.parse_nonce(json.loads(raw)["nonce"])

    def test_replay_bool_cannot_alias_one_and_large_decimals_are_bounded(self):
        values = dict(actor_did="did:key:z6MkeTGwHmLmuCmgg4ABYhzWVh6ZX7hTwWt8gguAretUfc9c",
                      action_class="SIGNED_ACTION", context="lobby",
                      signed_payload_sha256="a" * 64, signing_bytes_sha256="b" * 64,
                      target="resource:fixture", schema_version="replay-action-v1")
        one = replay.CanonicalAction(nonce="1", **values)
        self.assertEqual(one.nonce, "1")
        for invalid in (True, False, 1, 1.0, "01", "1" * 129, "1" * 1000):
            with self.subTest(invalid=invalid), self.assertRaises(replay.ReplaySafetyError):
                replay.CanonicalAction(nonce=invalid, **values)

    def test_compatibility_lifecycle_is_explicit_without_live_promotion(self):
        manifest = json.loads(Path("data/technocore_compatibility.json").read_text())
        schema = json.loads(Path("schemas/technocore-compatibility.v1.json").read_text())
        Draft202012Validator(schema).validate(manifest)
        nonce = manifest["nonce_compatibility"]
        self.assertEqual(nonce["lifecycle_states"], ["RELEASED", "MERGED_NOT_RELEASED",
                         "UNRELEASED", "LIVE_CONFIRMED", "LIVE_CURRENTNESS_UNREVIEWED"])
        self.assertEqual(nonce["current_lifecycle_assessment"],
                         "LIVE_CURRENTNESS_UNREVIEWED")


if __name__ == "__main__":
    unittest.main()
