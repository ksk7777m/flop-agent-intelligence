import stat
import tempfile
import unittest
from pathlib import Path

from flop_agent.identity import create_identity, _load_identity, _sign_message, public_key_from_did, verify_message


class IdentityTests(unittest.TestCase):
    def test_identity_round_trip_and_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secrets" / "identity.json"
            did = create_identity(path)
            self.assertTrue(did.startswith("did:key:z6Mk"))
            self.assertEqual(len(public_key_from_did(did)), 32)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            key, loaded_did = _load_identity(path)
            self.assertEqual(loaded_did, did)
            sig, clean = _sign_message(key, "lobby", 1, "hello\nworld")
            self.assertEqual(len(sig), 86)
            self.assertEqual(clean, "hello world")
            verify_message(did, sig, "lobby", 1, clean)

    def test_signature_rejects_changed_text(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.json"
            did = create_identity(path)
            key, _ = _load_identity(path)
            sig, _ = _sign_message(key, "lobby", 1, "hello")
            with self.assertRaises(Exception):
                verify_message(did, sig, "lobby", 1, "changed")
