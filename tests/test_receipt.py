import base64
import copy
import tempfile
import unittest
from pathlib import Path

from flop_agent.identity import create_identity, load_identity
from flop_agent.receipt import (
    SCHEMA, canonical_payload, create_receipt, verify_receipt,
)


def fixture_receipt(identity, repo, commit, artifact, timestamp):
    payload = {"schema": SCHEMA, "repo": repo, "commit": commit,
               "artifact_name": artifact, "timestamp": timestamp}
    key, did = load_identity(identity)
    signature = base64.urlsafe_b64encode(key.sign(canonical_payload(payload))).decode().rstrip("=")
    return {"schema": SCHEMA, "did": did, "payload": payload, "signature": signature}


class ReceiptTests(unittest.TestCase):
    def test_receipt_sign_and_verify_offline(self):
        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / "identity.json"
            did = create_identity(identity)
            receipt = fixture_receipt(
                identity, "https://github.com/example/flop-agent",
                "a" * 40, "FLOP Agent Intelligence & Safety Layer",
                "2026-08-26T00:00:00+00:00",
            )
            result = verify_receipt(receipt)
            self.assertEqual(result["status"], "VALID")
            self.assertEqual(result["did"], did)

    def test_tamper_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / "identity.json"
            create_identity(identity)
            receipt = fixture_receipt(
                identity, "https://github.com/example/flop-agent",
                "a" * 40, "artifact", "2026-08-26T00:00:00+00:00",
            )
            tampered = copy.deepcopy(receipt)
            tampered["payload"]["commit"] = "b" * 40
            with self.assertRaises(Exception):
                verify_receipt(tampered)

    def test_rejects_credentialed_repo_url(self):
        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / "identity.json"
            create_identity(identity)
            with self.assertRaises(ValueError):
                create_receipt(identity, "https://user:secret@example.com/repo", "a" * 40, "artifact")
