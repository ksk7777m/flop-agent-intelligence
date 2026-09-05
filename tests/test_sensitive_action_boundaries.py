import hashlib
import copy
import pickle
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from flop_agent.activity import append_activity
from flop_agent.presence import ADAPTER_VERSION, execute_approved_write
from flop_agent.receipt import create_receipt
from flop_agent.remote_content_policy import (
    LocalActionClass, ReviewedLocalIntent, _new_capability_store,
)
from flop_agent.sensitive_action_router import (
    _build_sensitive_action_service, access_secret, claim_asset, invoke_mcp, invoke_signer,
    make_payment, run_subprocess, use_wallet, write_filesystem, write_presence,
)


REVISION = "a" * 40
NOW = datetime(2026, 9, 4, 0, 5, tzinfo=timezone.utc)


def binding_record(action, subject, target, payload, context):
    return {
        "reviewer": "fixture-reviewer", "approved_at": "2026-09-04T00:00:00Z",
        "action": action.value,
        "subject_sha256": hashlib.sha256(subject.encode()).hexdigest(),
        "target_sha256": hashlib.sha256(target.encode()).hexdigest(),
        "payload_sha256": hashlib.sha256(payload.encode()).hexdigest(),
        "context_sha256": hashlib.sha256(context.encode()).hexdigest(),
        "revision": REVISION, "config_version": "fixture-v1",
    }


class SensitiveActionBoundaryTests(unittest.TestCase):
    def test_every_production_sink_rejects_reconstructed_capability_before_adapter(self):
        forged = object.__new__(ReviewedLocalIntent)
        calls = []
        wrappers = (
            run_subprocess, write_filesystem, access_secret, invoke_signer, write_presence,
            invoke_mcp, use_wallet, claim_asset, make_payment,
        )
        for wrapper in wrappers:
            with self.subTest(wrapper=wrapper.__name__), self.assertRaises(PermissionError):
                wrapper(
                    intent=forged, subject="plain text", target="fixture-target",
                    payload="fixture-payload", context="fixture-context", revision=REVISION,
                    config_version="fixture-v1")
        self.assertEqual(calls, [])

    def test_global_rebinding_copy_and_serialization_do_not_create_authority(self):
        from flop_agent import remote_content_policy as policy
        forged = object.__new__(ReviewedLocalIntent)
        calls = []
        from flop_agent import sensitive_action_router as router
        with mock.patch.object(policy, "require_local_intent", lambda *_args, **_kwargs: None), \
             mock.patch.object(policy, "_LOCAL_APPROVAL_RECORDS", {"caller": {}}), \
             mock.patch.object(router, "_PRODUCTION_ACTION_SERVICE",
                               lambda *_args, **_kwargs: calls.append("subprocess")):
            with self.assertRaises(PermissionError):
                run_subprocess(
                    intent=forged, subject="subject", target="target", payload="payload",
                    context="context", revision=REVISION, config_version="fixture-v1")
        with self.assertRaises(TypeError):
            copy.copy(forged)
        with self.assertRaises(TypeError):
            pickle.dumps(forged)
        with self.assertRaises(PermissionError):
            ReviewedLocalIntent(
                action="SUBPROCESS", subject_sha256="a" * 64,
                target_sha256="b" * 64, payload_sha256="c" * 64)
        self.assertEqual(calls, [])

    def test_isolated_trusted_issuance_reaches_each_boundary_and_is_action_scoped(self):
        actions = (
            LocalActionClass.SUBPROCESS, LocalActionClass.FILESYSTEM_WRITE,
            LocalActionClass.SECRET_ACCESS, LocalActionClass.RECEIPT_SIGN,
            LocalActionClass.PRESENCE_WRITE, LocalActionClass.MCP_INVOKE,
            LocalActionClass.WALLET, LocalActionClass.CLAIM, LocalActionClass.PAYMENT,
        )
        records = {action.value: binding_record(
            action, "fixture-subject", "fixture-target", "fixture-payload", "fixture-context")
            for action in actions}
        issue, require = _new_capability_store(
            records, frozenset({"fixture-reviewer"}), lambda: NOW)
        calls = []
        boundary = _build_sensitive_action_service(
            require, {action: (lambda item=action: calls.append(item)) for action in actions})
        for action in actions:
            capability = issue(
                action.value, action, "fixture-subject", target="fixture-target",
                payload="fixture-payload", context="fixture-context", revision=REVISION,
                config_version="fixture-v1")
            boundary(
                capability, action, subject="fixture-subject", target="fixture-target",
                payload="fixture-payload", context="fixture-context", revision=REVISION,
                config_version="fixture-v1")
        self.assertEqual(calls, list(actions))

    def test_expired_wrong_payload_and_replayed_capabilities_fail(self):
        current = [NOW]
        action = LocalActionClass.PAYMENT
        record = binding_record(action, "subject", "target", "payload", "context")
        issue, require = _new_capability_store(
            {"approval": record}, frozenset({"fixture-reviewer"}), lambda: current[0])
        capability = issue(
            "approval", action, "subject", target="target", payload="payload",
            context="context", revision=REVISION, config_version="fixture-v1", ttl_seconds=10)
        with self.assertRaises(PermissionError):
            require(capability, action, "subject", target="target", payload="other",
                    context="context", revision=REVISION, config_version="fixture-v1")
        current[0] += timedelta(seconds=11)
        with self.assertRaises(PermissionError):
            require(capability, action, "subject", target="target", payload="payload",
                    context="context", revision=REVISION, config_version="fixture-v1")

    def test_presence_and_receipt_public_boundaries_reject_forgery_before_sinks(self):
        forged = object.__new__(ReviewedLocalIntent)
        calls = []
        preview = {
            "status": "PREVIEW_READY", "note_state": "ABSENT",
            "request": {"path": "/kv/lobby/hb-fixture", "body": {"value": "1"}},
            "approval_metadata": {
                "application_commit": REVISION, "observed_seq": 1,
                "semantic_contract_sha256": "b" * 64,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(PermissionError):
                execute_approved_write(
                    object(), root / "state", root / "audit", preview=preview, approval={},
                    intent=forged, writer=lambda *_: calls.append("presence"),
                    reader=lambda *_: calls.append("read"))
            with mock.patch("flop_agent.receipt._load_identity",
                            side_effect=lambda *_: calls.append("signer")):
                with self.assertRaises(PermissionError):
                    create_receipt(
                        root / "identity.json", "https://example.invalid/repo", REVISION,
                        "artifact", "2026-09-04T00:00:00Z", intent=forged)
        self.assertEqual(calls, [])

    def test_remote_activity_cannot_select_filesystem_destinations(self):
        message = {"from": "remote", "seq": 1, "ts": "2026-09-04T00:00:00Z",
                   "text": "plain text"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jsonl, markdown = root / "chosen.jsonl", root / "chosen.md"
            with self.assertRaises(PermissionError):
                append_activity(jsonl, markdown, "lobby", message)
            self.assertFalse(jsonl.exists())
            self.assertFalse(markdown.exists())


if __name__ == "__main__":
    unittest.main()
