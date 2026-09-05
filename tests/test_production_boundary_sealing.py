import dataclasses
import hashlib
import inspect
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from flop_agent import receipt, remote_content_policy as policy
from flop_agent import sensitive_action_router as router
from flop_agent import testnet
from flop_agent import kv_observatory as kv
from flop_agent.activity import _build_activity_service
from flop_agent.kv_observatory import (
    NamespaceConfig,
    _reviewed_kv_read_target,
    official_get,
    parse_key_list,
)
from flop_agent.presence import (
    CAPABILITY_CONFIG_VERSION,
    AGENT_PATH,
    CONFIG_PATH,
    ROOMS_PATH,
    PresenceConfig,
    _build_presence_write_service,
    approval_digest,
    load_semantic_contract,
    preview_first_write,
)
from flop_agent.remote_content_policy import (
    ContractEvidenceRecord,
    ContractProvenance,
    LocalActionClass,
    RemoteOrigin,
    RemoteOriginMetadata,
    ReviewedLocalIntent,
    ReviewedSourceId,
    SinkClass,
    SourceTrustTier,
)


REVISION = "a" * 40
NOW = datetime(2026, 9, 4, 0, 5, tzinfo=timezone.utc)


def binding(action, subject, target, payload, context, config_version="fixture-v1"):
    return {
        "reviewer": "fixture-reviewer",
        "approved_at": "2026-09-04T00:00:00Z",
        "action": action.value,
        "subject_sha256": hashlib.sha256(subject.encode()).hexdigest(),
        "target_sha256": hashlib.sha256(target.encode()).hexdigest(),
        "payload_sha256": hashlib.sha256(payload.encode()).hexdigest(),
        "context_sha256": hashlib.sha256(context.encode()).hexdigest(),
        "revision": REVISION,
        "config_version": config_version,
    }


class ProductionBoundarySealingTests(unittest.TestCase):
    def test_exact_prior_adversarial_regressions_are_closed(self):
        forged = object.__new__(ReviewedLocalIntent)
        subprocess_calls = []
        with mock.patch.object(policy, "require_local_intent", lambda *_a, **_k: None), \
             mock.patch.object(router, "_PRODUCTION_ACTION_SERVICE",
                               lambda *_a, **_k: subprocess_calls.append(1)):
            with self.assertRaises(PermissionError):
                router.run_subprocess(
                    intent=forged, subject="subject", target="target", payload="payload",
                    context="context", revision=REVISION, config_version="fixture-v1")

        kv_http_calls = []
        key = parse_key_list('{"ns":"lobby","keys":["hb-caller"]}', "lobby")[0]
        with mock.patch.object(kv, "build_opener",
                               side_effect=lambda *_a: kv_http_calls.append(1)):
            with self.assertRaises(PermissionError):
                target = _reviewed_kv_read_target(
                    NamespaceConfig("lobby", key_prefixes=("hb-",)), key)
                official_get(target)

        receipt_key_calls = []
        with mock.patch.object(receipt, "invoke_signer",
                               lambda **kwargs: kwargs["adapter"](), create=True), \
             mock.patch.object(receipt, "load_identity",
                               side_effect=lambda *_a: receipt_key_calls.append(1)):
            with self.assertRaises(PermissionError):
                receipt.create_receipt(
                    Path("unused"), "https://example.invalid/repo", REVISION,
                    "artifact", "2026-09-04T00:00:00Z", intent=forged)

        contract = "0x" + "1" * 40
        proposal = ContractEvidenceRecord(
            contract, ReviewedSourceId.FLOP_FINANCE, "a" * 64,
            "2026-09-04T00:00:00Z", True)
        derive = policy._derive_contract_records
        with mock.patch.object(
                policy, "_derive_contract_records",
                lambda *_a, **_k: ContractProvenance.VERIFIED_FOR_TESTNET_USE):
            contract_result = derive((proposal,), contract)

        source = policy.resolve_reviewed_source(ReviewedSourceId.FLOP_FINANCE)
        forged_value = policy.evaluate_remote_content(source.url, RemoteOriginMetadata(
            RemoteOrigin.CONFIGURED_OFFICIAL_ENDPOINT, source.source_id.value,
            "2026-09-04T00:00:00Z", SourceTrustTier.TIER_0_OFFICIAL, "CONFIGURED"))
        with self.assertRaises(TypeError):
            dataclasses.replace(forged_value, _authority=object())
        official_allowed = policy.authorize_sink(
            forged_value, SinkClass.HTTP_READ_ONLY).allowed

        self.assertEqual(len(subprocess_calls), 0, "REBIND_SUBPROCESS_CALLS")
        self.assertEqual(len(kv_http_calls), 0, "CALLER_KV_HTTP_CALLS")
        self.assertEqual(len(receipt_key_calls), 0, "REBIND_RECEIPT_KEY_CALLS")
        self.assertIsNot(contract_result, ContractProvenance.VERIFIED_FOR_TESTNET_USE)
        self.assertFalse(official_allowed, "FORGED_OFFICIAL_ALLOWED")

    def test_sensitive_public_apis_expose_no_adapter_injection(self):
        from flop_agent import technocore
        self.assertNotIn("opener", inspect.signature(policy.read_configured_endpoint).parameters)
        for operation in (
                technocore.read_official, technocore.read_presence_note,
                technocore.update_did_note_cas, technocore.post_signed,
                technocore.find_signed):
            self.assertNotIn("opener", inspect.signature(operation).parameters)
            self.assertNotIn("signer", inspect.signature(operation).parameters)
        for operation in (
                router.run_subprocess, router.write_filesystem, router.access_secret,
                router.invoke_signer, router.write_presence, router.invoke_mcp,
                router.use_wallet, router.claim_asset, router.make_payment):
            self.assertNotIn("adapter", inspect.signature(operation).parameters)

    def test_compatibility_and_activity_services_ignore_late_rebinding(self):
        compatibility = testnet.compatibility_status
        forged = object.__new__(ReviewedLocalIntent)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            attacker_manifest = root / "compatibility.json"
            attacker_manifest.write_text(json.dumps({
                "status": "COMPATIBILITY_CURRENT", "freshness": {"status": "CURRENT"}}))
            with mock.patch.object(testnet, "COMPATIBILITY_MANIFEST", attacker_manifest):
                self.assertEqual(compatibility(), "COMPATIBILITY_REVIEW_REQUIRED")

            jsonl, markdown = root / "activity.jsonl", root / "activity.md"
            service = _build_activity_service(jsonl, markdown)
            from flop_agent import activity
            with mock.patch.object(activity, "require_local_intent", lambda *_a, **_k: None):
                with self.assertRaises(PermissionError):
                    service(
                        "lobby",
                        {"from": "remote", "seq": 1, "ts": "2026-09-04T00:00:00Z",
                         "text": "remote text"},
                        local_provenance=forged, revision=REVISION,
                        config_version="fixture-v1", output_scope="LOCAL_ONLY")
            self.assertFalse(jsonl.exists())
            self.assertFalse(markdown.exists())

    def test_production_equivalent_action_and_receipt_services_reach_final_spies(self):
        action = LocalActionClass.SUBPROCESS
        issue, require = policy._new_capability_store(
            {"subprocess": binding(action, "subject", "target", "payload", "context")},
            frozenset({"fixture-reviewer"}), lambda: NOW)
        calls = []
        service = router._build_sensitive_action_service(
            require, {action: lambda: calls.append("subprocess")})
        capability = issue(
            "subprocess", action, "subject", target="target", payload="payload",
            context="context", revision=REVISION, config_version="fixture-v1")
        service(capability, action, subject="subject", target="target", payload="payload",
                context="context", revision=REVISION, config_version="fixture-v1")
        self.assertEqual(calls, ["subprocess"])

        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / "identity.json"
            canonical = receipt.canonical_payload({
                "schema": receipt.SCHEMA, "repo": "https://example.invalid/repo",
                "commit": REVISION, "artifact_name": "artifact",
                "timestamp": "2026-09-04T00:00:00Z"}).decode()
            record = binding(
                LocalActionClass.RECEIPT_SIGN, canonical, str(identity.resolve()),
                canonical, receipt.DOMAIN, receipt.SCHEMA)
            issue_receipt, require_receipt = policy._new_capability_store(
                {"receipt": record}, frozenset({"fixture-reviewer"}), lambda: NOW)
            key_calls = []

            class Key:
                def sign(self, payload):
                    key_calls.append(payload)
                    return bytes(64)

            signer = receipt._build_receipt_signer(
                require_receipt, lambda _path: (Key(), "did:key:fixture"))
            capability = issue_receipt(
                "receipt", LocalActionClass.RECEIPT_SIGN, canonical,
                target=str(identity.resolve()), payload=canonical, context=receipt.DOMAIN,
                revision=REVISION, config_version=receipt.SCHEMA)
            result = signer(
                identity, "https://example.invalid/repo", REVISION, "artifact",
                "2026-09-04T00:00:00Z", intent=capability)
            self.assertEqual(result["did"], "did:key:fixture")
            self.assertEqual(len(key_calls), 1)

    def test_production_equivalent_presence_service_uses_real_registry_and_captured_writer(self):
        _, contract_digest = load_semantic_contract()
        config = PresenceConfig(
            room="lobby", nick="flop-agent-fixture",
            semantic_spec_anchor="technocore-presence-semantic-v0.1-reviewed-2026-08-29",
            approved_semantic_contract_sha256=contract_digest,
            approved_agent_version="0.10.0", operator_enabled=True,
            live_write_enabled=True, semantic_spec_approved=True,
            minimum_update_seconds=3600)
        current_note = [None]

        def reader(path):
            if path == ROOMS_PATH:
                return {"rooms": [{"room": "lobby", "last_seq": 10}]}
            if path == AGENT_PATH:
                return {"name": "technocore-chat", "version": "0.10.0",
                        "conventions": {"name_pattern": "^[a-z0-9][a-z0-9_-]{0,47}$"}}
            if path == CONFIG_PATH:
                return {"version": "fixture", "limits": {"reads": 1, "writes": 1,
                        "rooms": 1, "notes": 1}, "retention": {"idle_seconds": 1}}
            if path == config.note_path:
                return current_note[0]
            raise AssertionError(path)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, audit = root / "state.json", root / "audit.jsonl"
            preview = preview_first_write(
                config, state, reader=reader, application_commit=REVISION, now=NOW)
            metadata, request = preview["approval_metadata"], preview["request"]
            approval = {"metadata": metadata, "binding_sha256": approval_digest(metadata)}
            payload = json.dumps(request["body"], sort_keys=True, separators=(",", ":"))
            context = json.dumps({
                "action": "technocore-presence-write", "state_path": str(state.resolve()),
                "audit_path": str(audit.resolve())}, sort_keys=True, separators=(",", ":"))
            record = binding(
                LocalActionClass.PRESENCE_WRITE, approval_digest(metadata), request["path"],
                payload, context, CAPABILITY_CONFIG_VERSION)
            issue, require = policy._new_capability_store(
                {"presence": record}, frozenset({"fixture-reviewer"}), lambda: NOW)
            writer_calls = []

            def writer(path, body):
                writer_calls.append((path, body))
                current_note[0] = body["value"]
                return {"status": 204, "body": ""}

            service = _build_presence_write_service(
                config, state, audit, writer=writer, reader=reader,
                capability_validator=require)
            capability = issue(
                "presence", LocalActionClass.PRESENCE_WRITE, approval_digest(metadata),
                target=request["path"], payload=payload, context=context,
                revision=REVISION, config_version=CAPABILITY_CONFIG_VERSION)
            from flop_agent import presence
            with mock.patch.object(presence, "require_local_intent", lambda *_a, **_k: None), \
                 mock.patch.object(presence, "_execute_approved_write_after_capability",
                                   lambda *_a, **_k: {"status": "BYPASS"}):
                result = service(
                    preview=preview, approval=approval, intent=capability, now=NOW)
            self.assertEqual(result["status"], "SUCCESS")
            self.assertEqual(len(writer_calls), 1)


if __name__ == "__main__":
    unittest.main()
