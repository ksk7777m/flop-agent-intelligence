import dataclasses
import hashlib
import inspect
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from flop_agent import identity, monitor, readiness, receipt, remote_content_policy as policy
from flop_agent import sensitive_action_router as router
from flop_agent import technocore, testnet
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
    _build_configured_reader,
    _build_contract_verifier,
    resolve_reviewed_source,
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
    def test_http_services_capture_real_reviewed_reader_and_ignore_rebinding(self):
        captured_calls = []
        health_calls = []
        attacker_calls = []

        class Response:
            headers = {}

            def __init__(self, url):
                self.url = url

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def geturl(self):
                return self.url

            def read(self, _limit):
                return b'{}'

        def opener(request, timeout):
            captured_calls.append((request.full_url, request.method, timeout))
            return Response(request.full_url)

        reviewed_reader = _build_configured_reader(resolve_reviewed_source, opener)
        def decoder(url, request):
            health_calls.append((url, request.method))
            return {}

        health_reader, *_ = technocore._build_technocore_client(
            resolve_reviewed_source, policy.require_local_intent,
            identity._load_identity, identity._sign_message, decoder)
        healthcheck = technocore._build_technocore_health_service(health_reader)
        readiness_fetch, _, _ = readiness._build_readiness_service(reviewed_reader)
        monitor_fetch, _ = monitor._build_monitor_service(reviewed_reader)

        def attacker(*_args, **_kwargs):
            attacker_calls.append(1)
            return b'attacker'

        with mock.patch.object(technocore, "read_official", attacker), \
             mock.patch.object(readiness, "read_configured_endpoint", attacker), \
             mock.patch.object(readiness, "fetch_bytes", attacker), \
             mock.patch.object(monitor, "read_configured_endpoint", attacker), \
             mock.patch.object(monitor, "fetch_bytes", attacker):
            result = healthcheck()
            self.assertEqual(readiness_fetch(ReviewedSourceId.TECHNOCORE_HEALTH), b'{}')
            self.assertEqual(monitor_fetch(ReviewedSourceId.TECHNOCORE_HEALTH), b'{}')

        self.assertEqual(set(result), {"healthz", "rooms", "lobby"})
        self.assertEqual(len(captured_calls), 2)
        self.assertTrue(all(method == "GET" and timeout == 20
                            for _, method, timeout in captured_calls))
        expected_urls = {
            resolve_reviewed_source(ReviewedSourceId.TECHNOCORE_HEALTH).url,
            resolve_reviewed_source(ReviewedSourceId.TECHNOCORE_ROOMS).url,
            resolve_reviewed_source(ReviewedSourceId.TECHNOCORE_LOBBY_JSON).url,
        }
        self.assertEqual({url for url, method in health_calls if method == "GET"}, expected_urls)
        self.assertEqual(len(health_calls), 3)
        self.assertEqual({url for url, _, _ in captured_calls}, {
            resolve_reviewed_source(ReviewedSourceId.TECHNOCORE_HEALTH).url})
        self.assertEqual(attacker_calls, [])

        discovered = policy.discovered_remote_value(
            next(iter(expected_urls)), RemoteOrigin.REMOTE_DISCOVERED_URL, "remote")
        with self.assertRaises((PermissionError, TypeError, KeyError)):
            reviewed_reader(discovered)

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
             mock.patch.object(receipt, "_load_identity",
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
        self.assertNotIn("opener", inspect.signature(policy.read_configured_endpoint).parameters)
        for operation in (
                technocore.read_official, technocore.read_presence_note,
                technocore.update_did_note_cas, technocore.post_signed,
                technocore.find_signed):
            self.assertNotIn("opener", inspect.signature(operation).parameters)
            self.assertNotIn("signer", inspect.signature(operation).parameters)
        for operation in (
                technocore.healthcheck, readiness.fetch_bytes,
                readiness.compare_spec_hashes, readiness.run_readiness_check,
                monitor.fetch_bytes, monitor.run_monitor):
            for parameter in ("fetcher", "opener", "reader", "http_client", "adapter"):
                self.assertNotIn(parameter, inspect.signature(operation).parameters)
        self.assertFalse(hasattr(identity, "load_identity"))
        self.assertFalse(hasattr(identity, "sign_message"))
        for operation in (
                identity.get_public_did, identity.verify_local_identity_status,
                identity.sign_with_authorized_identity):
            for parameter in ("loader", "signer", "adapter", "identity_path"):
                self.assertNotIn(parameter, inspect.signature(operation).parameters)
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

    def test_identity_service_keeps_keys_internal_and_ignores_late_rebinding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.json"
            did = identity.create_identity(path)
            canonical, _ = identity.canonical_message("lobby", 7, "fixture")
            record = binding(
                LocalActionClass.IDENTITY_SIGN, canonical, str(path.resolve()),
                canonical, identity.IDENTITY_SIGN_CONTEXT)
            issue, require = policy._new_capability_store(
                {"identity": record}, frozenset({"fixture-reviewer"}), lambda: NOW)
            trusted_loader = identity._load_identity
            loader_calls = []
            attacker_loader_calls = []
            attacker_signer_calls = []

            def loader(selected):
                loader_calls.append(selected)
                return trusted_loader(selected)

            get_did, verify_status, sign = identity._build_local_identity_service(
                path, require, loader, identity._sign_message, identity.verify_message)
            capability = issue(
                "identity", LocalActionClass.IDENTITY_SIGN, canonical,
                target=str(path.resolve()), payload=canonical,
                context=identity.IDENTITY_SIGN_CONTEXT, revision=REVISION,
                config_version="fixture-v1")
            with mock.patch.object(
                    identity, "_load_identity",
                    side_effect=lambda *_a: attacker_loader_calls.append(1)), \
                 mock.patch.object(
                    identity, "_sign_message",
                    side_effect=lambda *_a: attacker_signer_calls.append(1)):
                result = sign(
                    "lobby", 7, "fixture", intent=capability,
                    revision=REVISION, config_version="fixture-v1")
                self.assertEqual(get_did(), did)
                self.assertEqual(verify_status()["verified"], True)

            self.assertEqual(result["did"], did)
            self.assertEqual(set(result), {"did", "signature", "text"})
            self.assertNotIn("seed", repr(result).lower())
            self.assertNotIn("private", repr(result).lower())
            self.assertEqual(len(loader_calls), 3)
            self.assertEqual(attacker_loader_calls, [])
            self.assertEqual(attacker_signer_calls, [])

            forged = object.__new__(ReviewedLocalIntent)
            guarded_loader_calls = []
            _, _, guarded_sign = identity._build_local_identity_service(
                path, require, lambda *_a: guarded_loader_calls.append(1),
                identity._sign_message, identity.verify_message)
            with self.assertRaises(PermissionError):
                guarded_sign(
                    "lobby", 7, "fixture", intent=forged,
                    revision=REVISION, config_version="fixture-v1")
            self.assertEqual(guarded_loader_calls, [])

    def test_receipt_authorized_path_ignores_late_loader_rebinding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.json"
            identity.create_identity(path)
            canonical = receipt.canonical_payload({
                "schema": receipt.SCHEMA, "repo": "https://example.invalid/repo",
                "commit": REVISION, "artifact_name": "artifact",
                "timestamp": "2026-09-04T00:00:00Z"}).decode()
            record = binding(
                LocalActionClass.RECEIPT_SIGN, canonical, str(path.resolve()),
                canonical, receipt.DOMAIN, receipt.SCHEMA)
            issue, require = policy._new_capability_store(
                {"receipt": record}, frozenset({"fixture-reviewer"}), lambda: NOW)
            trusted_loader = identity._load_identity
            trusted_calls = []
            attacker_calls = []

            def loader(selected):
                trusted_calls.append(selected)
                return trusted_loader(selected)

            signer = receipt._build_receipt_signer(require, loader)
            capability = issue(
                "receipt", LocalActionClass.RECEIPT_SIGN, canonical,
                target=str(path.resolve()), payload=canonical, context=receipt.DOMAIN,
                revision=REVISION, config_version=receipt.SCHEMA)
            with mock.patch.object(
                    receipt, "_load_identity",
                    side_effect=lambda *_a: attacker_calls.append("loader")), \
                 mock.patch.object(
                    receipt, "invoke_signer",
                    side_effect=lambda *_a, **_k: attacker_calls.append("signer"),
                    create=True):
                result = signer(
                    path, "https://example.invalid/repo", REVISION, "artifact",
                    "2026-09-04T00:00:00Z", intent=capability)
            self.assertEqual(result["schema"], receipt.SCHEMA)
            self.assertEqual(len(trusted_calls), 1)
            self.assertEqual(attacker_calls, [])

    def test_populated_contract_verifier_ignores_global_rebinding(self):
        contract = "0x" + "1" * 40
        first = ContractEvidenceRecord(
            contract, ReviewedSourceId.FLOP_FINANCE, "a" * 64,
            "2026-09-04T00:00:00Z", True)
        second = ContractEvidenceRecord(
            contract, ReviewedSourceId.TECHNOCORE_README, "b" * 64,
            "2026-09-04T00:00:01Z", True)
        records = {
            "first": {
                "source_id": first.source_id.value, "contract": contract,
                "artifact_sha256": first.artifact_sha256,
                "observed_at": first.observed_at,
                "canonical_artifact_id": "flop-contract", "reviewed_at": first.observed_at,
                "provenance_root": "FLOP_FINANCE", "reviewer": "fixture-reviewer",
                "policy_version": policy.POLICY_VERSION,
            },
            "second": {
                "source_id": second.source_id.value, "contract": contract,
                "artifact_sha256": second.artifact_sha256,
                "observed_at": second.observed_at,
                "canonical_artifact_id": "technocore-contract",
                "reviewed_at": second.observed_at,
                "provenance_root": "TECHNOCORE_PROJECT", "reviewer": "fixture-reviewer",
                "policy_version": policy.POLICY_VERSION,
            },
        }
        approvals = {"approved": {
            "contract": contract, "policy_version": policy.POLICY_VERSION,
            "status": "APPROVED_FOR_TESTNET_USE"}}
        reviewed, derive, _ = _build_contract_verifier(records, approvals, {})
        evidence = (reviewed("first", first), reviewed("second", second))
        self.assertEqual(
            derive(evidence, contract, approval_id="approved"),
            ContractProvenance.VERIFIED_FOR_TESTNET_USE)

        attacker_calls = []
        _, _, empty = _build_contract_verifier({}, {}, {})

        def attacker(*_args, **_kwargs):
            attacker_calls.append(1)
            return ContractProvenance.VERIFIED_FOR_TESTNET_USE

        with mock.patch.object(
                policy, "_derive_contract_records",
                side_effect=attacker), \
             mock.patch.object(policy, "_REVIEWED_EVIDENCE_RECORDS", {}), \
             mock.patch.object(policy, "_SOURCE_PROVENANCE_ROOTS", {}):
            result = derive(evidence, contract, approval_id="approved")
            negative = empty("attacker", contract)
        self.assertEqual(result, ContractProvenance.VERIFIED_FOR_TESTNET_USE)
        self.assertEqual(negative, ContractProvenance.UNVERIFIED)
        self.assertEqual(attacker_calls, [])

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
