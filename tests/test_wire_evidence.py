import base64, copy, dataclasses, hashlib, inspect, io, json, logging, pickle
import tempfile, traceback, unittest
from unittest import mock
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from flop_agent import evidence_authority as authority
from flop_agent import identity, technocore
from flop_agent import remote_content_policy as policy
from flop_agent import wire_evidence as wire
from flop_agent.proof import ProofRecord

REVISION = "a" * 40
NOW = datetime(2026, 9, 4, 0, 5, tzinfo=timezone.utc)
EVENTS = ("write_accepted", "read_back_observed", "decode_valid",
          "signature_valid", "state_replay_valid", "evidence_confirmed")

def b64(raw): return base64.urlsafe_b64encode(raw).decode().rstrip("=")
def public_b64(key):
    return b64(key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw))

def agreement_fixture(rail="bitcoin"):
    proposer, accepter = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    terms = {"lock_statement": "LOCKED", "units": "fixture-only"}
    offer_bytes = wire.agreement_proposal_signing_bytes(
        protocol="tclk-alpha", proposer_id="alice", counterparty_id="bob",
        terms=terms, rail_raw=rail, reference="ref-1")
    offer_sig = b64(proposer.sign(offer_bytes))
    offer_id = wire.recompute_offer_id(offer_bytes, offer_sig)
    proposal = wire.AgreementProposal(
        "tclk-alpha", "alice", "bob", public_b64(proposer), terms, rail,
        "ref-1", offer_sig, offer_id)
    accept_bytes = wire.agreement_acceptance_signing_bytes(
        protocol="tclk-alpha", accepter_id="bob", proposer_id="alice",
        offer_id=offer_id, statement="ACCEPT")
    accept_sig = b64(accepter.sign(accept_bytes))
    agreement_id = wire.recompute_agreement_id(offer_id, accept_bytes, accept_sig)
    acceptance = wire.AgreementAcceptance(
        "tclk-alpha", "bob", "alice", public_b64(accepter), offer_id,
        "ACCEPT", accept_sig, agreement_id)
    return proposal, acceptance

def binding(action, material, config="fixture-v1"):
    digest = lambda value: hashlib.sha256(value.encode()).hexdigest()
    return {"reviewer": "fixture-reviewer", "approved_at": "2026-09-04T00:00:00Z",
            "action": action.value, "subject_sha256": digest(material["subject"]),
            "target_sha256": digest(material["target"]),
            "payload_sha256": digest(material["payload"]),
            "context_sha256": digest(material["context"]), "revision": REVISION,
            "config_version": config}

def signing_store(action, context, target, purpose, config="fixture-v1"):
    material = wire.signing_capability_material(
        context, action_class=action.value, target=target, revision=REVISION,
        config_version=config, purpose=purpose)
    issue, require = policy._new_capability_store(
        {"sign": binding(action, material, config)},
        frozenset({"fixture-reviewer"}), lambda: NOW)
    intent = issue("sign", action, material["subject"], target=material["target"],
                   payload=material["payload"], context=material["context"],
                   revision=REVISION, config_version=config)
    return intent, require

class NonceAndSignerTests(unittest.TestCase):
    def test_nonce_exact_string_in_context_and_proof(self):
        for value in ("9007199254740992", "9223372036854775807",
                      str(wire.MAX_PROTOCOL_NONCE)):
            self.assertEqual(wire.parse_nonce(value).decimal, value)
            self.assertEqual(ProofRecord("x", "x", "x", None, "x", "x", nonce=value).nonce, value)
        for value in (1, 1.0, "01", "1e3", str(wire.MAX_PROTOCOL_NONCE + 1)):
            with self.subTest(value=value), self.assertRaises(wire.WireSafetyError):
                ProofRecord("x", "x", "x", None, "x", "x", nonce=value)
        activity = Path(__file__).resolve().parents[1] / "data" / "activity.jsonl"
        for line in activity.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            if "nonce" in record:
                self.assertIsInstance(record["nonce"], str)

    def test_capability_material_binds_all_signing_fields(self):
        context = wire.build_signing_context("lobby", "7", "hello")
        material = wire.signing_capability_material(
            context, action_class="SIGNED_ROOM_POST", target="lobby",
            revision=REVISION, config_version="fixture-v1", purpose="post")
        self.assertEqual(set(json.loads(material["subject"])), {
            "room", "nonce", "text_sha256", "canonical_sha256", "action_class",
            "target", "revision", "config_version"})
        self.assertEqual(material["payload"], "lobby|7|hello")

    def test_large_nonce_actual_identity_service_and_external_match(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.json"; identity._create_identity(path)
            nonce = str(wire.MAX_PROTOCOL_NONCE)
            context = wire.build_signing_context("lobby", nonce, "fixture")
            intent, require = signing_store(policy.LocalActionClass.IDENTITY_SIGN,
                                            context, str(path.resolve()),
                                            identity.IDENTITY_SIGN_CONTEXT)
            calls = []
            def signer(key, room, selected, text):
                calls.append(selected); return identity._sign_message(key, room, selected, text)
            _, _, sign = identity._build_local_identity_service(
                path, require, identity._load_identity, signer, identity.verify_message)
            result = sign("lobby", nonce, "fixture", intent=intent, revision=REVISION,
                          config_version="fixture-v1",
                          external_challenge=context.canonical_bytes)
            self.assertEqual((result["nonce"], calls), (nonce, [nonce]))

    def test_wrong_nonce_and_external_mismatch_precede_key_access(self):
        path = Path("/tmp/nonexistent-fixture-key")
        context = wire.build_signing_context("lobby", "7", "fixture")
        intent, require = signing_store(policy.LocalActionClass.IDENTITY_SIGN,
                                        context, str(path.resolve()),
                                        identity.IDENTITY_SIGN_CONTEXT)
        calls = []
        _, _, sign = identity._build_local_identity_service(
            path, require, lambda *_: calls.append("key"),
            lambda *_: calls.append("sign"), lambda *_: None)
        with self.assertRaises(PermissionError):
            sign("lobby", "8", "fixture", intent=intent, revision=REVISION,
                 config_version="fixture-v1")
        with self.assertRaises(wire.WireSafetyError) as caught:
            sign("lobby", "7", "fixture", intent=object(), revision=REVISION,
                 config_version="fixture-v1", external_challenge=b"wrong")
        self.assertEqual(caught.exception.code, "SIGNING_CONTEXT_MISMATCH")
        self.assertEqual(calls, [])

    def test_wrong_text_precedes_identity_key_and_signer_access(self):
        path = Path("/tmp/nonexistent-fixture-key")
        context = wire.build_signing_context("lobby", "7", "approved")
        intent, require = signing_store(
            policy.LocalActionClass.IDENTITY_SIGN, context, str(path.resolve()),
            identity.IDENTITY_SIGN_CONTEXT)
        calls = []
        _, _, sign = identity._build_local_identity_service(
            path, require, lambda *_: calls.append("key"),
            lambda *_: calls.append("sign"), lambda *_: None)
        with self.assertRaises(PermissionError):
            sign("lobby", "7", "changed", intent=intent, revision=REVISION,
                 config_version="fixture-v1")
        self.assertEqual(calls, [])

    def test_constructed_identity_service_ignores_material_and_canonical_rebinding(self):
        path = Path("/tmp/nonexistent-fixture-key")
        context = wire.build_signing_context("lobby", "7", "approved")
        intent, require = signing_store(
            policy.LocalActionClass.IDENTITY_SIGN, context, str(path.resolve()),
            identity.IDENTITY_SIGN_CONTEXT)
        effects = []
        _, _, sign = identity._build_local_identity_service(
            path, require,
            lambda *_: (effects.append("key") or (object(), "did:key:fixture")),
            lambda _key, _room, _nonce, text:
                (effects.append("sign") or ("signature", text)),
            lambda *_: None)
        attacker = lambda *_args, **_kwargs: effects.append("attacker")
        with mock.patch.object(identity, "_capture_signing_policy", attacker), \
             mock.patch.object(identity, "build_signing_context", attacker), \
             mock.patch.object(identity, "signing_capability_material", attacker), \
             mock.patch.object(identity, "canonical_message", attacker), \
             mock.patch.object(identity, "_load_identity", attacker), \
             mock.patch.object(identity, "_sign_message", attacker):
            with self.assertRaises(PermissionError):
                sign("lobby", "8", "changed", intent=intent, revision=REVISION,
                     config_version="fixture-v1")
            result = sign("lobby", "7", "approved", intent=intent, revision=REVISION,
                          config_version="fixture-v1")
        self.assertEqual((result["nonce"], effects), ("7", ["key", "sign"]))

    def test_production_equivalent_post_binds_nonce_before_key(self):
        context = wire.build_signing_context("lobby", "7", "fixture")
        intent, require = signing_store(policy.LocalActionClass.SIGNED_ROOM_POST,
                                        context, "lobby", "fixture-post")
        calls = []
        def decoder(_url, request):
            calls.append(request.method)
            return ({"messages": [{"from": "did:key:fixture", "nonce": "7",
                                    "text": "fixture", "seq": 1}]}
                    if request.method == "GET" else {"ok": True})
        _, _, _, post, _ = technocore._build_technocore_client(
            lambda *_: None, require, lambda *_: (object(), "did:key:fixture"),
            lambda *_: ("signature", "fixture"), decoder)
        result = post(Path("fixture"), "lobby", "fixture", intent=intent,
                      revision=REVISION, config_version="fixture-v1",
                      context="fixture-post", nonce="7",
                      external_challenge=context.canonical_bytes)
        self.assertEqual((result["nonce"], calls), ("7", ["POST", "GET"]))

    def test_constructed_post_ignores_rebinding_and_rejects_wrong_text_nonce(self):
        context = wire.build_signing_context("lobby", "7", "approved")
        intent, require = signing_store(
            policy.LocalActionClass.SIGNED_ROOM_POST, context, "lobby", "fixture-post")
        effects = []
        attacker = lambda *_args, **_kwargs: effects.append("attacker")
        def decoder(_url, request):
            effects.append(request.method)
            if request.method == "GET":
                return {"messages": [{"from": "did:key:fixture", "nonce": "7",
                                      "text": "approved", "seq": "1"}]}
            return {"ok": True}
        _, _, _, post, _ = technocore._build_technocore_client(
            lambda *_: None, require,
            lambda *_: (effects.append("key") or (object(), "did:key:fixture")),
            lambda _key, _room, _nonce, text:
                (effects.append("sign") or ("signature", text)), decoder)
        with mock.patch.object(technocore, "_capture_signing_policy", attacker), \
             mock.patch.object(technocore, "build_signing_context", attacker), \
             mock.patch.object(technocore, "signing_capability_material", attacker), \
             mock.patch.object(technocore, "canonical_message", attacker), \
             mock.patch.object(technocore, "_load_identity", attacker), \
             mock.patch.object(technocore, "_sign_message", attacker), \
             mock.patch.object(technocore, "_PRODUCTION_RESPONSE_DECODER", attacker):
            for nonce, text in (("8", "approved"), ("7", "changed")):
                with self.subTest(nonce=nonce, text=text), self.assertRaises(PermissionError):
                    post(Path("fixture"), "lobby", text, intent=intent,
                         revision=REVISION, config_version="fixture-v1",
                         context="fixture-post", nonce=nonce)
            result = post(Path("fixture"), "lobby", "approved", intent=intent,
                          revision=REVISION, config_version="fixture-v1",
                          context="fixture-post", nonce="7")
        self.assertEqual((result["nonce"], effects),
                         ("7", ["key", "sign", "POST", "GET"]))

class EvidenceAuthorityTests(unittest.TestCase):
    RAW = (b'{"seq":"1","generation":"gen-1"}\n'
           b'{"seq":"2","generation":"gen-1"}')

    def make_authority(self):
        # PRODUCTION_EQUIVALENT_FACTORY: no caller registry, policy, verifier,
        # clock, marker, or projection dependency enters this boundary.
        return authority._build_evidence_service_for_test()

    def complete(self, service):
        acquisition = service.acquire_reviewed_export("reviewed", self.RAW)
        return acquisition, service.verify_completeness(acquisition)

    def finality(self, service):
        proposal, acceptance = agreement_fixture()
        rail = wire.RailObservation.observed(
            "bitcoin", "ref-1", "COMPLETED", protocol_valid=True)
        agreement = service.verify_agreement(proposal, acceptance)
        finality = service.verify_rail(agreement, rail)
        artifact = service.describe_finality_artifact(finality)
        return agreement, finality, artifact

    def test_opaque_types_block_construction_copy_serialization(self):
        for cls in (authority.TrustedAcquisitionEvidence,
                    authority.VerifiedTranscriptCompleteness, authority.VerifiedAgreement,
                    authority.VerifiedRailFinality, authority.VerifiedReadBackEvidence,
                    authority.VerifiedEvidenceBundle):
            with self.assertRaises(PermissionError): cls()
        service = self.make_authority()
        acquisition, token = self.complete(service)
        for issued in (acquisition, token):
            for operation in (copy.copy, copy.deepcopy, pickle.dumps):
                with self.assertRaises(TypeError): operation(issued)

    def test_public_export_has_no_raw_and_third_party_never_complete(self):
        secret = "fixture-secret-90817"
        raw = json.dumps({"seq": "1", "generation": "gen-1", "message": secret}).encode()
        observation = authority.observe_third_party_export(
            raw, source_id="third-party", acquired_at_ms=1,
            verifier_revision=REVISION, generation="gen-1")
        rendered = repr(dataclasses.asdict(observation))
        self.assertNotIn(secret, rendered); self.assertNotIn("raw", rendered.lower())
        self.assertEqual(observation.as_public_evidence()["completeness"],
                         "TRANSCRIPT_COMPLETENESS_UNVERIFIED")
        self.assertIsNone(
            authority.production_evidence_authority.verify_completeness(observation))

    def test_completeness_consumes_only_bound_trusted_acquisition(self):
        service = self.make_authority()
        acquisition, complete = self.complete(service)
        observation = service.describe_acquisition(acquisition)
        self.assertEqual((observation.assessment.first_seq,
                          observation.assessment.last_seq,
                          observation.assessment.records), ("1", "2", 2))
        self.assertNotIn("first_seq", inspect.signature(service.verify_completeness).parameters)
        self.assertNotIn("last_seq", inspect.signature(service.verify_completeness).parameters)
        self.assertNotIn("truncation_indicated",
                         inspect.signature(service.verify_completeness).parameters)
        self.assertIsInstance(complete, authority.VerifiedTranscriptCompleteness)
        with self.assertRaises(PermissionError):
            service.acquire_reviewed_export("reviewed", self.RAW[:-1])
        for source_id in ("reviewed-truncated", "reviewed-outside-bounds",
                          "reviewed-descriptive"):
            acquisition = service.acquire_reviewed_export(source_id, self.RAW)
            self.assertIsNone(service.verify_completeness(acquisition))

    def test_replaced_observation_has_no_acquisition_authority(self):
        service = self.make_authority()
        acquisition = service.acquire_reviewed_export("reviewed", self.RAW)
        original = service.describe_acquisition(acquisition)
        clone = dataclasses.replace(original)
        self.assertIsNot(clone, original)
        self.assertEqual(clone, original)
        self.assertIsNone(service.verify_completeness(clone))

    def test_agreement_arbitrary_id_and_descriptive_forgery_fail(self):
        proposal, acceptance = agreement_fixture(); service = self.make_authority()
        self.assertIsInstance(service.verify_agreement(proposal, acceptance),
                              authority.VerifiedAgreement)
        self.assertIsNone(service.verify_agreement(
            proposal, dataclasses.replace(acceptance, agreement_id="0" * 64)))
        self.assertIsNone(wire.verify_tclk_alpha_agreement(
            proposal, acceptance).verified_agreement(proposal, acceptance))

    def test_agreement_enforces_state_progression(self):
        proposal, acceptance = agreement_fixture(); service = self.make_authority()
        self.assertIsNone(service.verify_agreement(
            proposal, dataclasses.replace(acceptance, statement="REJECT")))
        state = wire.AgreementState.PROPOSED
        for event in ("offer_verified", "acceptance_verified", "agreement_verified"):
            state = wire.transition_agreement(state, event)
        self.assertIs(state, wire.AgreementState.AGREEMENT_VERIFIED)

    def test_rail_finality_is_registry_issued_and_paper_is_impossible(self):
        proposal, acceptance = agreement_fixture()
        rail = wire.RailObservation.observed(
            "bitcoin", "ref-1", "COMPLETED",
            protocol_valid=True)
        service = self.make_authority()
        finality = service.verify_rail(service.verify_agreement(proposal, acceptance), rail)
        self.assertIsInstance(finality, authority.VerifiedRailFinality)
        self.assertEqual(wire.assess_finality("COMPLETED", rail).finality_status,
                         wire.EvidenceStatus.FINALITY_UNVERIFIED)
        pp, pa = agreement_fixture("paper")
        paper = wire.RailObservation.observed(
            "paper", "ref-1", "COMPLETED",
            protocol_valid=True)
        self.assertIsNone(service.verify_rail(service.verify_agreement(pp, pa), paper))

    def test_timestamp_flip_third_party_never_changes_finality(self):
        proposal, acceptance = agreement_fixture(); service = self.make_authority()
        agreement = service.verify_agreement(proposal, acceptance)
        self.assertIsInstance(agreement, authority.VerifiedAgreement)
        folds = []
        for raw in (b'{"seq":"1","ts":99,"generation":"gen-1"}',
                    b'{"seq":"1","ts":101,"generation":"gen-1"}'):
            observation = authority.observe_third_party_export(
                raw, source_id="third-party", acquired_at_ms=1,
                verifier_revision=REVISION, generation="gen-1")
            folds.append(authority.observed_deadline_fold(
                observation, deadline_ms=100))
            self.assertIsNone(service.verify_completeness(observation))
            bundle = service.issue_bundle(completeness=None, agreement=agreement,
                                          finality=None, readback=None)
            self.assertEqual(service.as_public_evidence(bundle)["finality"],
                             "FINALITY_UNVERIFIED")
        self.assertEqual(folds, ["PRE_DEADLINE_OBSERVED", "POST_DEADLINE_OBSERVED"])

    def test_readback_and_bundle_require_same_registry_issued_tokens(self):
        one, two = self.make_authority(), self.make_authority()
        agreement, finality, artifact = self.finality(one)
        self.assertIsNone(one.verify_readback(
            finality, artifact["artifact_sha256"],
            ("write_accepted", "evidence_confirmed")))
        self.assertIsNone(one.verify_readback(finality, "e" * 64, EVENTS))
        readback = one.verify_readback(
            finality, artifact["artifact_sha256"], EVENTS)
        self.assertIsInstance(readback, authority.VerifiedReadBackEvidence)
        with self.assertRaises(PermissionError):
            one.issue_bundle(completeness=None, agreement=agreement,
                             finality=finality,
                             readback=object.__new__(authority.VerifiedReadBackEvidence))
        with self.assertRaises(PermissionError):
            two.issue_bundle(completeness=None, agreement=None,
                             finality=None, readback=readback)
        with self.assertRaises(PermissionError):
            wire.EvidenceBundle(wire.EvidenceStatus.SIGNED_CONTENT_VERIFIED,
                wire.EvidenceStatus.VENUE_METADATA_OBSERVED,
                wire.EvidenceStatus.TRANSCRIPT_COMPLETENESS_VERIFIED,
                wire.EvidenceStatus.AGREEMENT_VERIFIED,
                wire.EvidenceStatus.RAIL_CRYPTO_VERIFIED,
                wire.EvidenceStatus.FINALITY_VERIFIED)

    def test_readback_finality_artifacts_cannot_be_mixed(self):
        service = self.make_authority()
        agreement_a, finality_a, artifact_a = self.finality(service)
        agreement_b, finality_b, artifact_b = self.finality(service)
        self.assertNotEqual(artifact_a["artifact_sha256"], artifact_b["artifact_sha256"])
        self.assertIsNone(service.verify_readback(
            finality_a, artifact_b["artifact_sha256"], EVENTS))
        readback_a = service.verify_readback(
            finality_a, artifact_a["artifact_sha256"], EVENTS)
        with self.assertRaises(PermissionError):
            service.issue_bundle(completeness=None, agreement=agreement_b,
                                 finality=finality_b, readback=readback_a)
        bundle = service.issue_bundle(
            completeness=None, agreement=agreement_a,
            finality=finality_a, readback=readback_a)
        projected = service.as_public_evidence(bundle)
        self.assertEqual((projected["finality"], projected["read_back"]),
                         ("FINALITY_VERIFIED", "EVIDENCE_CONFIRMED"))

    def test_full_production_equivalent_bundle_and_cross_authority_matrix(self):
        one, two = self.make_authority(), self.make_authority()
        proposal, acceptance = agreement_fixture()
        rail = wire.RailObservation.observed(
            "bitcoin", "ref-1", "COMPLETED", protocol_valid=True)
        acquisition, complete = self.complete(one)
        agreement = one.verify_agreement(proposal, acceptance)
        finality = one.verify_rail(agreement, rail)
        artifact = one.describe_finality_artifact(finality)
        readback = one.verify_readback(finality, artifact["artifact_sha256"], EVENTS)
        bundle = one.issue_bundle(completeness=complete, agreement=agreement,
                                  finality=finality, readback=readback)
        projected = dict(one.as_public_evidence(bundle))
        self.assertEqual({key: projected[key] for key in (
            "transcript", "agreement", "settlement", "finality", "read_back")}, {
            "transcript": "TRANSCRIPT_COMPLETENESS_VERIFIED",
            "agreement": "AGREEMENT_VERIFIED", "settlement": "RAIL_CRYPTO_VERIFIED",
            "finality": "FINALITY_VERIFIED", "read_back": "EVIDENCE_CONFIRMED"})
        self.assertEqual(projected["projection_schema"],
                         "flop-public-evidence-projection-v1")
        self.assertEqual(projected["authority_provenance"],
                         "OFFLINE_PRODUCTION_EQUIVALENT")
        self.assertEqual(projected["serialized_authority"], "DESCRIPTIVE_ONLY")
        with self.assertRaises(PermissionError): two.describe_acquisition(acquisition)
        self.assertIsNone(two.verify_completeness(acquisition))
        self.assertIsNone(two.verify_rail(agreement, rail))
        for kwargs in ({"completeness": complete, "agreement": None,
                        "finality": None, "readback": None},
                       {"completeness": None, "agreement": agreement,
                        "finality": None, "readback": None},
                       {"completeness": None, "agreement": None,
                        "finality": finality, "readback": None},
                       {"completeness": None, "agreement": None,
                        "finality": None, "readback": readback}):
            with self.assertRaises(PermissionError): two.issue_bundle(**kwargs)
        with self.assertRaises(PermissionError): two.as_public_evidence(bundle)
        with self.assertRaises(PermissionError):
            authority.production_evidence_authority.as_public_evidence(bundle)

    def test_registry_and_caller_authority_attacks_do_not_reach_production_projection(self):
        self.assertFalse(hasattr(authority, "_build_evidence_authority"))
        self.assertEqual(inspect.signature(
            authority._build_evidence_service_for_test).parameters, {})
        with self.assertRaises(PermissionError): authority._SealedEvidenceService()
        forged_finality = object.__new__(authority.VerifiedRailFinality)
        forged_bundle = object.__new__(authority.VerifiedEvidenceBundle)
        for name in ("_finality", "__finality", "_bundles", "__bundles", "__dict__"):
            self.assertFalse(hasattr(authority.production_evidence_authority, name))
        with self.assertRaises((AttributeError, TypeError)):
            setattr(authority.production_evidence_authority, "_finality", {forged_finality: object()})
        with self.assertRaises(PermissionError):
            authority.production_evidence_authority.issue_bundle(
                completeness=None, agreement=None, finality=forged_finality, readback=None)
        with self.assertRaises(PermissionError):
            authority.production_evidence_authority.as_public_evidence(forged_bundle)
        with self.assertRaises(TypeError):
            tuple.__new__(type(authority.production_evidence_authority), ())
        helper = object.__new__(type(authority.production_evidence_authority))
        with self.assertRaises(PermissionError):
            helper.as_public_evidence(forged_bundle)
        with self.assertRaises(PermissionError):
            authority.production_evidence_authority.as_public_evidence(forged_bundle)

    def test_constructed_root_ignores_later_module_global_rebinding(self):
        service = self.make_authority()
        proposal, acceptance = agreement_fixture()
        rail = wire.RailObservation.observed(
            "bitcoin", "ref-1", "COMPLETED", protocol_valid=True)
        names = ("wire", "_sha", "_safe_export_assessment", "_rail_observation_hash",
                 "AUTHORITY_SCHEMA_VERSION", "MappingProxyType", "ExportObservation",
                 "TrustedAcquisitionEvidence", "VerifiedAgreement",
                 "VerifiedRailFinality", "VerifiedReadBackEvidence",
                 "VerifiedEvidenceBundle", "_RailRecord", "_ReadBackRecord",
                 "_BundleRecord", "_SealedEvidenceService")
        originals = {name: getattr(authority, name) for name in names}
        try:
            for name in names:
                setattr(authority, name, object())
            acquisition = service.acquire_reviewed_export("reviewed", self.RAW)
            complete = service.verify_completeness(acquisition)
            agreement = service.verify_agreement(proposal, acceptance)
            finality = service.verify_rail(agreement, rail)
            artifact = service.describe_finality_artifact(finality)
            readback = service.verify_readback(
                finality, artifact["artifact_sha256"], EVENTS)
            bundle = service.issue_bundle(
                completeness=complete, agreement=agreement,
                finality=finality, readback=readback)
            self.assertEqual(service.as_public_evidence(bundle)["finality"],
                             "FINALITY_VERIFIED")
        finally:
            for name, value in originals.items(): setattr(authority, name, value)

    def test_all_verified_tokens_reject_reconstruction(self):
        service = self.make_authority(); proposal, acceptance = agreement_fixture()
        rail = wire.RailObservation.observed(
            "bitcoin", "ref-1", "COMPLETED", protocol_valid=True)
        acquisition, complete = self.complete(service)
        agreement = service.verify_agreement(proposal, acceptance)
        finality = service.verify_rail(agreement, rail)
        artifact = service.describe_finality_artifact(finality)
        readback = service.verify_readback(finality, artifact["artifact_sha256"], EVENTS)
        bundle = service.issue_bundle(completeness=complete, agreement=agreement,
                                      finality=finality, readback=readback)
        for token in (acquisition, complete, agreement, finality, readback, bundle):
            with self.subTest(token=type(token).__name__):
                for operation in (copy.copy, copy.deepcopy, pickle.dumps):
                    with self.assertRaises(TypeError): operation(token)
                with self.assertRaises(TypeError): dataclasses.replace(token)
                with self.assertRaises(TypeError): json.dumps(token)
                forged = object.__new__(type(token))
                with self.assertRaises(AttributeError): setattr(forged, "authority", True)
                reconstructed = json.loads(json.dumps({
                    "token_type": type(token).__name__, "verified": True}))
                self.assertIsInstance(reconstructed, dict)
                with self.assertRaises(SyntaxError): eval(repr(token), {})
        forged_agreement = object.__new__(authority.VerifiedAgreement)
        self.assertIsNone(service.verify_rail(forged_agreement, rail))

    def test_serialized_public_projection_never_regains_in_process_authority(self):
        service = self.make_authority()
        agreement, finality, artifact = self.finality(service)
        readback = service.verify_readback(finality, artifact["artifact_sha256"], EVENTS)
        bundle = service.issue_bundle(
            completeness=None, agreement=agreement, finality=finality, readback=readback)
        reconstructed = json.loads(json.dumps(dict(service.as_public_evidence(bundle))))
        self.assertEqual(reconstructed["serialized_authority"], "DESCRIPTIVE_ONLY")
        operations = (
            lambda: authority.production_evidence_authority.as_public_evidence(reconstructed),
            lambda: service.as_public_evidence(reconstructed),
            lambda: service.verify_rail(reconstructed, wire.RailObservation.observed(
                "bitcoin", "ref-1", "COMPLETED", protocol_valid=True)),
            lambda: service.issue_bundle(completeness=None, agreement=reconstructed,
                                         finality=None, readback=None),
        )
        for operation in operations:
            with self.assertRaises((PermissionError, TypeError)): operation()

    def test_public_verified_field_forgery_is_rejected(self):
        with self.assertRaises(PermissionError):
            wire.TranscriptCompletenessClaim("0" * 64, "gen-1", "1", "1", True)
        with self.assertRaises(PermissionError):
            wire.RailObservation.observed(
                "bitcoin", "tx-1", "COMPLETED",
                crypto_status=wire.RailCryptoStatus.RAIL_CRYPTO_VERIFIED)
        with self.assertRaises(PermissionError):
            wire.FinalityAssessment(None, wire.EvidenceStatus.RAIL_CRYPTO_VERIFIED,
                                    wire.EvidenceStatus.FINALITY_VERIFIED,
                                    "ECONOMIC_VALUE_VERIFIED", "forged")
        with self.assertRaises(PermissionError):
            wire.AgreementVerification(
                wire.EvidenceStatus.SIGNED_CONTENT_VERIFIED,
                wire.EvidenceStatus.SIGNED_CONTENT_VERIFIED,
                "OFFER_ID_VERIFIED", "AGREEMENT_ID_VERIFIED",
                "COUNTERPARTY_VERIFIED", "LOCK_SEMANTICS_VERIFIED",
                wire.EvidenceStatus.AGREEMENT_VERIFIED)

class RedactionAndSurfaceTests(unittest.TestCase):
    def assert_safe_error(self, operation, secret):
        stream = io.StringIO(); handler = logging.StreamHandler(stream)
        logger = logging.getLogger("wire-redaction-test"); logger.addHandler(handler)
        try:
            try: operation()
            except wire.WireSafetyError as error:
                rendered = (str(error) + repr(error) + repr(error.__dict__)
                            + repr(error.as_evidence())
                            + "".join(traceback.format_exception(
                                type(error), error, error.__traceback__)))
                self.assertIsNone(error.__cause__); self.assertIsNone(error.__context__)
                logger.error("safe boundary failure", exc_info=error)
            else: self.fail("safe error was not raised")
        finally: logger.removeHandler(handler)
        self.assertNotIn(secret, rendered + stream.getvalue())

    def test_json_and_utf8_upstream_errors_retain_no_raw(self):
        secret = "preimage-fixture-secret-7761"
        self.assert_safe_error(lambda: wire.decode_tclk_alpha_json_frame(
            ('{"statement":"' + secret + '"').encode()), secret)
        secret = "SECRET_BYTES_8123"
        self.assert_safe_error(lambda: wire.decode_tclk_alpha_json_frame(
            secret.encode() + b"\xff"), secret)

    def test_secret_field_matrix_is_absent_from_every_error_surface(self):
        for field in ("secret", "preimage", "witness", "presig.s", "paymentKey",
                      "private_key", "seed", "mnemonic"):
            secret = "raw-fixture-" + field + "-918273"
            raw = json.dumps({field: secret}).encode()
            with self.subTest(field=field):
                self.assert_safe_error(
                    lambda raw=raw: wire.decode_tclk_alpha_json_frame(raw), secret)

    def test_public_surface_has_no_effect_injection(self):
        forbidden = {"path", "transport", "fetcher", "writer", "callback", "executor", "signer", "adapter"}
        for name in wire.__all__:
            value = getattr(wire, name)
            if callable(value): self.assertTrue(forbidden.isdisjoint(inspect.signature(value).parameters))

class PreservedDefensiveCoverageTests(unittest.TestCase):
    def test_raw_frame_gate_precedes_json_decode(self):
        for raw, code in ((b"x" * 4097, "FRAME_TOO_LARGE"),
                          (b'{"x":1}\n{"x":2}', "FRAME_MULTILINE"),
                          (b"\xff", "FRAME_UTF8_INVALID"),
                          (b"not-json", "FRAME_SYNTAX_INVALID")):
            with self.assertRaises(wire.WireSafetyError) as caught:
                wire.decode_tclk_alpha_json_frame(raw)
            self.assertEqual(caught.exception.code, code)

    def test_time_validation_remains_bounded_and_integral(self):
        self.assertEqual(wire.validate_unix_ms(wire.MAX_UNIX_MS), wire.MAX_UNIX_MS)
        for value in (True, -1, wire.MAX_UNIX_MS + 1, 1.0, "1"):
            with self.assertRaises(wire.WireSafetyError): wire.validate_unix_ms(value)

    def test_venue_metadata_cannot_claim_signed_scope(self):
        with self.assertRaises(wire.WireSafetyError):
            wire.VenueMetadataEvidence(
                "1", 1, "gen-1", wire.EvidenceStatus.VENUE_METADATA_OBSERVED,
                signed_metadata=True)

    def test_documented_and_runtime_capability_evidence_stay_distinct(self):
        documented = wire.CapabilityObservation(
            "ordered-sequences", wire.CapabilityEvidenceKind.DOCUMENTED_CAPABILITY,
            "DOCUMENTED_ONLY")
        runtime = wire.CapabilityObservation(
            "ordered-sequences", wire.CapabilityEvidenceKind.RUNTIME_OBSERVED_CAPABILITY,
            "NOT_OBSERVED_OFFLINE")
        self.assertNotEqual(documented.evidence_kind, runtime.evidence_kind)

    def test_readiness_never_claims_activation(self):
        readiness = wire.wire_safety_readiness()
        self.assertEqual(readiness["activation"], wire.ActivationState.DO_NOT_ACTIVATE)
        self.assertNotEqual(readiness["rail_verifier_ready"], "LIVE_VERIFIED")

    def test_rail_alias_is_preserved_and_canonicalized_locally(self):
        observed = wire.RailObservation.observed("btc", "tx-1", "COMPLETED")
        self.assertEqual((observed.rail_raw, observed.rail_canonical),
                         ("btc", "BITCOIN"))
        with self.assertRaises(wire.WireSafetyError):
            wire.RailObservation("paper", "BITCOIN", "ref", "COMPLETED")

    def test_tampered_offer_id_is_descriptively_invalid(self):
        proposal, acceptance = agreement_fixture()
        altered = dataclasses.replace(proposal, offer_id="0" * 64)
        self.assertEqual(wire.verify_tclk_alpha_agreement(
            altered, acceptance).agreement_status, wire.EvidenceStatus.AGREEMENT_INVALID)

    def test_readback_descriptive_transitions_are_sequential(self):
        stage = wire.ReadBackStage.NOT_STARTED
        for event in EVENTS: stage = wire.advance_readback(stage, event)
        self.assertEqual(stage, wire.ReadBackStage.EVIDENCE_CONFIRMED)
        with self.assertRaises(wire.WireSafetyError):
            wire.advance_readback(wire.ReadBackStage.WRITE_ACCEPTED, "signature_valid")

    def test_third_party_export_reports_sequence_gap(self):
        observation = authority.observe_third_party_export(
            b'{"seq":"1"}\n{"seq":"3"}', source_id="third-party",
            acquired_at_ms=1, verifier_revision=REVISION)
        self.assertIn("SEQUENCE_GAP", observation.assessment.issues)

    def test_signing_validation_order_rejects_room_before_nonce(self):
        with self.assertRaises(wire.WireSafetyError) as caught:
            wire.build_signing_context("p-private", 7, object())
        self.assertEqual(caught.exception.code, "ROOM_INVALID")

if __name__ == "__main__": unittest.main()
