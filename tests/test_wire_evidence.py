import base64
import hashlib
import inspect
import json
import logging
import math
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from flop_agent import wire_evidence as wire
from flop_agent import technocore


REVISION = "a" * 40


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def public_b64(key):
    return b64(key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def export(records, source=wire.ExportSourceKind.CONFIGURED_REVIEWED_EXPORT,
           generation="gen-1"):
    raw = b"\n".join(json.dumps(value, separators=(",", ":")).encode()
                     for value in records)
    return wire.acquire_export_fixture(
        raw, source_kind=source, source_id="offline-fixture",
        acquired_at_ms=1_800_000_000_000, verifier_revision=REVISION,
        generation=generation)


def agreement_fixture():
    proposer = Ed25519PrivateKey.generate()
    accepter = Ed25519PrivateKey.generate()
    proposal_bytes = wire.agreement_proposal_signing_bytes(
        protocol="tclk-alpha", proposer_id="alice", counterparty_id="bob",
        terms={"lock_statement": "LOCKED", "units": "fixture-only"},
        rail_raw="paperrail", reference="ref-1")
    proposal_signature = b64(proposer.sign(proposal_bytes))
    offer_id = wire.recompute_offer_id(proposal_bytes, proposal_signature)
    proposal = wire.AgreementProposal(
        "tclk-alpha", "alice", "bob", public_b64(proposer),
        {"lock_statement": "LOCKED", "units": "fixture-only"},
        "paperrail", "ref-1", proposal_signature, offer_id)
    acceptance_bytes = wire.agreement_acceptance_signing_bytes(
        protocol="tclk-alpha", accepter_id="bob", proposer_id="alice",
        offer_id=offer_id, statement="ACCEPT")
    acceptance_signature = b64(accepter.sign(acceptance_bytes))
    agreement_id = wire.recompute_agreement_id(
        offer_id, acceptance_bytes, acceptance_signature)
    acceptance = wire.AgreementAcceptance(
        "tclk-alpha", "bob", "alice", public_b64(accepter), offer_id,
        "ACCEPT", acceptance_signature, agreement_id)
    return proposal, acceptance


class NonceAndFrameSafetyTests(unittest.TestCase):
    def test_nonce_remains_exact_decimal_string_across_js_boundary_values(self):
        values = (
            "9007199254740991", "9007199254740992",
            "9223372036854775807", str(wire.MAX_PROTOCOL_NONCE),
        )
        for value in values:
            with self.subTest(value=value):
                nonce = wire.parse_nonce(value)
                self.assertEqual(nonce.decimal, value)
                context = wire.build_signing_context("lobby", value, "fixture")
                self.assertEqual(context.nonce.decimal, value)
                self.assertIn(("|" + value + "|").encode(), context.canonical_bytes)

    def test_nonce_rejects_numeric_coercion_and_noncanonical_forms(self):
        for value in (0, 1, 1.0, "0", "01", "+1", "1.0", "1e3", "-1",
                      str(wire.MAX_PROTOCOL_NONCE + 1)):
            with self.subTest(value=value), self.assertRaises(wire.WireSafetyError):
                wire.parse_nonce(value)

    def test_signing_validation_order_and_exact_external_challenge(self):
        with self.assertRaises(wire.WireSafetyError) as caught:
            wire.build_signing_context("p-private", 7, object())
        self.assertEqual(caught.exception.code, "ROOM_INVALID")
        with self.assertRaises(wire.WireSafetyError) as caught:
            wire.build_signing_context("lobby", 7, object())
        self.assertEqual(caught.exception.code, "NONCE_INVALID")
        context = wire.build_signing_context("lobby", "7", "hello")
        same = wire.build_signing_context(
            "lobby", "7", "hello", external_challenge=context.canonical_bytes)
        self.assertEqual(same.canonical_sha256, context.canonical_sha256)
        with self.assertRaises(wire.WireSafetyError) as caught:
            wire.build_signing_context(
                "lobby", "7", "hello", external_challenge=b"remote-canonical")
        self.assertEqual(caught.exception.code, "SIGNING_CONTEXT_MISMATCH")

    def test_capability_binding_is_complete(self):
        context = wire.build_signing_context("lobby", "7", "hello")
        binding = context.capability_binding(
            action_class="IDENTITY_SIGN", target="lobby",
            revision=REVISION, config_version="wire-v1")
        self.assertEqual(set(binding), {
            "room", "nonce", "text_sha256", "canonical_sha256",
            "action_class", "target", "revision", "config_version"})
        self.assertEqual(binding["nonce"], "7")

    def test_tclk_raw_gate_precedes_json_decode(self):
        invalid = (
            b"x" * 4097, b'{"x":1}\n{"x":2}', b'{"x":"\x01"}',
            b"\xff", "é".encode(), b"not-json",
        )
        expected = (
            "FRAME_TOO_LARGE", "FRAME_MULTILINE", "FRAME_CHARACTER_INVALID",
            "FRAME_UTF8_INVALID", "FRAME_CHARACTER_INVALID", "FRAME_SYNTAX_INVALID",
        )
        for raw, code in zip(invalid, expected):
            with self.subTest(code=code), self.assertRaises(wire.WireSafetyError) as caught:
                wire.decode_tclk_alpha_json_frame(raw)
            self.assertEqual(caught.exception.code, code)
        self.assertEqual(wire.decode_tclk_alpha_json_frame(b'{"seq":"1"}')["seq"], "1")

    def test_time_is_bounded_integer_unix_ms(self):
        self.assertEqual(wire.validate_unix_ms(0), 0)
        self.assertEqual(wire.validate_unix_ms(wire.MAX_UNIX_MS), wire.MAX_UNIX_MS)
        for value in (True, -1, wire.MAX_UNIX_MS + 1, 1.0, math.nan,
                      math.inf, -math.inf, "1"):
            with self.subTest(value=value), self.assertRaises(wire.WireSafetyError) as caught:
                wire.validate_unix_ms(value)
            self.assertEqual(caught.exception.code, "TIME_INVALID")


class ExportEvidenceTests(unittest.TestCase):
    def test_export_preserves_provenance_without_exposing_raw(self):
        snapshot = export([{"seq": "1", "ts": 1, "generation": "gen-1"}])
        evidence = snapshot.evidence()
        self.assertEqual(evidence["source_kind"], "CONFIGURED_REVIEWED_EXPORT")
        self.assertEqual(evidence["acquired_at_ms"], 1_800_000_000_000)
        self.assertEqual(evidence["verifier_revision"], REVISION)
        self.assertEqual(evidence["snapshot_sha256"], hashlib.sha256(
            snapshot.raw_snapshot).hexdigest())
        self.assertFalse(evidence["raw_included"])
        self.assertNotIn("seq", repr(snapshot))

    def test_snapshot_cannot_be_constructed_with_mismatched_hash(self):
        with self.assertRaises(wire.WireSafetyError) as caught:
            wire.ExportSnapshot(
                wire.ExportSourceKind.THIRD_PARTY_SUPPLIED, "fixture", 1,
                "0" * 64, REVISION, None, b"bytes")
        self.assertEqual(caught.exception.code, "HASH_INVALID")

    def test_clean_structure_is_not_completeness(self):
        snapshot = export([
            {"seq": "1", "ts": 1, "generation": "gen-1"},
            {"seq": "2", "ts": 2, "generation": "gen-1"},
        ])
        result = wire.assess_export(snapshot)
        self.assertEqual(result.structure_status, wire.EvidenceStatus.TRANSCRIPT_STRUCT_VALID)
        self.assertEqual(result.completeness_status,
                         wire.EvidenceStatus.TRANSCRIPT_COMPLETENESS_UNVERIFIED)

    def test_only_independent_reviewed_exact_claim_can_verify_completeness(self):
        snapshot = export([
            {"seq": "1", "generation": "gen-1"},
            {"seq": "2", "generation": "gen-1"},
        ])
        claim = wire.TranscriptCompletenessClaim(
            snapshot.snapshot_sha256, "gen-1", "1", "2", True)
        self.assertEqual(wire.assess_export(snapshot, completeness_claim=claim).completeness_status,
                         wire.EvidenceStatus.TRANSCRIPT_COMPLETENESS_VERIFIED)
        third_party = export(
            [{"seq": "1", "generation": "gen-1"},
             {"seq": "2", "generation": "gen-1"}],
            wire.ExportSourceKind.THIRD_PARTY_SUPPLIED)
        third_claim = wire.TranscriptCompletenessClaim(
            third_party.snapshot_sha256, "gen-1", "1", "2", True)
        self.assertEqual(wire.assess_export(
            third_party, completeness_claim=third_claim).completeness_status,
            wire.EvidenceStatus.TRANSCRIPT_COMPLETENESS_UNVERIFIED)

    def test_direct_observation_and_third_party_metadata_stay_distinct(self):
        direct = export([{"seq": "1", "ts": 1}],
                        wire.ExportSourceKind.DIRECT_VENUE_SNAPSHOT, None)
        supplied = export([{"seq": "1", "ts": 1}],
                          wire.ExportSourceKind.THIRD_PARTY_SUPPLIED, None)
        self.assertEqual(wire.assess_export(direct).venue_metadata[0].provenance,
                         wire.EvidenceStatus.DIRECT_VENUE_OBSERVATION)
        self.assertEqual(wire.assess_export(supplied).venue_metadata[0].provenance,
                         wire.EvidenceStatus.VENUE_METADATA_OBSERVED)
        self.assertFalse(wire.assess_export(direct).venue_metadata[0].signed_metadata)
        with self.assertRaises(wire.WireSafetyError):
            wire.VenueMetadataEvidence(
                "1", 1, None, wire.EvidenceStatus.DIRECT_VENUE_OBSERVATION,
                signed_metadata=True)

    def test_export_detects_gap_duplicate_reversal_generation_time_and_bounds(self):
        cases = (
            ([{"seq": "1"}, {"seq": "3"}], "SEQUENCE_GAP"),
            ([{"seq": "1"}, {"seq": "1"}], "DUPLICATE_SEQUENCE"),
            ([{"seq": "2"}, {"seq": "1"}], "SEQUENCE_REVERSAL"),
            ([{"seq": "1", "generation": "gen-1"},
              {"seq": "2", "generation": "gen-2"}], "GENERATION_INCONSISTENT"),
            ([{"seq": "1", "ts": -1}], "TIME_INVALID"),
        )
        for records, issue in cases:
            with self.subTest(issue=issue):
                self.assertIn(issue, wire.assess_export(export(records)).issues)
        bounded = wire.assess_export(
            export([{"seq": "2"}]), acquisition_first_seq="1",
            acquisition_last_seq="3", truncation_indicated=True)
        self.assertEqual(set(bounded.issues), {
            "TRUNCATION_INDICATED", "ACQUISITION_FIRST_BOUND_MISMATCH",
            "ACQUISITION_LAST_BOUND_MISMATCH"})


class AgreementRailAndReadbackTests(unittest.TestCase):
    def test_two_signature_agreement_verifies_all_independent_conditions(self):
        proposal, acceptance = agreement_fixture()
        result = wire.verify_tclk_alpha_agreement(proposal, acceptance)
        self.assertEqual(result.proposal_signature, wire.EvidenceStatus.SIGNED_CONTENT_VERIFIED)
        self.assertEqual(result.acceptance_signature, wire.EvidenceStatus.SIGNED_CONTENT_VERIFIED)
        self.assertEqual(result.agreement_status, wire.EvidenceStatus.AGREEMENT_VERIFIED)
        self.assertEqual(result.classification, wire.TCLK_ALPHA_CLASSIFICATION)
        agreement = result.verified_agreement(proposal, acceptance)
        self.assertIsInstance(agreement, wire.Agreement)
        rail = wire.RailObservation.observed("paper", "ref-1", "COMPLETED")
        attempt = wire.TransferAttempt(
            "attempt-1", agreement.agreement_id, rail,
            wire.ActivityQuality.PROTOCOL_VALID_ACTIVITY)
        self.assertEqual(attempt.rail.rail_canonical, "PAPER")
        self.assertFalse(attempt.rail.economic_value_verified)
        state = wire.AgreementState.PROPOSED
        for event in ("offer_verified", "acceptance_verified", "agreement_verified"):
            state = wire.transition_agreement(state, event)
        self.assertEqual(state, wire.AgreementState.AGREEMENT_VERIFIED)
        with self.assertRaises(wire.WireSafetyError):
            wire.transition_agreement(
                wire.AgreementState.PROPOSED, "agreement_verified")

    def test_valid_signatures_do_not_override_bad_offer_reference(self):
        proposal, acceptance = agreement_fixture()
        altered = wire.AgreementAcceptance(
            acceptance.protocol, acceptance.accepter_id, acceptance.proposer_id,
            acceptance.accepter_public_key_b64, "0" * 64, acceptance.statement,
            acceptance.signature_b64, acceptance.agreement_id)
        result = wire.verify_tclk_alpha_agreement(proposal, altered)
        self.assertEqual(result.agreement_status, wire.EvidenceStatus.AGREEMENT_INVALID)
        self.assertEqual(result.counterparty_status, "COUNTERPARTY_INVALID")
        self.assertIsNone(result.verified_agreement(proposal, altered))

    def test_tampered_ids_and_counterparties_fail_closed(self):
        proposal, acceptance = agreement_fixture()
        bad_offer = wire.AgreementProposal(
            proposal.protocol, proposal.proposer_id, proposal.counterparty_id,
            proposal.proposer_public_key_b64, proposal.terms, proposal.rail_raw,
            proposal.reference, proposal.signature_b64, "0" * 64)
        self.assertEqual(wire.verify_tclk_alpha_agreement(
            bad_offer, acceptance).agreement_status, wire.EvidenceStatus.AGREEMENT_INVALID)
        bad_agreement = wire.AgreementAcceptance(
            acceptance.protocol, acceptance.accepter_id, acceptance.proposer_id,
            acceptance.accepter_public_key_b64, acceptance.offer_id,
            acceptance.statement, acceptance.signature_b64, "0" * 64)
        self.assertEqual(wire.verify_tclk_alpha_agreement(
            proposal, bad_agreement).agreement_status, wire.EvidenceStatus.AGREEMENT_INVALID)

    def test_rail_preserves_alias_and_blocks_direct_canonical_bypass(self):
        observed = wire.RailObservation.observed(
            "btc", "tx-1", "COMPLETED",
            crypto_status=wire.RailCryptoStatus.RAIL_CRYPTO_VERIFIED,
            independent_finality_verified=True, protocol_valid=True)
        self.assertEqual((observed.rail_raw, observed.rail_canonical), ("btc", "BITCOIN"))
        with self.assertRaises(wire.WireSafetyError):
            wire.RailObservation("paper", "BITCOIN", "ref", "COMPLETED")

    def test_transcript_and_venue_deadlines_never_imply_finality(self):
        no_rail = wire.assess_finality("COMPLETED", None)
        self.assertEqual(no_rail.finality_status, wire.EvidenceStatus.FINALITY_UNVERIFIED)
        paper = wire.RailObservation.observed(
            "paper", "ref", "COMPLETED",
            crypto_status=wire.RailCryptoStatus.RAIL_CRYPTO_VERIFIED,
            independent_finality_verified=True, protocol_valid=True)
        paper_result = wire.assess_finality("COMPLETED", paper)
        self.assertEqual(paper_result.finality_status, wire.EvidenceStatus.FINALITY_UNVERIFIED)
        self.assertFalse(paper.economic_value_verified)

    def test_independent_nonpaper_crypto_can_verify_finality(self):
        rail = wire.RailObservation.observed(
            "bitcoin", "tx-1", "COMPLETED",
            crypto_status=wire.RailCryptoStatus.RAIL_CRYPTO_VERIFIED,
            independent_finality_verified=True, protocol_valid=True)
        result = wire.assess_finality(None, rail)
        self.assertEqual(result.finality_status, wire.EvidenceStatus.FINALITY_VERIFIED)
        self.assertTrue(rail.economic_value_verified)
        incomplete = wire.RailObservation.observed(
            "bitcoin", "tx-2", "COMPLETED",
            crypto_status=wire.RailCryptoStatus.RAIL_CRYPTO_VERIFIED,
            independent_finality_verified=True, protocol_valid=False)
        self.assertEqual(wire.assess_finality(
            "COMPLETED", incomplete).finality_status,
            wire.EvidenceStatus.FINALITY_UNVERIFIED)

    def test_readback_stages_are_strictly_sequential(self):
        stage = wire.ReadBackStage.NOT_STARTED
        for event in ("write_accepted", "read_back_observed", "decode_valid",
                      "signature_valid", "state_replay_valid", "evidence_confirmed"):
            stage = wire.advance_readback(stage, event)
        self.assertEqual(stage, wire.ReadBackStage.EVIDENCE_CONFIRMED)
        with self.assertRaises(wire.WireSafetyError):
            wire.advance_readback(wire.ReadBackStage.WRITE_ACCEPTED, "signature_valid")

    def test_evidence_bundle_rejects_cross_layer_status(self):
        with self.assertRaises(wire.WireSafetyError):
            wire.EvidenceBundle(
                wire.EvidenceStatus.SIGNED_CONTENT_VERIFIED,
                wire.EvidenceStatus.VENUE_METADATA_OBSERVED,
                wire.EvidenceStatus.TRANSCRIPT_COMPLETENESS_UNVERIFIED,
                wire.EvidenceStatus.AGREEMENT_VERIFIED,
                wire.EvidenceStatus.FINALITY_VERIFIED,
                wire.EvidenceStatus.FINALITY_VERIFIED)


class SecretAndReadinessTests(unittest.TestCase):
    def test_secret_like_fields_never_appear_in_error_or_evidence(self):
        secret_value = "fixture-secret-value-49381"
        messages = []

        class Capture(logging.Handler):
            def emit(self, record):
                messages.append(record.getMessage())

        handler = Capture()
        logging.getLogger().addHandler(handler)
        keys = ("secret", "preimage", "witness", "presig.s", "paymentKey",
                "private_key")
        try:
            for key in keys:
                raw = json.dumps({key: secret_value}, separators=(",", ":")).encode()
                with self.subTest(key=key), self.assertRaises(wire.WireSafetyError) as caught:
                    wire.decode_tclk_alpha_json_frame(raw)
                rendered = str(caught.exception) + repr(caught.exception.as_evidence())
                self.assertNotIn(secret_value, rendered)
            raw = json.dumps({"statement": "contains preimage " + secret_value}).encode()
            with self.assertRaises(wire.WireSafetyError) as caught:
                wire.decode_tclk_alpha_json_frame(raw)
            self.assertNotIn(secret_value, str(caught.exception))
        finally:
            logging.getLogger().removeHandler(handler)
        self.assertNotIn(secret_value, "\n".join(messages))

    def test_readiness_is_typed_and_does_not_claim_activation(self):
        readiness = wire.wire_safety_readiness()
        self.assertEqual(set(readiness), {
            "nonce_safe", "venue_provenance_ready", "export_verifier_ready",
            "signer_context_ready", "agreement_verifier_ready",
            "rail_verifier_ready", "evidence_readback_ready", "classification",
            "activation"})
        self.assertEqual(readiness["activation"], "DO_NOT_ACTIVATE")
        self.assertNotEqual(readiness["rail_verifier_ready"], "LIVE_VERIFIED")
        self.assertIsInstance(readiness["nonce_safe"], wire.ReadinessState)
        self.assertIsInstance(readiness["activation"], wire.ActivationState)

    def test_documented_and_runtime_capability_evidence_cannot_be_conflated(self):
        documented = wire.CapabilityObservation(
            "ordered-sequences", wire.CapabilityEvidenceKind.DOCUMENTED_CAPABILITY,
            "DOCUMENTED_ONLY", "0" * 64)
        observed = wire.CapabilityObservation(
            "ordered-sequences",
            wire.CapabilityEvidenceKind.RUNTIME_OBSERVED_CAPABILITY,
            "NOT_OBSERVED_OFFLINE")
        self.assertNotEqual(documented.evidence_kind, observed.evidence_kind)
        with self.assertRaises(wire.WireSafetyError):
            wire.CapabilityObservation(
                "ordered-sequences",
                wire.CapabilityEvidenceKind.RUNTIME_OBSERVED_CAPABILITY,
                "RUNTIME_OBSERVED")

    def test_public_module_has_no_effect_injection_parameters(self):
        forbidden = {"path", "transport", "fetcher", "writer", "callback", "executor"}
        for name in wire.__all__ if hasattr(wire, "__all__") else ():
            value = getattr(wire, name)
            if callable(value):
                self.assertTrue(forbidden.isdisjoint(inspect.signature(value).parameters))

    def test_production_post_validates_context_before_capability_or_key_access(self):
        calls = []
        _, _, _, post, _ = technocore._build_technocore_client(
            lambda *_: None,
            lambda *_args, **_kwargs: calls.append("capability"),
            lambda *_: calls.append("key"),
            lambda *_: calls.append("sign"),
            lambda *_: calls.append("network"))
        with self.assertRaises(wire.WireSafetyError) as caught:
            post(None, "p-private", "fixture", intent=object(),
                 revision=REVISION, config_version="wire-v1", context="fixture",
                 nonce="7")
        self.assertEqual(caught.exception.code, "ROOM_INVALID")
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
