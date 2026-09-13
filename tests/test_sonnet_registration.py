import base64
import json
import pickle
import unittest
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from flop_agent import sonnet_registration as registration
from flop_agent import wire_evidence
from flop_agent.did_key import did_from_public_key


NOW = datetime(2026, 9, 13, 6, 0, tzinfo=timezone.utc)


def approval(**changes):
    value = {
        **registration.fixed_binding(),
        "reviewer": "fixture-reviewer",
        "approved_at": "2026-09-13T05:59:00Z",
    }
    value.update(changes)
    return value


class FixtureBoundary:
    def __init__(self, *, approvals=None, transport=None, signature_verifier=None):
        self.effects = []

        def key_loader():
            self.effects.append("key")
            return object(), registration.PARTICIPANT_DID

        def signer(_key, target):
            self.effects.append("sign")
            self.target = target
            return "fixture-signature"

        def default_transport(url, payload, *, timeout_seconds, allow_redirects):
            self.effects.append("transport")
            self.transport_call = (url, dict(payload), timeout_seconds, allow_redirects)
            return registration.TransportObservation(200, registration.POST_URL, False)

        def default_verifier(did, signature, canonical):
            self.effects.append("verify")
            self.verification_call = (did, signature, canonical)
            if signature != "valid-signature":
                raise registration.RegistrationBoundaryError("RECEIPT_SIGNATURE_INVALID")

        self.service, self.issue = registration._build_registration_service_for_test(
            approvals={"fixture": approval()} if approvals is None else approvals,
            trusted_reviewers=frozenset({"fixture-reviewer"}),
            clock=lambda: NOW,
            key_loader=key_loader,
            signer=signer,
            transport=transport or default_transport,
            signature_verifier=signature_verifier or default_verifier,
        )


class FixedPreflightTests(unittest.TestCase):
    def test_fixed_packet_and_signing_target(self):
        candidate = registration.fixed_candidate()
        result = registration.production_registration_service.preflight(candidate)
        self.assertEqual(result["status"], "REGISTRATION_WRITE_APPROVAL_REQUIRED")
        self.assertFalse(result["ready_to_sign"])
        self.assertFalse(result["authorized_to_write"])
        self.assertEqual(result["external_writes"], 0)
        self.assertEqual(len(registration.PACKET_BYTES), 169)
        self.assertEqual(len(registration.SIGNING_TARGET_BYTES), 208)
        self.assertEqual(
            registration.SIGNING_TARGET_BYTES,
            (registration.ROOM + "|" + registration.NONCE + "|"
             + registration.PACKET_TEXT).encode("utf-8"))

    def test_production_has_no_permit_issuer_and_cannot_execute(self):
        service = registration.production_registration_service
        self.assertFalse(hasattr(service, "issue"))
        self.assertFalse(hasattr(registration, "_production_issue"))
        with self.assertRaises(registration.RegistrationBoundaryError) as caught:
            service.execute(registration.fixed_candidate())
        self.assertEqual(caught.exception.code, "PERMIT_INVALID")

    def test_permit_is_opaque_nonconstructible_and_nonserializable(self):
        fixture = FixtureBoundary()
        permit = fixture.issue("fixture")
        with self.assertRaises(TypeError):
            registration._RegistrationPermit()
        with self.assertRaises(TypeError):
            pickle.dumps(permit)

    def test_other_mb_rooms_and_sonnet1_fail_before_key_load(self):
        rooms = (
            "mb-other-registration",
            "mb-sonnet-2-discovery",
            "mb-sonnet-2-votes",
            "mb-sonnet-2-submissions",
            "mb-sonnet-1-registration",
        )
        for room in rooms:
            with self.subTest(room=room):
                fixture = FixtureBoundary()
                candidate = registration.fixed_candidate()
                candidate["room"] = room
                with self.assertRaises(registration.RegistrationBoundaryError):
                    fixture.service.execute(candidate, fixture.issue("fixture"))
                self.assertEqual(fixture.effects, [])

    def test_role_did_x_request_nonce_and_contest_mutations_precede_key(self):
        mutations = (
            ("role", "voter"),
            ("role", "organizer"),
            ("participant_did", "did:key:z6Mkinvalid"),
            ("x_account_url", "https://x.com/other"),
            ("request_id", "other-request"),
            ("nonce", "1789279012381"),
            ("contest_id", "sonnet-1"),
            ("protocol_type", "sonnet.register.v2"),
            ("action_class", "SIGNED_ROOM_POST"),
            ("referee_did", "did:key:z6Mkforged"),
            ("manifest_commit", "0" * 40),
            ("manifest_sha256", "0" * 64),
        )
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                fixture = FixtureBoundary()
                candidate = registration.fixed_candidate()
                candidate[field] = value
                with self.assertRaises(registration.RegistrationBoundaryError):
                    fixture.service.execute(candidate, fixture.issue("fixture"))
                self.assertEqual(fixture.effects, [])

    def test_packet_key_add_delete_whitespace_order_and_character_mutation(self):
        original = json.loads(registration.PACKET_TEXT)
        variants = []
        added = dict(original); added["metadata"] = "x"; variants.append(json.dumps(added, separators=(",", ":")))
        deleted = dict(original); del deleted["role"]; variants.append(json.dumps(deleted, separators=(",", ":")))
        variants.append(json.dumps(original))
        variants.append(json.dumps(dict(reversed(tuple(original.items()))), separators=(",", ":")))
        variants.append(registration.PACKET_TEXT.replace("Giappone", "GiapponeX"))
        for packet in variants:
            with self.subTest(packet_length=len(packet)):
                fixture = FixtureBoundary()
                candidate = registration.fixed_candidate(); candidate["packet"] = packet
                with self.assertRaises(registration.RegistrationBoundaryError):
                    fixture.service.execute(candidate, fixture.issue("fixture"))
                self.assertEqual(fixture.effects, [])

    def test_missing_extra_candidate_and_hash_mutations_precede_key(self):
        variants = []
        missing = registration.fixed_candidate(); del missing["request_id"]; variants.append(missing)
        extra = registration.fixed_candidate(); extra["metadata"] = {}; variants.append(extra)
        packet_hash = registration.fixed_candidate(); packet_hash["packet_sha256"] = "0" * 64; variants.append(packet_hash)
        target_hash = registration.fixed_candidate(); target_hash["signing_target_sha256"] = "0" * 64; variants.append(target_hash)
        packet_length = registration.fixed_candidate(); packet_length["packet_byte_length"] = 168; variants.append(packet_length)
        target_length = registration.fixed_candidate(); target_length["signing_target_byte_length"] = 207; variants.append(target_length)
        for candidate in variants:
            fixture = FixtureBoundary()
            with self.assertRaises(registration.RegistrationBoundaryError):
                fixture.service.execute(candidate, fixture.issue("fixture"))
            self.assertEqual(fixture.effects, [])


class ApprovalAndExecutionTests(unittest.TestCase):
    def test_approval_missing_precedes_key_load(self):
        fixture = FixtureBoundary(approvals={})
        with self.assertRaises(registration.RegistrationBoundaryError):
            fixture.issue("missing")
        with self.assertRaises(registration.RegistrationBoundaryError):
            fixture.service.execute(registration.fixed_candidate(), None)
        self.assertEqual(fixture.effects, [])

    def test_approval_hash_and_every_binding_are_exact(self):
        changes = (
            {"packet_sha256": "0" * 64},
            {"signing_target_sha256": "0" * 64},
            {"request_id": "different"},
            {"nonce": "1789279012381"},
            {"room": "mb-sonnet-2-discovery"},
            {"role": "voter"},
        )
        for change in changes:
            with self.subTest(change=change):
                fixture = FixtureBoundary(approvals={"fixture": approval(**change)})
                with self.assertRaises(registration.RegistrationBoundaryError):
                    fixture.issue("fixture")
                self.assertEqual(fixture.effects, [])

    def test_approval_unknown_fields_untrusted_reviewer_and_time_fail(self):
        extra = approval(); extra["metadata"] = "authority"
        cases = (
            extra,
            approval(reviewer="remote-referee"),
            approval(approved_at="2026-09-13T05:00:00Z"),
            approval(approved_at="2026-09-13T07:00:00Z"),
        )
        for value in cases:
            fixture = FixtureBoundary(approvals={"fixture": value})
            with self.assertRaises(registration.RegistrationBoundaryError):
                fixture.issue("fixture")
            self.assertEqual(fixture.effects, [])

    def test_one_approval_cannot_issue_two_permits(self):
        fixture = FixtureBoundary()
        fixture.issue("fixture")
        with self.assertRaises(registration.RegistrationBoundaryError) as caught:
            fixture.issue("fixture")
        self.assertEqual(caught.exception.code, "APPROVAL_ALREADY_USED")
        self.assertEqual(fixture.effects, [])

    def test_exact_permit_signs_and_posts_once_without_retry(self):
        fixture = FixtureBoundary()
        result = fixture.service.execute(registration.fixed_candidate(), fixture.issue("fixture"))
        self.assertEqual(fixture.effects, ["key", "sign", "transport"])
        self.assertEqual(fixture.target, registration.SIGNING_TARGET_BYTES)
        self.assertEqual(result["status"], "POST_OBSERVED_RECEIPT_REQUIRED")
        self.assertEqual(result["writes_attempted"], 1)
        self.assertFalse(result["automatic_retry"])
        url, payload, timeout, redirects = fixture.transport_call
        self.assertEqual(url, registration.POST_URL)
        self.assertEqual(timeout, 20)
        self.assertFalse(redirects)
        self.assertEqual(set(payload), {"did", "sig", "nonce", "text"})
        self.assertEqual(payload["nonce"], registration.NONCE)
        self.assertEqual(payload["text"], registration.PACKET_TEXT)

    def test_permit_reuse_and_nonce_resigning_are_rejected_before_key(self):
        fixture = FixtureBoundary()
        permit = fixture.issue("fixture")
        fixture.service.execute(registration.fixed_candidate(), permit)
        first = list(fixture.effects)
        with self.assertRaises(registration.RegistrationBoundaryError) as caught:
            fixture.service.execute(registration.fixed_candidate(), permit)
        self.assertEqual(caught.exception.code, "PERMIT_ALREADY_USED")
        self.assertEqual(fixture.effects, first)

    def test_cross_authority_permit_is_rejected(self):
        one, two = FixtureBoundary(), FixtureBoundary()
        permit = one.issue("fixture")
        with self.assertRaises(registration.RegistrationBoundaryError):
            two.service.execute(registration.fixed_candidate(), permit)
        self.assertEqual(two.effects, [])

    def test_redirect_is_unknown_and_never_retried(self):
        calls = []

        def transport(*_args, **_kwargs):
            calls.append("transport")
            return registration.TransportObservation(307, "https://other.invalid/", True)

        fixture = FixtureBoundary(transport=transport)
        permit = fixture.issue("fixture")
        result = fixture.service.execute(registration.fixed_candidate(), permit)
        self.assertEqual(result["status"], "WRITE_OUTCOME_UNKNOWN")
        self.assertEqual(calls, ["transport"])
        self.assertFalse(result["automatic_retry"])
        with self.assertRaises(registration.RegistrationBoundaryError):
            fixture.service.execute(registration.fixed_candidate(), permit)
        self.assertEqual(calls, ["transport"])

    def test_timeout_and_disconnect_are_unknown_without_retry(self):
        for error in (TimeoutError(), ConnectionError(), OSError()):
            calls = []

            def transport(*_args, selected=error, **_kwargs):
                calls.append("transport")
                raise selected

            fixture = FixtureBoundary(transport=transport)
            permit = fixture.issue("fixture")
            result = fixture.service.execute(registration.fixed_candidate(), permit)
            self.assertEqual(result["status"], "WRITE_OUTCOME_UNKNOWN")
            self.assertEqual(calls, ["transport"])
            with self.assertRaises(registration.RegistrationBoundaryError):
                fixture.service.execute(registration.fixed_candidate(), permit)
            self.assertEqual(calls, ["transport"])

    def test_malformed_response_is_unknown(self):
        fixture = FixtureBoundary(transport=lambda *_args, **_kwargs: {"status": "accepted"})
        result = fixture.service.execute(registration.fixed_candidate(), fixture.issue("fixture"))
        self.assertEqual(result["status"], "WRITE_OUTCOME_UNKNOWN")
        self.assertFalse(result["automatic_retry"])

    def test_http_408_and_other_non_success_are_unknown_without_retry(self):
        for status in (408, 409, 500):
            calls = []

            def transport(*_args, selected=status, **_kwargs):
                calls.append(selected)
                return registration.TransportObservation(
                    selected, registration.POST_URL, False)

            fixture = FixtureBoundary(transport=transport)
            permit = fixture.issue("fixture")
            result = fixture.service.execute(registration.fixed_candidate(), permit)
            self.assertEqual(result["status"], "WRITE_OUTCOME_UNKNOWN")
            self.assertEqual(calls, [status])
            self.assertFalse(result["automatic_retry"])
            with self.assertRaises(registration.RegistrationBoundaryError):
                fixture.service.execute(registration.fixed_candidate(), permit)
            self.assertEqual(calls, [status])

    def test_created_service_ignores_late_global_rebinding(self):
        fixture = FixtureBoundary()
        originals = {
            "PARTICIPANT_DID": registration.PARTICIPANT_DID,
            "NONCE": registration.NONCE,
            "PACKET_TEXT": registration.PACKET_TEXT,
            "SIGNING_TARGET_BYTES": registration.SIGNING_TARGET_BYTES,
            "POST_URL": registration.POST_URL,
            "REFEREE_DID": registration.REFEREE_DID,
            "validate_candidate": registration.validate_candidate,
        }
        try:
            registration.PARTICIPANT_DID = "did:key:attacker"
            registration.NONCE = "1"
            registration.PACKET_TEXT = "{}"
            registration.SIGNING_TARGET_BYTES = b"attacker"
            registration.POST_URL = "https://attacker.invalid/"
            registration.REFEREE_DID = "did:key:attacker"
            registration.validate_candidate = lambda candidate: candidate
            result = fixture.service.execute(
                {**registration.fixed_candidate(), "packet": "{}"},
                fixture.issue("fixture"),
            )
            self.fail(f"late rebinding unexpectedly executed: {result}")
        except registration.RegistrationBoundaryError:
            self.assertEqual(fixture.effects, [])
        finally:
            for name, value in originals.items():
                setattr(registration, name, value)


class ReceiptVerificationTests(unittest.TestCase):
    @staticmethod
    def receipt(**changes):
        body = {
            "type": "sonnet.receipt.v1",
            "contest_id": registration.CONTEST_ID,
            "request_id": registration.REQUEST_ID,
            "participant_did": registration.PARTICIPANT_DID,
            "role": registration.ROLE,
            "x_account_url": registration.X_ACCOUNT_URL,
            "status": "accepted",
            "reason": "",
        }
        body.update(changes)
        return {
            "from": registration.REFEREE_DID,
            "sig": "valid-signature",
            "nonce": "1789279013000",
            "text": json.dumps(body, separators=(",", ":")),
            "seq": 1,
            "ts": "untrusted-transport-time",
            "generation": 99,
        }

    def test_valid_signed_receipt_projects_only_authenticated_fields(self):
        fixture = FixtureBoundary()
        result = fixture.service.verify_receipt(self.receipt())
        self.assertEqual(result["status"], "ACCEPTED_VERIFIED")
        self.assertEqual(result["referee_signature"], "VALID")
        self.assertEqual(result["transport_metadata"], "UNSIGNED_NOT_PROJECTED")
        self.assertNotIn("seq", result)
        self.assertNotIn("ts", result)
        self.assertNotIn("generation", result)
        self.assertEqual(fixture.effects, ["verify"])
        self.assertTrue(fixture.verification_call[2].startswith(
            (registration.ROOM + "|1789279013000|").encode()))

    def test_forged_wrong_referee_and_unsigned_accepted_fail(self):
        forged = self.receipt(); forged["sig"] = "forged"
        wrong = self.receipt(); wrong["from"] = registration.PARTICIPANT_DID
        unsigned = self.receipt(); del unsigned["sig"]
        for record in (forged, wrong, unsigned):
            fixture = FixtureBoundary()
            with self.assertRaises(registration.RegistrationBoundaryError):
                fixture.service.verify_receipt(record)

    def test_receipt_binding_status_role_x_and_required_fields_are_exact(self):
        changes = (
            {"status": "rejected"},
            {"status": "pending"},
            {"request_id": "other"},
            {"participant_did": "did:key:other"},
            {"role": "voter"},
            {"x_account_url": "https://x.com/other"},
            {"contest_id": "sonnet-1"},
            {"type": "notice"},
        )
        for change in changes:
            fixture = FixtureBoundary()
            with self.assertRaises(registration.RegistrationBoundaryError):
                fixture.service.verify_receipt(self.receipt(**change))
        for missing in ("role", "x_account_url"):
            record = self.receipt(); body = json.loads(record["text"]); del body[missing]
            record["text"] = json.dumps(body, separators=(",", ":"))
            fixture = FixtureBoundary()
            with self.assertRaises(registration.RegistrationBoundaryError):
                fixture.service.verify_receipt(record)

    def test_receipt_text_signature_and_nonce_are_bounded(self):
        cases = []
        signature = self.receipt(); signature["sig"] = "a" * 129; cases.append(signature)
        text = self.receipt(); text["text"] = "a" * 4097; cases.append(text)
        nonce = self.receipt(); nonce["nonce"] = "1" * 20; cases.append(nonce)
        zero = self.receipt(); zero["nonce"] = "01"; cases.append(zero)
        for record in cases:
            fixture = FixtureBoundary()
            with self.assertRaises(registration.RegistrationBoundaryError):
                fixture.service.verify_receipt(record)
            self.assertEqual(fixture.effects, [])

    def test_real_ed25519_verifier_accepts_exact_bytes_and_rejects_forgery(self):
        key = Ed25519PrivateKey.generate()
        did = did_from_public_key(key.public_key().public_bytes_raw())
        canonical = b"mb-fixture|7|accepted"
        signature = base64.urlsafe_b64encode(key.sign(canonical)).decode().rstrip("=")
        registration._verify_ed25519(did, signature, canonical)
        with self.assertRaises(registration.RegistrationBoundaryError):
            registration._verify_ed25519(did, signature, canonical + b"x")


class GenericGuardRegressionTests(unittest.TestCase):
    def test_generic_signer_still_rejects_every_mb_room(self):
        for room in (
            registration.ROOM,
            "mb-sonnet-2-discovery",
            "mb-sonnet-2-votes",
            "mb-sonnet-2-submissions",
            "mb-arbitrary",
        ):
            with self.subTest(room=room), self.assertRaises(wire_evidence.WireSafetyError) as caught:
                wire_evidence.build_signing_context(room, registration.NONCE, registration.PACKET_TEXT)
            self.assertEqual(caught.exception.code, "ROOM_INVALID")


if __name__ == "__main__":
    unittest.main()
