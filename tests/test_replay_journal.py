import inspect
import json
import os
import pickle
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from flop_agent import replay_journal as journal


NOW = datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc)
HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64


def action(*, nonce="900719925474099312345678901234567890", payload=HASH_A):
    return journal.CanonicalAction(
        "did:key:zFixture", "SIGNED_TEST_ACTION", "lobby", nonce, payload,
        HASH_B, "resource:fixture", "fixture-schema-v1")


def service(path):
    return journal._build_replay_journal_service(path, lambda: NOW)


def prepare(value, item):
    value.observe(item)
    proof = value._issue_validation(item)
    value.validate(item, proof)
    authority = value._issue_effect_authority(item, "reviewed-authority:fixture")
    return authority


class ReplayJournalTests(unittest.TestCase):
    def test_first_and_duplicate_observation_share_one_record(self):
        with tempfile.TemporaryDirectory() as directory:
            value = service(Path(directory) / "private" / "ledger.sqlite3")
            first, second = value.observe(action()), value.observe(action())
            self.assertEqual(first["decision"], "FIRST_OBSERVATION")
            self.assertEqual(second["decision"], "DUPLICATE_OBSERVATION")
            self.assertEqual(second["observation_count"], 2)
            self.assertEqual(first["replay_id"], second["replay_id"])

    def test_lossless_nonce_and_canonical_identity(self):
        item = action()
        with tempfile.TemporaryDirectory() as directory:
            value = service(Path(directory) / "db")
            self.assertEqual(value.replay_id(item), value.replay_id(action()))
            with self.assertRaises(journal.ReplaySafetyError):
                action(nonce=1e30)
            value.observe(item)
            self.assertEqual(value.inspect(item)["state"], "OBSERVED")

    def test_nonce_reuse_with_different_payload_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            value = service(Path(directory) / "db")
            original = action()
            value.observe(original)
            result = value.observe(action(payload=HASH_C))
            self.assertEqual(result["decision"], "REPLAY_IDENTITY_CONFLICT")
            self.assertEqual(value.inspect(original)["state"], "REPLAY_IDENTITY_CONFLICT")

    def test_validated_is_not_authority_and_invalid_transitions_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            value = service(Path(directory) / "db")
            item = action()
            value.observe(item)
            with self.assertRaises(PermissionError):
                value.validate(item, object.__new__(journal.ValidationAuthority))
            with self.assertRaises(PermissionError):
                value.reserve(item, object.__new__(journal.EffectAuthority),
                              journal.EffectClass.PAYMENT, "rail:1", HASH_C)
            proof = value._issue_validation(item)
            value.validate(item, proof)
            with self.assertRaises(journal.ReplaySafetyError):
                value.validate(item, proof)

    def test_confirmed_duplicate_never_reserves_twice(self):
        with tempfile.TemporaryDirectory() as directory:
            value = service(Path(directory) / "db")
            item = action()
            authority = prepare(value, item)
            reservation = value.reserve(item, authority, journal.EffectClass.FAUCET_CLAIM,
                                        "faucet:test", HASH_C)
            value.attempted(reservation)
            value.confirm(reservation, HASH_A)
            self.assertEqual(value.inspect(item)["retry_classification"], "DO_NOT_RETRY")
            value.observe(item)
            with self.assertRaises(journal.ReplaySafetyError):
                value.reserve(item, authority, journal.EffectClass.FAUCET_CLAIM,
                              "faucet:test", HASH_C)

    def test_concurrent_duplicate_gets_exactly_one_reservation(self):
        with tempfile.TemporaryDirectory() as directory:
            value = service(Path(directory) / "db")
            item = action()
            authority = prepare(value, item)
            outcomes = []
            barrier = threading.Barrier(2)
            def worker():
                barrier.wait()
                try:
                    value.reserve(item, authority, journal.EffectClass.PAYMENT, "rail:7", HASH_C)
                    outcomes.append("reserved")
                except journal.ReplaySafetyError:
                    outcomes.append("duplicate")
            threads = [threading.Thread(target=worker) for _ in range(2)]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            self.assertEqual(sorted(outcomes), ["duplicate", "reserved"])

    def test_restart_recovers_attempt_as_unknown_not_safe_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "db"
            first = service(path)
            item = action()
            authority = prepare(first, item)
            reservation = first.reserve(item, authority, journal.EffectClass.INFERENCE_SPEND,
                                        "model:fixture", HASH_C)
            first.attempted(reservation)
            restarted = service(path)
            self.assertEqual(restarted.recover(), 1)
            result = restarted.inspect(item)
            self.assertEqual(result["state"], "EFFECT_OUTCOME_UNKNOWN")
            self.assertEqual(result["retry_classification"], "RECONCILIATION_REQUIRED")

    def test_reserved_crash_is_not_marked_attempted_and_safe_failure_can_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "db"
            first = service(path)
            item = action()
            authority = prepare(first, item)
            reservation = first.reserve(item, authority, journal.EffectClass.AGENT_TASK,
                                        "job:99999999999999999999", HASH_C)
            self.assertEqual(service(path).recover(), 0)
            self.assertEqual(first.inspect(item)["state"], "EFFECT_RESERVED")
            first.fail_safe(reservation)
            self.assertEqual(first.inspect(item)["retry_classification"], "SAFE_TO_RETRY")
            retry_authority = first._issue_effect_authority(item, "reviewed-authority:retry")
            retry = first.reserve(item, retry_authority, journal.EffectClass.AGENT_TASK,
                                  "job:99999999999999999999", HASH_C)
            self.assertIs(type(retry), journal.Reservation)

    def test_unknown_requires_service_local_reconciliation_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "db"
            first = service(path)
            item = action()
            authority = prepare(first, item)
            reservation = first.reserve(item, authority, journal.EffectClass.PAYMENT,
                                        "rail:12345678901234567890", HASH_C)
            first.attempted(reservation)
            restarted = service(path)
            restarted.recover()
            foreign = first._issue_reconciliation(item, True, HASH_A)
            with self.assertRaises(PermissionError):
                restarted.reconcile(item, foreign)
            proof = restarted._issue_reconciliation(item, True, HASH_A)
            result = restarted.reconcile(item, proof)
            self.assertEqual(result["state"], "EFFECT_FAILED_SAFE")
            self.assertEqual(result["confirmation_evidence_hash"], HASH_A)

    def test_projection_and_serialization_cannot_manufacture_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            value = service(Path(directory) / "db")
            item = action()
            value.observe(item)
            projection = dict(value.inspect(item))
            projection["state"] = "EFFECT_CONFIRMED"
            projection = json.loads(json.dumps(projection))
            self.assertEqual(value.inspect(item)["state"], "OBSERVED")
            for token_type in (journal.ValidationAuthority, journal.EffectAuthority,
                               journal.Reservation):
                with self.assertRaises(TypeError):
                    pickle.dumps(object.__new__(token_type))

    def test_cross_service_authority_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            one = service(Path(directory) / "one")
            two = service(Path(directory) / "two")
            item = action()
            one.observe(item)
            two.observe(item)
            proof = one._issue_validation(item)
            with self.assertRaises(PermissionError):
                two.validate(item, proof)

    def test_private_permissions_and_symlink_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private" / "db"
            value = service(path)
            value.observe(action())
            self.assertEqual(os.stat(path.parent).st_mode & 0o777, 0o700)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            link = Path(directory) / "linked"
            link.symlink_to(path)
            unsafe = service(link)
            with self.assertRaises(journal.ReplaySafetyError):
                unsafe.observe(action(nonce="2"))

    def test_public_api_inventory_and_module_rebinding(self):
        forbidden = {"path", "db_path", "store", "clock", "policy", "transition",
                     "validator", "callback", "effect_adapter", "authority_issuer"}
        for operation in (journal.observe_action, journal.inspect_action,
                          journal.canonical_replay_id, journal.recover_incomplete_attempts):
            self.assertFalse(forbidden & set(inspect.signature(operation).parameters))
        self.assertFalse(hasattr(journal, "reserve_effect"))
        with tempfile.TemporaryDirectory() as directory:
            value = service(Path(directory) / "db")
            item = action()
            before = value.replay_id(item)
            with mock.patch.object(journal, "POLICY_VERSION", "forged"), \
                 mock.patch.object(journal, "hashlib", None), \
                 mock.patch.object(journal, "ReplayState", None):
                self.assertEqual(value.replay_id(item), before)

    def test_security_sensitive_dynamic_globals_are_zero_recursively(self):
        seen = set()
        stack = [journal.observe_action, journal.inspect_action,
                 journal.canonical_replay_id, journal.recover_incomplete_attempts]
        while stack:
            function = stack.pop()
            if id(function) in seen or not inspect.isfunction(function):
                continue
            seen.add(id(function))
            self.assertEqual(inspect.getclosurevars(function).globals, {}, function)
            for cell in function.__closure__ or ():
                try:
                    value = cell.cell_contents
                except ValueError:
                    continue
                if inspect.isfunction(value):
                    stack.append(value)
                elif isinstance(value, dict):
                    stack.extend(item for item in value.values() if inspect.isfunction(item))


if __name__ == "__main__":
    unittest.main()
