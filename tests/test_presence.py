import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flop_agent.presence import (
    AGENT_PATH, CONFIG_PATH, ROOMS_PATH, SEMANTIC_CONTRACT_PATH,
    SEMANTIC_CONTRACT_ANCHOR, LiveWriteDisabled, PresenceConfig, PresenceError,
    approval_digest, apply_payload, canonical_sha256, classify_note,
    execute_approved_write, observe, presence_path, preview_first_write,
    load_semantic_contract, runtime_context, scalar_value, validate_approval,
    _build_presence_write_service,
)

NOW = datetime(2026, 8, 29, 0, 0, tzinfo=timezone.utc)
NICK = "flop-agent-1df29904c79a56"
CONTRACT, CONTRACT_SHA256 = load_semantic_contract()


def config(**changes):
    values = dict(room="lobby", nick=NICK, semantic_spec_anchor=SEMANTIC_CONTRACT_ANCHOR,
                  approved_semantic_contract_sha256=CONTRACT_SHA256,
                  approved_agent_version="0.10.0", operator_enabled=True,
                  live_write_enabled=False, semantic_spec_approved=True,
                  minimum_update_seconds=3600)
    values.update(changes)
    return PresenceConfig(**values)


DISCOVERY = {"name": "technocore-chat", "version": "0.10.0",
             "conventions": {"name_pattern": "^[a-z0-9][a-z0-9_-]{0,47}$"}}
DEPLOYMENT = {"version": "2026.08", "limits": {"reads": 120, "writes": 60,
              "rooms": 20480, "notes": 4096}, "retention": {"idle_seconds": 86400}}


def execute_write_mechanism(config, state, audit, *, preview, approval, writer, reader,
                            now=None, semantic_contract_path=SEMANTIC_CONTRACT_PATH):
    service = _build_presence_write_service(
        config, state, audit, writer=writer, reader=reader,
        semantic_contract_path=semantic_contract_path,
        capability_validator=lambda *_args, **_kwargs: None)
    return service(preview=preview, approval=approval, intent=None, now=now)


class PresenceAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.state, self.audit = root / "state.json", root / "audit.jsonl"

    def tearDown(self):
        self.tmp.cleanup()

    def reader(self, seq=10, note=None, agent=DISCOVERY, deployment=DEPLOYMENT):
        def read(path):
            if path == ROOMS_PATH:
                return {"rooms": [{"room": "lobby", "last_seq": seq}]}
            if path == AGENT_PATH:
                return agent
            if path == CONFIG_PATH:
                if isinstance(deployment, Exception):
                    raise deployment
                return deployment
            if path == config().note_path:
                return note
            raise AssertionError(path)
        return read

    def preview(self, seq=10, note=None, cfg=None, at=NOW):
        return preview_first_write(cfg or config(), self.state, reader=self.reader(seq, note),
                                   application_commit="a" * 40, now=at)

    def approve(self, preview):
        metadata = preview["approval_metadata"]
        return {"metadata": metadata, "binding_sha256": approval_digest(metadata)}

    def test_exact_official_path_and_scalar(self):
        self.assertEqual(presence_path("lobby", NICK), f"/kv/lobby/hb-{NICK}")
        self.assertEqual(scalar_value(123), "123")
        with self.assertRaises(PresenceError):
            scalar_value(True)

    def test_invalid_room_and_nick(self):
        for room in ("", "Lobby", "bad/room"):
            with self.subTest(room=room), self.assertRaises(PresenceError):
                presence_path(room, NICK)
        for nick in ("", "BAD", "x/1"):
            with self.subTest(nick=nick), self.assertRaises(PresenceError):
                presence_path("lobby", nick)

    def test_private_and_unlisted_rooms_rejected(self):
        for room in ("p-secret", "mb-box", "mb-p-secret", "e-p-secret"):
            with self.subTest(room=room), self.assertRaises(PresenceError):
                presence_path(room, NICK)

    def test_absent_expected_unexpected(self):
        self.assertEqual(classify_note(None, None), "ABSENT")
        self.assertEqual(classify_note("10", 10), "EXPECTED")
        self.assertEqual(classify_note("hostile", 10), "UNEXPECTED")

    def test_absent_prepares_if_absent_scalar(self):
        result = self.preview()
        self.assertEqual(result["request"]["body"], {"value": "10", "if_absent": True})
        self.assertFalse(result["write_performed"])

    def test_expected_prepares_exact_cas(self):
        self.preview()
        state = json.loads(self.state.read_text())
        state.update(last_successfully_published_seq=10, last_successful_write_at="2026-08-28T22:00:00Z",
                     known_note_present=True)
        self.state.write_text(json.dumps(state))
        result = self.preview(seq=11, note="10")
        self.assertEqual(result["request"]["body"], {"value": "11", "if": "10"})

    def test_unexpected_hashes_value_and_conflicts(self):
        result = self.preview(note="do-not-store-me")
        state = json.loads(self.state.read_text())
        self.assertEqual(result["status"], "CONFLICT")
        self.assertNotIn("do-not-store-me", self.state.read_text())
        self.assertEqual(len(state["unexpected_value_sha256"]), 64)

    def test_rate_limited_observation_is_preserved(self):
        self.preview()
        state = json.loads(self.state.read_text())
        state.update(last_successfully_published_seq=10, last_successful_write_at="2026-08-28T23:30:00Z",
                     known_note_present=True)
        self.state.write_text(json.dumps(state))
        result = self.preview(seq=11, note="10")
        self.assertEqual(result["status"], "RATE_LIMITED")
        saved = json.loads(self.state.read_text())
        self.assertEqual(saved["last_observed_seq"], 11)
        self.assertEqual(saved["last_observed_at"], "2026-08-29T00:00:00Z")

    def test_sequence_regression_conflicts(self):
        self.preview(seq=10)
        self.assertEqual(self.preview(seq=9)["status"], "CONFLICT")

    def test_disappearance_requires_reapproval(self):
        self.preview()
        state = json.loads(self.state.read_text())
        state.update(last_successfully_published_seq=10, known_note_present=True)
        self.state.write_text(json.dumps(state))
        self.assertEqual(self.preview(seq=11, note=None)["status"], "REAPPROVAL_REQUIRED")

    def test_semantic_spec_drift(self):
        bad = dict(DISCOVERY, version="0.11.0")
        result = preview_first_write(config(), self.state, reader=self.reader(agent=bad),
                                     application_commit="a" * 40, now=NOW)
        self.assertEqual(result["status"], "SPEC_CHANGED")

    def test_local_contract_provenance_and_anchor(self):
        contract, digest = load_semantic_contract(expected_sha256=CONTRACT_SHA256)
        self.assertEqual(digest, CONTRACT_SHA256)
        with self.assertRaises(PresenceError):
            config(semantic_spec_anchor="unreviewed")
        self.assertEqual(contract["classification"],
                         "LOCALLY_REVIEWED_OFFICIAL_SEMANTIC_CONTRACT")
        self.assertEqual(contract["path_template"], "/kv/<room>/hb-<nick>")
        self.assertEqual(contract["conditional_create"], "if_absent")
        self.assertEqual(contract["conditional_update"], "exact_value_cas_if")
        self.assertEqual(contract["conflict"], "http_409_returns_current_value")

    def test_contract_digest_is_canonical_and_semantic_changes_alter_it(self):
        reversed_contract = dict(reversed(list(CONTRACT.items())))
        self.assertEqual(canonical_sha256(CONTRACT), canonical_sha256(reversed_contract))
        compact = self.state.parent / "compact.json"
        pretty = self.state.parent / "pretty.json"
        compact.write_text(json.dumps(reversed_contract, separators=(",", ":")))
        pretty.write_text(json.dumps(CONTRACT, indent=4))
        self.assertEqual(load_semantic_contract(compact)[1], load_semantic_contract(pretty)[1])
        changed = dict(CONTRACT, conditional_update="different")
        self.assertNotEqual(canonical_sha256(CONTRACT), canonical_sha256(changed))

    def test_missing_malformed_and_hash_mismatch_fail_closed(self):
        missing = self.state.parent / "missing.json"
        malformed = self.state.parent / "malformed.json"
        malformed.write_text("{")
        for path in (missing, malformed):
            with self.subTest(path=path):
                if self.state.exists():
                    self.state.unlink()
                result = preview_first_write(config(), self.state, reader=self.reader(),
                    application_commit="a" * 40, now=NOW, semantic_contract_path=path)
                self.assertEqual(result["status"], "SPEC_CHANGED")
        if self.state.exists():
            self.state.unlink()
        mismatch = config(approved_semantic_contract_sha256="0" * 64)
        result = preview_first_write(mismatch, self.state, reader=self.reader(),
            application_commit="a" * 40, now=NOW)
        self.assertEqual(result["status"], "SPEC_CHANGED")

    def test_approval_is_bound_to_contract_digest(self):
        preview = self.preview()
        self.assertEqual(preview["approval_metadata"]["semantic_contract_sha256"], CONTRACT_SHA256)
        approval = self.approve(preview)
        changed = dict(preview["approval_metadata"], semantic_contract_sha256="0" * 64)
        self.assertFalse(validate_approval(changed, approval))

    def test_contract_change_after_approval_fails_closed(self):
        cfg, preview, approval = self.enabled_preview()
        changed = dict(CONTRACT, reviewed_at="2026-08-30T00:00:00Z")
        path = self.state.parent / "changed-contract.json"
        path.write_text(json.dumps(changed))
        with self.assertRaises(LiveWriteDisabled):
            execute_write_mechanism(cfg, self.state, self.audit, preview=preview, approval=approval,
                writer=lambda *_: self.fail("writer called"), reader=lambda _: None,
                now=NOW, semantic_contract_path=path)

    def test_manifest_hash_change_triggers_review(self):
        good = config(approved_agent_manifest_sha256=canonical_sha256(DISCOVERY))
        self.assertEqual(self.preview(cfg=good)["status"], "PREVIEW_READY")
        self.state.unlink()
        changed = dict(DISCOVERY, extra="changed")
        result = preview_first_write(good, self.state, reader=self.reader(agent=changed),
                                     application_commit="a" * 40, now=NOW)
        self.assertEqual(result["status"], "SPEC_CHANGED")

    def test_runtime_context_is_informational(self):
        result = self.preview()
        self.assertEqual(result["runtime_context"]["classification"], "RUNTIME_CONTEXT")
        self.assertEqual(result["runtime_context"]["write_rate_limit"], 60)
        self.assertFalse(result["runtime_context_required_for_write"])

    def test_runtime_context_unavailable_malformed_and_missing(self):
        for raw in (RuntimeError("offline"), "bad", {}):
            with self.subTest(raw=raw):
                if self.state.exists():
                    self.state.unlink()
                result = preview_first_write(config(), self.state, reader=self.reader(deployment=raw),
                                             application_commit="a" * 40, now=NOW)
                self.assertEqual(result["status"], "PREVIEW_READY")
                self.assertIn(result["runtime_context"]["status"], {"UNKNOWN", "PARTIAL"})
                self.assertTrue(result["runtime_context"]["warnings"])

    def test_server_limit_cannot_weaken_local_floor(self):
        self.assertEqual(runtime_context({"limits": {"writes": 100000}})["write_rate_limit"], 100000)
        with self.assertRaises(PresenceError):
            config(minimum_update_seconds=3599)

    def test_kill_switch_prevents_write(self):
        preview = self.preview()
        with self.assertRaises(LiveWriteDisabled):
            execute_write_mechanism(config(), self.state, self.audit, preview=preview,
                approval=self.approve(preview), writer=lambda *_: self.fail("writer called"),
                reader=lambda _: "10", now=NOW)
        self.assertFalse(self.audit.exists())

    def test_approval_binding_and_invalidation(self):
        preview = self.preview()
        approval = self.approve(preview)
        self.assertTrue(validate_approval(preview["approval_metadata"], approval))
        changed = dict(preview["approval_metadata"], observed_seq=11)
        self.assertFalse(validate_approval(changed, approval))
        with self.assertRaises(LiveWriteDisabled):
            apply_payload(preview, confirm=True)
        with self.assertRaises(PresenceError):
            preview_first_write(config(), self.state, reader=self.reader(), application_commit="main", now=NOW)

    def test_zero_write_preview_never_calls_writer(self):
        result = self.preview()
        self.assertEqual(result["mode"], "ZERO_WRITE")
        self.assertEqual(result["status"], "PREVIEW_READY")
        self.assertFalse(result["write_performed"])

    def enabled_preview(self):
        cfg = config(live_write_enabled=True)
        preview = self.preview(cfg=cfg)
        return cfg, preview, self.approve(preview)

    def test_readback_match_and_append_only_audit(self):
        cfg, preview, approval = self.enabled_preview()
        reads = iter((None, "10"))
        result = execute_write_mechanism(cfg, self.state, self.audit, preview=preview, approval=approval,
            writer=lambda path, body: {"status": 200, "body": "ok"}, reader=lambda path: next(reads), now=NOW)
        self.assertEqual(result["status"], "SUCCESS")
        self.assertEqual(result["state"]["last_successfully_published_seq"], 10)
        audit = self.audit.read_text()
        self.assertIn('"result":"SUCCESS"', audit)
        self.assertNotIn('"body":"ok"', audit)

    def test_alternate_2xx_performs_readback(self):
        cfg, preview, approval = self.enabled_preview()
        reads = iter((None, "10"))
        result = execute_write_mechanism(cfg, self.state, self.audit, preview=preview, approval=approval,
            writer=lambda *_: {"status": 204}, reader=lambda _: next(reads), now=NOW)
        self.assertEqual(result["status"], "SUCCESS")

    def test_non_2xx_fails_closed_without_readback(self):
        for status in (300, 400, 403, 404, 429, 500, 799):
            with self.subTest(status=status):
                if self.state.exists():
                    self.state.unlink()
                if self.audit.exists():
                    self.audit.unlink()
                cfg, preview, approval = self.enabled_preview()
                calls = []
                result = execute_write_mechanism(cfg, self.state, self.audit, preview=preview, approval=approval,
                    writer=lambda *_: {"status": status},
                    reader=lambda _: calls.append("prewrite") or None, now=NOW)
                self.assertEqual(result["status"], "RATE_LIMITED" if status == 429 else "HTTP_ERROR")
                self.assertEqual(calls, ["prewrite"])

    def test_missing_status_fails_closed_without_readback(self):
        cfg, preview, approval = self.enabled_preview()
        calls = []
        result = execute_write_mechanism(cfg, self.state, self.audit, preview=preview, approval=approval,
            writer=lambda *_: {}, reader=lambda _: calls.append("prewrite") or None, now=NOW)
        self.assertEqual(result["status"], "HTTP_ERROR")
        self.assertEqual(calls, ["prewrite"])

    def test_readback_mismatch_kill_switches(self):
        cfg, preview, approval = self.enabled_preview()
        reads = iter((None, "11"))
        result = execute_write_mechanism(cfg, self.state, self.audit, preview=preview, approval=approval,
            writer=lambda *_: {"status": 200}, reader=lambda _: next(reads), now=NOW)
        self.assertEqual(result["status"], "READBACK_MISMATCH")
        self.assertFalse(result["state"]["live_write_ready"])

    def test_409_conflict_hashes_returned_value(self):
        cfg, preview, approval = self.enabled_preview()
        result = execute_write_mechanism(cfg, self.state, self.audit, preview=preview, approval=approval,
            writer=lambda *_: {"status": 409, "body": "untrusted"}, reader=lambda _: None, now=NOW)
        self.assertEqual(result["status"], "CONFLICT")
        self.assertNotIn("untrusted", self.state.read_text())
        self.assertNotIn("untrusted", self.audit.read_text())

    def test_prewrite_reconciliation_blocks_changed_note(self):
        cfg, preview, approval = self.enabled_preview()
        result = execute_write_mechanism(cfg, self.state, self.audit, preview=preview, approval=approval,
            writer=lambda *_: self.fail("writer called"), reader=lambda _: "changed", now=NOW)
        self.assertEqual(result["status"], "CONFLICT")
        self.assertNotIn("changed", self.state.read_text())

    def test_one_hour_attempt_floor(self):
        cfg, preview, approval = self.enabled_preview()
        state = json.loads(self.state.read_text())
        state["last_attempted_write_at"] = "2026-08-28T23:30:00Z"
        self.state.write_text(json.dumps(state))
        with self.assertRaises(LiveWriteDisabled):
            execute_write_mechanism(cfg, self.state, self.audit, preview=preview, approval=approval,
                writer=lambda *_: self.fail("writer called"), reader=lambda _: "10", now=NOW)
        self.assertEqual(json.loads(self.state.read_text())["frequency_guard_status"],
                         "FREQUENCY_GUARD_TRIPPED")

    def test_readme_and_public_contract_are_current(self):
        root = Path(__file__).resolve().parents[1]
        readme = (root / "README.md").read_text()
        self.assertIn("LIVE READY — DISABLED", readme)
        self.assertIn("No production HTTP writer", readme)
        self.assertIn("CLI has no live-write command", readme)
        self.assertNotIn("Presence V0 is `DRY_RUN_ONLY`", readme)
        contract = json.loads((root / "data/presence_semantic_contract.json").read_text())
        self.assertEqual(contract, CONTRACT)

    def test_live_unknown_never_observed_and_disabled(self):
        disabled = observe(config(operator_enabled=False), self.state, reader=lambda _: self.fail("read"), now=NOW)
        self.assertEqual(disabled["status"], "DISABLED")
        self.state.unlink()
        first = observe(config(), self.state, reader=lambda _: {"rooms": [{"room": "lobby", "last_seq": 10}]}, now=NOW)
        self.assertEqual(first["status"], "UNKNOWN")
        second = observe(config(), self.state, reader=lambda _: {"rooms": [{"room": "lobby", "last_seq": 11}]}, now=NOW + timedelta(minutes=5))
        self.assertEqual(second["status"], "LIVE")


if __name__ == "__main__":
    unittest.main()
