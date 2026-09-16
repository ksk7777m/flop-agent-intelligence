from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import pickle
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from flop_agent import sonnet_checkpoint_migration as migration
from flop_agent import sonnet_receipt_observer as observer
from flop_agent import sonnet_registration as registration


START = datetime(2026, 9, 13, 7, 38, tzinfo=timezone.utc)


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.root = Path(self.temporary.name) / "private"
        self.root.mkdir(mode=0o700)
        self.child = self.root / observer.RECEIPT_CHILD_BASENAME
        self.child.mkdir(mode=0o700)
        self.archive = self.root / migration.ARCHIVE_BASENAME
        self.archive.mkdir(mode=0o700)
        self.checkpoint_raw, self.progress_raw = self.seed(progress=False)

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def reference():
        return hashlib.sha256(
            registration.REQUEST_ID.encode("utf-8")).hexdigest()

    def legacy(self, *, schema, cursor=10):
        return {
            "schema": schema,
            "request_reference_sha256": self.reference(),
            "contest_id": observer.CONTEST_ID,
            "room": observer.ROOM,
            "generation": 1,
            "cursor": cursor,
            "observation_started_at": START.isoformat().replace("+00:00", "Z"),
        }

    def seed(self, *, progress):
        for path in self.child.iterdir():
            path.unlink()
        checkpoint_raw = json.dumps(
            self.legacy(
                schema=migration.LEGACY_CHECKPOINT_SCHEMA),
            sort_keys=True, separators=(",", ":")).encode()
        store = observer.PrivateReceiptStore(self.child)
        try:
            store._atomic_write(
                f"{hashlib.sha256(checkpoint_raw).hexdigest()}.checkpoint",
                checkpoint_raw)
            progress_raw = None
            if progress:
                progress_raw = json.dumps(
                    self.legacy(
                        schema=migration.LEGACY_PROGRESS_SCHEMA, cursor=12),
                    sort_keys=True, separators=(",", ":")).encode()
                store._atomic_replace(
                    observer.CURSOR_PROGRESS_BASENAME, progress_raw)
        finally:
            store.close()
        return checkpoint_raw, progress_raw

    def prepare(self):
        return migration._prepare_migration_core(
            self.root,
            _worktrees=lambda _root: (observer.REPOSITORY_ROOT,),
            _filesystem_validator=lambda _path: True)

    def apply(self, plan, *, fault=lambda _stage: None):
        return migration._apply_migration_core(
            plan,
            _worktrees=lambda _root: (observer.REPOSITORY_ROOT,),
            _filesystem_validator=lambda _path: True, _fault=fault)

    def verify_v2(self, expected_cursor):
        store = observer.PrivateReceiptStore(self.child)
        try:
            store.acquire_session_lock(create=False)
            value = store.load_restart_checkpoint(
                request_reference_sha256=self.reference(),
                lineage_binding_sha256=
                    observer._PRODUCTION_LINEAGE_BINDING_SHA256)
            self.assertEqual(value["generation"], 1)
            self.assertEqual(value["cursor"], expected_cursor)
            self.assertEqual(
                value["observation_started_at"],
                START.isoformat().replace("+00:00", "Z"))
        finally:
            store.close()

    def test_checkpoint_only_migrates_and_archives_exact_bytes(self):
        plan = self.prepare()
        self.assertEqual(plan.status, "LEGACY_MIGRATION_PREPARED")
        self.assertEqual(
            dict(self.apply(plan)), {"status": "LEGACY_MIGRATION_APPLIED"})
        self.assertEqual(
            (self.archive / migration.ARCHIVE_CHECKPOINT).read_bytes(),
            self.checkpoint_raw)
        self.assertFalse((self.archive / migration.ARCHIVE_PROGRESS).exists())
        self.verify_v2(10)
        self.assertFalse((self.child / migration.TRANSACTION_MARKER).exists())

    def test_checkpoint_and_progress_preserve_latest_cursor_and_lineage(self):
        self.checkpoint_raw, self.progress_raw = self.seed(progress=True)
        self.apply(self.prepare())
        self.assertEqual(
            (self.archive / migration.ARCHIVE_PROGRESS).read_bytes(),
            self.progress_raw)
        self.verify_v2(12)
        progress = json.loads(
            (self.child / observer.CURSOR_PROGRESS_BASENAME).read_text())
        self.assertEqual(progress["schema"], migration.PROGRESS_V2_SCHEMA)
        self.assertEqual(
            progress["lineage_binding_sha256"],
            observer._PRODUCTION_LINEAGE_BINDING_SHA256)

    def test_plan_is_path_free_opaque_single_use_and_not_serializable(self):
        plan = self.prepare()
        rendered = repr(plan)
        self.assertNotIn(str(self.root), rendered)
        with self.assertRaises(TypeError):
            pickle.dumps(plan)
        with self.assertRaises(TypeError):
            __import__("copy").copy(plan)
        self.apply(plan)
        with self.assertRaisesRegex(
                migration.MigrationError, "MIGRATION_PLAN_CONSUMED"):
            self.apply(plan)

    def test_lock_absent_and_contended_make_no_changes(self):
        lock = self.child / observer.SESSION_LOCK_BASENAME
        lock.unlink()
        before = self.checkpoint_raw
        with self.assertRaises(observer.ReceiptObserverError):
            self.prepare()
        self.assertEqual(next(self.child.glob("*.checkpoint")).read_bytes(), before)
        self.assertEqual(list(self.archive.iterdir()), [])

        lock.write_bytes(b"")
        os.chmod(lock, 0o600)
        holder = observer.PrivateReceiptStore(self.child)
        try:
            holder.acquire_session_lock(create=False)
            with self.assertRaises(observer.ReceiptObserverError):
                self.prepare()
        finally:
            holder.close()
        self.assertEqual(list(self.archive.iterdir()), [])

    def test_invalid_schema_digest_progress_and_regression_are_rejected(self):
        path = next(self.child.glob("*.checkpoint"))
        path.write_bytes(path.read_bytes() + b"x")
        os.chmod(path, 0o600)
        with self.assertRaises(migration.MigrationError):
            self.prepare()

        self.checkpoint_raw, self.progress_raw = self.seed(progress=True)
        progress = self.child / observer.CURSOR_PROGRESS_BASENAME
        value = json.loads(progress.read_text())
        value["cursor"] = 9
        progress.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")))
        os.chmod(progress, 0o600)
        with self.assertRaisesRegex(
                migration.MigrationError, "LEGACY_MIGRATION_PROGRESS_INVALID"):
            self.prepare()

    def test_receipt_metadata_conflict_unknown_and_temporary_block_prepare(self):
        names = (
            f"{'a' * 64}.receipt", f"{'b' * 64}.json",
            f"{'c' * 64}.conflict", "unknown", ".tmp-interrupted",
        )
        for name in names:
            with self.subTest(name=name):
                path = self.child / name
                path.write_bytes(b"x")
                os.chmod(path, 0o600)
                with self.assertRaisesRegex(
                        migration.MigrationError,
                        "LEGACY_MIGRATION_UNEXPECTED_ARTIFACT"):
                    self.prepare()
                path.unlink()

    def test_special_symlink_mode_and_link_count_are_rejected_without_blocking(self):
        original = next(self.child.glob("*.checkpoint"))
        raw = original.read_bytes()
        original.unlink()
        cases = ("directory", "symlink", "fifo", "mode", "hardlink")
        for case in cases:
            with self.subTest(case=case):
                target = self.child / f"{hashlib.sha256(raw).hexdigest()}.checkpoint"
                if case == "directory":
                    target.mkdir()
                elif case == "symlink":
                    target.symlink_to(self.archive)
                elif case == "fifo":
                    os.mkfifo(target, 0o600)
                else:
                    target.write_bytes(raw)
                    os.chmod(target, 0o644 if case == "mode" else 0o600)
                    if case == "hardlink":
                        os.link(target, self.child / "extra-link")
                with self.assertRaises(migration.MigrationError):
                    self.prepare()
                for item in list(self.child.iterdir()):
                    if item.name != observer.SESSION_LOCK_BASENAME:
                        if item.is_dir() and not item.is_symlink():
                            item.rmdir()
                        else:
                            item.unlink()

    def test_archive_failure_keeps_active_legacy_bytes(self):
        plan = self.prepare()
        def fault(stage):
            if stage == "after_archive_checkpoint":
                raise RuntimeError("fixture fault")
        with self.assertRaises(RuntimeError):
            self.apply(plan, fault=fault)
        self.assertEqual(
            next(self.child.glob("*.checkpoint")).read_bytes(),
            self.checkpoint_raw)
        self.assertFalse((self.child / migration.TRANSACTION_MARKER).exists())

    def test_every_precommit_fault_boundary_is_fail_closed_and_unlocks(self):
        stages = (
            "before_archive_checkpoint", "after_archive_checkpoint",
            "before_archive_progress", "after_archive_progress",
            "before_archive_manifest", "after_archive_manifest",
            "before_transaction_marker", "after_transaction_marker",
            "before_stage_checkpoint", "after_stage_checkpoint",
            "before_stage_progress", "after_stage_progress",
            "before_switch_checkpoint", "after_switch_checkpoint",
            "before_marker_remove",
        )
        for stage in stages:
            with self.subTest(stage=stage):
                with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
                    root = Path(temporary) / "private"
                    root.mkdir(mode=0o700)
                    child = root / observer.RECEIPT_CHILD_BASENAME
                    child.mkdir(mode=0o700)
                    archive = root / migration.ARCHIVE_BASENAME
                    archive.mkdir(mode=0o700)
                    value = self.legacy(
                        schema=migration.LEGACY_CHECKPOINT_SCHEMA)
                    raw = json.dumps(
                        value, sort_keys=True, separators=(",", ":")).encode()
                    store = observer.PrivateReceiptStore(child)
                    store._atomic_write(
                        f"{hashlib.sha256(raw).hexdigest()}.checkpoint", raw)
                    progress = self.legacy(
                        schema=migration.LEGACY_PROGRESS_SCHEMA, cursor=12)
                    progress_raw = json.dumps(
                        progress, sort_keys=True,
                        separators=(",", ":")).encode()
                    store._atomic_replace(
                        observer.CURSOR_PROGRESS_BASENAME, progress_raw)
                    store.close()
                    plan = migration._prepare_migration_core(
                        root, _worktrees=lambda _root: (observer.REPOSITORY_ROOT,),
                        _filesystem_validator=lambda _path: True)
                    def fail(current):
                        if current == stage:
                            raise RuntimeError("fixture fault")
                    with self.assertRaises(RuntimeError):
                        migration._apply_migration_core(
                            plan,
                            _worktrees=lambda _root: (observer.REPOSITORY_ROOT,),
                            _filesystem_validator=lambda _path: True,
                            _fault=fail)
                    check = observer.PrivateReceiptStore(child)
                    try:
                        check.acquire_session_lock(create=False)
                    finally:
                        check.close()
                    verifier = observer.PrivateReceiptStore(child)
                    try:
                        with self.assertRaises(observer.ReceiptObserverError):
                            verifier.load_restart_checkpoint(
                                request_reference_sha256=self.reference(),
                                lineage_binding_sha256=
                                    observer._PRODUCTION_LINEAGE_BINDING_SHA256)
                    finally:
                        verifier.close()

    def test_fault_after_marker_removal_leaves_a_valid_committed_v2(self):
        plan = self.prepare()
        def fault(stage):
            if stage == "after_marker_remove":
                raise RuntimeError("fixture fault")
        with self.assertRaises(RuntimeError):
            self.apply(plan, fault=fault)
        self.verify_v2(10)
        self.assertFalse((self.child / migration.TRANSACTION_MARKER).exists())

    def test_archive_must_be_preprovisioned_empty_and_private(self):
        self.archive.rmdir()
        with self.assertRaises(observer.ReceiptObserverError):
            self.prepare()
        self.archive.mkdir(mode=0o700)
        (self.archive / "unexpected").write_bytes(b"x")
        with self.assertRaisesRegex(
                migration.MigrationError, "LEGACY_MIGRATION_ARCHIVE_INVALID"):
            self.prepare()
        (self.archive / "unexpected").unlink()
        self.archive.chmod(0o755)
        with self.assertRaises(observer.ReceiptObserverError):
            self.prepare()

    def test_completed_rerun_rejects_without_rewriting_evidence(self):
        self.apply(self.prepare())
        active_before = {
            item.name: item.read_bytes() for item in self.child.iterdir()
        }
        archive_before = {
            item.name: item.read_bytes() for item in self.archive.iterdir()
        }
        with self.assertRaises(migration.MigrationError):
            self.prepare()
        self.assertEqual(
            {item.name: item.read_bytes() for item in self.child.iterdir()},
            active_before)
        self.assertEqual(
            {item.name: item.read_bytes() for item in self.archive.iterdir()},
            archive_before)

    def test_owner_mismatch_is_rejected_without_writes(self):
        before_child = sorted(item.name for item in self.child.iterdir())
        before_archive = sorted(item.name for item in self.archive.iterdir())
        with mock.patch.object(
                observer.os, "getuid", return_value=os.getuid() + 1):
            with self.assertRaises(observer.ReceiptObserverError):
                self.prepare()
        self.assertEqual(
            sorted(item.name for item in self.child.iterdir()), before_child)
        self.assertEqual(
            sorted(item.name for item in self.archive.iterdir()), before_archive)

    def test_prepare_then_target_change_rejects_before_archive_write(self):
        plan = self.prepare()
        path = next(self.child.glob("*.checkpoint"))
        path.write_bytes(path.read_bytes() + b"x")
        os.chmod(path, 0o600)
        with self.assertRaises(migration.MigrationError):
            self.apply(plan)
        self.assertEqual(list(self.archive.iterdir()), [])

    def test_import_and_default_projection_do_not_write_or_start_network(self):
        before_child = sorted(item.name for item in self.child.iterdir())
        before_archive = sorted(item.name for item in self.archive.iterdir())
        plan = self.prepare()
        projection = dict(migration.preparation_projection(plan))
        self.assertEqual(projection, {"status": "LEGACY_MIGRATION_PREPARED"})
        self.assertEqual(sorted(item.name for item in self.child.iterdir()), before_child)
        self.assertEqual(sorted(item.name for item in self.archive.iterdir()), before_archive)
        source = (Path(__file__).parents[1] / "scripts" /
                  "migrate_sonnet_checkpoint.py").read_text()
        self.assertNotIn("urllib", source)
        self.assertNotIn("requests", source)
        self.assertNotIn("identity", source.lower())

    def test_cli_initialization_failure_is_fixed_and_redacted(self):
        script = (Path(__file__).parents[1] / "scripts" /
                  "migrate_sonnet_checkpoint.py")
        spec = importlib.util.spec_from_file_location(
            "fixture_sonnet_migration_cli", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        with mock.patch.object(
                sys, "path", [str(script.parent), *sys.path]):
            spec.loader.exec_module(module)
        output = io.StringIO()
        with mock.patch.object(
                module, "install_trusted_project_import_path",
                side_effect=RuntimeError("private fixture detail")):
            with mock.patch.object(sys, "argv", [str(script)]):
                with redirect_stdout(output):
                    self.assertEqual(module.main(), 1)
        self.assertEqual(
            json.loads(output.getvalue()),
            {"status": "LEGACY_MIGRATION_INTERNAL_FAILURE"})
        self.assertNotIn("private fixture detail", output.getvalue())


if __name__ == "__main__":
    unittest.main()
