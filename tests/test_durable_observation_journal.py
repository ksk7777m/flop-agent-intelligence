import copy
import fcntl
import inspect
import json
import math
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import jsonschema

from flop_agent import durable_observation_journal as journal
from flop_agent import evidence_transport, observation_retention, replay_journal


class DurableObservationJournalTests(unittest.TestCase):
    def service(self, root, fault=None):
        values = journal._build_store(Path(root), fault=fault, fixture_issuers=True)
        return dict(zip(("prepare", "intent", "source_intent", "started", "result",
            "commit", "finalize", "inspect", "permit", "issue_result", "issue_evidence"), values))

    def prepared(self, root):
        api = self.service(root); token = api["prepare"](); return api, token

    def complete(self, root):
        api, token = self.prepared(root); api["intent"](token)
        for source in observation_retention.FIXED_SOURCES:
            api["source_intent"](token, source)
            api["started"](token, source)
            api["result"](token, source, api["issue_result"](source))
        return api, token

    def test_production_api_has_fixed_root_and_no_dependency_injection(self):
        self.assertEqual(tuple(inspect.signature(journal.prepare_attempt).parameters), ())
        self.assertEqual(tuple(inspect.signature(journal.inspect_journal).parameters), ())
        for name in journal.__all__:
            self.assertNotIn(name, {"_build_store", "_fixture_result", "_fixture_evidence"})
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(len(journal._build_store(Path(folder))), 9)
        source = inspect.getsource(journal)
        for forbidden in ("import urllib", "import requests", "import httpx", "import socket",
                          "import subprocess", "invoke_mcp(", "invoke_signer(", "use_wallet("):
            self.assertNotIn(forbidden, source.lower())

    def test_secure_files_and_duplicate_attempt(self):
        with tempfile.TemporaryDirectory() as folder:
            api, _ = self.prepared(folder); root = Path(folder)
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            for path in (root / "journal.jsonl", root / "journal.lock"):
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(path.stat().st_nlink, 1)
            with self.assertRaisesRegex(journal.JournalError, "JOURNAL_ALREADY_EXISTS"):
                api["prepare"]()

    def test_symlink_nonregular_wrong_mode_and_hardlink_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); root.chmod(0o700); target = root / "target"; target.write_bytes(b"")
            (root / "journal.jsonl").symlink_to(target)
            with self.assertRaises(journal.JournalError): self.service(root)["inspect"]()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); root.chmod(0o700); (root / "journal.jsonl").mkdir()
            with self.assertRaises(journal.JournalError): self.service(root)["inspect"]()
        with tempfile.TemporaryDirectory() as folder:
            api, _ = self.prepared(folder); path = Path(folder) / "journal.jsonl"; path.chmod(0o644)
            with self.assertRaises(journal.JournalError): api["inspect"]()
        with tempfile.TemporaryDirectory() as folder:
            api, _ = self.prepared(folder); path = Path(folder) / "journal.jsonl"; os.link(path, Path(folder) / "copy")
            with self.assertRaises(journal.JournalError): api["inspect"]()

    def test_symlink_lock_and_duplicate_writer_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); root.chmod(0o700); target = root / "target"; target.write_bytes(b"")
            (root / "journal.lock").symlink_to(target)
            with self.assertRaises(journal.JournalError): self.service(root)["prepare"]()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); api, token = self.prepared(root)
            with (root / "journal.lock").open("r+b") as held:
                fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaisesRegex(journal.JournalError, "DUPLICATE_WRITER"):
                    api["intent"](token)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); root.chmod(0o700); target = root / "target"; target.write_bytes(b"")
            (root / ".journal.candidate").symlink_to(target)
            with self.assertRaises(journal.JournalError): self.service(root)["prepare"]()

    @unittest.skipUnless(hasattr(os, "fork"), "fork required")
    def test_other_process_writer_lock_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); api, token = self.prepared(root)
            ready_r, ready_w = os.pipe(); release_r, release_w = os.pipe(); pid = os.fork()
            if pid == 0:
                os.close(ready_r); os.close(release_w)
                fd = os.open(root / "journal.lock", os.O_RDWR)
                fcntl.flock(fd, fcntl.LOCK_EX); os.write(ready_w, b"1"); os.read(release_r, 1)
                os.close(fd); os.close(ready_w); os.close(release_r); os._exit(0)
            os.close(ready_w); os.close(release_r); self.assertEqual(os.read(ready_r, 1), b"1")
            with self.assertRaisesRegex(journal.JournalError, "DUPLICATE_WRITER"):
                api["intent"](token)
            os.write(release_w, b"1"); os.close(release_w); os.close(ready_r); os.waitpid(pid, 0)

    def test_symlink_runtime_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder); real = parent / "real"; real.mkdir(mode=0o700)
            linked = parent / "linked"; linked.symlink_to(real, target_is_directory=True)
            with self.assertRaises(journal.JournalError): self.service(linked)["inspect"]()

    def test_thread_updates_are_serialized_without_lost_update(self):
        with tempfile.TemporaryDirectory() as folder:
            api, token = self.prepared(folder); barrier = threading.Barrier(2); outcomes = []
            def worker():
                barrier.wait()
                try: api["intent"](token); outcomes.append("OK")
                except journal.JournalError as error: outcomes.append(error.code)
            workers = [threading.Thread(target=worker) for _ in range(2)]
            for worker in workers: worker.start()
            for worker in workers: worker.join()
            self.assertEqual(sorted(outcomes), ["DUPLICATE_ATTEMPT_INTENT", "OK"])
            self.assertEqual(api["inspect"]()["record_count"], 2)

    @unittest.skipUnless(hasattr(os, "fork"), "fork required")
    def test_forked_process_cannot_reuse_parent_token(self):
        with tempfile.TemporaryDirectory() as folder:
            api, token = self.prepared(folder); read_fd, write_fd = os.pipe(); pid = os.fork()
            if pid == 0:
                os.close(read_fd)
                try: api["intent"](token); code = b"BAD"
                except journal.JournalError as error: code = error.code.encode("ascii")
                os.write(write_fd, code); os.close(write_fd); os._exit(0)
            os.close(write_fd); result = os.read(read_fd, 128); os.close(read_fd); os.waitpid(pid, 0)
            self.assertEqual(result, b"FOREIGN_PROCESS_ATTEMPT")
            self.assertEqual(api["inspect"]()["record_count"], 1)

    def test_short_writes_complete_and_write_failure_preserves_good_state(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); real_write = os.write
            def short(fd, data): return real_write(fd, data[:max(1, min(9, len(data)))])
            api = self.service(root)
            with mock.patch.object(journal.os, "write", side_effect=short): token = api["prepare"]()
            self.assertEqual(api["inspect"]()["journal_integrity"], "VALID")
            before = (root / "journal.jsonl").read_bytes()
            with mock.patch.object(journal.os, "write", return_value=0):
                with self.assertRaises(journal.JournalError): api["intent"](token)
            self.assertEqual((root / "journal.jsonl").read_bytes(), before)

    def test_file_and_directory_fsync_failures_are_not_reported_durable(self):
        with tempfile.TemporaryDirectory() as folder:
            api = self.service(folder)
            with mock.patch.object(journal.os, "fsync", side_effect=OSError("private")):
                with self.assertRaisesRegex(journal.JournalError, "LOCAL_PERSISTENCE_FAILED"):
                    api["prepare"]()
            self.assertFalse((Path(folder) / "journal.jsonl").exists())
        with tempfile.TemporaryDirectory() as folder:
            calls = 0; real = os.fsync
            def fail_directory(fd):
                nonlocal calls; calls += 1
                if calls == 2: raise OSError("private")
                return real(fd)
            api = self.service(folder)
            with mock.patch.object(journal.os, "fsync", side_effect=fail_directory):
                with self.assertRaisesRegex(journal.JournalError, "DIRECTORY_FSYNC_DURABILITY_UNKNOWN"):
                    api["prepare"]()
            value = api["inspect"]()
            self.assertEqual(value["journal_integrity"], "VALID")
            self.assertEqual(value["durability"], "UNKNOWN")
            self.assertTrue(value["reconciliation_required"])
            with self.assertRaisesRegex(journal.JournalError, "DURABILITY_RECONCILIATION_REQUIRED"):
                api["prepare"]()

    def test_hash_chain_sequence_duplicate_and_middle_corruption(self):
        with tempfile.TemporaryDirectory() as folder:
            api, token = self.prepared(folder); api["intent"](token)
            path = Path(folder) / "journal.jsonl"; original = path.read_bytes()
            rows = [json.loads(line) for line in original.splitlines()]
            for mutation in (lambda r: r[1].__setitem__("sequence", 9),
                             lambda r: r[1].__setitem__("previous_hash", "1" * 64),
                             lambda r: r[0].__setitem__("record_type", "ALTERED")):
                changed = json.loads(json.dumps(rows)); mutation(changed)
                path.write_text("".join(json.dumps(row) + "\n" for row in changed)); path.chmod(0o600)
                result = api["inspect"](); self.assertEqual(result["journal_integrity"], "CORRUPT")
                self.assertTrue(result["manual_investigation_required"])
                path.write_bytes(original); path.chmod(0o600)

    def test_torn_tail_is_not_repaired_or_counted(self):
        with tempfile.TemporaryDirectory() as folder:
            api, _ = self.prepared(folder); path = Path(folder) / "journal.jsonl"
            before = path.read_bytes(); path.write_bytes(before + b'{"partial":'); path.chmod(0o600)
            result = api["inspect"]()
            self.assertEqual(result["journal_integrity"], "TORN_TAIL")
            self.assertEqual(result["record_count"], 1)
            self.assertEqual(path.read_bytes(), before + b'{"partial":')

    def test_restart_after_source_intent_or_request_boundary_is_unknown(self):
        for boundary in ("source_intent", "started"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as folder:
                api, token = self.prepared(folder); api["intent"](token)
                source = observation_retention.FIXED_SOURCES[0]
                api["source_intent"](token, source)
                if boundary == "started": api["started"](token, source)
                restarted = self.service(folder); value = restarted["inspect"]()
                self.assertEqual(value["sources"][0]["state"], "OUTCOME_UNKNOWN")
                self.assertTrue(value["reconciliation_required"])
                self.assertFalse(value["automatic_resume_allowed"])
                self.assertFalse(value["automatic_retry_allowed"])
                with self.assertRaises(journal.JournalError): restarted["intent"](token)

    def test_absence_does_not_prove_unexecuted(self):
        with tempfile.TemporaryDirectory() as folder:
            value = self.service(folder)["inspect"]()
            self.assertFalse(value["durable_state_found"])
            self.assertTrue(value["reconciliation_required"])
            self.assertTrue(value["execution_blocked"])
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); root.chmod(0o700); path = root / "journal.jsonl"
            path.write_bytes(b""); path.chmod(0o600)
            value = self.service(root)["inspect"]()
            self.assertEqual(value["journal_integrity"], "CORRUPT")
            self.assertTrue(value["manual_investigation_required"])

    def test_result_requires_intent_and_is_not_retried(self):
        with tempfile.TemporaryDirectory() as folder:
            api, token = self.prepared(folder); source = observation_retention.FIXED_SOURCES[0]
            result = api["issue_result"](source)
            with self.assertRaisesRegex(journal.JournalError, "SOURCE_INTENT_REQUIRED"):
                api["result"](token, source, result)
            api["intent"](token); api["source_intent"](token, source); api["result"](token, source, result)
            with self.assertRaisesRegex(journal.JournalError, "DUPLICATE_SOURCE_RESULT"):
                api["result"](token, source, api["issue_result"](source))
            self.assertEqual(api["inspect"]()["sources"][0]["state"], "RESULT_DURABLE")

    def test_attempt_intent_and_fixed_source_order_are_write_ahead(self):
        with tempfile.TemporaryDirectory() as folder:
            api, token = self.prepared(folder); first, second = observation_retention.FIXED_SOURCES[:2]
            with self.assertRaisesRegex(journal.JournalError, "ATTEMPT_INTENT_REQUIRED"):
                api["source_intent"](token, first)
            api["intent"](token)
            with self.assertRaisesRegex(journal.JournalError, "DUPLICATE_ATTEMPT_INTENT"):
                api["intent"](token)
            with self.assertRaisesRegex(journal.JournalError, "SOURCE_ORDER_OR_PRIOR_OUTCOME_INVALID"):
                api["source_intent"](token, second)
            api["source_intent"](token, first)
            with self.assertRaisesRegex(journal.JournalError, "SOURCE_ORDER_OR_PRIOR_OUTCOME_INVALID"):
                api["source_intent"](token, second)

    def test_permit_consumption_is_durable_once_and_precedes_attempt_intent(self):
        with tempfile.TemporaryDirectory() as folder:
            api, token = self.prepared(folder)
            api["permit"](token); api["intent"](token)
            with self.assertRaisesRegex(journal.JournalError, "DUPLICATE_PERMIT_CONSUMPTION"):
                api["permit"](token)
            rows = [json.loads(line) for line in
                    (Path(folder) / "journal.jsonl").read_text().splitlines()]
            self.assertEqual([row["record_type"] for row in rows[:3]],
                             ["PLAN_PREPARED", "PERMIT_CONSUMED", "ATTEMPT_INTENT"])
        with tempfile.TemporaryDirectory() as folder:
            api, token = self.prepared(folder); api["intent"](token)
            with self.assertRaisesRegex(journal.JournalError, "PERMIT_CONSUMPTION_ORDER_INVALID"):
                api["permit"](token)

    def test_four_results_need_sealed_evidence_then_finalize_once(self):
        with tempfile.TemporaryDirectory() as folder:
            api, token = self.complete(folder)
            self.assertEqual(api["inspect"]()["attempt_state"], "RESULTS_COMPLETE")
            with self.assertRaises(journal.JournalError): api["commit"](token, "0" * 64)
            api["commit"](token, api["issue_evidence"]())
            value = api["inspect"](); self.assertTrue(value["evidence_committed"]); self.assertFalse(value["finalized"])
            api["finalize"](token); value = api["inspect"]()
            self.assertTrue(value["finalized"]); self.assertTrue(value["execution_blocked"])
            with self.assertRaisesRegex(journal.JournalError, "ATTEMPT_TERMINAL"):
                api["finalize"](token)

    def test_partial_results_cannot_commit(self):
        with tempfile.TemporaryDirectory() as folder:
            api, token = self.prepared(folder); api["intent"](token)
            source = observation_retention.FIXED_SOURCES[0]; api["source_intent"](token, source)
            api["result"](token, source, api["issue_result"](source))
            with self.assertRaisesRegex(journal.JournalError, "FOUR_DURABLE_RESULTS_REQUIRED"):
                api["commit"](token, api["issue_evidence"]())

    def test_token_copy_serialization_and_foreign_generation_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            api, token = self.prepared(folder)
            with self.assertRaises(TypeError): copy.copy(token)
            with self.assertRaises(TypeError): token.__reduce__()
            with tempfile.TemporaryDirectory() as other:
                with self.assertRaises(journal.JournalError): self.service(other)["intent"](token)
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            fixture, token = self.complete(first); sealed = fixture["issue_evidence"]()
            production_shaped = journal._build_store(Path(second))
            production_shaped[0]()
            with self.assertRaisesRegex(journal.JournalError, "SEALED_V2_EVIDENCE_REQUIRED"):
                production_shaped[5](object(), sealed)

    def test_updates_use_directory_fd_anchoring(self):
        with tempfile.TemporaryDirectory() as folder:
            real_open = os.open; real_replace = os.replace
            with mock.patch.object(journal.os, "open", wraps=real_open) as opened, \
                 mock.patch.object(journal.os, "replace", wraps=real_replace) as replaced:
                self.service(folder)["prepare"]()
            self.assertTrue(any(call.kwargs.get("dir_fd") is not None for call in opened.call_args_list))
            self.assertTrue(all(call.kwargs.get("src_dir_fd") is not None
                                and call.kwargs.get("dst_dir_fd") is not None
                                for call in replaced.call_args_list))

    def test_public_projection_schema_privacy_and_semantics(self):
        with tempfile.TemporaryDirectory() as folder:
            value = dict(self.service(folder)["inspect"]())
            schema = json.loads(Path("schemas/durable-observation-attempt-journal.v1.json").read_text())
            jsonschema.Draft202012Validator(schema).validate(value)
            self.assertEqual(journal.validate_projection(value), ())
            self.assertEqual(set(value), set(schema["properties"]))
            encoded = json.dumps(value).lower()
            for forbidden in (str(Path(folder)).lower(), "pid", "uid", "hostname", "url", "raw_body", "header", "cookie", "authorization"):
                self.assertNotIn(forbidden, encoded)
            for change in ({"extra": {}}, {"record_count": True}, {"retry_count": 1},
                           {"automatic_retry_allowed": True}, {"sources": [{"raw": "private"}] * 4}):
                forged = dict(value); forged.update(change); self.assertTrue(journal.validate_projection(forged))

    def test_public_projection_rejects_finalized_incomplete_and_unblocked_states(self):
        with tempfile.TemporaryDirectory() as folder:
            value = dict(self.service(folder)["inspect"]())
            forged = dict(value); forged["execution_blocked"] = False
            self.assertTrue(journal.validate_projection(forged))
            forged = dict(value); forged.update({"finalized": True, "evidence_committed": True,
                "attempt_state": "FINALIZED"})
            self.assertTrue(journal.validate_projection(forged))

    def test_fault_points_never_trigger_resume_or_network(self):
        points = {"BEFORE_CREATE", "LOCKED", "WRITE_PARTIAL", "FILE_FSYNCED", "RENAMED", "DIRECTORY_FSYNCED"}
        for point in points:
            with self.subTest(point=point), tempfile.TemporaryDirectory() as folder:
                def fault(current):
                    if current == point: raise OSError("private")
                api = self.service(folder, fault); calls = 0
                try: api["prepare"]()
                except (OSError, journal.JournalError): pass
                value = self.service(folder)["inspect"]()
                self.assertFalse(value["automatic_resume_allowed"])
                self.assertFalse(value["automatic_retry_allowed"])
                self.assertEqual(calls, 0)

    def test_semantic_crash_boundary_matrix_is_inspection_only(self):
        for point, operation in (
            ("PLAN_DURABLE", "prepare"), ("ATTEMPT_INTENT_DURABLE", "intent"),
            ("SOURCE_INTENT_DURABLE", "source_intent"),
            ("REQUEST_MAY_HAVE_STARTED", "started")):
            with self.subTest(point=point), tempfile.TemporaryDirectory() as folder:
                armed = False
                def fault(current):
                    if armed and current == point: raise OSError("private")
                api = self.service(folder, fault)
                if operation == "prepare":
                    armed = True
                    with self.assertRaises(OSError): api["prepare"]()
                else:
                    token = api["prepare"](); armed = True
                    if operation == "intent": call = lambda: api["intent"](token)
                    elif operation == "source_intent":
                        armed = False; api["intent"](token); armed = True
                        call = lambda: api["source_intent"](token, observation_retention.FIXED_SOURCES[0])
                    else:
                        armed = False; api["intent"](token); api["source_intent"](token, observation_retention.FIXED_SOURCES[0]); armed = True
                        call = lambda: api["started"](token, observation_retention.FIXED_SOURCES[0])
                    with self.assertRaises(OSError): call()
                recovered = self.service(folder)["inspect"]()
                self.assertTrue(recovered["execution_blocked"])
                self.assertFalse(recovered["automatic_resume_allowed"])
                self.assertFalse(recovered["automatic_retry_allowed"])

        for point in ("EVIDENCE_COMMITTED", "BEFORE_FINALIZE", "FINALIZED"):
            with self.subTest(point=point), tempfile.TemporaryDirectory() as folder:
                armed = False
                def fault(current):
                    if armed and current == point: raise OSError("private")
                api = self.service(folder, fault); token = api["prepare"](); api["intent"](token)
                for source in observation_retention.FIXED_SOURCES:
                    api["source_intent"](token, source); api["started"](token, source)
                    api["result"](token, source, api["issue_result"](source))
                sealed = api["issue_evidence"]()
                if point == "EVIDENCE_COMMITTED":
                    armed = True
                    with self.assertRaises(OSError): api["commit"](token, sealed)
                else:
                    api["commit"](token, sealed); armed = True
                    with self.assertRaises(OSError): api["finalize"](token)
                recovered = self.service(folder)["inspect"]()
                self.assertTrue(recovered["evidence_committed"])
                self.assertEqual(recovered["finalized"], point == "FINALIZED")
                self.assertTrue(recovered["execution_blocked"])

    def test_strict_hash_types_and_cross_package_semantics(self):
        self.assertNotEqual(journal._strict_hash({"v": True}, "A"), journal._strict_hash({"v": 1}, "A"))
        for invalid in (1.0, math.nan, math.inf):
            with self.assertRaises(journal.JournalError): journal._strict_hash({"v": invalid}, "A")
        self.assertEqual(replay_journal.RetryClassification.DO_NOT_RETRY.value, "DO_NOT_RETRY")
        self.assertNotEqual(evidence_transport.Completeness.PARTIAL,
                            evidence_transport.Completeness.COMPLETE_VERIFIED)
        self.assertFalse(observation_retention.public_projection(
            observation_retention.historical_llms_evidence())["authorized_to_act"])


if __name__ == "__main__": unittest.main()
