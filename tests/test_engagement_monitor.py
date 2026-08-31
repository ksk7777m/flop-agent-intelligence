import fcntl, io, json, math, os, signal, subprocess, sys, tempfile, threading, time, unittest
from unittest import mock
from email.message import Message
from pathlib import Path
from urllib.error import HTTPError

from flop_agent.engagement import SOURCE_URL, build_sample, diff, room_status, series
from flop_agent.engagement_history import HistoryCorruption, append, latest, load, validate
from flop_agent.engagement_history import HistoryDeadlineExceeded
from scripts.collect_engagement import (
    CollectionError, MAX_IPC_BYTES, MAX_RESPONSE_BYTES, MAX_TOTAL_COLLECTION_DEADLINE_SECONDS,
    OwnershipState, WorkerOwnership,
    SOCKET_TIMEOUT_SECONDS, TOTAL_COLLECTION_DEADLINE_SECONDS,
    TotalDeadlineExceeded, _cleanup_owned, _decode_worker_result, backoff, commit_sample, fetch,
    interval_minutes, prepare_sample, run_with_total_deadline, total_deadline_seconds, validate_endpoint,
)
import jsonschema


def _worker_sample(when="2026-08-29T00:00:00Z"):
    return build_sample({"rooms":[{"room":"a","window":0}],"engagement":{}}, fetched_at=when,
                        source_sha256="0"*64, collector_version="test")


def successful_worker(connection, root, timeout, revision):
    connection.send_bytes(json.dumps({"ok":True,"sample":_worker_sample()}).encode())
    connection.close()


def slow_successful_worker(connection, root, timeout, revision):
    time.sleep(.6); successful_worker(connection,root,timeout,revision)


def stalled_worker(connection, root, timeout, revision):
    time.sleep(10)


def descendant_worker(connection, root, timeout, revision):
    signal_code="import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(10)"
    child=subprocess.Popen([sys.executable,"-c",signal_code])
    Path(root,"worker-pids").write_text(f"{os.getpid()} {child.pid}")
    import signal
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(10)


def crashed_worker(connection, root, timeout, revision):
    os._exit(7)


def failing_setsid():
    raise OSError("simulated setsid failure")


def marker_worker(connection, root, timeout, revision):
    Path(root,"worker-ran").write_text("unexpected")


def offline_prepare_worker(connection, root, timeout, revision):
    calls=Path(root,"request-count")
    def opener(request, timeout):
        calls.write_text(str(int(calls.read_text())+1 if calls.exists() else 1))
        return Response(b'{"total":1,"rooms":[{"room":"safe","window":20}],"engagement":{}}')
    sample=prepare_sample(Path(root),timeout=timeout,opener=opener,
                          fetched_at="2026-08-29T00:00:00Z",git_revision=revision)
    connection.send_bytes(json.dumps({"ok":True,"sample":sample}).encode()); connection.close()


class Response:
    status = 200
    headers = Message()
    def __init__(self, body=b'{}', url=SOURCE_URL): self.body, self.url = body, url
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, size=-1): return self.body if size < 0 else self.body[:size]
    def geturl(self): return self.url


class EngagementMonitorTests(unittest.TestCase):
    def sample(self, when="2026-08-29T00:00:00Z"):
        return build_sample({"rooms":[{"room":"a","window":0}],"engagement":{}}, fetched_at=when,
                            source_sha256="0"*64, collector_version="test")

    def test_fixed_get_endpoint_redirect_and_cross_origin(self):
        self.assertEqual(validate_endpoint(SOURCE_URL), SOURCE_URL)
        for url in (
            "https://example.test/", "https://technocore.chat/r/a", "https://technocore.chat/kv/a",
            "https://technocore.chat/rooms?limit=200&format=json",
            "https://technocore.chat/rooms?format=json&limit=200&limit=200",
            "https://technocore.chat/rooms?format=%6ason&limit=200",
            SOURCE_URL + "#fragment", "https://technocore.chat:443/rooms?format=json&limit=200",
            "https://TECHNOCORE.chat/rooms?format=json&limit=200",
            "https://technocore.chat/rooms/?format=json&limit=200",
            "http://technocore.chat/rooms?format=json&limit=200",
        ):
            with self.assertRaises(ValueError): validate_endpoint(url)
        seen = {}
        def ok(req, timeout): seen.update(method=req.method, timeout=timeout); return Response()
        fetch(opener=ok); self.assertEqual(seen["method"], "GET")
        with self.assertRaises(CollectionError): fetch(opener=lambda req, timeout: Response(url="https://example.test/"))
        with self.assertRaises(CollectionError): fetch(opener=lambda req, timeout: Response(url="https://technocore.chat/rooms?format=json"))

    def test_success_body_size_is_bounded_by_header_and_actual_read(self):
        headers=Message(); headers["Content-Length"]=str(MAX_RESPONSE_BYTES + 1)
        response=Response(b"{}"); response.headers=headers
        with self.assertRaises(CollectionError) as caught:
            fetch(opener=lambda req, timeout: response)
        self.assertEqual(caught.exception.code,"RESPONSE_TOO_LARGE")
        oversized=Response(b"x" * (MAX_RESPONSE_BYTES + 1))
        with self.assertRaises(CollectionError) as caught:
            fetch(opener=lambda req, timeout: oversized)
        self.assertEqual(caught.exception.code,"RESPONSE_TOO_LARGE")

    def test_total_deadline_configuration_and_fast_offline_success(self):
        self.assertEqual(SOCKET_TIMEOUT_SECONDS,20.0)
        self.assertEqual(TOTAL_COLLECTION_DEADLINE_SECONDS,30.0)
        self.assertEqual(MAX_TOTAL_COLLECTION_DEADLINE_SECONDS,30.0)
        for invalid in (0, .99, 30.01, math.inf):
            with self.assertRaises(ValueError): total_deadline_seconds(invalid)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            result=run_with_total_deadline(root,total_deadline=1,worker_target=successful_worker)
            self.assertTrue(result["ok"]); self.assertEqual(result["sample"]["schema"],"engagement-sample-v1")
            self.assertEqual(len(load(root/"runtime/engagement/history.jsonl")),1)

    def test_process_deadline_bounds_stalls_without_rollback(self):
        for stage in ("connect-worker","dns","body-read","normalization","schema-validation","history-lock"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as folder:
                root=Path(folder); history=root/"runtime/engagement/history.jsonl"
                append(history,_worker_sample())
                before=history.read_bytes(); lock=history.with_suffix(".jsonl.lock"); inode=lock.stat().st_ino
                with self.assertRaises(TotalDeadlineExceeded) as caught:
                    run_with_total_deadline(root,total_deadline=1,worker_target=stalled_worker)
                self.assertEqual(caught.exception.metadata["error_class"],"TOTAL_DEADLINE_EXCEEDED")
                self.assertEqual(caught.exception.metadata["configured_total_deadline"],1)
                self.assertEqual(history.read_bytes(),before)
                self.assertEqual(lock.stat().st_ino,inode)
                self.assertEqual(list((root/"runtime").rglob("*.deadline-*")),[])

    def test_process_group_is_killed_and_reaped(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            with self.assertRaises(TotalDeadlineExceeded):
                run_with_total_deadline(root,total_deadline=1,worker_target=descendant_worker)
            pids=[int(value) for value in (root/"worker-pids").read_text().split()]
            for _ in range(50):
                if all(self._process_gone(pid) for pid in pids): break
                time.sleep(.02)
            self.assertTrue(all(self._process_gone(pid) for pid in pids))

    @staticmethod
    def _process_gone(pid):
        try: os.kill(pid,0); return False
        except ProcessLookupError: return True

    def test_ipc_protocol_and_crash_fail_closed(self):
        sample=_worker_sample()
        valid=json.dumps({"ok":True,"sample":sample}).encode()
        self.assertTrue(_decode_worker_result(valid,0)["ok"])
        self.assertEqual(_decode_worker_result(b'{"ok":false,"error_class":"HTTP_TIMEOUT"}',0)["error_class"],"HTTP_TIMEOUT")
        invalid=[b'{"ok":true}',b'{"safe":"result"}',b'{"ok":true,"sample":1}',
                 b'{"ok":true,"sample":{},"extra":1}',b'bad',b'',b'x'*(MAX_IPC_BYTES+1)]
        for payload in invalid:
            with self.subTest(payload=payload[:20]),self.assertRaises(CollectionError) as caught:
                _decode_worker_result(payload,0)
            self.assertEqual(caught.exception.code,"WORKER_PROTOCOL_ERROR")
        with self.assertRaises(CollectionError) as caught: _decode_worker_result(valid,7)
        self.assertEqual(caught.exception.code,"WORKER_CRASHED")
        with tempfile.TemporaryDirectory() as folder,self.assertRaises(CollectionError) as caught:
            run_with_total_deadline(Path(folder),total_deadline=1,worker_target=crashed_worker)
        self.assertEqual(caught.exception.code,"WORKER_CRASHED")

    def test_remaining_budget_prevents_commit(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); called=[]
            def forbidden_commit(*args,**kwargs): called.append(True)
            with self.assertRaises(TotalDeadlineExceeded):
                run_with_total_deadline(root,total_deadline=1,worker_target=slow_successful_worker,commit=forbidden_commit)
            self.assertEqual(called,[]); self.assertFalse((root/"runtime").exists())

    def test_timeout_never_rolls_back_concurrent_commits(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); history=root/"runtime/engagement/history.jsonl"
            append(history,_worker_sample())
            committed=_worker_sample("2026-08-29T01:00:00Z")
            thread=threading.Thread(target=lambda: (time.sleep(.1),append(history,committed)))
            thread.start()
            with self.assertRaises(TotalDeadlineExceeded):
                run_with_total_deadline(root,total_deadline=1,worker_target=stalled_worker)
            thread.join(); self.assertEqual([r["fetched_at"] for r in load(history)],
                                           ["2026-08-29T00:00:00Z","2026-08-29T01:00:00Z"])
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); history=root/"runtime/engagement/history.jsonl"
            with self.assertRaises(TotalDeadlineExceeded):
                run_with_total_deadline(root,total_deadline=1,worker_target=stalled_worker)
            append(history,_worker_sample()); self.assertEqual(len(load(history)),1)

    def test_parent_commits_serialize_and_dedupe_under_stable_lock(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); results=[]; barrier=threading.Barrier(2)
            def commit():
                barrier.wait(); results.append(commit_sample(root,_worker_sample()))
            threads=[threading.Thread(target=commit) for _ in range(2)]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            history=root/"runtime/engagement/history.jsonl"
            self.assertEqual(sorted(results),[False,True]); self.assertEqual(len(load(history)),1)
            lock=history.with_suffix(".jsonl.lock")
            inode=lock.stat().st_ino
            commit_sample(root,_worker_sample("2026-08-29T01:00:00Z"))
            self.assertEqual(lock.stat().st_ino,inode); self.assertEqual(len(load(history)),2)
            self.assertEqual(oct(history.stat().st_mode & 0o777),"0o600")

    def test_worker_cli_bypass_is_rejected(self):
        root=Path(__file__).resolve().parents[1]
        result=subprocess.run([sys.executable,str(root/"scripts/collect_engagement.py"),"--worker"],
                              cwd=root,capture_output=True,text=True,timeout=3)
        self.assertEqual(result.returncode,2); self.assertIn("unrecognized arguments",result.stderr)

    def test_ownership_release_prevents_late_or_stale_group_signals(self):
        class Process:
            pid=123
            def join(self,*args): pass
            def is_alive(self): return False
        ownership=WorkerOwnership(OwnershipState.RELEASED,None,None,None); signals=[]
        _cleanup_owned(Process(),ownership,killpg=lambda *args: signals.append(args))
        self.assertEqual(signals,[])
        owned=WorkerOwnership(OwnershipState.OWNED,123,123,123)
        with self.assertRaises(CollectionError) as caught:
            _cleanup_owned(Process(),owned,killpg=lambda *args: signals.append(args),
                           getpgid=lambda pid:999,getsid=lambda pid:123)
        self.assertEqual(caught.exception.code,"WORKER_CLEANUP_UNVERIFIED"); self.assertEqual(signals,[])

    def test_setsid_failure_is_fail_closed_before_worker(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            with self.assertRaises(CollectionError) as caught:
                run_with_total_deadline(root,total_deadline=1,worker_target=marker_worker,
                                        session_setup=failing_setsid)
            self.assertEqual(caught.exception.code,"WORKER_STARTUP_FAILED")
            self.assertFalse((root/"worker-ran").exists()); self.assertFalse((root/"runtime").exists())

    def test_cleanup_signal_failure_is_explicit(self):
        class Process:
            pid=321
            def join(self,*args): pass
            def is_alive(self): return True
        ownership=WorkerOwnership(OwnershipState.OWNED,321,321,321)
        with self.assertRaises(CollectionError) as caught:
            _cleanup_owned(Process(),ownership,killpg=lambda *args: (_ for _ in ()).throw(OSError()),
                           getpgid=lambda pid:321,getsid=lambda pid:321)
        self.assertEqual(caught.exception.code,"WORKER_CLEANUP_FAILED")

    def test_one_second_git_budget_exhaustion_starts_no_worker(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            with mock.patch("scripts.collect_engagement.subprocess.run",
                            side_effect=subprocess.TimeoutExpired("git",.9)) as run:
                with self.assertRaises(TotalDeadlineExceeded) as caught:
                    run_with_total_deadline(root,total_deadline=1,worker_target=marker_worker)
            self.assertLessEqual(run.call_args.kwargs["timeout"],1)
            self.assertEqual(caught.exception.metadata["error_class"],"TOTAL_DEADLINE_EXCEEDED")
            self.assertFalse((root/"worker-ran").exists()); self.assertFalse((root/"runtime").exists())

    def test_commit_point_deadline_semantics(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); history=root/"runtime/engagement/history.jsonl"; transaction={}
            with mock.patch("flop_agent.engagement_history.os.replace",side_effect=HistoryDeadlineExceeded()):
                with self.assertRaises(HistoryDeadlineExceeded):
                    append(history,_worker_sample(),transaction=transaction)
            self.assertEqual(transaction["state"],"PRE_COMMIT"); self.assertFalse(history.exists())
        for state in ("COMMITTED","DURABLE"):
            with self.subTest(state=state),tempfile.TemporaryDirectory() as folder:
                root=Path(folder)
                def committed_then_deadline(root,sample,deadline_at,transaction):
                    append(root/"runtime/engagement/history.jsonl",sample,transaction=transaction)
                    transaction["state"]=state
                    raise HistoryDeadlineExceeded()
                result=run_with_total_deadline(root,total_deadline=1,worker_target=successful_worker,
                                               commit=committed_then_deadline)
                self.assertTrue(result["ok"]); self.assertTrue(result["deadline_cleanup_overrun"])
                self.assertEqual(result["commit_state"],state); self.assertEqual(len(load(root/"runtime/engagement/history.jsonl")),1)

    def test_recovery_tail_and_previews_are_atomic_private_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); history=root/"history.jsonl"
            append(history,_worker_sample())
            with history.open("ab") as stream: stream.write(b'{"partial":')
            append(history,_worker_sample("2026-08-29T01:00:00Z"))
            recovery=history.with_suffix(".jsonl.recovery-tail")
            self.assertEqual(recovery.stat().st_mode & 0o777,0o600)
            self.assertEqual(list(root.glob(".*.candidate-*")),[])
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); commit_sample(root,_worker_sample())
            previews=list((root/"runtime/engagement/public-preview").glob("*.json"))
            self.assertEqual(len(previews),3); self.assertTrue(all(p.stat().st_mode & 0o777==0o600 for p in previews))
            self.assertEqual(list(root.rglob(".*.candidate-*")),[])

    def test_offline_end_to_end_real_preparation_path(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            result=run_with_total_deadline(root,total_deadline=1,worker_target=offline_prepare_worker)
            self.assertTrue(result["ok"]); self.assertEqual((root/"request-count").read_text(),"1")
            self.assertEqual(len(load(root/"runtime/engagement/history.jsonl")),1)
            self.assertEqual(len(list((root/"runtime/engagement/public-preview").glob("*.json"))),3)

    def test_held_lock_obeys_global_deadline_without_corruption(self):
        with tempfile.TemporaryDirectory() as folder:
            history=Path(folder)/"history.jsonl"; append(history,_worker_sample()); before=history.read_bytes()
            lock_path=history.with_suffix(".jsonl.lock")
            with lock_path.open("a+b") as lock:
                fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
                with self.assertRaises(HistoryDeadlineExceeded):
                    append(history,_worker_sample("2026-08-29T01:00:00Z"),deadline_at=time.monotonic()+.1)
            self.assertEqual(history.read_bytes(),before)

    def test_http_failures_no_body_read_and_no_retry(self):
        headers=Message(); headers["Retry-After"]="37"
        def limited(req, timeout): raise HTTPError(SOURCE_URL,429,"",headers,io.BytesIO(b"secret-error-body"))
        with self.assertRaises(CollectionError) as caught: fetch(opener=limited)
        self.assertEqual(caught.exception.retry_after,37)
        self.assertIsNone(backoff(429,retry_header="tomorrow")); self.assertEqual(backoff(503,99),21600)
        with self.assertRaises(TimeoutError): fetch(opener=lambda req, timeout: (_ for _ in ()).throw(TimeoutError()))

    def test_interval_and_normalization(self):
        self.assertEqual(interval_minutes("15"),15)
        with self.assertRaises(ValueError): interval_minutes("4")
        row=self.sample(); self.assertEqual(row["per_room"][0]["status"],"INSUFFICIENT_WINDOW")
        self.assertIsNone(row["per_room"][0]["generation"]); self.assertEqual(room_status(20),"OBSERVED")
        self.assertNotIn("topic",json.dumps(row)); self.assertNotIn("raw",json.dumps(row))
        self.assertEqual(row["source_evidence_level"],"OFFICIAL_PUBLIC_ENDPOINT")
        self.assertEqual(row["derived_evidence_level"],"LOCAL_DERIVED")

    def test_optional_nulls_and_invalid_source_numerics(self):
        row=build_sample({"rooms":[{"room":"a"}],"engagement":{"zero_response_share":None}},
                         fetched_at="2026-08-29T00:00:00Z",source_sha256="0"*64,collector_version="test")
        for field in ("rooms_total","notes_total","notes_capacity"):
            self.assertIsNone(row[field])
        for field in ("first_seq","generation"):
            self.assertIsNone(row["per_room"][0][field])
        invalid = [
            {"total":-1}, {"engagement":{"zero_response_share":1.1}},
            {"engagement":{"nick_diversity":-0.1}}, {"engagement":{"windowed_messages":1.5}},
            {"rooms":[{"room":"a","last_seq":"1"}]}, {"rooms":[{"room":"a","window":math.nan}]},
            {"rooms":[{"room":"a","idle_seconds":math.inf}]},
        ]
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                build_sample(raw,fetched_at="2026-08-29T00:00:00Z",source_sha256="0"*64,collector_version="test")

    def test_history_dedupe_restart_order_invalid_partial(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"history.jsonl"; self.assertEqual(load(path),[])
            old=self.sample(); new=self.sample("2026-08-29T01:00:00Z")
            self.assertTrue(append(path,new)); self.assertTrue(append(path,old)); self.assertFalse(append(path,old))
            self.assertEqual(latest(load(path))["fetched_at"],new["fetched_at"])
            with path.open("a") as handle: handle.write('{"partial":')
            self.assertEqual(len(load(path)),2)
            self.assertTrue(append(path,self.sample("2026-08-29T02:00:00Z")))
            self.assertTrue(path.with_suffix(".jsonl.recovery-tail").exists())
            self.assertEqual(len(load(path)),3)

    def test_middle_history_corruption_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"history.jsonl"
            append(path,self.sample())
            with path.open("a") as handle: handle.write('{"bad":true}\n')
            append_payload=json.dumps(self.sample("2026-08-29T01:00:00Z"))+"\n"
            with path.open("a") as handle: handle.write(append_payload)
            with self.assertRaises(HistoryCorruption): load(path)

    def test_concurrent_duplicate_is_appended_once(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"history.jsonl"; results=[]
            barrier=threading.Barrier(2)
            def worker():
                barrier.wait(); results.append(append(path,self.sample()))
            threads=[threading.Thread(target=worker) for _ in range(2)]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            self.assertEqual(sorted(results),[False,True]); self.assertEqual(len(load(path)),1)

    def test_short_writes_are_completed_and_invalid_sample_is_not_appended(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"history.jsonl"; original_write=__import__("os").write
            def short_write(descriptor, data):
                return original_write(descriptor, data[:max(1, min(7, len(data)))])
            with mock.patch("flop_agent.engagement_history.os.write",side_effect=short_write):
                self.assertTrue(append(path,self.sample()))
            self.assertEqual(len(load(path)),1)
            bad=dict(self.sample("2026-08-29T01:00:00Z")); bad["unexpected"]=True
            with self.assertRaises(ValueError): append(path,bad)
            self.assertEqual(len(load(path)),1)

    def test_diff_and_conservative_interpretation(self):
        old=self.sample(); new=self.sample("2026-08-29T01:00:00Z")
        old["per_room"][0]["room"]="old"; new["per_room"][0]["room"]="new"
        result=diff(old,new); self.assertEqual(result["new_rooms"],["new"])
        self.assertEqual(result["not_observed_in_latest_snapshot"],["old"])
        encoded=json.dumps(series([old,new])); self.assertIn("NO_PERSISTENT_CHANGE_ESTABLISHED",encoded)
        for prohibited in ("SPAM","BOT","DEAD","SYBIL","AIR_DROP_SCORE","REWARD_SCORE"):
            self.assertNotIn(prohibited,encoded)
        same_old=self.sample(); same_new=self.sample("2026-08-29T01:00:00Z")
        same_new["per_room"][0]["window"]=20
        changed=diff(same_old,same_new)["changed_rooms"][0]
        self.assertEqual(changed["changed_fields"],[])
        self.assertEqual(changed["observation_context"],"OBSERVATION_CONTEXT_CHANGED")

    def test_strict_schema_and_negative_cases(self):
        root=Path(__file__).resolve().parents[1]
        schema=json.loads((root/"schemas/engagement-sample.v1.json").read_text())
        sample=self.sample(); jsonschema.Draft202012Validator(schema).validate(sample)
        bad=dict(sample); bad["raw_body"]="forbidden"
        with self.assertRaises(jsonschema.ValidationError): jsonschema.Draft202012Validator(schema).validate(bad)
        with self.assertRaises(ValueError): validate(bad)
        bad=dict(sample); bad["source_sha256"]="no"
        with self.assertRaises(jsonschema.ValidationError): jsonschema.Draft202012Validator(schema).validate(bad)

    def test_public_api_schemas_and_capabilities_are_strict(self):
        root=Path(__file__).resolve().parents[1]
        family=json.loads((root/"schemas/engagement-api.v1.json").read_text())
        for name, definition in (("engagement-status","status"),("engagement-diff","diff"),("engagement-series","series")):
            payload=json.loads((root/f"api/{name}.json").read_text())
            jsonschema.Draft202012Validator(family).validate(payload)
            bad=dict(payload); bad["unexpected"]=True
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.Draft202012Validator(family).validate(bad)
        capabilities=json.loads((root/"api/capabilities.json").read_text())
        cap_schema=json.loads((root/"schemas/capabilities.v1.json").read_text())
        jsonschema.Draft202012Validator(cap_schema).validate(capabilities)
        self.assertEqual(capabilities["scheduler"],"DISABLED")
        self.assertEqual(capabilities["drift_implementation"],"NOT_IMPLEMENTED")
        self.assertFalse(capabilities["live_write_enabled"])

    def test_no_engagement_scheduler_or_auto_start(self):
        root=Path(__file__).resolve().parents[1]
        workflows="\n".join(path.read_text() for path in (root/".github/workflows").glob("*.y*ml"))
        self.assertNotIn("collect_engagement",workflows)
        readme=(root/"README.md").read_text().lower()
        self.assertIn("scheduling disabled",readme)
        self.assertIn("no scheduler is installed or activated",readme)
    def test_dashboard_is_independently_loaded_and_inert(self):
        root=Path(__file__).resolve().parents[1]
        js=(root/"dashboard.js").read_text(); html=(root/"index.html").read_text()
        self.assertIn("ENGAGEMENT DATA UNAVAILABLE",js)
        self.assertIn("loadPresenceData().then",js); self.assertIn("loadKvData().then",js)
        self.assertIn("textContent",js); self.assertNotIn("innerHTML",js)
        self.assertIn("NO REVIEWED ENGAGEMENT HISTORY YET",html)
        self.assertIn("malformed Engagement API",js)
        self.assertNotIn("<canvas",html.lower())


if __name__ == "__main__": unittest.main()
