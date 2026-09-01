import io, json, os, subprocess, sys, tempfile, threading, unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from flop_agent.engagement import build_sample
from flop_agent.engagement_scheduler import (
    DAILY_WINDOW, FAILURE_CLASSES, LEGACY_SCHEMA, MAX_REQUESTS_PER_DAY, MINIMUM_INTERVAL,
    NORMAL_INTERVAL, SCHEMA, SchedulerStateError, approve_reset, disable_scheduled,
    disabled_state, dry_run, enable_scheduled, evaluate, load_state, _provision_result,
    provision_disabled, run_once, scheduler_lock, validate_state, write_state,
)
from scripts.engagement_scheduler import (CODE_ROOT, REVIEWED_COLLECTOR, REVIEWED_PYTHON,
                                          _collector, _validated_result, main)

NOW=datetime(2026,9,1,12,0,0,tzinfo=timezone.utc)


def stamp(value): return value.isoformat().replace("+00:00","Z")


def ready_state():
    state=disabled_state(); state.update(scheduler_enabled=True,circuit_state="READY",
                                         not_before_at=stamp(NOW))
    return state


def diagnostics():
    return {"failure_stage":None,"total_elapsed_seconds":1.0,"open_elapsed_seconds":.4,
            "body_elapsed_seconds":.5,"http_status":200,"response_bytes":100,
            "configured_socket_timeout":20.0,"configured_total_deadline":30.0}


def success_result():
    sample=build_sample({"rooms":[],"engagement":{}},fetched_at="2026-09-01T12:00:00Z",
                        source_sha256="0"*64,collector_version="0.1.0")
    return {"ok":True,"success":True,"sample":sample,
            "commit_state":"DURABLE","preview_state":"UPDATED","cleanup_state":"COMPLETED",
            "deadline_cleanup_overrun":False,"error_class":None,"durability_warning":None,
            "preview_warning":None,"cleanup_error":None,"network_diagnostics":diagnostics()}


def failure_result(error="HTTP_BODY_TIMEOUT"):
    network = None
    if error in {"HTTP_OPEN_TIMEOUT","HTTP_OPEN_FAILED","HTTP_BODY_TIMEOUT","HTTP_BODY_FAILED"}:
        network=diagnostics(); network.update(failure_stage="HTTP_OPEN" if error.startswith("HTTP_OPEN") else "HTTP_BODY",
                                              http_status=None if error=="HTTP_OPEN_TIMEOUT" else 500,response_bytes=None)
        if error.startswith("HTTP_OPEN"): network["body_elapsed_seconds"]=None
    return {"success":False,"commit_state":"PRE_COMMIT","preview_state":"NOT_ATTEMPTED",
            "cleanup_state":"COMPLETED","deadline_cleanup_overrun":False,"error_class":error,
            "durability_warning":None,"preview_warning":None,"cleanup_error":None,
            "network_diagnostics":network,"collector_version":"0.1.0","git_revision":None}


class EngagementSchedulerTests(unittest.TestCase):
    def paths(self,root):
        return root/"runtime/engagement/scheduler-state.json",root/"runtime/engagement/scheduler-state.lock"

    def test_policy_constants_and_disabled_never_invokes_collector(self):
        self.assertEqual(NORMAL_INTERVAL,timedelta(minutes=60))
        self.assertEqual(MINIMUM_INTERVAL,timedelta(minutes=30))
        self.assertEqual((MAX_REQUESTS_PER_DAY,DAILY_WINDOW),(24,timedelta(hours=24)))
        with tempfile.TemporaryDirectory() as folder:
            state_path,lock_path=self.paths(Path(folder)); write_state(state_path,disabled_state(),now=NOW)
            calls=[]; result=run_once(state_path,lock_path,lambda:calls.append(1),now=NOW)
            self.assertEqual((result["outcome"],result["collector_invocations"]),("SCHEDULER_DISABLED",0))
            self.assertEqual(calls,[])

    def test_legacy_disabled_state_migrates_in_memory_without_rewrite(self):
        with tempfile.TemporaryDirectory() as folder:
            state_path,_=self.paths(Path(folder)); legacy=disabled_state()
            legacy.pop("not_before_at"); legacy["schema"]=LEGACY_SCHEMA
            state_path.parent.mkdir(parents=True); state_path.write_text(json.dumps(legacy)+"\n")
            os.chmod(state_path,0o600); before=state_path.read_bytes()
            loaded=load_state(state_path,now=NOW)
            self.assertEqual((loaded["schema"],loaded["not_before_at"]),(SCHEMA,None))
            self.assertEqual(state_path.read_bytes(),before)

    def test_enable_not_before_blocks_then_allows_one_synthetic_attempt(self):
        with tempfile.TemporaryDirectory() as folder:
            state_path,lock_path=self.paths(Path(folder)); write_state(state_path,disabled_state(),now=NOW)
            enabled=enable_scheduled(state_path,lock_path,now=NOW)
            self.assertEqual((enabled["success"],enabled["outcome"],enabled["commit_state"]),
                             (True,"SCHEDULER_ENABLE_SCHEDULED","DURABLE"))
            self.assertEqual(enabled["not_before_at"],stamp(NOW+NORMAL_INTERVAL))
            self.assertEqual((enabled["network_requests"],enabled["collector_invocations"]),(0,0))
            before=state_path.read_bytes(); calls=[]
            blocked=dry_run(state_path,lock_path,now=NOW+timedelta(minutes=1))
            self.assertEqual((blocked["allowed"],blocked["outcome"]),(False,"SCHEDULER_NOT_BEFORE"))
            run=run_once(state_path,lock_path,lambda:calls.append(1),now=NOW+timedelta(minutes=59))
            self.assertEqual((run["outcome"],run["collector_invocations"],calls),
                             ("SCHEDULER_NOT_BEFORE",0,[]))
            self.assertEqual(state_path.read_bytes(),before)
            self.assertTrue(dry_run(state_path,lock_path,now=NOW+NORMAL_INTERVAL)["allowed"])
            run=run_once(state_path,lock_path,
                         lambda:(calls.append(1) or {"success":True,"error_class":None}),
                         now=NOW+NORMAL_INTERVAL)
            self.assertEqual((run["outcome"],run["collector_invocations"],calls),
                             ("SCHEDULER_COLLECTION_SUCCEEDED",1,[1]))
            self.assertEqual(load_state(state_path,now=NOW+NORMAL_INTERVAL)["not_before_at"],
                             stamp(NOW+NORMAL_INTERVAL))

    def test_enable_rejects_invalid_states_and_is_concurrent_once(self):
        invalid=[]
        for state in (ready_state(),{**disabled_state(),"run_in_progress":True},
                      {**disabled_state(),"circuit_state":"CIRCUIT_OPEN",
                       "consecutive_failures":2,"last_error_class":"HTTP_OPEN_FAILED"}):
            invalid.append(state)
        for state in invalid:
            with self.subTest(state=state),tempfile.TemporaryDirectory() as folder:
                state_path,lock_path=self.paths(Path(folder)); write_state(state_path,state,now=NOW)
                result=enable_scheduled(state_path,lock_path,now=NOW)
                self.assertFalse(result["success"]); self.assertEqual(result["collector_invocations"],0)
        with tempfile.TemporaryDirectory() as folder:
            state_path,lock_path=self.paths(Path(folder)); write_state(state_path,disabled_state(),now=NOW)
            barrier=threading.Barrier(2); results=[]
            def enable(): barrier.wait(); results.append(enable_scheduled(state_path,lock_path,now=NOW))
            threads=[threading.Thread(target=enable) for _ in range(2)]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            self.assertEqual(sum(item["success"] for item in results),1)
            self.assertEqual(load_state(state_path,now=NOW)["not_before_at"],stamp(NOW+NORMAL_INTERVAL))

    def test_disable_preserves_forensics_and_reenable_sets_fresh_boundary(self):
        with tempfile.TemporaryDirectory() as folder:
            state_path,lock_path=self.paths(Path(folder)); state=ready_state()
            attempt=stamp(NOW-timedelta(hours=1)); state.update(
                last_error_class="HTTP_OPEN_FAILED",
                last_attempt_at=attempt,attempts_24h=[attempt])
            write_state(state_path,state,now=NOW)
            disabled=disable_scheduled(state_path,lock_path,now=NOW)
            self.assertTrue(disabled["success"]); saved=load_state(state_path,now=NOW)
            self.assertEqual((saved["last_attempt_at"],saved["attempts_24h"],saved["last_error_class"]),
                             (attempt,[attempt],"HTTP_OPEN_FAILED"))
            self.assertFalse(saved["scheduler_enabled"])
            reenabled=enable_scheduled(state_path,lock_path,now=NOW+timedelta(minutes=5))
            self.assertTrue(reenabled["success"])
            self.assertEqual(reenabled["not_before_at"],stamp(NOW+timedelta(minutes=65)))

    def test_malformed_not_before_fails_closed(self):
        for value in ("not-a-time","2026-09-01T13:00:00",stamp(NOW+timedelta(days=2)),None):
            with self.subTest(value=value):
                state=ready_state(); state["not_before_at"]=value
                with self.assertRaises(SchedulerStateError): validate_state(state,now=NOW)
        with tempfile.TemporaryDirectory() as folder:
            state_path,lock_path=self.paths(Path(folder)); write_state(state_path,disabled_state(),now=NOW)
            self.assertEqual(enable_scheduled(state_path,lock_path,now=NOW.replace(tzinfo=None))["outcome"],
                             "SCHEDULER_CLOCK_INVALID")

    def test_enable_directory_fsync_failure_reports_visible_commit(self):
        with tempfile.TemporaryDirectory() as folder:
            state_path,lock_path=self.paths(Path(folder)); write_state(state_path,disabled_state(),now=NOW)
            real_fsync=os.fsync; calls=[]
            def fail_directory(descriptor):
                calls.append(descriptor)
                if len(calls)==2: raise OSError("bounded")
                return real_fsync(descriptor)
            with mock.patch("flop_agent.engagement_scheduler.os.fsync",side_effect=fail_directory):
                result=enable_scheduled(state_path,lock_path,now=NOW)
            self.assertEqual((result["success"],result["commit_state"],result["outcome"]),
                             (False,"PUBLISHED","SCHEDULER_STATE_COMMITTED_NOT_DURABLE"))
            self.assertTrue(load_state(state_path,now=NOW)["scheduler_enabled"])

    def test_dry_run_never_invokes_collector_and_reports_status(self):
        with tempfile.TemporaryDirectory() as folder:
            state_path,lock_path=self.paths(Path(folder)); write_state(state_path,ready_state(),now=NOW)
            result=dry_run(state_path,lock_path,now=NOW)
            self.assertTrue(result["allowed"]); self.assertEqual(result["outcome"],"SCHEDULER_READY")
            self.assertEqual(result["requests_24h"],0); self.assertIn("next_eligible_at",result)
            self.assertFalse(result["overlap_active"]); self.assertEqual(result["normal_interval_minutes"],60)

    def test_due_run_invokes_once_and_success_resets_degraded(self):
        with tempfile.TemporaryDirectory() as folder:
            state_path,lock_path=self.paths(Path(folder)); state=ready_state()
            state.update(circuit_state="DEGRADED",consecutive_failures=1,
                         last_error_class="HTTP_OPEN_TIMEOUT",last_attempt_at=stamp(NOW-timedelta(hours=1)),
                         attempts_24h=[stamp(NOW-timedelta(hours=1))])
            write_state(state_path,state,now=NOW); calls=[]
            result=run_once(state_path,lock_path,lambda:(calls.append(1) or {"success":True,"error_class":None}),now=NOW)
            self.assertTrue(result["success"]); self.assertEqual((len(calls),result["collector_invocations"]),(1,1))
            saved=load_state(state_path,now=NOW)
            self.assertEqual((saved["circuit_state"],saved["consecutive_failures"],saved["last_error_class"]),("READY",0,None))

    def test_no_retry_first_failure_then_second_opens_circuit(self):
        with tempfile.TemporaryDirectory() as folder:
            state_path,lock_path=self.paths(Path(folder)); write_state(state_path,ready_state(),now=NOW); calls=[]
            def fail(): calls.append(1); return {"success":False,"error_class":"HTTP_OPEN_TIMEOUT"}
            first=run_once(state_path,lock_path,fail,now=NOW)
            self.assertEqual((first["outcome"],first["circuit_state"],len(calls)),("SCHEDULER_COLLECTION_FAILED","DEGRADED",1))
            later=NOW+timedelta(minutes=61)
            second=run_once(state_path,lock_path,fail,now=later)
            self.assertEqual((second["circuit_state"],len(calls)),("CIRCUIT_OPEN",2))
            much_later=later+timedelta(days=7)
            blocked=run_once(state_path,lock_path,fail,now=much_later)
            self.assertEqual((blocked["outcome"],blocked["collector_invocations"],len(calls)),("SCHEDULER_CIRCUIT_OPEN",0,2))

    def test_all_failure_classes_are_bounded_and_never_retried(self):
        for error in FAILURE_CLASSES:
            with self.subTest(error=error),tempfile.TemporaryDirectory() as folder:
                state_path,lock_path=self.paths(Path(folder)); write_state(state_path,ready_state(),now=NOW); calls=[]
                result=run_once(state_path,lock_path,
                                lambda e=error:(calls.append(1) or {"success":False,"error_class":e}),now=NOW)
                self.assertEqual((result["error_class"],result["collector_invocations"],len(calls)),(error,1,1))

    def test_minimum_interval_and_daily_budget_prevent_requests(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); state_path,lock_path=self.paths(root); calls=[]
            state=ready_state(); recent=NOW-timedelta(minutes=29)
            state.update(last_attempt_at=stamp(recent),attempts_24h=[stamp(recent)])
            write_state(state_path,state,now=NOW)
            result=run_once(state_path,lock_path,lambda:calls.append(1),now=NOW)
            self.assertEqual(result["outcome"],"SCHEDULER_MIN_INTERVAL")
            result=run_once(state_path,lock_path,lambda:calls.append(1),now=NOW+timedelta(minutes=2))
            self.assertEqual(result["outcome"],"SCHEDULER_MIN_INTERVAL")
            attempts=[NOW-timedelta(minutes=30)-timedelta(hours=i) for i in reversed(range(24))]
            state.update(normal_interval_minutes=30,last_attempt_at=stamp(attempts[-1]),
                         attempts_24h=[stamp(item) for item in attempts])
            write_state(state_path,state,now=NOW)
            result=run_once(state_path,lock_path,lambda:calls.append(1),now=NOW)
            self.assertEqual(result["outcome"],"SCHEDULER_DAILY_BUDGET_EXCEEDED")
            self.assertEqual(calls,[])

    def test_exception_text_is_not_persisted(self):
        with tempfile.TemporaryDirectory() as folder:
            state_path,lock_path=self.paths(Path(folder)); write_state(state_path,ready_state(),now=NOW)
            def fail(): raise RuntimeError("private dns or tls detail")
            result=run_once(state_path,lock_path,fail,now=NOW)
            self.assertEqual(result["error_class"],"WORKER_CRASHED")
            self.assertNotIn("private",state_path.read_text()); self.assertNotIn("dns",state_path.read_text())

    def test_overlap_lock_prevents_request(self):
        with tempfile.TemporaryDirectory() as folder:
            state_path,lock_path=self.paths(Path(folder)); write_state(state_path,ready_state(),now=NOW); calls=[]
            with scheduler_lock(lock_path):
                result=run_once(state_path,lock_path,lambda:calls.append(1),now=NOW)
            self.assertEqual((result["outcome"],result["collector_invocations"],calls),("SCHEDULER_RUN_ALREADY_ACTIVE",0,[]))
            with scheduler_lock(lock_path): result=dry_run(state_path,lock_path,now=NOW)
            self.assertTrue(result["overlap_active"])

    def test_explicit_reset_is_two_step_and_does_not_invoke(self):
        with tempfile.TemporaryDirectory() as folder:
            state_path,lock_path=self.paths(Path(folder)); state=disabled_state()
            attempts=[stamp(NOW-timedelta(hours=2)),stamp(NOW-timedelta(hours=1))]
            state.update(circuit_state="CIRCUIT_OPEN",consecutive_failures=2,
                         last_error_class="HTTP_BODY_TIMEOUT",last_attempt_at=attempts[-1],
                         last_success_at=attempts[0],attempts_24h=attempts)
            write_state(state_path,state,now=NOW)
            result=approve_reset(state_path,lock_path,now=NOW)
            self.assertEqual((result["outcome"],result["collector_invocations"]),("SCHEDULER_RESET_APPROVED",0))
            saved=load_state(state_path,now=NOW)
            self.assertEqual((saved["circuit_state"],saved["scheduler_enabled"]),("READY_DISABLED",False))
            self.assertEqual(saved["last_error_class"],"HTTP_BODY_TIMEOUT")
            self.assertEqual(saved["attempts_24h"],attempts)
            self.assertEqual((saved["last_attempt_at"],saved["last_success_at"]),(attempts[-1],attempts[0]))

    def test_missing_corrupt_future_and_unsafe_state_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            state_path,lock_path=self.paths(Path(folder)); calls=[]
            for expected in ("SCHEDULER_STATE_MISSING",):
                result=run_once(state_path,lock_path,lambda:calls.append(1),now=NOW)
                self.assertEqual(result["outcome"],expected)
            state_path.parent.mkdir(parents=True,exist_ok=True); state_path.write_text("not-json"); os.chmod(state_path,0o600)
            self.assertEqual(run_once(state_path,lock_path,lambda:calls.append(1),now=NOW)["outcome"],"SCHEDULER_STATE_INVALID")
            state=ready_state(); state.update(last_attempt_at=stamp(NOW+timedelta(hours=1)),
                                              attempts_24h=[stamp(NOW+timedelta(hours=1))])
            state_path.write_text(json.dumps(state)); os.chmod(state_path,0o600)
            self.assertEqual(run_once(state_path,lock_path,lambda:calls.append(1),now=NOW)["outcome"],"SCHEDULER_STATE_INVALID")
            write_state(state_path,ready_state(),now=NOW); os.chmod(state_path,0o644)
            self.assertEqual(run_once(state_path,lock_path,lambda:calls.append(1),now=NOW)["outcome"],"SCHEDULER_STATE_PERMISSIONS")
            state=ready_state(); state["last_attempt_at"]=stamp(NOW-timedelta(hours=1))
            state_path.write_text(json.dumps(state)); os.chmod(state_path,0o600)
            self.assertEqual(run_once(state_path,lock_path,lambda:calls.append(1),now=NOW)["outcome"],"SCHEDULER_STATE_INVALID")
            self.assertEqual(calls,[])

    def test_atomic_private_state_and_failed_replace_preserve_old_state(self):
        with tempfile.TemporaryDirectory() as folder:
            state_path,_=self.paths(Path(folder)); old=disabled_state(); write_state(state_path,old,now=NOW)
            self.assertEqual(state_path.stat().st_mode&0o777,0o600)
            new=ready_state()
            with mock.patch("flop_agent.engagement_scheduler.os.replace",side_effect=OSError("private detail")):
                with self.assertRaises(OSError): write_state(state_path,new,now=NOW)
            self.assertEqual(load_state(state_path,now=NOW),old)
            self.assertEqual(list(state_path.parent.glob(".*.candidate-*")),[])

    def test_interrupted_run_recovery_records_failure_without_request(self):
        with tempfile.TemporaryDirectory() as folder:
            state_path,lock_path=self.paths(Path(folder)); state=ready_state()
            state.update(run_in_progress=True,last_attempt_at=stamp(NOW-timedelta(minutes=31)),
                         attempts_24h=[stamp(NOW-timedelta(minutes=31))])
            write_state(state_path,state,now=NOW); calls=[]
            result=run_once(state_path,lock_path,lambda:calls.append(1),now=NOW)
            self.assertEqual((result["outcome"],result["collector_invocations"],calls),
                             ("SCHEDULER_RECOVERED_INTERRUPTED_RUN",0,[]))
            recovered=load_state(state_path,now=NOW)
            self.assertEqual(recovered["circuit_state"],"DEGRADED")
            self.assertEqual(recovered["attempts_24h"],[stamp(NOW-timedelta(minutes=31))])
            blocked=run_once(state_path,lock_path,lambda:calls.append(1),now=NOW+timedelta(minutes=28))
            self.assertEqual((blocked["outcome"],calls),("SCHEDULER_MIN_INTERVAL",[]))

    def test_cli_collector_invocation_is_exactly_once_and_bounded(self):
        completed=mock.Mock(stdout=json.dumps(failure_result()).encode(),returncode=1)
        with mock.patch("scripts.engagement_scheduler.subprocess.run",return_value=completed) as called:
            result=_collector(Path("/repo"))
        self.assertEqual(result,{"success":False,"error_class":"HTTP_BODY_TIMEOUT"})
        called.assert_called_once()
        command=called.call_args.args[0]
        self.assertEqual(command[:3],[str(REVIEWED_PYTHON),'-I','-c'])
        self.assertIn(str(REVIEWED_COLLECTOR),command[3])
        self.assertIn(str(CODE_ROOT/'src'),command[3])
        self.assertEqual(command[4:],['--root','/repo'])
        self.assertNotIn("curl"," ".join(command)); self.assertNotIn("http"," ".join(command))
        completed=mock.Mock(stdout=b'{"success":true,"error_class":null}',returncode=7)
        with mock.patch("scripts.engagement_scheduler.subprocess.run",return_value=completed):
            self.assertEqual(_collector(Path("/repo"))["error_class"],"COLLECTOR_RESULT_INVALID")

    def test_runtime_root_cannot_substitute_collector(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); malicious=root/"scripts/collect_engagement.py"; marker=root/"executed"
            malicious.parent.mkdir(); malicious.write_text("from pathlib import Path\nPath(%r).touch()\n" % str(marker))
            completed=mock.Mock(stdout=json.dumps(failure_result()).encode(),returncode=1)
            with mock.patch("scripts.engagement_scheduler.subprocess.run",return_value=completed) as called:
                _collector(root)
            command=called.call_args.args[0]
            self.assertEqual(command[1:3],["-I","-c"])
            self.assertIn(str(CODE_ROOT/"scripts/collect_engagement.py"),command[3])
            self.assertNotIn(str(malicious),command[3])
            self.assertFalse(marker.exists())

    def test_collector_child_isolated_flags_and_hostile_environment(self):
        completed=mock.Mock(stdout=json.dumps(failure_result()).encode(),returncode=1)
        with mock.patch("scripts.engagement_scheduler.subprocess.run",return_value=completed) as called:
            _collector(Path("/repo"))
        command=called.call_args.args[0]
        self.assertEqual(command[:3],[str(REVIEWED_PYTHON),"-I","-c"])
        probe=subprocess.run([sys.executable,"-I","-c",
            "import json,sys;print(json.dumps([sys.flags.isolated,sys.flags.no_user_site,sys.flags.ignore_environment,sys.path]))"],
            env={**os.environ,"PYTHONPATH":"/private/tmp/hostile","PYTHONUSERBASE":"/private/tmp/hostile"},
            capture_output=True,check=True,text=True)
        isolated,no_user_site,ignore_environment,path=json.loads(probe.stdout)
        self.assertEqual((isolated,no_user_site,ignore_environment),(1,1,1))
        self.assertNotIn("/private/tmp/hostile",path)

    def test_strict_collector_result_matrix(self):
        self.assertEqual(_validated_result(success_result(),0),{"success":True,"error_class":None})
        self.assertEqual(_validated_result(failure_result(),1)["error_class"],"HTTP_BODY_TIMEOUT")
        invalid=[]
        underspecified={"success":True,"error_class":None}
        invalid.append(underspecified)
        for field,value in (("commit_state","PRE_COMMIT"),("cleanup_state","FAILED"),
                            ("error_class","VALIDATION_FAILED")):
            item=success_result(); item[field]=value; invalid.append(item)
        item=failure_result(); item["commit_state"]="DURABLE"; invalid.append(item)
        item=success_result(); item["network_diagnostics"]["failure_stage"]="UNKNOWN"; invalid.append(item)
        item=success_result(); item["unknown"]="dangerous"; invalid.append(item)
        for item in invalid:
            with self.subTest(item=item):
                self.assertEqual(_validated_result(item,0 if item.get("success") else 1)["error_class"],
                                 "COLLECTOR_RESULT_INVALID")
        item=success_result(); item["commit_state"]="COMMITTED"; item["durability_warning"]="POST_COMMIT_DURABILITY_WARNING"
        self.assertEqual(_validated_result(item,0)["error_class"],"COLLECTOR_RESULT_NOT_DURABLE")
        item=success_result(); item["preview_state"]="FAILED"; item["preview_warning"]="POST_COMMIT_PREVIEW_WARNING"
        self.assertEqual(_validated_result(item,0)["error_class"],"COLLECTOR_PREVIEW_FAILED")

    def test_success_sample_schema_and_version_are_strict(self):
        self.assertTrue(_validated_result(success_result(),0)["success"])
        invalid_samples=[{}, {"schema":"engagement-sample-v1"}]
        for field,value in (("schema",None),("schema","wrong"),("collector_version",None),
                            ("collector_version","wrong"),("returned_rooms","bad")):
            sample=dict(success_result()["sample"])
            if value is None: sample.pop(field)
            else: sample[field]=value
            invalid_samples.append(sample)
        sample=dict(success_result()["sample"]); sample["dangerous"]="unexpected"; invalid_samples.append(sample)
        for sample in invalid_samples:
            with self.subTest(sample=sample):
                result=success_result(); result["sample"]=sample
                self.assertEqual(_validated_result(result,0)["error_class"],"COLLECTOR_RESULT_INVALID")
        with tempfile.TemporaryDirectory() as folder:
            state_path,lock_path=self.paths(Path(folder)); write_state(state_path,ready_state(),now=NOW)
            malformed=success_result(); malformed["sample"]={}
            result=run_once(state_path,lock_path,lambda:_validated_result(malformed,0),now=NOW)
            saved=load_state(state_path,now=NOW)
            self.assertEqual((result["success"],saved["last_success_at"],saved["last_error_class"]),
                             (False,None,"COLLECTOR_RESULT_INVALID"))

    def test_failure_diagnostic_semantic_matrix(self):
        for error in ("HTTP_OPEN_TIMEOUT","HTTP_OPEN_FAILED","HTTP_BODY_TIMEOUT","HTTP_BODY_FAILED"):
            self.assertEqual(_validated_result(failure_result(error),1)["error_class"],error)
            wrong=failure_result(error)
            wrong["network_diagnostics"]["failure_stage"]=(
                "HTTP_BODY" if error.startswith("HTTP_OPEN") else "HTTP_OPEN")
            self.assertEqual(_validated_result(wrong,1)["error_class"],"COLLECTOR_RESULT_INVALID")
        invalid=[]
        for error in ("HTTP_BODY_TIMEOUT","HTTP_BODY_FAILED"):
            item=failure_result(error); item["network_diagnostics"]["http_status"]=None; invalid.append(item)
            item=failure_result(error); item["network_diagnostics"]["response_bytes"]=1; invalid.append(item)
        for error in ("HTTP_OPEN_TIMEOUT","HTTP_OPEN_FAILED"):
            item=failure_result(error); item["network_diagnostics"]["body_elapsed_seconds"]=.1; invalid.append(item)
            item=failure_result(error); item["network_diagnostics"]["response_bytes"]=1; invalid.append(item)
        item=failure_result(); item["network_diagnostics"].update(total_elapsed_seconds=.1,
                                                                   open_elapsed_seconds=.2,
                                                                   body_elapsed_seconds=.3); invalid.append(item)
        for value in (float("nan"),float("inf"),-1,30.02):
            item=failure_result(); item["network_diagnostics"]["total_elapsed_seconds"]=value; invalid.append(item)
        for item in invalid:
            self.assertEqual(_validated_result(item,1)["error_class"],"COLLECTOR_RESULT_INVALID")
        self.assertEqual(_validated_result(failure_result("HTTP_TIMEOUT"),1)["error_class"],
                         "COLLECTOR_RESULT_INVALID")

    def test_cleanup_state_error_matrix(self):
        invalid=[]
        for state,error in (("COMPLETED","WORKER_CLEANUP_FAILED"),("FAILED",None),
                            ("UNKNOWN",None),("FAILED","UNKNOWN")):
            item=success_result(); item.update(cleanup_state=state,cleanup_error=error); invalid.append(item)
        for item in invalid:
            self.assertEqual(_validated_result(item,0)["error_class"],"COLLECTOR_RESULT_INVALID")
        for error in ("WORKER_CLEANUP_FAILED","WORKER_CLEANUP_UNVERIFIED"):
            item=success_result(); item.update(cleanup_state="FAILED",cleanup_error=error)
            self.assertEqual(_validated_result(item,0)["error_class"],error)

    def test_real_collector_cli_deadline_contract(self):
        program=("from scripts.collect_engagement import main,TotalDeadlineExceeded\n"
                 "def deadline(*args,**kwargs): raise TotalDeadlineExceeded({})\n"
                 "main(run=deadline)\n")
        completed=subprocess.run([sys.executable,"-c",program],cwd=CODE_ROOT,
                                 capture_output=True,timeout=5,check=False)
        self.assertEqual((completed.returncode,completed.stderr),(2,b""))
        envelope=json.loads(completed.stdout)
        self.assertEqual((envelope["success"],envelope["commit_state"],envelope["error_class"]),
                         (False,"PRE_COMMIT","TOTAL_DEADLINE_EXCEEDED"))
        self.assertNotIn("elapsed_seconds",envelope)
        self.assertEqual(_validated_result(envelope,completed.returncode)["error_class"],
                         "TOTAL_DEADLINE_EXCEEDED")
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch("scripts.engagement_scheduler.subprocess.run",return_value=completed):
                self.assertEqual(_collector(Path(folder))["error_class"],"TOTAL_DEADLINE_EXCEEDED")
        compact={"error_class":"TOTAL_DEADLINE_EXCEEDED","configured_total_deadline":30.0}
        self.assertEqual(_validated_result(compact,2)["error_class"],"COLLECTOR_RESULT_INVALID")
        self.assertEqual(_validated_result(envelope,1)["error_class"],"COLLECTOR_RESULT_INVALID")
        self.assertEqual(_validated_result(success_result(),2)["error_class"],"COLLECTOR_RESULT_INVALID")
        cleanup_program=("from scripts.collect_engagement import main,_structured_result\n"
                         "def failure(*args,**kwargs):\n"
                         " return _structured_result(None,{'state':'PRE_COMMIT','preview_state':'NOT_ATTEMPTED','error_class':'PRE_COMMIT_FAILURE'},cleanup_state='FAILED',cleanup_error='WORKER_CLEANUP_FAILED',success=False)\n"
                         "main(run=failure)\n")
        cleanup=subprocess.run([sys.executable,"-c",cleanup_program],cwd=CODE_ROOT,
                               capture_output=True,timeout=5,check=False)
        self.assertEqual((cleanup.returncode,cleanup.stderr),(1,b""))
        self.assertEqual(_validated_result(json.loads(cleanup.stdout),1)["error_class"],
                         "WORKER_CLEANUP_FAILED")

    def test_preview_state_warning_matrix(self):
        invalid=[]
        for state,warning in (("UNKNOWN",None),("FAILED",None),
                              ("UPDATED","POST_COMMIT_PREVIEW_WARNING"),
                              ("NOT_ATTEMPTED","POST_COMMIT_PREVIEW_WARNING"),
                              ("FAILED","UNKNOWN")):
            item=success_result(); item.update(preview_state=state,preview_warning=warning); invalid.append(item)
        for item in invalid:
            self.assertEqual(_validated_result(item,0)["error_class"],"COLLECTOR_RESULT_INVALID")
        valid=success_result(); valid.update(preview_state="FAILED",
                                             preview_warning="POST_COMMIT_PREVIEW_WARNING")
        self.assertEqual(_validated_result(valid,0)["error_class"],"COLLECTOR_PREVIEW_FAILED")

    def test_lock_is_private_from_creation_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            lock=Path(folder)/"scheduler.lock"
            with mock.patch("flop_agent.engagement_scheduler.os.open",wraps=os.open) as opened:
                with scheduler_lock(lock):
                    self.assertEqual(lock.stat().st_mode&0o777,0o600)
            self.assertEqual(opened.call_args.args[2],0o600)
            target=Path(folder)/"target"; target.touch(); lock.unlink(); lock.symlink_to(target)
            with self.assertRaises(SchedulerStateError):
                with scheduler_lock(lock): pass

    def test_no_publication_presence_kv_or_schedule_activation_surface(self):
        root=Path(__file__).resolve().parents[1]
        scheduler=(root/"src/flop_agent/engagement_scheduler.py").read_text()
        cli=(root/"scripts/engagement_scheduler.py").read_text()
        combined=scheduler+cli
        for forbidden in ("api/engagement","git push","/kv/","/r/","requests.","urllib"):
            self.assertNotIn(forbidden,combined)
        self.assertNotIn("--ignore",combined); self.assertNotIn("--force",combined)
        self.assertEqual(list((root/".github/workflows").glob("*scheduler*")),[])

    def test_provision_disabled_creates_exact_private_initial_state_offline(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            with mock.patch("scripts.engagement_scheduler._collector",side_effect=AssertionError), \
                 mock.patch("scripts.engagement_scheduler.subprocess.run",side_effect=AssertionError), \
                 mock.patch("flop_agent.engagement_scheduler.os.open",wraps=os.open) as opened:
                result=provision_disabled(root,now=NOW)
            self.assertEqual(result,{"success":True,"action":"PROVISION_DISABLED",
                "state_created":True,"commit_state":"DURABLE","durability_confirmed":True,
                "error_class":None,"scheduler_enabled":False,"circuit_state":"READY_DISABLED",
                "network_requests":0,"collector_invocations":0,
                "outcome":"SCHEDULER_STATE_PROVISIONED_DISABLED"})
            state_path,lock_path=self.paths(root)
            self.assertEqual(state_path.stat().st_mode&0o777,0o600)
            self.assertEqual(lock_path.stat().st_mode&0o777,0o600)
            self.assertIn(0o600,[call.args[2] for call in opened.call_args_list if len(call.args)>2])
            state=load_state(state_path,now=NOW)
            self.assertEqual(state,disabled_state())
            self.assertEqual(evaluate(state,now=NOW)["outcome"],"SCHEDULER_DISABLED")
            self.assertEqual(dry_run(state_path,lock_path,now=NOW)["outcome"],"SCHEDULER_DISABLED")

    def test_provision_disabled_existing_state_is_unchanged(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); state_path,_=self.paths(root)
            write_state(state_path,ready_state(),now=NOW); before=state_path.read_bytes()
            result=provision_disabled(root,now=NOW)
            self.assertEqual(result["outcome"],"SCHEDULER_STATE_ALREADY_EXISTS")
            self.assertFalse(result["state_created"]); self.assertEqual(state_path.read_bytes(),before)

    def test_provision_disabled_rejects_symlinks_and_unsafe_types(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); state_path,_=self.paths(root); state_path.parent.mkdir(parents=True)
            target=root/"target"; target.write_text("evidence")
            state_path.symlink_to(target)
            self.assertEqual(provision_disabled(root,now=NOW)["outcome"],"SCHEDULER_STATE_PATH_UNSAFE")
            self.assertEqual(target.read_text(),"evidence")
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); runtime=root/"runtime"; target=root/"outside"
            target.mkdir(); runtime.symlink_to(target,target_is_directory=True)
            self.assertEqual(provision_disabled(root,now=NOW)["outcome"],"SCHEDULER_STATE_PATH_UNSAFE")
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); state_path,_=self.paths(root); state_path.mkdir(parents=True)
            self.assertEqual(provision_disabled(root,now=NOW)["outcome"],"SCHEDULER_STATE_PATH_UNSAFE")
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); _,lock_path=self.paths(root); lock_path.parent.mkdir(parents=True)
            target=root/"target"; target.touch(); lock_path.symlink_to(target)
            self.assertEqual(provision_disabled(root,now=NOW)["outcome"],"SCHEDULER_STATE_INVALID")
            self.assertFalse(self.paths(root)[0].exists())
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); runtime=root/"runtime"; runtime.mkdir(); os.chmod(runtime,0o777)
            self.assertEqual(provision_disabled(root,now=NOW)["outcome"],"SCHEDULER_STATE_PATH_UNSAFE")

    def test_concurrent_provision_disabled_initializes_once(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); results=[]; barrier=threading.Barrier(2)
            def provision():
                barrier.wait(); results.append(provision_disabled(root,now=NOW))
            threads=[threading.Thread(target=provision) for _ in range(2)]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            self.assertEqual(sum(item["state_created"] for item in results),1)
            self.assertEqual({item["outcome"] for item in results},
                             {"SCHEDULER_STATE_PROVISIONED_DISABLED","SCHEDULER_STATE_ALREADY_EXISTS"})
            self.assertEqual(load_state(self.paths(root)[0],now=NOW),disabled_state())

    def test_failed_initial_atomic_write_leaves_no_partial_state(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            with mock.patch("flop_agent.engagement_scheduler.os.link",side_effect=OSError("bounded")):
                result=provision_disabled(root,now=NOW)
            state_path,_=self.paths(root)
            self.assertEqual(result["outcome"],"SCHEDULER_STATE_WRITE_FAILED")
            self.assertFalse(state_path.exists())
            self.assertEqual(list(state_path.parent.glob(".*.candidate-*")),[])

    def test_directory_fsync_failure_truthfully_reports_published_state(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); real_fsync=os.fsync; calls=[]
            def fail_directory(descriptor):
                calls.append(descriptor)
                if len(calls)==2: raise OSError("bounded")
                return real_fsync(descriptor)
            with mock.patch("flop_agent.engagement_scheduler.os.fsync",side_effect=fail_directory):
                result=provision_disabled(root,now=NOW)
            state_path,_=self.paths(root)
            self.assertEqual((result["success"],result["state_created"],result["commit_state"],
                              result["durability_confirmed"],result["error_class"]),
                             (False,True,"PUBLISHED",False,
                              "SCHEDULER_STATE_COMMITTED_NOT_DURABLE"))
            self.assertEqual(load_state(state_path,now=NOW),disabled_state())

    def test_post_publish_readback_failure_preserves_visible_state(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            with mock.patch("flop_agent.engagement_scheduler.load_state",
                            side_effect=SchedulerStateError("SCHEDULER_STATE_INVALID")):
                result=provision_disabled(root,now=NOW)
            state_path,_=self.paths(root)
            self.assertEqual((result["success"],result["state_created"],result["commit_state"],
                              result["durability_confirmed"],result["error_class"]),
                             (False,True,"DURABLE",True,
                              "SCHEDULER_STATE_PUBLISHED_VALIDATION_FAILED"))
            self.assertTrue(state_path.exists())

    def test_preexisting_candidate_is_untouched_and_not_state_exists(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); directory=root/"runtime/engagement"; directory.mkdir(parents=True)
            candidate=directory/".scheduler-state.json.candidate-preexisting"
            candidate.write_bytes(b"forensic evidence"); os.chmod(candidate,0o600)
            before=(candidate.read_bytes(),candidate.stat().st_mode&0o777)
            result=provision_disabled(root,now=NOW)
            self.assertTrue(result["success"])
            self.assertEqual((candidate.read_bytes(),candidate.stat().st_mode&0o777),before)

    def test_candidate_creation_collision_is_not_state_exists_or_unlinked(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); directory=root/"runtime/engagement"; directory.mkdir(parents=True)
            candidate=directory/".scheduler-state.json.candidate-collision"
            candidate.write_bytes(b"forensic evidence"); os.chmod(candidate,0o600)
            with mock.patch("flop_agent.engagement_scheduler.tempfile.mkstemp",
                            side_effect=FileExistsError()):
                result=provision_disabled(root,now=NOW)
            self.assertEqual(result["error_class"],"SCHEDULER_STATE_WRITE_FAILED")
            self.assertNotEqual(result["error_class"],"SCHEDULER_STATE_ALREADY_EXISTS")
            self.assertEqual(candidate.read_bytes(),b"forensic evidence")
            self.assertFalse(self.paths(root)[0].exists())

    def test_owned_candidate_cleanup_and_unique_concurrent_candidates(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            with mock.patch("flop_agent.engagement_scheduler.os.link",side_effect=OSError("bounded")):
                result=provision_disabled(root,now=NOW)
            self.assertEqual((result["state_created"],result["commit_state"]),(False,"PRE_PUBLISH"))
            self.assertEqual(list((root/"runtime/engagement").glob(".*.candidate-*")),[])
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); names=[]; real_mkstemp=tempfile.mkstemp
            def record_candidate(*args,**kwargs):
                descriptor,name=real_mkstemp(*args,**kwargs); names.append(name); return descriptor,name
            results=[]; barrier=threading.Barrier(2)
            def provision(): barrier.wait(); results.append(provision_disabled(root,now=NOW))
            with mock.patch("flop_agent.engagement_scheduler.tempfile.mkstemp",
                            side_effect=record_candidate):
                threads=[threading.Thread(target=provision) for _ in range(2)]
                for thread in threads: thread.start()
                for thread in threads: thread.join()
            self.assertEqual(len(names),1)
            self.assertEqual(len(set(names)),1)
            self.assertEqual(sum(item["state_created"] for item in results),1)
            self.assertEqual(load_state(self.paths(root)[0],now=NOW),disabled_state())

    def test_candidate_names_are_unique_and_private_across_attempts(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); observed=[]
            def reject_publish(source,*_args,**_kwargs):
                path=Path(source); observed.append((path.name,path.stat().st_mode&0o777))
                raise OSError("bounded")
            with mock.patch("flop_agent.engagement_scheduler.os.link",side_effect=reject_publish):
                results=[provision_disabled(root,now=NOW),provision_disabled(root,now=NOW)]
            self.assertEqual(len({name for name,_mode in observed}),2)
            self.assertEqual({mode for _name,mode in observed},{0o600})
            self.assertTrue(all(item["commit_state"]=="PRE_PUBLISH" for item in results))
            self.assertEqual(list((root/"runtime/engagement").glob(".*.candidate-*")),[])

    def test_provision_result_rejects_contradictory_combinations(self):
        with self.assertRaises(ValueError):
            _provision_result(success=True,commit_state="PRE_PUBLISH")
        with self.assertRaises(ValueError):
            _provision_result(success=True,commit_state="PUBLISHED")
        with self.assertRaises(ValueError):
            _provision_result(success=False,commit_state="DURABLE")
        with self.assertRaises(ValueError):
            _provision_result(success=False,commit_state="UNKNOWN",error_class="BOUNDED")

    def test_provision_disabled_has_no_activation_or_external_effect_surface(self):
        source=(Path(__file__).resolve().parents[1]/"src/flop_agent/engagement_scheduler.py").read_text()
        section=source[source.index("def provision_disabled"):source.index("def scheduler_lock")]
        for forbidden in ("run_once(", "_collector(", "subprocess", "urllib", "requests.",
                          "launchctl", "crontab", "git ", "READY\"", "scheduler_enabled=True"):
            self.assertNotIn(forbidden,section)

    def test_temp_provision_does_not_mutate_real_history(self):
        real=CODE_ROOT/"runtime/engagement/history.jsonl"
        before=real.read_bytes() if real.exists() else None
        with tempfile.TemporaryDirectory() as folder:
            self.assertTrue(provision_disabled(Path(folder),now=NOW)["success"])
        after=real.read_bytes() if real.exists() else None
        self.assertEqual(after,before)

    def test_temporary_cli_provision_integrates_with_status_and_dry_run(self):
        with tempfile.TemporaryDirectory() as folder, \
             mock.patch("scripts.engagement_scheduler._collector",side_effect=AssertionError), \
             mock.patch("scripts.engagement_scheduler.subprocess.run",side_effect=AssertionError):
            outputs=[]
            for command in ("provision-disabled","status","dry-run"):
                stream=io.StringIO()
                with mock.patch.object(sys,"argv",["engagement_scheduler.py",command,"--root",folder]), \
                     redirect_stdout(stream):
                    main()
                outputs.append(json.loads(stream.getvalue()))
            self.assertEqual(outputs[0]["outcome"],"SCHEDULER_STATE_PROVISIONED_DISABLED")
            self.assertEqual((outputs[1]["circuit_state"],outputs[1]["scheduler_enabled"]),
                             ("READY_DISABLED",False))
            self.assertEqual(outputs[2]["outcome"],"SCHEDULER_DISABLED")
            self.assertEqual(outputs[2]["requests_24h"],0)

    def test_enable_disable_cli_are_offline_only(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); state_path,_=self.paths(root); write_state(state_path,disabled_state())
            with mock.patch("scripts.engagement_scheduler._collector",side_effect=AssertionError), \
                 mock.patch("scripts.engagement_scheduler.subprocess.run",side_effect=AssertionError):
                outputs=[]
                for command in ("enable-scheduled","disable-scheduled"):
                    stream=io.StringIO()
                    with mock.patch.object(sys,"argv",["engagement_scheduler.py",command,"--root",folder]), \
                         redirect_stdout(stream): main()
                    outputs.append(json.loads(stream.getvalue()))
            self.assertEqual([item["outcome"] for item in outputs],
                             ["SCHEDULER_ENABLE_SCHEDULED","SCHEDULER_DISABLED_OFFLINE"])
            self.assertTrue(all(item["network_requests"]==item["collector_invocations"]==0
                                for item in outputs))


if __name__ == "__main__": unittest.main()
