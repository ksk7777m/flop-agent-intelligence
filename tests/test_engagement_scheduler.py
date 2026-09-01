import json, os, tempfile, unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from flop_agent.engagement import build_sample
from flop_agent.engagement_scheduler import (
    DAILY_WINDOW, FAILURE_CLASSES, MAX_REQUESTS_PER_DAY, MINIMUM_INTERVAL, NORMAL_INTERVAL,
    SchedulerStateError, approve_reset, disabled_state, dry_run, evaluate, load_state,
    run_once, scheduler_lock, validate_state, write_state,
)
from scripts.engagement_scheduler import CODE_ROOT, REVIEWED_COLLECTOR, _collector, _validated_result

NOW=datetime(2026,9,1,12,0,0,tzinfo=timezone.utc)


def stamp(value): return value.isoformat().replace("+00:00","Z")


def ready_state():
    state=disabled_state(); state.update(scheduler_enabled=True,circuit_state="READY")
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
        self.assertEqual(command[1:],[str(REVIEWED_COLLECTOR),'--root','/repo'])
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
            self.assertEqual(called.call_args.args[0][1],str(CODE_ROOT/"scripts/collect_engagement.py"))
            self.assertFalse(marker.exists())

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


if __name__ == "__main__": unittest.main()
