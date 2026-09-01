import json, os, tempfile, unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from flop_agent.engagement_scheduler import (
    DAILY_WINDOW, FAILURE_CLASSES, MAX_REQUESTS_PER_DAY, MINIMUM_INTERVAL, NORMAL_INTERVAL,
    SchedulerStateError, approve_reset, disabled_state, dry_run, evaluate, load_state,
    run_once, scheduler_lock, validate_state, write_state,
)
from scripts.engagement_scheduler import _collector

NOW=datetime(2026,9,1,12,0,0,tzinfo=timezone.utc)


def stamp(value): return value.isoformat().replace("+00:00","Z")


def ready_state():
    state=disabled_state(); state.update(scheduler_enabled=True,circuit_state="READY")
    return state


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
            state.update(circuit_state="CIRCUIT_OPEN",consecutive_failures=2,
                         last_error_class="HTTP_BODY_TIMEOUT")
            write_state(state_path,state,now=NOW)
            result=approve_reset(state_path,lock_path,now=NOW)
            self.assertEqual((result["outcome"],result["collector_invocations"]),("SCHEDULER_RESET_APPROVED",0))
            saved=load_state(state_path,now=NOW)
            self.assertEqual((saved["circuit_state"],saved["scheduler_enabled"]),("READY_DISABLED",False))

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
            self.assertEqual(load_state(state_path,now=NOW)["circuit_state"],"DEGRADED")

    def test_cli_collector_invocation_is_exactly_once_and_bounded(self):
        completed=mock.Mock(stdout=b'{"success":false,"error_class":"HTTP_BODY_TIMEOUT"}',returncode=1)
        with mock.patch("scripts.engagement_scheduler.subprocess.run",return_value=completed) as called:
            result=_collector(Path("/repo"))
        self.assertEqual(result,{"success":False,"error_class":"HTTP_BODY_TIMEOUT"})
        called.assert_called_once()
        command=called.call_args.args[0]
        self.assertEqual(command[1:],['/repo/scripts/collect_engagement.py','--root','/repo'])
        self.assertNotIn("curl"," ".join(command)); self.assertNotIn("http"," ".join(command))
        completed=mock.Mock(stdout=b'{"success":true,"error_class":null,"cleanup_error":"WORKER_CLEANUP_FAILED"}',returncode=0)
        with mock.patch("scripts.engagement_scheduler.subprocess.run",return_value=completed):
            self.assertEqual(_collector(Path("/repo"))["error_class"],"WORKER_CLEANUP_FAILED")
        completed=mock.Mock(stdout=b'{"success":true,"error_class":null}',returncode=7)
        with mock.patch("scripts.engagement_scheduler.subprocess.run",return_value=completed):
            self.assertEqual(_collector(Path("/repo"))["error_class"],"VALIDATION_FAILED")

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
