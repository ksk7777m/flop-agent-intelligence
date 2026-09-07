import inspect,json,os,pickle,shutil,sqlite3,tempfile,threading,unittest
from decimal import Decimal
from datetime import datetime,timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from flop_agent import replay_journal as j

NOW=datetime(2026,9,7,tzinfo=timezone.utc); A="a"*64;B="b"*64;C="c"*64
def action(nonce="900719925474099312345678901234567890",payload=A,target="resource:fixture"):
    return j.CanonicalAction("did:key:zFixture","SIGNED_TEST_ACTION","lobby",nonce,payload,B,target,"fixture-schema-v1")
def family(root):return j._new_test_family(root,lambda _now=NOW:_now)
def ready(fam,item,effect=j.EffectClass.PAYMENT,target="rail:1"):
    worker=fam.worker();worker.observe(item);worker.validate(item,fam.issue_validation(item));auth=fam.issue_effect_authority(item,"reviewed:authority");reservation=worker.reserve(item,auth,effect,target,C);return worker,reservation

class ReplayJournalTests(unittest.TestCase):
    def test_observation_duplicate_lossless_and_nonce_conflict(self):
        with tempfile.TemporaryDirectory() as d:
            w=family(Path(d)).worker();item=action();one=w.observe(item);two=w.observe(item)
            self.assertEqual(one["replay_id"],two["replay_id"]);self.assertEqual(two["observation_count"],2)
            conflict=w.observe(action(payload=C));self.assertEqual(conflict["decision"],"REPLAY_IDENTITY_CONFLICT")
            self.assertEqual(w.inspect(item)["state"],"OBSERVED")
            with self.assertRaises(j.ReplaySafetyError):action(nonce=1e30)

    def test_attempted_and_unknown_cannot_fail_safe_without_sealed_proof(self):
        with tempfile.TemporaryDirectory() as d:
            fam=family(Path(d));item=action();w,res=ready(fam,item);w.attempted(res)
            self.assertFalse(hasattr(w,"fail_safe"))
            for forged in (True,A,{},object.__new__(j.VerifiedReconciliation)):
                with self.assertRaises((TypeError,PermissionError,j.ReplaySafetyError)):
                    w.reconcile(item,forged)
            w.recover();self.assertEqual(w.inspect(item)["state"],"EFFECT_OUTCOME_UNKNOWN")
            with self.assertRaises(PermissionError):w.reconcile(item,object.__new__(j.VerifiedReconciliation))
            proof=fam.issue_reconciliation(item,j.ReviewedEvidenceFixture.READBACK_PROVES_ABSENCE)
            self.assertEqual(w.reconcile(item,proof)["state"],"EFFECT_FAILED_SAFE")
            retry=w.reserve(item,fam.issue_effect_authority(item,"reviewed:retry"),j.EffectClass.PAYMENT,"rail:1",C)
            self.assertIs(type(retry),j.Reservation)

    def test_reserved_crash_has_explicit_sealed_release(self):
        with tempfile.TemporaryDirectory() as d:
            fam=family(Path(d));item=action();w,_=ready(fam,item)
            reopened=fam.worker();self.assertEqual(reopened.inspect(item)["retry_classification"],"RECONCILIATION_REQUIRED")
            proof=fam.issue_reconciliation(item,j.ReviewedEvidenceFixture.RESERVED_NOT_INVOKED)
            self.assertEqual(reopened.reconcile(item,proof)["state"],"EFFECT_FAILED_SAFE")

    def test_confirmation_is_opaque_typed_and_exactly_bound(self):
        with tempfile.TemporaryDirectory() as d:
            fam=family(Path(d));a1=action();w,r1=ready(fam,a1,j.EffectClass.PAYMENT,"rail:1");w.attempted(r1)
            evidence=fam.issue_confirmation(r1,j.ReviewedEvidenceFixture.PAYMENT_FINAL)
            with self.assertRaises((TypeError,PermissionError)):w.confirm(r1,A)
            # A second action's valid evidence cannot confirm the first.
            a2=action(nonce="2",target="resource:two");w2,r2=ready(fam,a2,j.EffectClass.PAYMENT,"rail:2");w2.attempted(r2)
            other=fam.issue_confirmation(r2,j.ReviewedEvidenceFixture.PAYMENT_FINAL)
            with self.assertRaises(PermissionError):w.confirm(r1,other)
            self.assertEqual(w.inspect(a1)["state"],"EFFECT_ATTEMPTED")
            self.assertEqual(w.confirm(r1,evidence)["state"],"EFFECT_CONFIRMED")
            self.assertEqual(w.inspect(a1)["confirmation_evidence_type"],"RAIL_FINALITY")

    def test_wrong_attempt_confirmation_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            fam=family(Path(d));item=action();w,r1=ready(fam,item,j.EffectClass.AGENT_TASK,"job:9")
            proof=fam.issue_reconciliation(item,j.ReviewedEvidenceFixture.RESERVED_NOT_INVOKED);w.reconcile(item,proof)
            old=fam.issue_confirmation(r1,j.ReviewedEvidenceFixture.AGENT_TASK_CONFIRMED)
            r2=w.reserve(item,fam.issue_effect_authority(item,"reviewed:retry"),j.EffectClass.AGENT_TASK,"job:9",C);w.attempted(r2)
            with self.assertRaises(PermissionError):w.confirm(r2,old)

    def test_confirmed_duplicate_is_do_not_retry(self):
        with tempfile.TemporaryDirectory() as d:
            fam=family(Path(d));item=action();w,res=ready(fam,item,j.EffectClass.FAUCET_CLAIM,"faucet:test");w.attempted(res);proof=fam.issue_confirmation(res,j.ReviewedEvidenceFixture.FAUCET_CONFIRMED);w.confirm(res,proof);w.observe(item)
            self.assertEqual(w.inspect(item)["retry_classification"],"DO_NOT_RETRY")
            with self.assertRaises(j.ReplaySafetyError):w.reserve(item,fam.issue_effect_authority(item,"reviewed:again"),j.EffectClass.FAUCET_CLAIM,"faucet:test",C)

    def test_same_database_new_family_cannot_mutate_and_clone_is_not_authoritative(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/"one";root.mkdir(mode=0o700);first=family(root);item=action();w,_=ready(first,item)
            with self.assertRaises(j.ReplaySafetyError):family(root)
            clone=Path(d)/"clone";clone.mkdir(mode=0o700);(clone/"replay-safety").mkdir(mode=0o700);shutil.copy2(root/"replay-safety"/"ledger.sqlite3",clone/"replay-safety"/"ledger.sqlite3")
            with self.assertRaises(j.ReplaySafetyError):family(clone).worker().inspect(item)
            self.assertEqual(w.inspect(item)["state"],"EFFECT_RESERVED")

    def test_forged_actions_are_revalidated_before_identity_or_storage(self):
        with tempfile.TemporaryDirectory() as d:
            fam=family(Path(d));w=fam.worker();path=Path(d)/"replay-safety"/"ledger.sqlite3"
            bad_values=(1e30,1.0,123,Decimal("123"),"1e30","+1"," 1","-1","1.0")
            for value in bad_values:
                forged=object.__new__(j.CanonicalAction)
                for name,field in action().__dict__.items():object.__setattr__(forged,name,field)
                object.__setattr__(forged,"nonce",value)
                with self.assertRaises(j.ReplaySafetyError):w.observe(forged)
            for field,value in (("signed_payload_sha256","A"*64),("signing_bytes_sha256","abc"),("action_class","UNKNOWN"),("target","bad target")):
                forged=object.__new__(j.CanonicalAction)
                for name,original in action().__dict__.items():object.__setattr__(forged,name,original)
                object.__setattr__(forged,field,value)
                with self.assertRaises(j.ReplaySafetyError):w.replay_id(forged)
            self.assertEqual(sqlite3.connect(path).execute("SELECT COUNT(*) FROM replay_records").fetchone()[0],0)

    def test_terminal_nonce_conflict_is_recorded_without_changing_authoritative_result(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);fam=family(root);item=action();w,res=ready(fam,item);w.attempted(res);w.confirm(res,fam.issue_confirmation(res,j.ReviewedEvidenceFixture.PAYMENT_FINAL))
            result=w.observe(action(payload=C))
            self.assertEqual(result["decision"],"REPLAY_IDENTITY_CONFLICT");self.assertEqual(result["authoritative_state"],"EFFECT_CONFIRMED")
            self.assertEqual(w.inspect(item)["state"],"EFFECT_CONFIRMED")
            con=sqlite3.connect(root/"replay-safety"/"ledger.sqlite3");self.assertEqual(con.execute("SELECT COUNT(*) FROM replay_conflicts").fetchone()[0],1);con.close()
            with self.assertRaises(j.ReplaySafetyError):w.reserve(action(payload=C),fam.issue_effect_authority(action(payload=C),"reviewed:conflict"),j.EffectClass.PAYMENT,"rail:1",C)

    def test_path_swap_between_validation_and_sqlite_open_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);fam=family(root);w=fam.worker();path=root/"replay-safety"/"ledger.sqlite3";held=root/"replay-safety"/"held.sqlite3"
            original=sqlite3.connect;swapped=False
            def swap_then_connect(name,*args,**kwargs):
                nonlocal swapped
                if not swapped:
                    os.replace(path,held);attacker=original(path);attacker.execute("CREATE TABLE attacker_marker(value TEXT)");attacker.commit();attacker.close();swapped=True
                return original(name,*args,**kwargs)
            with mock.patch.object(sqlite3,"connect",side_effect=swap_then_connect):
                with self.assertRaises(j.ReplaySafetyError):w.observe(action())
            attacker=original(path);self.assertEqual(attacker.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='replay_records'").fetchone()[0],0);attacker.close()
            os.unlink(path);os.replace(held,path);self.assertEqual(w.observe(action())["state"],"OBSERVED")

    def test_parent_and_final_symlinks_and_production_root_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);outside=base/"outside";outside.mkdir(mode=0o700);root=base/"root";root.mkdir(mode=0o700);(root/"replay-safety").symlink_to(outside,target_is_directory=True)
            with self.assertRaises((OSError,j.ReplaySafetyError)):family(root).worker().observe(action())
            self.assertFalse((outside/"ledger.sqlite3").exists())
            root2=base/"root2";root2.mkdir(mode=0o700);(root2/"replay-safety").mkdir(mode=0o700);target=outside/"db";target.touch();(root2/"replay-safety"/"ledger.sqlite3").symlink_to(target)
            with self.assertRaises((OSError,j.ReplaySafetyError)):family(root2).worker().observe(action())
            with self.assertRaises(j.ReplaySafetyError):j._new_test_family(j._PRODUCTION_ROOT,lambda:NOW)

    def test_permissions_transaction_rollback_and_reopen(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);fam=family(root);item=action();w=fam.worker();w.observe(item);w.validate(item,fam.issue_validation(item));path=root/"replay-safety"/"ledger.sqlite3"
            self.assertEqual(os.stat(path.parent).st_mode&0o777,0o700);self.assertEqual(os.stat(path).st_mode&0o777,0o600)
            con=sqlite3.connect(path);con.execute("CREATE TRIGGER deny BEFORE INSERT ON effects BEGIN SELECT RAISE(ABORT,'fixture'); END");con.commit();con.close()
            with self.assertRaises((sqlite3.DatabaseError,j.ReplaySafetyError)):w.reserve(item,fam.issue_effect_authority(item,"reviewed:a"),j.EffectClass.PAYMENT,"rail:1",C)
            self.assertEqual(w.inspect(item)["state"],"VALIDATED")

    def test_attempt_confirm_reconcile_and_conflict_failures_roll_back_atomically(self):
        def counts(path):
            con=sqlite3.connect(path);value=(con.execute("SELECT state FROM replay_records ORDER BY created_at DESC LIMIT 1").fetchone()[0],con.execute("SELECT COUNT(*) FROM replay_events").fetchone()[0],con.execute("SELECT COUNT(*) FROM replay_conflicts").fetchone()[0],con.execute("PRAGMA integrity_check").fetchone()[0]);con.close();return value
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);fam=family(root);item=action();w,res=ready(fam,item);path=root/"replay-safety"/"ledger.sqlite3";before=counts(path)
            con=sqlite3.connect(path);con.execute("CREATE TRIGGER deny_attempt BEFORE UPDATE OF result_state ON effects WHEN NEW.result_state='EFFECT_ATTEMPTED' BEGIN SELECT RAISE(ABORT,'fixture'); END");con.commit();con.close()
            with self.assertRaises(sqlite3.DatabaseError):w.attempted(res)
            self.assertEqual(counts(path),before)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);fam=family(root);item=action();w,res=ready(fam,item);w.attempted(res);proof=fam.issue_confirmation(res,j.ReviewedEvidenceFixture.PAYMENT_FINAL);path=root/"replay-safety"/"ledger.sqlite3";before=counts(path)
            con=sqlite3.connect(path);con.execute("CREATE TRIGGER deny_confirm BEFORE UPDATE OF result_state ON effects WHEN NEW.result_state='EFFECT_CONFIRMED' BEGIN SELECT RAISE(ABORT,'fixture'); END");con.commit();con.close()
            with self.assertRaises(sqlite3.DatabaseError):w.confirm(res,proof)
            self.assertEqual(counts(path),before)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);fam=family(root);item=action();w,res=ready(fam,item);w.attempted(res);w.recover();proof=fam.issue_reconciliation(item,j.ReviewedEvidenceFixture.READBACK_PROVES_ABSENCE);path=root/"replay-safety"/"ledger.sqlite3";before=counts(path)
            con=sqlite3.connect(path);con.execute("CREATE TRIGGER deny_reconcile BEFORE UPDATE OF result_state ON effects WHEN NEW.result_state='EFFECT_FAILED_SAFE' BEGIN SELECT RAISE(ABORT,'fixture'); END");con.commit();con.close()
            with self.assertRaises(sqlite3.DatabaseError):w.reconcile(item,proof)
            self.assertEqual(counts(path),before)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);fam=family(root);item=action();w=fam.worker();w.observe(item);path=root/"replay-safety"/"ledger.sqlite3";before=counts(path)
            con=sqlite3.connect(path);con.execute("CREATE TRIGGER deny_conflict BEFORE INSERT ON replay_conflicts BEGIN SELECT RAISE(ABORT,'fixture'); END");con.commit();con.close()
            with self.assertRaises(sqlite3.DatabaseError):w.observe(action(payload=C))
            self.assertEqual(counts(path),before)

    def test_multiservice_concurrency_one_winner_no_corruption(self):
        with tempfile.TemporaryDirectory() as d:
            fam=family(Path(d));item=action();seed=fam.worker();seed.observe(item);seed.validate(item,fam.issue_validation(item));workers=[fam.worker() for _ in range(8)];barrier=threading.Barrier(8);out=[];lock=threading.Lock()
            def run(i):
                auth=fam.issue_effect_authority(item,f"reviewed:{i}");barrier.wait()
                try:workers[i].reserve(item,auth,j.EffectClass.PAYMENT,"rail:1",C);value="yes"
                except Exception:value="no"
                with lock:out.append(value)
            threads=[threading.Thread(target=run,args=(i,)) for i in range(8)];[x.start() for x in threads];[x.join() for x in threads]
            self.assertEqual(out.count("yes"),1);con=sqlite3.connect(Path(d)/"replay-safety"/"ledger.sqlite3");self.assertEqual(con.execute("PRAGMA integrity_check").fetchone()[0],"ok");con.close()

    def test_attempted_restart_unknown_and_confirmed_reopen_persist(self):
        with tempfile.TemporaryDirectory() as d:
            fam=family(Path(d));item=action();w,res=ready(fam,item,j.EffectClass.INFERENCE_SPEND,"model:x");w.attempted(res);reopened=fam.worker();reopened.recover();self.assertEqual(reopened.inspect(item)["state"],"EFFECT_OUTCOME_UNKNOWN");self.assertEqual(reopened.inspect(item)["retry_classification"],"RECONCILIATION_REQUIRED")
        with tempfile.TemporaryDirectory() as d:
            fam=family(Path(d));item=action();w,res=ready(fam,item,j.EffectClass.REPUTATION_CREDIT,"rep:1");w.attempted(res);w.confirm(res,fam.issue_confirmation(res,j.ReviewedEvidenceFixture.REPUTATION_CONFIRMED));self.assertEqual(fam.worker().inspect(item)["state"],"EFFECT_CONFIRMED")

    def test_serialization_cross_authority_and_module_surface(self):
        with tempfile.TemporaryDirectory() as d:
            fam=family(Path(d));item=action();w=fam.worker();w.observe(item);projection=json.loads(json.dumps(dict(w.inspect(item))));projection["state"]="EFFECT_CONFIRMED";self.assertEqual(w.inspect(item)["state"],"OBSERVED")
            other_root=Path(d)/"other";other_root.mkdir(mode=0o700);other=family(other_root);other.worker().observe(item)
            with self.assertRaises(PermissionError):other.worker().validate(item,fam.issue_validation(item))
            for typ in (j.Reservation,j.VerifiedEffectConfirmation,j.VerifiedReconciliation):
                with self.assertRaises(TypeError):pickle.dumps(object.__new__(typ))
        privileged={"validate","reserve","attempted","confirm","reconcile","recover","issue_validation","issue_effect_authority","issue_confirmation","issue_reconciliation"}
        for value in vars(j).values():
            if isinstance(value,SimpleNamespace):self.assertFalse(privileged&set(vars(value)))
        self.assertFalse(hasattr(j,"_PRODUCTION"));self.assertFalse(hasattr(j,"_build_service_family"))
        self.assertIsNone(j._new_test_family.__defaults__);self.assertIsNone(j._new_test_family.__kwdefaults__);self.assertIsNone(j._new_test_family.__closure__)

    def test_all_privileged_callables_have_zero_dynamic_globals_and_resist_rebinding(self):
        with tempfile.TemporaryDirectory() as d:
            fam=family(Path(d));w=fam.worker();functions=[*vars(fam).values(),*vars(w).values()]
            for fn in functions:
                if inspect.isfunction(fn):self.assertEqual(inspect.getclosurevars(fn).globals,{},fn)
            item=action();before=w.replay_id(item)
            with mock.patch.object(j,"SAFE_TEXT",None),mock.patch.object(j,"HEX64",None),mock.patch.object(j,"hashlib",None),mock.patch.object(j,"ReplayState",None):
                self.assertEqual(w.replay_id(item),before);w.observe(item);w.validate(item,fam.issue_validation(item));res=w.reserve(item,fam.issue_effect_authority(item,"reviewed:a"),j.EffectClass.PAYMENT,"rail:1",C);w.attempted(res)
                with self.assertRaises((TypeError,PermissionError)):w.confirm(res,A)

if __name__=="__main__":unittest.main()
