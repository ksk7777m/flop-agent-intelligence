import inspect,json,os,pickle,shutil,sqlite3,tempfile,threading,unittest
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
            self.assertEqual(w.inspect(item)["state"],"REPLAY_IDENTITY_CONFLICT")
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
            second=family(root)
            with self.assertRaises(j.ReplaySafetyError):second.worker().inspect(item)
            clone=Path(d)/"clone";clone.mkdir(mode=0o700);(clone/"replay-safety").mkdir(mode=0o700);shutil.copy2(root/"replay-safety"/"ledger.sqlite3",clone/"replay-safety"/"ledger.sqlite3")
            with self.assertRaises(j.ReplaySafetyError):family(clone).worker().inspect(item)
            self.assertEqual(w.inspect(item)["state"],"EFFECT_RESERVED")

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
