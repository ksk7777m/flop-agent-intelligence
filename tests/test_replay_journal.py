import importlib.util,inspect,json,os,pickle,shutil,socket,sqlite3,struct,subprocess,sys,tempfile,threading,types,unittest
from importlib.machinery import SourceFileLoader
from decimal import Decimal
from datetime import datetime,timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from flop_agent import replay_journal as client

HELPER_PATH=Path(__file__).resolve().parents[1]/"libexec"/"flop_replay_store_helper"
_loader=SourceFileLoader("_replay_store_helper_test_only",str(HELPER_PATH));_spec=importlib.util.spec_from_loader(_loader.name,_loader)
j=importlib.util.module_from_spec(_spec);sys.modules[_loader.name]=j;_loader.exec_module(j)

NOW=datetime(2026,9,7,tzinfo=timezone.utc); A="a"*64;B="b"*64;C="c"*64;DID="did:key:z6MkeTGwHmLmuCmgg4ABYhzWVh6ZX7hTwWt8gguAretUfc9c"
def action(nonce="900719925474099312345678901234567890",payload=A,target="resource:fixture"):
    return j.CanonicalAction(DID,"SIGNED_TEST_ACTION","lobby",nonce,payload,B,target,"replay-action-v1")
def family(root):return j._new_test_family(root.resolve(),lambda _now=NOW:_now)
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

    def test_forged_semantic_actor_schema_policy_context_and_target_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            fam=family(Path(d));w=fam.worker();path=Path(d).resolve()/"replay-safety"/"ledger.sqlite3"
            for field,value in (("actor_did","x"),("actor_did","did:web:example.test"),("schema_version","attacker-schema"),("context","room/name"),("target","rail:wrong-class")):
                forged=object.__new__(j.CanonicalAction)
                for name,original in action().__dict__.items():object.__setattr__(forged,name,original)
                object.__setattr__(forged,field,value)
                with self.assertRaises(j.ReplaySafetyError):w.observe(forged)
            forged=object.__new__(j.CanonicalAction)
            for name,original in action().__dict__.items():object.__setattr__(forged,name,original)
            object.__setattr__(forged,"policy_version","attacker-policy")
            with self.assertRaises(j.ReplaySafetyError):w.replay_id(forged)
            con=sqlite3.connect(path);self.assertEqual(con.execute("SELECT COUNT(*) FROM replay_records").fetchone()[0],0);con.close()

    def test_ed25519_did_key_decoding_codec_length_and_canonical_form(self):
        alphabet="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        def b58(raw):
            leading=len(raw)-len(raw.lstrip(b"\0"));number=int.from_bytes(raw,"big");out=""
            while number:number,remainder=divmod(number,58);out=alphabet[remainder]+out
            return "1"*leading+out
        invalid=(""," did:key:z1","did:web:example.test","did:key:abc","did:key:z0","did:key:z"+b58(b"\xec\x01"+bytes(32)),"did:key:z"+b58(b"\xed\x01"+bytes(31)),"did:key:z"+b58(b"\xed\x01"+bytes(33)),"did:key:z"+b58(b"\xed\x01"+bytes(32)+b"x"))
        with tempfile.TemporaryDirectory() as d:
            fam=family(Path(d));w=fam.worker();path=Path(d).resolve()/"replay-safety"/"ledger.sqlite3"
            for actor in invalid:
                forged=object.__new__(j.CanonicalAction)
                for name,value in action().__dict__.items():object.__setattr__(forged,name,value)
                object.__setattr__(forged,"actor_did",actor)
                with self.assertRaises(j.ReplaySafetyError):w.replay_id(forged)
            self.assertEqual(w.observe(action())["state"],"OBSERVED")
            con=sqlite3.connect(path);self.assertEqual(con.execute("SELECT COUNT(*) FROM replay_records").fetchone()[0],1);con.close()

    def test_public_client_has_no_sqlite_path_or_writable_factory(self):
        seen=set();sqlite_values=[];paths=[];factories=[]
        def walk(value):
            if id(value) in seen:return
            seen.add(id(value))
            if isinstance(value,(str,Path)) and ("ledger.sqlite3" in str(value) or "replay-safety" in str(value)):paths.append(value)
            if isinstance(value,types.ModuleType):
                if value.__name__=="sqlite3":sqlite_values.append(value)
                if hasattr(value,"connect") and value.__name__=="sqlite3":factories.append(value.connect)
                return
            if inspect.isfunction(value):
                for cell in value.__closure__ or ():
                    try:walk(cell.cell_contents)
                    except ValueError:pass
                for item in value.__defaults__ or ():walk(item)
                for item in (value.__kwdefaults__ or {}).values():walk(item)
                for name in value.__code__.co_names:
                    if name in value.__globals__:walk(value.__globals__[name])
        for fn in (client.observe_action,client.inspect_action,client.canonical_replay_id):walk(fn)
        self.assertEqual(sqlite_values,[]);self.assertEqual(paths,[]);self.assertEqual(factories,[])
        self.assertNotIn("sqlite3",Path(client.__file__).read_text())

    def test_process_boundary_restarts_and_replays_safely(self):
        script="""from flop_agent import replay_journal as j
a=j.CanonicalAction('did:key:z6MkeTGwHmLmuCmgg4ABYhzWVh6ZX7hTwWt8gguAretUfc9c','SIGNED_ACTION','lobby','1','a'*64,'b'*64,'resource:fixture','replay-action-v1')
import os,sys
os.environ['PYTHONPATH']=sys.argv[2]
if sys.argv[1] in ('SET_STATE','EXEC_SQL'):
 try:j.observe_action.__closure__[0].cell_contents(sys.argv[1],a)
 except j.ReplaySafetyError as exc:print(exc.code)
else:print(j.observe_action(a)['decision'] if sys.argv[1]=='observe' else j.inspect_action(a)['state'])"""
        with tempfile.TemporaryDirectory() as d:
            base=Path(d).resolve();pkg=base/"src"/"flop_agent";pkg.mkdir(parents=True);(base/"secrets").mkdir(mode=0o700);(base/"libexec").mkdir()
            shutil.copy2(client.__file__,pkg/"replay_journal.py");shutil.copy2(HELPER_PATH,base/"libexec"/"flop_replay_store_helper");(pkg/"__init__.py").touch()
            attack=base/"attack";attack.mkdir();marker=base/"helper-import-hijacked";(attack/"sitecustomize.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
            env={"PYTHONDONTWRITEBYTECODE":"1","PYTHONPATH":str(base/"src")}
            runs=[subprocess.run([sys.executable,"-c",script,mode,str(attack)],capture_output=True,text=True,env=env) for mode in ("observe","inspect","observe","SET_STATE","EXEC_SQL")]
            for run in runs:self.assertEqual(run.returncode,0,run.stderr)
            outputs=[run.stdout.strip() for run in runs]
            self.assertEqual(outputs,["FIRST_OBSERVATION","OBSERVED","DUPLICATE_OBSERVATION","IPC_COMMAND_UNSUPPORTED","IPC_COMMAND_UNSUPPORTED"])
            self.assertFalse(marker.exists());self.assertIsNone(importlib.util.find_spec("flop_agent.replay_store_helper"))
            self.assertEqual(os.stat(base/"secrets"/"replay-safety"/"store.credential").st_mode&0o777,0o600)

    def test_ipc_auth_schema_commands_and_canonical_input_fail_closed(self):
        source=HELPER_PATH.read_text()
        with tempfile.TemporaryDirectory() as d:
            fake=Path(d).resolve()/"libexec"/"flop_replay_store_helper";fake.parent.mkdir();fake.parents[1].joinpath("secrets").mkdir(mode=0o700)
            module=types.ModuleType("replay_ipc_fixture");module.__file__=str(fake);module.__package__="flop_agent";sys.modules[module.__name__]=module;exec(compile(source,str(fake),"exec"),module.__dict__)
            base={"version":"replay-ipc-v1","request_id":"b"*32,"auth":"0"*64,"command":"OBSERVE","policy_version":j.POLICY_VERSION,"action":dict(action().__dict__)}
            def exchange(value,declared=None,use_server_auth=True,trailing=b""):
                parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM);worker=threading.Thread(target=module._serve_ipc_once,args=(child.detach(),));worker.start();server_auth=parent.recv(64).decode()
                if callable(value):encoded=value(server_auth)
                elif isinstance(value,bytes):encoded=value
                else:
                    value=json.loads(json.dumps(value))
                    if use_server_auth:value["auth"]=server_auth
                    encoded=json.dumps(value,separators=(",",":")).encode()
                parent.sendall(struct.pack("!I",len(encoded) if declared is None else declared)+encoded+trailing)
                try:parent.shutdown(socket.SHUT_WR)
                except OSError:pass
                header=b""
                while len(header)<4:header+=parent.recv(4-len(header))
                size=struct.unpack("!I",header)[0];payload=b""
                while len(payload)<size:payload+=parent.recv(size-len(payload))
                response=json.loads(payload);parent.close();worker.join();return response
            wrong=dict(base);wrong["auth"]="c"*64;self.assertFalse(exchange(wrong,use_server_auth=False)["ok"])
            cases=[]
            for command in ("EXEC_SQL","SET_STATE","OPEN_DB"):
                value=dict(base);value["command"]=command;cases.append(value)
            extra=dict(base);extra["sql"]="UPDATE replay_records";cases.append(extra)
            bad_nonce=json.loads(json.dumps(base));bad_nonce["action"]["nonce"]=1.0;cases.append(bad_nonce)
            bad_did=json.loads(json.dumps(base));bad_did["action"]["actor_did"]="did:key:z0";cases.append(bad_did)
            bad_hash=json.loads(json.dumps(base));bad_hash["action"]["signed_payload_sha256"]="bad";cases.append(bad_hash)
            bad_schema=json.loads(json.dumps(base));bad_schema["action"]["schema_version"]="attacker";cases.append(bad_schema)
            bad_policy=dict(base);bad_policy["policy_version"]="attacker";cases.append(bad_policy)
            for value in cases:self.assertFalse(exchange(value)["ok"],value)
            oversized=exchange(b"x",module.IPC_MAX_REQUEST_BYTES+1);self.assertFalse(oversized["ok"])
            truncated=exchange(b"{}",10);self.assertFalse(truncated["ok"])
            trailing=exchange(base,trailing=b"hidden");self.assertFalse(trailing["ok"])
            duplicate=exchange(lambda auth:(json.dumps(base,separators=(",",":"))[:-1]+',"auth":"'+auth+'"}').encode());self.assertFalse(duplicate["ok"])
            captured=[]
            def capture(auth):
                value=json.loads(json.dumps(base));value["auth"]=auth;encoded=json.dumps(value,separators=(",",":")).encode();captured.append(encoded);return encoded
            first=exchange(capture);self.assertTrue(first["ok"]);self.assertEqual(first["result"]["decision"],"FIRST_OBSERVATION")
            self.assertFalse(exchange(captured[0])["ok"])
            self.assertEqual(exchange(base)["result"]["decision"],"DUPLICATE_OBSERVATION")
            sys.modules.pop(module.__name__,None)

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

    def test_root_intermediate_and_nested_parent_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d).resolve();outside=base/"outside";outside.mkdir(mode=0o700);(outside/"root").mkdir(mode=0o700)
            direct=base/"linked-parent";direct.symlink_to(outside,target_is_directory=True)
            with self.assertRaises((OSError,j.ReplaySafetyError)):j._new_test_family(direct/"root",lambda:NOW)
            self.assertFalse((outside/"root"/"replay-safety").exists())
            real=base/"real";real.mkdir(mode=0o700);nested=real/"nested";nested.symlink_to(outside,target_is_directory=True)
            with self.assertRaises((OSError,j.ReplaySafetyError)):j._new_test_family(nested/"root",lambda:NOW)
            self.assertFalse((outside/"root"/"replay-safety").exists())
            root_link=base/"root-link";root_link.symlink_to(outside/"root",target_is_directory=True)
            with self.assertRaises((OSError,j.ReplaySafetyError)):j._new_test_family(root_link,lambda:NOW)

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
            root=Path(d);fam=family(root);item=action();w,res=ready(fam,item);w.attempted(res);w.recover();proof=fam.issue_reconciliation(item,j.ReviewedEvidenceFixture.READBACK_PROVES_EFFECT);path=root/"replay-safety"/"ledger.sqlite3";before=counts(path)
            con=sqlite3.connect(path);con.execute("CREATE TRIGGER deny_reconcile_confirmed BEFORE UPDATE OF result_state ON effects WHEN NEW.result_state='EFFECT_CONFIRMED' BEGIN SELECT RAISE(ABORT,'fixture'); END");con.commit();con.close()
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
