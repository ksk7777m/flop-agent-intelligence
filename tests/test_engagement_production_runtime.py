import hashlib, json, os, shutil, stat, subprocess, tempfile, threading, types, unittest
from pathlib import Path
from unittest import mock

from scripts import engagement_scheduler_launcher as launcher
from scripts import provision_engagement_runtime as provisioner
from scripts import validate_engagement_production_runtime as runtime_validator
from scripts.engagement_runtime_contract import validate_scheduler_status_result
from scripts import engagement_runtime_contract as runtime_contract

REVISION="1"*40


class EngagementProductionRuntimeTests(unittest.TestCase):
    @staticmethod
    def nonproduction_mode():
        branch=subprocess.run(["git","symbolic-ref","--short","HEAD"],
            cwd=provisioner.CODE_ROOT,capture_output=True,check=True,text=True).stdout.strip()
        return (provisioner.ProvisionMode.VALIDATION_ONLY if branch=="main"
                else provisioner.ProvisionMode.STANDARD)

    @classmethod
    def nonproduction_eligibility(cls):
        return (provisioner.VALIDATION_ONLY
                if cls.nonproduction_mode() is provisioner.ProvisionMode.VALIDATION_ONLY
                else provisioner.PREVIEW_ONLY)

    def test_account_home_is_environment_independent_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            home=Path(folder).resolve(); uid=os.getuid()
            account=types.SimpleNamespace(pw_dir=str(home))
            hostile={"HOME":"/private/tmp/attacker-home","USER":"attacker",
                "LOGNAME":"attacker","PWD":"/private/tmp","PYTHONPATH":"/private/tmp/hostile"}
            with mock.patch.dict(os.environ,hostile,clear=True), \
                 mock.patch.object(runtime_contract.pwd,"getpwuid",return_value=account), \
                 mock.patch.object(runtime_contract.os,"getuid",return_value=uid), \
                 mock.patch.object(runtime_contract.os,"geteuid",return_value=uid):
                self.assertEqual(runtime_contract.resolve_account_home(),home)
                self.assertEqual(runtime_contract.production_runtime_root(),
                    home/runtime_contract.RUNTIME_SUFFIX)
            for home_value in (None,"","relative","x"*8192,str(home/"link")):
                environment={} if home_value is None else {"HOME":home_value}
                with self.subTest(HOME=home_value), mock.patch.dict(os.environ,environment,clear=True), \
                     mock.patch.object(runtime_contract.pwd,"getpwuid",return_value=account):
                    self.assertEqual(runtime_contract.resolve_account_home(),home)
            with mock.patch.object(runtime_contract.pwd,"getpwuid",side_effect=KeyError):
                self.assertIsNone(runtime_contract.resolve_account_home())
            with mock.patch.object(runtime_contract.pwd,"getpwuid",
                    return_value=types.SimpleNamespace(pw_dir="relative")):
                self.assertIsNone(runtime_contract.resolve_account_home())
            with mock.patch.object(runtime_contract.pwd,"getpwuid",
                    return_value=types.SimpleNamespace(pw_dir=str(home/"missing"))):
                self.assertIsNone(runtime_contract.resolve_account_home())
            with mock.patch.object(runtime_contract.os,"geteuid",return_value=uid+1):
                self.assertIsNone(runtime_contract.resolve_account_home())
            with mock.patch.object(runtime_contract.os,"getuid",return_value=0), \
                 mock.patch.object(runtime_contract.os,"geteuid",return_value=0), \
                 mock.patch.object(runtime_contract.pwd,"getpwuid",return_value=account):
                self.assertIsNone(runtime_contract.resolve_account_home())
            home.chmod(0o777)
            with mock.patch.object(runtime_contract.pwd,"getpwuid",return_value=account):
                self.assertIsNone(runtime_contract.resolve_account_home())
            home.chmod(0o700)
            link=home.parent/(home.name+"-link"); link.symlink_to(home,target_is_directory=True)
            try:
                with mock.patch.object(runtime_contract.pwd,"getpwuid",
                        return_value=types.SimpleNamespace(pw_dir=str(link))):
                    self.assertIsNone(runtime_contract.resolve_account_home())
            finally: link.unlink()

    @staticmethod
    def valid_status():
        return {"success":True,"allowed":False,"outcome":"SCHEDULER_NOT_BEFORE",
            "overlap_active":False,"circuit_state":"READY","scheduler_enabled":True,
            "run_in_progress":False,"last_attempt_at":None,"last_success_at":None,
            "not_before_at":"2026-09-03T00:00:00Z","consecutive_failures":0,
            "last_error_class":None,"normal_interval_minutes":60,
            "minimum_interval_minutes":30,"next_eligible_at":"2026-09-03T00:00:00Z",
            "requests_24h":0}

    def test_strict_scheduler_status_contract_matrix(self):
        valid=self.valid_status(); self.assertIsNotNone(validate_scheduler_status_result(valid))
        mutations={
            "success_only":{"success":True},
            "missing":{key:value for key,value in valid.items() if key!="run_in_progress"},
            "wrong_scheduler":{**valid,"scheduler_enabled":False},
            "wrong_circuit":{**valid,"circuit_state":"DEGRADED"},
            "running":{**valid,"run_in_progress":True},
            "extra":{**valid,"unexpected":True},
            "wrong_type":{**valid,"requests_24h":"0"},
            "failure":{**valid,"success":False},
            "contradiction":{**valid,"outcome":"SCHEDULER_READY","allowed":False},
            "error":{**valid,"last_error_class":"WORKER_CRASHED"},
        }
        for case,value in mutations.items():
            with self.subTest(case=case): self.assertIsNone(validate_scheduler_status_result(value))
        with self.assertRaises(json.JSONDecodeError): json.loads(b"not-json")

    def test_runtime_directory_trust_attack_matrix(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); root.chmod(0o700)
            generations=root/"generations"; generations.mkdir(mode=0o700)
            generation=generations/REVISION; generation.mkdir(mode=0o700)
            (generation/"python").mkdir(mode=0o755); (generation/"wheelhouse").mkdir(mode=0o700)
            self.assertTrue(launcher._runtime_directories_trusted(root,generation,REVISION,False))
            for target,mode in ((root,0o770),(generations,0o777),(generation,0o770)):
                with self.subTest(target=target,mode=oct(mode)):
                    old=stat.S_IMODE(target.stat().st_mode); target.chmod(mode)
                    self.assertFalse(launcher._runtime_directories_trusted(root,generation,REVISION,False))
                    target.chmod(old)
            self.assertFalse(launcher._runtime_directories_trusted(root,root/REVISION,REVISION,False))
            with mock.patch.object(launcher.os,"getuid",return_value=os.getuid()+1):
                self.assertFalse(launcher._runtime_directories_trusted(root,generation,REVISION,False))
            for child in (generation/"python",generation/"wheelhouse"):
                with self.subTest(symlink=child.name):
                    child.rmdir(); child.symlink_to(root,target_is_directory=True)
                    self.assertFalse(launcher._runtime_directories_trusted(root,generation,REVISION,False))
                    child.unlink(); child.mkdir(mode=0o755 if child.name=="python" else 0o700)

    def test_runtime_root_and_generation_symlinks_are_rejected(self):
        for target_name in ("runtime","generations","generation"):
            with self.subTest(target=target_name), tempfile.TemporaryDirectory() as folder:
                base=Path(folder).resolve(); real=base/"real"; real.mkdir(mode=0o700)
                runtime=base/"runtime"; runtime.mkdir(mode=0o700)
                generations=runtime/"generations"; generations.mkdir(mode=0o700)
                generation=generations/REVISION; generation.mkdir(mode=0o700)
                (generation/"python").mkdir(); (generation/"wheelhouse").mkdir(mode=0o700)
                victim={"runtime":runtime,"generations":generations,"generation":generation}[target_name]
                if target_name=="runtime":
                    shutil.rmtree(runtime); runtime.symlink_to(real,target_is_directory=True)
                    generation=runtime/"generations"/REVISION
                else:
                    shutil.rmtree(victim); victim.symlink_to(real,target_is_directory=True)
                self.assertFalse(launcher._runtime_directories_trusted(runtime,generation,REVISION,False))

    def test_os_chain_attack_matrix_uses_safe_model_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder).resolve(); approved=base/"approved"; approved.mkdir(mode=0o755)
            directory=approved/"usr/bin"; directory.mkdir(parents=True)
            final=approved/"python3.9"; final.write_bytes(b"python"); final.chmod(0o755)
            link=directory/"python3"; link.symlink_to(final)
            kwargs={"approved":approved,"ancestors":(approved,),"expected_owner":os.getuid()}
            self.assertEqual(launcher._trusted_os_chain(link,**kwargs),str(final))
            self.assertIsNone(launcher._trusted_os_chain(link,approved=approved,
                ancestors=(approved,),expected_owner=0))
            directory.chmod(0o777)
            self.assertIsNone(launcher._trusted_os_chain(link,**kwargs)); directory.chmod(0o755)
            outside=base/"outside-python"; outside.write_bytes(b"python")
            link.unlink(); link.symlink_to(outside)
            self.assertIsNone(launcher._trusted_os_chain(link,**kwargs)); outside.unlink()
            replacement=base/"replacement"; replacement.mkdir()
            alias=base/"approved-link"; alias.symlink_to(replacement,target_is_directory=True)
            self.assertIsNone(launcher._trusted_os_chain(alias/"python3",approved=alias,
                ancestors=(alias,),expected_owner=os.getuid()))

    def test_manifest_wheel_inventory_is_exact(self):
        resolved=Path("/approved/python3.9")
        value={"schema":launcher.RUNTIME_SCHEMA,"runtime_version":launcher.RUNTIME_VERSION,
            "project_revision":REVISION,"python":"python/bin/python3","python_version":"3.9.6",
            "dependency_lock":"requirements-engagement-production.txt","dependency_lock_sha256":"a"*64,
            "packages":launcher.RUNTIME_PACKAGES,"wheels":launcher.RUNTIME_WHEELS,
            "project_root":str(launcher.CODE_ROOT),"eligibility":"PREVIEW_ONLY_FEATURE_REVISION",
            "previous_generations":[],"readiness":"READY","approved_main_revision":None,
            "verified_origin_revision":None,"interpreter_realpath":str(resolved),
            "created_at":"2026-09-03T00:00:00Z"}
        self.assertTrue(launcher._manifest_contract_valid(value,resolved))
        variants=[]
        altered=dict(launcher.RUNTIME_WHEELS); altered[next(iter(altered))]="0"*64; variants.append(altered)
        extra=dict(launcher.RUNTIME_WHEELS); extra["extra-1.0.whl"]="0"*64; variants.append(extra)
        missing=dict(launcher.RUNTIME_WHEELS); missing.pop(next(iter(missing))); variants.append(missing)
        renamed=dict(launcher.RUNTIME_WHEELS); digest=renamed.pop(next(iter(renamed))); renamed["wrong.whl"]=digest; variants.append(renamed)
        wrong_version=dict(value); wrong_version["packages"]={**launcher.RUNTIME_PACKAGES,"attrs":"0"}
        for wheels in variants:
            self.assertFalse(launcher._manifest_contract_valid({**value,"wheels":wheels},resolved))
        self.assertFalse(launcher._manifest_contract_valid(wrong_version,resolved))
    def verified_wheelhouse(self):
        path=Path.home()/"Library/Application Support/flop-agent-intelligence/production-runtime/python-wheelhouse"
        if not provisioner.verify_wheelhouse(path): self.skipTest("verified private wheelhouse unavailable")
        if subprocess.run(["git","status","--porcelain"],cwd=provisioner.CODE_ROOT,
                          capture_output=True,check=True).stdout:
            self.skipTest("real-runtime integration requires committed clean feature")
        return path

    @staticmethod
    def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()

    def test_wheel_contract_is_exact_and_hash_pinned(self):
        lines=[line for line in provisioner.LOCK.read_text().splitlines()
               if line and not line.startswith("#")]
        self.assertEqual(len(lines),9)
        self.assertTrue(all("==" in line and "--hash=sha256:" in line for line in lines))
        self.assertEqual(len(provisioner.WHEELS),9)
        self.assertEqual(provisioner.WHEELS,launcher.RUNTIME_WHEELS)
        self.assertEqual(set(provisioner.PACKAGES),{"attrs","cffi","cryptography","jsonschema",
            "jsonschema-specifications","pycparser","referencing","rpds-py","typing-extensions"})

    def test_wheelhouse_rejects_missing_extra_symlink_and_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); root.chmod(0o700)
            self.assertFalse(provisioner.verify_wheelhouse(root))
            for name,digest in provisioner.WHEELS.items():
                path=root/name; path.write_bytes(b"wrong"); path.chmod(0o600)
            self.assertFalse(provisioner.verify_wheelhouse(root))
            extra=root/"extra.whl"; extra.write_bytes(b""); extra.chmod(0o600)
            self.assertFalse(provisioner.verify_wheelhouse(root))

    def test_all_runtime_origins_fail_closed_when_wrong(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); python=root/"generation/python"; source=root/"repo/src"
            python.mkdir(parents=True); source.mkdir(parents=True)
            good={"isolated":1,"no_user_site":1,"ignore_environment":1,
                "jsonschema":str(python/"site-packages/jsonschema/__init__.py"),
                "cryptography":str(python/"site-packages/cryptography/__init__.py"),
                "flop_agent":str(source/"flop_agent/engagement_history.py")}
            self.assertTrue(provisioner._valid_origins(good,python,source))
            for field in ("jsonschema","cryptography","flop_agent"):
                invalid=dict(good); invalid[field]=str(root/"untrusted"/field)
                self.assertFalse(provisioner._valid_origins(invalid,python,source),field)

    def test_runtime_manifest_revision_interpreter_and_dependency_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); generation=root/"generations"/REVISION
            python=generation/"python/bin/python3"; python.parent.mkdir(parents=True)
            root.chmod(0o700); (root/"generations").chmod(0o700); generation.chmod(0o700)
            (generation/"wheelhouse").mkdir(mode=0o700)
            python.symlink_to("/Library/Developer/CommandLineTools/usr/bin/python3")
            value={"schema":launcher.RUNTIME_SCHEMA,"runtime_version":launcher.RUNTIME_VERSION,
                "project_revision":REVISION,"python":"python/bin/python3","python_version":"3.9.6",
                "dependency_lock":"requirements-engagement-production.txt",
                "dependency_lock_sha256":hashlib.sha256((launcher.CODE_ROOT/"requirements-engagement-production.txt").read_bytes()).hexdigest(),
                "packages":launcher.RUNTIME_PACKAGES,"wheels":launcher.RUNTIME_WHEELS,
                "project_root":str(launcher.CODE_ROOT),"eligibility":provisioner.VALIDATION_ONLY,
                "previous_generations":[],"readiness":"READY","approved_main_revision":None,
                "verified_origin_revision":None,
                "interpreter_realpath":str(Path("/Library/Developer/CommandLineTools/usr/bin/python3").resolve()),
                "created_at":"2026-09-02T00:00:00Z"}
            manifest=generation/"production-runtime.json"
            manifest.write_text(json.dumps(value)); manifest.chmod(0o600)
            self.assertEqual(launcher.validate_runtime(root,"2"*40),"PRODUCTION_RUNTIME_NOT_READY")
            value["project_revision"]="2"*40; manifest.write_text(json.dumps(value)); manifest.chmod(0o600)
            self.assertEqual(launcher.validate_runtime(root,REVISION),"CODE_REVISION_MISMATCH")
            value["project_revision"]=REVISION; manifest.write_text(json.dumps(value)); manifest.chmod(0o600)
            self.assertEqual(launcher.validate_runtime(root,REVISION),"PRODUCTION_INTERPRETER_MISMATCH")
            self.assertEqual(launcher.validate_runtime(root,REVISION,require_production=True),
                             "PRODUCTION_RUNTIME_NOT_READY")
            with mock.patch.object(launcher.sys,"executable",str(python)), \
                 mock.patch("importlib.metadata.version",side_effect=lambda name: {
                     "jsonschema":"4.25.1","cryptography":"0"}[name]):
                self.assertEqual(launcher.validate_runtime(root,REVISION),
                                 "PRODUCTION_DEPENDENCY_MISSING")

    def test_prelog_is_private_bounded_and_allowlisted(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); (root/"runtime/engagement").mkdir(parents=True)
            launcher.append_prelog(root,"RUNTIME","PRODUCTION_RUNTIME_NOT_READY",REVISION)
            path=root/"runtime/engagement/launcher-logs/launcher-preflight.jsonl"
            value=json.loads(path.read_text())
            self.assertEqual(set(value),launcher.PRELOG_KEYS)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
            self.assertNotIn("stderr",value); self.assertNotIn("environment",value)

    def test_prelog_rollover_remains_bounded_private_and_secret_free(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); (root/"runtime/engagement").mkdir(parents=True)
            with mock.patch.object(launcher,"MAX_LOG_BYTES",512):
                for _ in range(30):
                    launcher.append_prelog(root,"RUNTIME","PRODUCTION_RUNTIME_NOT_READY",REVISION)
            path=root/"runtime/engagement/launcher-logs/launcher-preflight.jsonl"
            self.assertLessEqual(path.stat().st_size,512)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
            self.assertNotIn("secret",path.read_text().lower())

    def test_provisioner_has_no_network_activation_or_collection_surface(self):
        source=Path(provisioner.__file__).read_text()
        for forbidden in ("urllib","requests.","curl","launchctl","bootstrap","kickstart",
                          "run-once","--confirm","scheduler_enabled"):
            self.assertNotIn(forbidden,source)

    def test_actual_private_runtime_status_is_isolated_and_preserves_data(self):
        wheelhouse=self.verified_wheelhouse()
        revision=subprocess.run(["git","rev-parse","HEAD"],cwd=provisioner.CODE_ROOT,
            capture_output=True,check=True,text=True).stdout.strip()
        production=Path.home()/"Library/Application Support/flop-agent-intelligence/production-runtime/runtime/engagement"
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); root.chmod(0o700)
            engagement=root/"runtime/engagement"; engagement.mkdir(parents=True,mode=0o700)
            tracked=[]
            for name in ("scheduler-state.json","scheduler-state.lock","history.jsonl","history.jsonl.lock"):
                shutil.copyfile(production/name,engagement/name); (engagement/name).chmod(0o600); tracked.append(engagement/name)
            generations=root/"generations"; generations.mkdir(mode=0o700)
            old=generations/"old-reviewed-generation"; old.mkdir(mode=0o700)
            before={path.name:self.digest(path) for path in tracked}
            result=provisioner.provision(root,wheelhouse,revision,
                mode=self.nonproduction_mode())
            self.assertTrue(result["success"],result)
            self.assertEqual(result["eligibility"],self.nonproduction_eligibility())
            generation=Path(result["generation"]); manifest=json.loads((generation/"production-runtime.json").read_text())
            self.assertIn("old-reviewed-generation",manifest["previous_generations"])
            hostile=root/"hostile"; hostile.mkdir(); (hostile/"jsonschema.py").write_text("raise AssertionError\n")
            entry=("import runpy,sys;"+f"sys.path.insert(0,{str(provisioner.CODE_ROOT/'src')!r});"
                +f"sys.argv[0]={str(provisioner.CODE_ROOT/'scripts/engagement_scheduler.py')!r};"
                +f"runpy.run_path({str(provisioner.CODE_ROOT/'scripts/engagement_scheduler.py')!r},run_name='__main__')")
            command=[result["python"],"-I","-c",entry,"status","--root",str(root)]
            completed=subprocess.run(command,cwd=hostile,env={**os.environ,"PYTHONPATH":str(hostile),
                "PYTHONUSERBASE":str(hostile)},capture_output=True,check=True,text=True)
            status=json.loads(completed.stdout)
            self.assertTrue(status["success"]); self.assertIn(status["outcome"],{"SCHEDULER_READY","SCHEDULER_NOT_BEFORE"})
            self.assertEqual(before,{path.name:self.digest(path) for path in tracked})

    def test_failed_generation_never_switches_or_touches_scheduler_data(self):
        wheelhouse=self.verified_wheelhouse()
        revision=subprocess.run(["git","rev-parse","HEAD"],cwd=provisioner.CODE_ROOT,
            capture_output=True,check=True,text=True).stdout.strip()
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); root.chmod(0o700)
            engagement=root/"runtime/engagement"; engagement.mkdir(parents=True,mode=0o700)
            state=engagement/"scheduler-state.json"; state.write_bytes(b"authoritative"); state.chmod(0o600)
            generations=root/"generations"; generations.mkdir(mode=0o700)
            old=generations/"old"; old.mkdir(mode=0o700)
            real_run=subprocess.run
            def fail_venv(command,*args,**kwargs):
                if len(command)>=4 and command[1:3]==["-m","venv"]:
                    return subprocess.CompletedProcess(command,1,b"",b"")
                return real_run(command,*args,**kwargs)
            with mock.patch.object(provisioner.subprocess,"run",side_effect=fail_venv):
                result=provisioner.provision(root,wheelhouse,revision,
                    mode=self.nonproduction_mode())
            self.assertEqual(result["outcome"],"RUNTIME_REPROVISION_FAILED")
            self.assertEqual(state.read_bytes(),b"authoritative"); self.assertTrue(old.exists())
            self.assertFalse((root/"generations"/revision).exists())

    def test_status_failure_prevents_generation_publication(self):
        wheelhouse=self.verified_wheelhouse()
        revision=subprocess.run(["git","rev-parse","HEAD"],cwd=provisioner.CODE_ROOT,
            capture_output=True,check=True,text=True).stdout.strip()
        production=Path.home()/"Library/Application Support/flop-agent-intelligence/production-runtime/runtime/engagement"
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); root.chmod(0o700)
            target=root/"runtime/engagement"; target.mkdir(parents=True,mode=0o700)
            for name in provisioner.STATE_FILES:
                shutil.copyfile(production/name,target/name); (target/name).chmod(0o600)
            real_run=subprocess.run
            def fail_status(command,*args,**kwargs):
                if len(command)>4 and command[-3]=="status":
                    return subprocess.CompletedProcess(command,0,b'{"success":true}',b'')
                return real_run(command,*args,**kwargs)
            with mock.patch.object(provisioner.subprocess,"run",side_effect=fail_status):
                result=provisioner.provision(root,wheelhouse,revision,
                    mode=self.nonproduction_mode())
            self.assertEqual(result["outcome"],"RUNTIME_REPROVISION_FAILED")
            self.assertFalse((root/"generations"/revision).exists())

    def test_publication_lock_contention_is_bounded_and_same_sha_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as folder:
            generations=Path(folder).resolve(); generations.chmod(0o700)
            with provisioner._publication_lock(generations):
                with self.assertRaises(TimeoutError):
                    with provisioner._publication_lock(generations,timeout=.01): pass
            generation=generations/REVISION; generation.mkdir(mode=0o700)
            marker=generation/"evidence"; marker.write_text("immutable")
            for case,payload in (("valid",'{"readiness":"READY"}'),("invalid","not-json")):
                with self.subTest(case=case), tempfile.TemporaryDirectory() as runtime_folder:
                    root=Path(runtime_folder).resolve(); root.chmod(0o700)
                    (root/"generations").mkdir(mode=0o700)
                    existing=root/"generations"/REVISION; existing.mkdir(mode=0o700)
                    proof=existing/"production-runtime.json"; proof.write_text(payload)
                    before=proof.read_bytes()
                    with mock.patch.object(provisioner,"repository_eligibility",return_value=provisioner.PREVIEW_ONLY), \
                         mock.patch.object(provisioner,"verify_wheelhouse",return_value=True):
                        result=provisioner.provision(root,Path("/not-read"),REVISION)
                    self.assertEqual(result["outcome"],"PRODUCTION_RUNTIME_ALREADY_EXISTS")
                    self.assertEqual(proof.read_bytes(),before)

    def test_validation_only_pre_push_is_distinct_from_production_eligibility(self):
        old="2"*40
        def git_result(command):
            if command[:2]==["rev-parse","HEAD"]: return subprocess.CompletedProcess(command,0,(REVISION+"\n").encode(),b"")
            if command[:2]==["diff-index","--quiet"]: return subprocess.CompletedProcess(command,0,b"",b"")
            if command[:2]==["ls-files","--others"]: return subprocess.CompletedProcess(command,0,b"",b"")
            if command[:2]==["symbolic-ref","--short"]: return subprocess.CompletedProcess(command,0,b"main\n",b"")
            if command[:2]==["rev-parse","refs/remotes/origin/main"]: return subprocess.CompletedProcess(command,0,(old+"\n").encode(),b"")
            raise AssertionError(command)
        with mock.patch.object(provisioner,"_git",side_effect=git_result):
            self.assertEqual(provisioner.repository_eligibility(REVISION,
                mode=provisioner.ProvisionMode.VALIDATION_ONLY),provisioner.VALIDATION_ONLY)
            self.assertEqual(provisioner.repository_eligibility(REVISION,REVISION,REVISION),
                             "PRODUCTION_INELIGIBLE_REVISION")
        def pushed(command):
            result=git_result(command)
            if command[:2]==["rev-parse","refs/remotes/origin/main"]:
                return subprocess.CompletedProcess(command,0,(REVISION+"\n").encode(),b"")
            return result
        with mock.patch.object(provisioner,"_git",side_effect=pushed):
            self.assertEqual(provisioner.repository_eligibility(REVISION,REVISION,REVISION),
                             provisioner.PRODUCTION_ELIGIBLE)

    def test_validation_only_is_main_typed_and_disposable_only(self):
        clean=lambda stdout=b"": subprocess.CompletedProcess([],0,stdout,b"")
        feature=[clean((REVISION+"\n").encode()),clean(),clean(),clean(b"codex/feature\n")]
        with mock.patch.object(provisioner,"_git",side_effect=feature):
            self.assertEqual(provisioner.repository_eligibility(REVISION,
                mode=provisioner.ProvisionMode.VALIDATION_ONLY),"PRODUCTION_INELIGIBLE_REVISION")
        self.assertEqual(provisioner.repository_eligibility(REVISION,mode="VALIDATION_ONLY"),
                         "PRODUCTION_INELIGIBLE_REVISION")
        trusted=runtime_contract.trusted_production_runtime_root(); self.assertIsNotNone(trusted)
        with mock.patch.object(provisioner,"repository_eligibility",return_value=provisioner.VALIDATION_ONLY):
            result=provisioner.provision(trusted,trusted/"python-wheelhouse",REVISION,
                mode=provisioner.ProvisionMode.VALIDATION_ONLY)
            self.assertEqual(result["outcome"],"VALIDATION_ROOT_UNSAFE")
            result=provisioner.provision(trusted,trusted/"python-wheelhouse",REVISION,
                production=True,mode=provisioner.ProvisionMode.VALIDATION_ONLY)
            self.assertEqual(result["outcome"],"VALIDATION_ROOT_UNSAFE")

    def test_validation_only_repository_checks_remain_fail_closed(self):
        def eligibility(*,head=REVISION,dirty=False,untracked=b"",branch=b"main\n"):
            def run(command):
                if command[:2]==["rev-parse","HEAD"]:
                    return subprocess.CompletedProcess(command,0,(head+"\n").encode(),b"")
                if command[:2]==["diff-index","--quiet"]:
                    return subprocess.CompletedProcess(command,1 if dirty else 0,b"",b"")
                if command[:2]==["ls-files","--others"]:
                    return subprocess.CompletedProcess(command,0,untracked,b"")
                if command[:2]==["symbolic-ref","--short"]:
                    return subprocess.CompletedProcess(command,0,branch,b"")
                raise AssertionError(command)
            with mock.patch.object(provisioner,"_git",side_effect=run):
                return provisioner.repository_eligibility(REVISION,
                    mode=provisioner.ProvisionMode.VALIDATION_ONLY)
        for case,kwargs in (("head",{"head":"2"*40}),("tracked",{"dirty":True}),
                ("untracked",{"untracked":b"scripts/shadow.py\n"}),
                ("branch",{"branch":b"codex/feature\n"})):
            with self.subTest(case=case):
                self.assertEqual(eligibility(**kwargs),"PRODUCTION_INELIGIBLE_REVISION")

    def test_validation_only_requires_account_and_production_root_trust(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); root.chmod(0o700)
            with mock.patch.object(provisioner,"repository_eligibility",
                    return_value=provisioner.VALIDATION_ONLY), \
                 mock.patch.object(provisioner,"resolve_account_home",return_value=None):
                result=provisioner.provision(root,root/"wheels",REVISION,
                    mode=provisioner.ProvisionMode.VALIDATION_ONLY)
                self.assertEqual(result["outcome"],"PRODUCTION_ACCOUNT_HOME_INVALID")
            with mock.patch.object(provisioner,"repository_eligibility",
                    return_value=provisioner.VALIDATION_ONLY), \
                 mock.patch.object(provisioner,"trusted_production_runtime_root",return_value=None):
                result=provisioner.provision(root,root/"wheels",REVISION,
                    mode=provisioner.ProvisionMode.VALIDATION_ONLY)
                self.assertEqual(result["outcome"],"PRODUCTION_RUNTIME_ROOT_INVALID")

    def test_user_controlled_interpreter_chain_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); target=root/"python3.9"; target.write_bytes(b"python")
            link=root/"python3"; link.symlink_to(target)
            self.assertIsNone(provisioner._trusted_chain(link,root))

    def test_concurrent_same_sha_publication_has_exactly_one_winner(self):
        with tempfile.TemporaryDirectory() as folder:
            generations=Path(folder).resolve(); generations.chmod(0o700)
            candidates=[]
            for index in range(2):
                candidate=generations/f"candidate-{index}"; candidate.mkdir(mode=0o700)
                (candidate/"identity").write_text(str(index)); candidates.append(candidate)
            final=generations/REVISION; barrier=threading.Barrier(2); results=[]
            def publish(candidate):
                barrier.wait(); results.append(provisioner._publish_generation(candidate,final,generations))
            threads=[threading.Thread(target=publish,args=(candidate,)) for candidate in candidates]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            self.assertEqual(sorted(results),[False,True])
            winner=(final/"identity").read_text(); self.assertIn(winner,{"0","1"})
            self.assertEqual(sum(candidate.exists() for candidate in candidates),1)

    def test_dedicated_validator_missing_prerequisites_is_failure_not_skip(self):
        root=runtime_contract.trusted_production_runtime_root()
        self.assertIsNotNone(root)
        result=runtime_validator.validate(root,root/"missing-wheelhouse",REVISION)
        self.assertEqual((result["success"],result["outcome"]),
                         (False,"TEST_ENVIRONMENT_MISSING"))

    def test_dedicated_validator_account_and_root_fail_closed(self):
        root=runtime_contract.trusted_production_runtime_root(); self.assertIsNotNone(root)
        wheelhouse=root/"python-wheelhouse"
        with mock.patch.object(runtime_validator,"resolve_account_home",return_value=None):
            self.assertEqual(runtime_validator.validate(root,wheelhouse,REVISION)["outcome"],
                             "PRODUCTION_ACCOUNT_HOME_INVALID")
        with mock.patch.object(runtime_validator,"resolve_account_home",side_effect=OSError):
            self.assertEqual(runtime_validator.validate(root,wheelhouse,REVISION)["outcome"],
                             "PRODUCTION_ACCOUNT_HOME_INVALID")
        with mock.patch.object(runtime_validator,"trusted_production_runtime_root",return_value=None):
            self.assertEqual(runtime_validator.validate(root,wheelhouse,REVISION)["outcome"],
                             "PRODUCTION_RUNTIME_ROOT_INVALID")
        with mock.patch.object(runtime_validator,"trusted_production_runtime_root",
                               side_effect=AssertionError):
            self.assertEqual(runtime_validator.validate(root,wheelhouse,REVISION)["outcome"],
                             "PRODUCTION_RUNTIME_ROOT_INVALID")
        with tempfile.TemporaryDirectory() as folder:
            alternate=Path(folder).resolve()
            with mock.patch.object(runtime_validator,"trusted_production_runtime_root",return_value=root):
                self.assertEqual(runtime_validator.validate(alternate,wheelhouse,REVISION)["outcome"],
                                 "PRODUCTION_RUNTIME_ROOT_INVALID")


if __name__=="__main__": unittest.main()
