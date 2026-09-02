import hashlib, json, os, shutil, stat, subprocess, tempfile, unittest
from pathlib import Path
from unittest import mock

from scripts import engagement_scheduler_launcher as launcher
from scripts import provision_engagement_runtime as provisioner

REVISION="1"*40


class EngagementProductionRuntimeTests(unittest.TestCase):
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

    def test_runtime_manifest_revision_interpreter_and_dependency_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); generation=root/"generations"/REVISION
            python=generation/"python/bin/python3"; python.parent.mkdir(parents=True)
            python.symlink_to("/Library/Developer/CommandLineTools/usr/bin/python3")
            value={"schema":launcher.RUNTIME_SCHEMA,"runtime_version":launcher.RUNTIME_VERSION,
                "project_revision":REVISION,"python":"python/bin/python3","python_version":"3.9.6",
                "dependency_lock":"requirements-engagement-production.txt",
                "dependency_lock_sha256":hashlib.sha256((launcher.CODE_ROOT/"requirements-engagement-production.txt").read_bytes()).hexdigest(),
                "packages":launcher.RUNTIME_PACKAGES,"wheels":{},
                "project_root":str(launcher.CODE_ROOT),"eligibility":"PREVIEW_ONLY_FEATURE_REVISION",
                "previous_generations":[],
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
            result=provisioner.provision(root,wheelhouse,revision)
            self.assertTrue(result["success"],result); self.assertEqual(result["eligibility"],provisioner.PREVIEW_ONLY)
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
                result=provisioner.provision(root,wheelhouse,revision)
            self.assertEqual(result["outcome"],"RUNTIME_REPROVISION_FAILED")
            self.assertEqual(state.read_bytes(),b"authoritative"); self.assertTrue(old.exists())
            self.assertFalse((root/"generations"/revision).exists())


if __name__=="__main__": unittest.main()
