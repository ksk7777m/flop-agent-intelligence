import hashlib, json, os, shutil, stat, subprocess, tempfile, unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts import engagement_runtime_contract as runtime_contract
from scripts import provision_engagement_runtime as provisioner


ROOT = Path(__file__).resolve().parents[1]
STATE_FILES = ("scheduler-state.json", "scheduler-state.lock", "history.jsonl", "history.jsonl.lock")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class EngagementProductionImportBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="flop-import-behavior-")
        cls.base = Path(cls.temporary.name).resolve(); cls.base.chmod(0o700)
        cls.repo = cls.base / "repo"
        subprocess.run(["git", "clone", "-q", "--no-hardlinks", str(ROOT), str(cls.repo)],
                       check=True, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        initial_revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=cls.repo,
            check=True, capture_output=True, text=True).stdout.strip()
        subprocess.run(["git", "checkout", "-q", "-B", "main", initial_revision], cwd=cls.repo,
                       check=True, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        production_files = ("scripts/engagement_runtime_contract.py",
            "scripts/engagement_scheduler.py", "scripts/engagement_scheduler_launcher.py")
        for name in production_files:
            shutil.copy2(ROOT / name, cls.repo / name)
        changed = subprocess.run(["git", "status", "--porcelain", "--", *production_files],
            cwd=cls.repo, check=True, capture_output=True, text=True).stdout
        if changed:
            subprocess.run(["git", "add", "--", *production_files], cwd=cls.repo, check=True)
            subprocess.run(["git", "-c", "user.name=Test", "-c",
                "user.email=test@example.invalid", "commit", "-qm", "temporary reviewed fix"],
                cwd=cls.repo, check=True)
        cls.revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=cls.repo,
            check=True, capture_output=True, text=True).stdout.strip()
        subprocess.run(["git", "update-ref", "refs/remotes/origin/main", cls.revision],
                       cwd=cls.repo, check=True, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        self_status = subprocess.run(["git", "status", "--porcelain"], cwd=cls.repo,
                                     check=True, capture_output=True)
        if self_status.stdout: raise AssertionError("isolated repository is not clean")

        real_root = runtime_contract.trusted_production_runtime_root()
        if real_root is None: raise AssertionError("trusted production root unavailable")
        cls.real_root = real_root
        cls.state_snapshot = {name: (real_root / "runtime/engagement" / name).read_bytes()
                              for name in STATE_FILES}
        cls.real_hashes = {name: digest(real_root / "runtime/engagement" / name)
                           for name in STATE_FILES}
        cls.failed_manifest = real_root / "generations/ad1cf60d611a6514f8c2855d3b2f40a9c88c9a36/production-runtime.json"
        cls.failed_hash = digest(cls.failed_manifest)
        cls.wheelhouse = real_root / "python-wheelhouse"
        if not provisioner.verify_wheelhouse(cls.wheelhouse):
            raise AssertionError("verified offline wheelhouse unavailable")

        cls.runtime = cls.base / "trusted-runtime"; cls.runtime.mkdir(mode=0o700)
        engagement = cls.runtime / "runtime/engagement"
        engagement.mkdir(parents=True, mode=0o700)
        for name in STATE_FILES:
            shutil.copyfile(real_root / "runtime/engagement" / name, engagement / name)
            (engagement / name).chmod(0o600)
        program = (
            "import json,sys;"
            f"sys.path.insert(0,{str(cls.repo / 'scripts')!r});"
            "import provision_engagement_runtime as p;"
            f"r=p.provision(__import__('pathlib').Path({str(cls.runtime)!r}),"
            f"__import__('pathlib').Path({str(cls.wheelhouse)!r}),{cls.revision!r},"
            f"approved_main_revision={cls.revision!r},verified_origin_revision={cls.revision!r});"
            "print(json.dumps(r,sort_keys=True))"
        )
        completed = subprocess.run(["/usr/bin/python3", "-I", "-c", program], cwd=cls.repo,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"},
            check=True, capture_output=True, text=True)
        cls.provision_result = json.loads(completed.stdout)
        if (not cls.provision_result.get("success")
                or cls.provision_result.get("eligibility") != "PRODUCTION_ELIGIBLE"):
            raise AssertionError(cls.provision_result)
        cls.generation = Path(cls.provision_result["generation"])
        cls.interpreter = Path(cls.provision_result["python"])

    def setUp(self):
        engagement = self.runtime / "runtime/engagement"
        for name, data in self.state_snapshot.items():
            path = engagement / name; path.write_bytes(data); path.chmod(0o600)

    @classmethod
    def tearDownClass(cls):
        try:
            current = {name: digest(cls.real_root / "runtime/engagement" / name)
                       for name in STATE_FILES}
            if current != cls.real_hashes: raise AssertionError("real production state changed")
            if digest(cls.failed_manifest) != cls.failed_hash:
                raise AssertionError("failed generation changed")
        finally:
            cls.temporary.cleanup()

    def run_private(self, program: str, *, cwd: Path, hostile: bool = False):
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"}
        if hostile:
            env.update({"HOME": str(self.base / "hostile-home"), "USER": "attacker",
                "LOGNAME": "attacker", "PWD": str(self.base / "hostile"),
                "PYTHONPATH": str(self.base / "hostile"),
                "PYTHONUSERBASE": str(self.base / "hostile")})
        return subprocess.run([str(self.interpreter), "-I", "-c", program], cwd=cwd,
                              env=env, check=True, capture_output=True, text=True)

    def validator_program(self) -> str:
        return (
            "import json,site,sys;"
            f"sys.path.insert(0,{str(self.repo / 'scripts')!r});"
            "import engagement_scheduler_launcher as l;"
            f"l.production_runtime_root=lambda:__import__('pathlib').Path({str(self.runtime)!r});"
            f"error=l.validate_runtime(__import__('pathlib').Path({str(self.runtime)!r}),"
            f"{self.revision!r},require_production=True);"
            "import cryptography,jsonschema,flop_agent;"
            "print(json.dumps({'error':error,'isolated':sys.flags.isolated,"
            "'user_site':site.ENABLE_USER_SITE,'flop_agent':flop_agent.__file__,"
            "'jsonschema':jsonschema.__file__,'cryptography':cryptography.__file__},sort_keys=True))"
        )

    def test_actual_renderer_production_readiness_and_origins(self):
        old = ("import sys;"
            f"sys.path.insert(0,{str(self.repo / 'scripts')!r});"
            "import engagement_scheduler_launcher;import flop_agent")
        failed = subprocess.run([str(self.interpreter), "-I", "-c", old], cwd=Path("/"),
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True, text=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("ModuleNotFoundError", failed.stderr)
        program = (
            "import json,subprocess,sys;"
            f"sys.path.insert(0,{str(self.repo / 'scripts')!r});"
            "import render_engagement_launchagent as r;real=subprocess.run;"
            f"root={str(self.runtime)!r}\n"
            "def patched(command,*args,**kwargs):\n"
            " command=list(command)\n"
            " if len(command)>3 and command[1:3]==['-I','-c'] and 'l.validate_runtime' in command[3]:\n"
            "  command[3]=command[3].replace('import engagement_scheduler_launcher as l;',"
            "'import engagement_scheduler_launcher as l;l.production_runtime_root=lambda:__import__(\\'pathlib\\').Path('+repr(root)+');')\n"
            " return real(command,*args,**kwargs)\n"
            "r.subprocess.run=patched\n"
            f"print(json.dumps({{'ready':r._runtime_ready(__import__('pathlib').Path(root),{self.revision!r},r.CODE_ROOT,True)}}))"
        )
        rendered = json.loads(self.run_private(program, cwd=Path("/"), hostile=True).stdout)
        self.assertTrue(rendered["ready"])
        origins = json.loads(self.run_private(self.validator_program(), cwd=Path("/"), hostile=True).stdout)
        self.assertIsNone(origins["error"])
        self.assertEqual((origins["isolated"], origins["user_site"]), (1, False))
        self.assertTrue(Path(origins["flop_agent"]).resolve().is_relative_to(self.repo / "src"))
        for name in ("jsonschema", "cryptography"):
            self.assertTrue(Path(origins[name]).resolve().is_relative_to(self.generation / "python"))

    def test_actual_launcher_status_is_cwd_and_environment_independent(self):
        engagement = self.runtime / "runtime/engagement"
        state_path = engagement / "scheduler-state.json"
        state = json.loads(state_path.read_text())
        state["not_before_at"] = (datetime.now(timezone.utc) + timedelta(hours=1)).replace(
            microsecond=0).isoformat().replace("+00:00", "Z")
        state_path.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n")
        state_path.chmod(0o600)
        before = {name: digest(engagement / name) for name in STATE_FILES}
        program = (
            "import json,sys;"
            f"sys.path.insert(0,{str(self.repo / 'scripts')!r});"
            "import engagement_scheduler_launcher as l;"
            f"root=__import__('pathlib').Path({str(self.runtime)!r});"
            "l.production_runtime_root=lambda:root;"
            f"result=l.launch(root,{self.revision!r});"
            "print(json.dumps(result,sort_keys=True))"
        )
        neutral = self.base / "neutral"; neutral.mkdir(mode=0o700)
        hostile = self.base / "hostile"; hostile.mkdir(mode=0o700, exist_ok=True)
        for cwd in (Path("/"), Path.home(), neutral):
            value = json.loads(self.run_private(program, cwd=cwd, hostile=True).stdout)
            self.assertEqual(value["scheduler_outcome"], "SCHEDULER_NOT_BEFORE", value)
            self.assertEqual(value["collector_invocations"], 0)
        self.assertEqual(before, {name: digest(engagement / name) for name in STATE_FILES})

    def test_actual_launcher_run_once_reaches_only_mocked_collector_boundary(self):
        engagement = self.runtime / "runtime/engagement"
        # This cloned-state test must not inherit whether the real production
        # scheduler happens to be inside its one-hour natural-run interval.
        state_path = engagement / "scheduler-state.json"
        state = json.loads(state_path.read_text())
        due = (datetime.now(timezone.utc) - timedelta(hours=2)).replace(microsecond=0)
        due_stamp = due.isoformat().replace("+00:00", "Z")
        state.update(last_attempt_at=due_stamp, last_success_at=due_stamp,
                     attempts_24h=[due_stamp], not_before_at=due_stamp)
        state_path.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n")
        state_path.chmod(0o600)
        history_before = digest(engagement / "history.jsonl")
        failure = {"success": False, "commit_state": "PRE_COMMIT", "durability_warning": None,
            "preview_state": "NOT_ATTEMPTED", "preview_warning": None,
            "cleanup_state": "COMPLETED", "cleanup_error": None,
            "deadline_cleanup_overrun": False, "error_class": "VALIDATION_FAILED",
            "network_diagnostics": None, "collector_version": "0.1.0", "git_revision": None}
        prefix = ("import subprocess as _sp;_real_collector_run=_sp.run;"
            f"_collector_payload={json.dumps(failure, separators=(',', ':')).encode()!r};"
            "_sp.run=lambda command,*args,**kwargs:_sp.CompletedProcess(command,1,_collector_payload,b'') "
            "if isinstance(command,list) and len(command)>3 and 'collect_engagement.py' in command[3] "
            "else _real_collector_run(command,*args,**kwargs);")
        program = (
            "import json,subprocess,sys;"
            f"sys.path.insert(0,{str(self.repo / 'scripts')!r});"
            "import engagement_scheduler_launcher as l;"
            f"root=__import__('pathlib').Path({str(self.runtime)!r});"
            "l.production_runtime_root=lambda:root;real=subprocess.run;seen=[]\n"
            "def runner(command,cwd,timeout):\n"
            " command=list(command)\n"
            " if 'run-once' in command:\n"
            "  seen.append('run-once')\n"
            f"  command[3]={prefix!r}+command[3]\n"
            " return real(command,cwd=cwd,env=l.SAFE_ENV,capture_output=True,check=False,timeout=timeout)\n"
            f"result=l.launch(root,{self.revision!r},runner=runner);"
            "print(json.dumps({'result':result,'seen':seen},sort_keys=True))"
        )
        value = json.loads(self.run_private(program, cwd=self.base, hostile=True).stdout)
        self.assertEqual(value["seen"], ["run-once"])
        self.assertEqual(value["result"]["scheduler_outcome"], "SCHEDULER_COLLECTION_FAILED")
        self.assertEqual(value["result"]["collector_invocations"], 1)
        self.assertEqual(digest(engagement / "history.jsonl"), history_before)

    def test_fork_worker_and_pre_post_publication_imports_are_equivalent(self):
        staged = self.base / "staged-generation"
        shutil.copytree(self.generation, staged, symlinks=True)
        staged.chmod(0o700)
        probe = (
            "import json,multiprocessing,site,sys;"
            f"sys.path.insert(0,{str(self.repo / 'scripts')!r});"
            "from pathlib import Path;"
            "from engagement_runtime_contract import install_trusted_project_import_path as install;"
            f"source=install(Path({str(self.repo)!r}));"
            "import cryptography,jsonschema,flop_agent,collect_engagement as collector\n"
            "try:\n"
            " collector.fetch(opener=lambda *args,**kwargs:(_ for _ in ()).throw(OSError('mocked boundary')))\n"
            "except collector.CollectionError as error:\n"
            " boundary=error.code\n"
            "parent,child=multiprocessing.get_context('fork').Pipe(False)\n"
            "def worker(connection):\n"
            " import flop_agent as f\n"
            " connection.send((sys.path[0],f.__file__,sys.executable))\n"
            " connection.close()\n"
            "process=multiprocessing.get_context('fork').Process(target=worker,args=(child,));process.start();"
            "inherited=parent.recv();process.join();"
            "print(json.dumps({'isolated':sys.flags.isolated,'user_site':site.ENABLE_USER_SITE,"
            "'source':str(source),'flop_agent':flop_agent.__file__,'jsonschema':jsonschema.__file__,"
            "'cryptography':cryptography.__file__,'inherited':inherited,'exitcode':process.exitcode,"
            "'boundary':boundary},sort_keys=True))"
        )
        values=[]
        for interpreter in (staged / "python/bin/python3", self.interpreter):
            completed=subprocess.run([str(interpreter), "-I", "-c", probe], cwd=self.base,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1",
                     "PYTHONPATH": str(self.base / "hostile")},
                check=True, capture_output=True, text=True)
            values.append(json.loads(completed.stdout))
        self.assertEqual((staged / "production-runtime.json").read_bytes(),
                         (self.generation / "production-runtime.json").read_bytes())
        for value, generation in zip(values, (staged, self.generation)):
            self.assertEqual((value["isolated"], value["user_site"], value["exitcode"]), (1, False, 0))
            self.assertEqual(value["boundary"], "HTTP_OPEN_FAILED")
            self.assertEqual(Path(value["source"]), self.repo / "src")
            self.assertTrue(Path(value["flop_agent"]).resolve().is_relative_to(self.repo / "src"))
            self.assertTrue(Path(value["jsonschema"]).resolve().is_relative_to(generation / "python"))
            self.assertTrue(Path(value["cryptography"]).resolve().is_relative_to(generation / "python"))
            self.assertEqual(Path(value["inherited"][0]), self.repo / "src")
            self.assertEqual(Path(value["inherited"][1]).resolve(), Path(value["flop_agent"]).resolve())
        self.assertEqual(Path(values[0]["flop_agent"]).resolve(), Path(values[1]["flop_agent"]).resolve())
        self.assertEqual(values[0]["isolated"], values[1]["isolated"])

    def test_root_location_patch_is_subprocess_scoped(self):
        self.assertEqual(runtime_contract.trusted_production_runtime_root(), self.real_root)
        self.assertNotEqual(self.real_root, self.runtime)


if __name__ == "__main__": unittest.main()
