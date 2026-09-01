import json, os, plistlib, shutil, subprocess, tempfile, unittest
from pathlib import Path
from unittest import mock

from scripts import engagement_scheduler_launcher as launcher

REVISION="25f8a734211137171d12b8b8994b959d6b04da85"


def completed(value=b"",returncode=0,stderr=b""):
    return subprocess.CompletedProcess([],returncode,value,stderr)


class FakeRunner:
    def __init__(self,revision=REVISION,dirty=False,status=None,run=None):
        self.revision=revision; self.dirty=dirty; self.calls=[]
        self.status=status or {"success":True,"outcome":"SCHEDULER_DISABLED",
            "scheduler_enabled":False,"circuit_state":"READY_DISABLED","requests_24h":0}
        self.run=run or {"success":False,"outcome":"SCHEDULER_DISABLED",
            "collector_invocations":0,"circuit_state":"READY_DISABLED"}
    def __call__(self,command,cwd,timeout):
        self.calls.append(command)
        if command[1:3]==["rev-parse","HEAD"]: return completed((self.revision+"\n").encode())
        if command[1:3]==["diff-index","--quiet"]: return completed(returncode=1 if self.dirty else 0)
        if command[1:3]==["ls-files","--others"]: return completed()
        if "status" in command: return completed(json.dumps(self.status).encode())
        if "run-once" in command:
            return completed(json.dumps(self.run).encode(),returncode=0 if self.run.get("success") else 1)
        raise AssertionError(command)


class EngagementLauncherTests(unittest.TestCase):
    def runtime(self,root):
        path=root/"runtime/engagement"; path.mkdir(parents=True); return path

    def test_disabled_launcher_is_bounded_offline_and_invokes_scheduler_once(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); self.runtime(root); runner=FakeRunner()
            with mock.patch("scripts.engagement_scheduler_launcher.subprocess.run",side_effect=AssertionError):
                result=launcher.launch(root,REVISION,runner=runner)
            self.assertEqual(result,{"success":True,"outcome":"OK_DISABLED",
                "scheduler_invoked":True,"scheduler_outcome":"SCHEDULER_DISABLED",
                "collector_invocations":0,"network_requests":0,"circuit_state":"READY_DISABLED",
                "log_persisted":True,"log_error_class":None})
            self.assertEqual(sum("run-once" in call for call in runner.calls),1)
            records=(root/"runtime/engagement/launcher-logs/launcher.jsonl").read_text().splitlines()
            self.assertEqual([json.loads(item)["outcome"] for item in records],
                             ["PREFLIGHT_READY","OK_DISABLED"])

    def test_revision_mismatch_and_dirty_tree_fail_before_scheduler(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); self.runtime(root); wrong=FakeRunner(revision="0"*40)
            self.assertEqual(launcher.launch(root,REVISION,runner=wrong)["outcome"],
                             "CODE_REVISION_MISMATCH")
            self.assertFalse(any("status" in call or "run-once" in call for call in wrong.calls))
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); self.runtime(root); dirty=FakeRunner(dirty=True)
            self.assertEqual(launcher.launch(root,REVISION,runner=dirty)["outcome"],"CODE_TREE_DIRTY")
            self.assertFalse(any("status" in call or "run-once" in call for call in dirty.calls))

    def test_ignored_runtime_does_not_enter_tracked_tree_check(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); directory=self.runtime(root)
            for name in ("scheduler-state.json","scheduler-state.lock","history.jsonl","ignored.log"):
                (directory/name).touch()
            runner=FakeRunner(); result=launcher.launch(root,REVISION,runner=runner)
            self.assertEqual(result["outcome"],"OK_DISABLED")
            check=next(call for call in runner.calls if "diff-index" in call)
            self.assertEqual(check,["/usr/bin/git","diff-index","--quiet","HEAD","--"])

    def test_missing_state_and_unsafe_code_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); self.runtime(root)
            missing=FakeRunner(status={"success":False,"outcome":"SCHEDULER_STATE_MISSING"})
            self.assertEqual(launcher.launch(root,REVISION,runner=missing)["outcome"],"STATE_MISSING")
            self.assertFalse(any("run-once" in call for call in missing.calls))
            bad=Path(folder)/"code"; bad.mkdir()
            runner=FakeRunner()
            self.assertEqual(launcher.launch(root,REVISION,runner=runner,code_root=bad)["outcome"],
                             "CODE_PATH_UNSAFE")
            self.assertEqual(runner.calls,[])

    def test_log_rotation_is_bounded_private_and_content_is_allowlisted(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); self.runtime(root)
            with mock.patch.object(launcher,"MAX_LOG_BYTES",256):
                for index in range(30):
                    launcher.append_log(root,{"timestamp":"2026-09-01T00:00:00Z",
                        "outcome":"OK_DISABLED","circuit_state":"READY_DISABLED",
                        "collector_invocations":0})
            directory=root/"runtime/engagement/launcher-logs"
            logs=list(directory.glob("launcher.jsonl*"))
            data=b"".join(path.read_bytes() for path in logs if path.name!="launcher.log.lock")
            self.assertLessEqual(len([p for p in logs if p.name!="launcher.log.lock"]),3)
            self.assertTrue(all(path.stat().st_mode&0o777==0o600 for path in logs))
            self.assertNotIn(b"response",data); self.assertNotIn(b"secret",data)
            with self.assertRaises(OSError):
                launcher.append_log(root,{"timestamp":"2026-09-01T00:00:00Z",
                    "outcome":"OK_DISABLED","circuit_state":"READY_DISABLED","secret":"no"})

    def test_log_symlink_and_unsafe_directory_fail_closed_before_scheduler(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); engagement=self.runtime(root); directory=engagement/"launcher-logs"
            directory.mkdir(); target=root/"foreign"; target.write_text("evidence")
            (directory/"launcher.jsonl").symlink_to(target)
            runner=FakeRunner(); result=launcher.launch(root,REVISION,runner=runner)
            self.assertEqual(result["outcome"],"LOG_UNAVAILABLE")
            self.assertFalse(any("run-once" in call for call in runner.calls))
            self.assertEqual(target.read_text(),"evidence")
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); engagement=self.runtime(root); directory=engagement/"launcher-logs"
            directory.mkdir(); os.chmod(directory,0o777)
            runner=FakeRunner(); self.assertEqual(launcher.launch(root,REVISION,runner=runner)["outcome"],
                                                  "LOG_UNAVAILABLE")
            self.assertFalse(any("run-once" in call for call in runner.calls))

    def test_plist_is_unloaded_minimal_and_uses_placeholders(self):
        path=launcher.CODE_ROOT/"launchd/com.flop-agent-intelligence.engagement-scheduler.plist.template"
        value=plistlib.loads(path.read_bytes())
        self.assertEqual(value["Label"],launcher.LABEL)
        self.assertEqual(value["StartInterval"],3600); self.assertFalse(value["RunAtLoad"])
        self.assertNotIn("KeepAlive",value); self.assertNotIn("WorkingDirectory",value)
        for forbidden in ("WatchPaths","QueueDirectories","StartOnMount","Sockets","MachServices"):
            self.assertNotIn(forbidden,value)
        self.assertEqual(value["ProgramArguments"][0],"/usr/bin/python3")
        self.assertEqual(value["ProgramArguments"][1],"-I")
        self.assertIn("<APPROVED_REPOSITORY_ROOT>"," ".join(value["ProgramArguments"]))
        self.assertNotIn("/Users/",path.read_text())
        self.assertEqual((value["StandardOutPath"],value["StandardErrorPath"]),("/dev/null","/dev/null"))

    def test_real_state_and_history_are_read_only_to_launcher_tests(self):
        root=launcher.CODE_ROOT; paths=[root/"runtime/engagement/scheduler-state.json",
            root/"runtime/engagement/scheduler-state.lock",root/"runtime/engagement/history.jsonl"]
        before=[path.read_bytes() for path in paths]
        with tempfile.TemporaryDirectory() as folder:
            temporary=Path(folder); self.runtime(temporary)
            self.assertEqual(launcher.launch(temporary,REVISION,runner=FakeRunner())["outcome"],"OK_DISABLED")
        self.assertEqual([path.read_bytes() for path in paths],before)

    def test_source_has_no_activation_network_or_shell_surface(self):
        source=Path(launcher.__file__).read_text()
        for forbidden in ("shell=True","launchctl","bootstrap","kickstart","curl","urllib",
                          "requests.","scheduler_enabled=True","git pull","git fetch","git reset"):
            self.assertNotIn(forbidden,source)

    def test_production_commands_are_isolated_and_environment_is_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); self.runtime(root); runner=FakeRunner()
            launcher.launch(root,REVISION,runner=runner)
        python_calls=[call for call in runner.calls if call[0]=="/usr/bin/python3"]
        self.assertEqual(len(python_calls),2)
        self.assertTrue(all(call[1]=="-I" for call in python_calls))
        self.assertNotIn("PYTHONPATH",launcher.SAFE_ENV)
        self.assertFalse(any(key.startswith("GIT_") for key in launcher.SAFE_ENV))
        probe=subprocess.run(["/usr/bin/python3","-I","-c",
            "import json,sys;print(json.dumps({'isolated':sys.flags.isolated,'no_user_site':sys.flags.no_user_site,'path':sys.path}))"],
            env={**os.environ,"PYTHONPATH":str(Path(folder)/"hostile")},capture_output=True,check=True,text=True)
        isolation=json.loads(probe.stdout)
        self.assertEqual((isolation["isolated"],isolation["no_user_site"]),(1,1))
        self.assertNotIn(str(Path(folder)/"hostile"),isolation["path"])

    def test_exact_production_launcher_command_passes_git_and_disabled_path(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); (root/"scripts").mkdir(); (root/"src/flop_agent").mkdir(parents=True)
            shutil.copy2(launcher.__file__,root/"scripts/engagement_scheduler_launcher.py")
            (root/"scripts/collect_engagement.py").write_text("raise AssertionError('collector invoked')\n")
            scheduler=root/"scripts/engagement_scheduler.py"
            scheduler.write_text("import json,sys\na='status' if 'status' in sys.argv else 'run-once'\n"
                "print(json.dumps({'success':a=='status','outcome':'SCHEDULER_DISABLED',"
                "'scheduler_enabled':False,'circuit_state':'READY_DISABLED','requests_24h':0,"
                "'collector_invocations':0}))\nraise SystemExit(0 if a=='status' else 1)\n")
            (root/"src/flop_agent/engagement_scheduler.py").write_text("# reviewed fixture\n")
            (root/".gitignore").write_text("runtime/\n.DS_Store\nscripts/json.py\n")
            runtime=root/"runtime/engagement"; runtime.mkdir(parents=True)
            subprocess.run(["git","init","-q"],cwd=root,check=True)
            subprocess.run(["git","add","."],cwd=root,check=True)
            subprocess.run(["git","-c","user.name=Test","-c","user.email=test@example.invalid",
                            "commit","-qm","fixture"],cwd=root,check=True)
            revision=subprocess.run(["git","rev-parse","HEAD"],cwd=root,capture_output=True,
                                    check=True,text=True).stdout.strip()
            (root/"src/.DS_Store").write_bytes(b"metadata")
            hostile=root/"runtime/hostile"; hostile.mkdir(); marker=root/"runtime/hostile-marker"
            (hostile/"json.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
            command=["/usr/bin/python3","-I",str(root/"scripts/engagement_scheduler_launcher.py"),
                     "--expected-revision",revision,"--runtime-root",str(root)]
            completed=subprocess.run(command,cwd=hostile,
                env={**os.environ,"PYTHONPATH":str(hostile),"PYTHONUSERBASE":str(hostile)},
                capture_output=True,text=True)
            self.assertEqual(completed.returncode,0,(completed.stdout,completed.stderr))
            result=json.loads(completed.stdout)
            self.assertEqual((result["outcome"],result["collector_invocations"]),("OK_DISABLED",0))
            self.assertFalse(marker.exists())
            wrong=subprocess.run(command[:4]+["0"*40]+command[5:],cwd=hostile,
                env={**os.environ,"PYTHONPATH":str(hostile)},capture_output=True,text=True)
            self.assertEqual(json.loads(wrong.stdout)["outcome"],"CODE_REVISION_MISMATCH")
            adjacent=root/"scripts/json.py"
            adjacent.write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
            blocked=subprocess.run(command,cwd=hostile,env={**os.environ,"PYTHONPATH":str(hostile)},
                                   capture_output=True,text=True)
            self.assertEqual(json.loads(blocked.stdout)["outcome"],"CODE_TREE_DIRTY")
            self.assertFalse(marker.exists())

    def test_isolated_python_ignores_adjacent_and_pythonpath_shadow_modules(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); adjacent=root/"adjacent"; hostile=root/"pythonpath"
            adjacent.mkdir(); hostile.mkdir(); marker=root/"executed"
            script=adjacent/"probe.py"
            script.write_text("import json,sys\nprint(sys.flags.isolated,sys.flags.no_user_site,json.__file__)\n")
            payload=f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n"
            (adjacent/"json.py").write_text(payload); (hostile/"json.py").write_text(payload)
            completed=subprocess.run(["/usr/bin/python3","-I",str(script)],cwd=root,
                env={**os.environ,"PYTHONPATH":str(hostile),"PYTHONUSERBASE":str(hostile)},
                capture_output=True,check=True,text=True)
            self.assertTrue(completed.stdout.startswith("1 1 "))
            self.assertNotIn(str(adjacent),completed.stdout); self.assertFalse(marker.exists())

    def test_untracked_code_fails_before_scheduler(self):
        class UntrackedRunner(FakeRunner):
            def __call__(self,command,cwd,timeout):
                if command[1:3]==["ls-files","--others"]:
                    self.calls.append(command); return completed(b"scripts/json.py\0")
                return super().__call__(command,cwd,timeout)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); self.runtime(root); runner=UntrackedRunner()
            result=launcher.launch(root,REVISION,runner=runner)
        self.assertEqual(result["outcome"],"CODE_TREE_DIRTY")
        self.assertFalse(any("status" in call or "run-once" in call for call in runner.calls))

    def test_ignored_executable_code_fails_before_scheduler(self):
        class IgnoredCodeRunner(FakeRunner):
            def __call__(self,command,cwd,timeout):
                if "--ignored" in command:
                    self.calls.append(command); return completed(b"scripts/json.pyc\0")
                return super().__call__(command,cwd,timeout)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); self.runtime(root); runner=IgnoredCodeRunner()
            result=launcher.launch(root,REVISION,runner=runner)
        self.assertEqual(result["outcome"],"CODE_TREE_DIRTY")
        self.assertFalse(any("status" in call or "run-once" in call for call in runner.calls))

    def test_ignored_harmless_metadata_is_allowed(self):
        class MetadataRunner(FakeRunner):
            def __call__(self,command,cwd,timeout):
                if "--ignored" in command:
                    self.calls.append(command); return completed(b"src/.DS_Store\0")
                return super().__call__(command,cwd,timeout)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); self.runtime(root); runner=MetadataRunner()
            self.assertEqual(launcher.launch(root,REVISION,runner=runner)["outcome"],"OK_DISABLED")

    def test_scheduler_result_semantic_matrix(self):
        valid=[
            ({"success":False,"outcome":"SCHEDULER_DISABLED","collector_invocations":0,
              "circuit_state":"READY_DISABLED"},"OK_DISABLED"),
            ({"success":True,"outcome":"SCHEDULER_COLLECTION_SUCCEEDED","collector_invocations":1,
              "circuit_state":"READY"},"OK_SCHEDULER_INVOKED"),
            ({"success":False,"outcome":"SCHEDULER_COLLECTION_FAILED","collector_invocations":1,
              "circuit_state":"DEGRADED"},"OK_SCHEDULER_INVOKED"),
            ({"success":False,"outcome":"SCHEDULER_CIRCUIT_OPEN","collector_invocations":0,
              "circuit_state":"CIRCUIT_OPEN"},"OK_SCHEDULER_INVOKED"),
            ({"success":False,"outcome":"SCHEDULER_MIN_INTERVAL","collector_invocations":0,
              "circuit_state":"READY"},"OK_SCHEDULER_INVOKED"),
        ]
        invalid=[]
        for value in (valid[0][0],valid[1][0],valid[3][0]):
            item=dict(value); item["collector_invocations"]=1-item["collector_invocations"]; invalid.append(item)
        item=dict(valid[1][0]); item["request_count"]=0; invalid.append(item)
        item=dict(valid[1][0]); item["circuit_state"]="CIRCUIT_OPEN"; invalid.append(item)
        item=dict(valid[0][0]); item["outcome"]="UNKNOWN"; invalid.append(item)
        item=dict(valid[0][0]); item["collector_invocations"]=True; invalid.append(item)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); self.runtime(root)
            for value,expected in valid:
                with self.subTest(valid=value):
                    result=launcher.launch(root,REVISION,runner=FakeRunner(run=value))
                    self.assertEqual(result["outcome"],expected)
            for value in invalid:
                with self.subTest(invalid=value):
                    result=launcher.launch(root,REVISION,runner=FakeRunner(run=value))
                    self.assertEqual((result["outcome"],result["scheduler_invoked"],
                                      result["scheduler_outcome"],result["collector_invocations"]),
                                     ("LAUNCHER_INTERNAL_ERROR",True,"SCHEDULER_RESULT_INVALID",0))

    def test_pre_and_post_run_log_failures_have_distinct_truthful_results(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); self.runtime(root); runner=FakeRunner()
            with mock.patch.object(launcher,"append_log",side_effect=OSError):
                result=launcher.launch(root,REVISION,runner=runner)
            self.assertEqual((result["outcome"],result["scheduler_invoked"],result["log_persisted"],
                              result["log_error_class"]),
                             ("LOG_UNAVAILABLE",False,False,"LOG_UNAVAILABLE"))
            self.assertFalse(any("run-once" in call for call in runner.calls))
        for scheduler_result,expected in (({"success":False,"outcome":"SCHEDULER_DISABLED",
                "collector_invocations":0,"circuit_state":"READY_DISABLED"},("OK_DISABLED",0)),
                ({"success":True,"outcome":"SCHEDULER_COLLECTION_SUCCEEDED",
                "collector_invocations":1,"circuit_state":"READY"},("OK_SCHEDULER_INVOKED",1))):
            with tempfile.TemporaryDirectory() as folder:
                root=Path(folder); self.runtime(root); runner=FakeRunner(run=scheduler_result)
                with mock.patch.object(launcher,"append_log",side_effect=[None,OSError]):
                    result=launcher.launch(root,REVISION,runner=runner)
                self.assertEqual((result["outcome"],result["collector_invocations"],
                                  result["network_requests"]), (expected[0],expected[1],expected[1]))
                self.assertTrue(result["scheduler_invoked"])
                self.assertEqual(result["scheduler_outcome"],scheduler_result["outcome"])
                self.assertEqual((result["log_persisted"],result["log_error_class"],result["success"]),
                                 (False,"LOG_UNAVAILABLE",False))
                self.assertEqual(sum("run-once" in call for call in runner.calls),1)


if __name__=="__main__": unittest.main()
