import json, os, plistlib, subprocess, tempfile, unittest
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
        if "status" in command: return completed(json.dumps(self.status).encode())
        if "run-once" in command: return completed(json.dumps(self.run).encode(),returncode=1)
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
                "scheduler_invoked":True,"collector_invocations":0,"network_requests":0,
                "circuit_state":"READY_DISABLED"})
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


if __name__=="__main__": unittest.main()
