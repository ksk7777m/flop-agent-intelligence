import json, os, plistlib, subprocess, tempfile, threading, unittest
from pathlib import Path
from unittest import mock

from scripts import render_engagement_launchagent as renderer


REVISION="647a823d186c2cba0075b1387e3ee02a898078b3"


def completed(stdout=b"",returncode=0,stderr=b""):
    return subprocess.CompletedProcess([],returncode,stdout,stderr)


class Runner:
    def __init__(self,revision=REVISION,dirty=False,branch="main",origin=None):
        self.revision=revision; self.dirty=dirty; self.branch=branch; self.origin=origin or revision
    def __call__(self,command,cwd,timeout):
        if command[1:3]==["rev-parse","HEAD"]: return completed((self.revision+"\n").encode())
        if command[1:3]==["rev-parse","refs/remotes/origin/main"]: return completed((self.origin+"\n").encode())
        if command[1:3]==["symbolic-ref","--short"]: return completed((self.branch+"\n").encode())
        if command[1:3]==["diff-index","--quiet"]: return completed(returncode=1 if self.dirty else 0)
        if command[1:3]==["ls-files","--others"]: return completed()
        raise AssertionError(command)

def render(output,runtime,revision,**kwargs):
    return renderer.render(output,runtime,revision,production=True,
        approved_main_revision=revision,verified_origin_revision=revision,**kwargs)


class EngagementActivationTests(unittest.TestCase):
    def setUp(self):
        self.runtime_patch=mock.patch.object(renderer,"_runtime_ready",return_value=True)
        self.runtime_patch.start()

    def tearDown(self): self.runtime_patch.stop()

    def test_feature_is_noninstallable_preview_and_production_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); runtime=root/"runtime"; staged=root/"staged"
            runtime.mkdir(mode=0o700); staged.mkdir(mode=0o700)
            feature=Runner(branch="codex/feature")
            self.runtime_patch.stop()
            try:
                bypass=renderer.render(staged/"bypass.plist",runtime,REVISION,runner=feature,
                    production=True,approved_main_revision=REVISION,verified_origin_revision=REVISION)
            finally: self.runtime_patch.start()
            self.assertEqual(bypass["outcome"],"PRODUCTION_RUNTIME_NOT_READY")
            with mock.patch.object(renderer,"_runtime_ready",return_value=True):
                preview=renderer.render(staged/"preview.json",runtime,REVISION,runner=feature)
            self.assertEqual((preview["success"],preview["eligibility"],preview["installable"],
                              preview["artifact_format"]),
                             (True,"PREVIEW_ONLY_FEATURE_REVISION",False,"NON_INSTALLABLE_JSON"))
            self.assertEqual(json.loads((staged/"preview.json").read_text())["installability"],
                             "NON_INSTALLABLE")
            with mock.patch.object(renderer,"_runtime_ready",return_value=True):
                rejected=renderer.render(staged/"production.plist",runtime,REVISION,runner=feature,
                    production=True,approved_main_revision=REVISION,verified_origin_revision=REVISION)
            self.assertEqual(rejected["outcome"],"PRODUCTION_REVISION_NOT_ELIGIBLE")
            self.assertFalse((staged/"production.plist").exists())

    def test_main_requires_matching_explicit_origin_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); runtime=root/"runtime"; staged=root/"staged"
            runtime.mkdir(mode=0o700); staged.mkdir(mode=0o700)
            for runner,approved,verified in ((Runner(),None,None),
                    (Runner(origin="2"*40),REVISION,REVISION),(Runner(),REVISION,"2"*40)):
                with mock.patch.object(renderer,"_runtime_ready",return_value=True):
                    result=renderer.render(staged/f"{len(list(staged.iterdir()))}.plist",runtime,REVISION,
                        runner=runner,production=True,approved_main_revision=approved,
                        verified_origin_revision=verified)
                self.assertEqual(result["outcome"],"PRODUCTION_REVISION_NOT_ELIGIBLE")

    def test_validation_only_runtime_cannot_render_production_plist(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); runtime=root/"runtime"; staged=root/"staged"
            runtime.mkdir(mode=0o700); staged.mkdir(mode=0o700)
            def readiness(path,revision,code_root,require_production):
                return not require_production
            with mock.patch.object(renderer,"_runtime_ready",side_effect=readiness):
                result=renderer.render(staged/"production.plist",runtime,REVISION,
                    runner=Runner(),production=True,approved_main_revision=REVISION,
                    verified_origin_revision=REVISION)
            self.assertEqual(result["outcome"],"PRODUCTION_RUNTIME_NOT_READY")
            self.assertFalse((staged/"production.plist").exists())

    def test_production_render_rejects_untracked_artifact(self):
        class Untracked(Runner):
            def __call__(self,command,cwd,timeout):
                if command[1:3]==["ls-files","--others"]: return completed(b"src/flop_agent/shadow.py\0")
                return super().__call__(command,cwd,timeout)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); runtime=root/"runtime"; staged=root/"staged"
            runtime.mkdir(mode=0o700); staged.mkdir(mode=0o700)
            result=render(staged/"production.plist",runtime,REVISION,runner=Untracked())
            self.assertEqual(result["outcome"],"CODE_TREE_DIRTY")
            self.assertFalse((staged/"production.plist").exists())

    def test_private_plist_render_is_exact_unloaded_and_exclusive(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); runtime=root/"runtime-root"; staged=root/"staged"
            runtime.mkdir(mode=0o700); staged.mkdir(mode=0o700); output=staged/"scheduler.plist"
            result=render(output,runtime,REVISION,runner=Runner())
            self.assertTrue(result["success"]); self.assertEqual(result["outcome"],"PLIST_RENDERED")
            self.assertEqual((result["eligibility"],result["installable"],result["artifact_format"]),
                             ("PRODUCTION_ELIGIBLE",True,"PLIST"))
            self.assertEqual(output.stat().st_mode&0o777,0o600)
            value=plistlib.loads(output.read_bytes()); arguments=value["ProgramArguments"]
            self.assertEqual(arguments,[str(runtime/"generations"/REVISION/"python/bin/python3"),"-I",str(renderer.LAUNCHER),
                "--expected-revision",REVISION,"--runtime-root",str(runtime)])
            self.assertEqual((value["StartInterval"],value["RunAtLoad"]),(3600,False))
            self.assertNotIn("KeepAlive",value); self.assertNotIn(b"APPROVED_",output.read_bytes())
            before=output.read_bytes(); mode=output.stat().st_mode&0o777
            again=render(output,runtime,REVISION,runner=Runner())
            self.assertEqual(again["outcome"],"PLIST_ALREADY_EXISTS")
            self.assertEqual(output.read_bytes(),before)
            self.assertEqual(output.stat().st_mode&0o777,mode)

    def test_prepublication_faults_never_expose_target_and_clean_owned_candidate(self):
        stages=(
            ("create",mock.patch.object(renderer.tempfile,"mkstemp",side_effect=OSError("bounded"))),
            ("write",mock.patch.object(renderer.os,"write",side_effect=OSError("bounded"))),
            ("candidate-fsync",mock.patch.object(renderer.os,"fsync",side_effect=OSError("bounded"))),
            ("candidate-validation",mock.patch.object(renderer,"_valid_payload",side_effect=[True,False])),
            ("publication",mock.patch.object(renderer.os,"link",side_effect=OSError("bounded"))),
        )
        for stage,patcher in stages:
            with self.subTest(stage=stage),tempfile.TemporaryDirectory() as folder:
                root=Path(folder).resolve(); runtime=root/"runtime"; staged=root/"staged"
                runtime.mkdir(mode=0o700); staged.mkdir(mode=0o700); output=staged/"job.plist"
                with patcher: result=render(output,runtime,REVISION,runner=Runner())
                self.assertEqual((result["success"],result["plist_created"],result["commit_state"],
                                  result["durability_confirmed"]),(False,False,"PRE_PUBLISH",False))
                self.assertFalse(output.exists())
                self.assertEqual(list(staged.glob(".job.plist.candidate-*")),[])

    def test_directory_fsync_failure_preserves_complete_published_target(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); runtime=root/"runtime"; staged=root/"staged"
            runtime.mkdir(mode=0o700); staged.mkdir(mode=0o700); output=staged/"job.plist"
            real_fsync=os.fsync; calls=[]
            def fail_directory(descriptor):
                calls.append(descriptor)
                if len(calls)==2: raise OSError("bounded")
                return real_fsync(descriptor)
            with mock.patch.object(renderer.os,"fsync",side_effect=fail_directory):
                result=render(output,runtime,REVISION,runner=Runner())
            self.assertEqual((result["success"],result["outcome"],result["plist_created"],
                              result["commit_state"],result["durability_confirmed"]),
                             (False,"PLIST_COMMITTED_NOT_DURABLE",True,"PUBLISHED",False))
            self.assertEqual(plistlib.loads(output.read_bytes())["Label"],
                             "com.flop-agent-intelligence.engagement-scheduler")

    def test_partial_candidate_write_never_exposes_final_target(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); runtime=root/"runtime"; staged=root/"staged"
            runtime.mkdir(mode=0o700); staged.mkdir(mode=0o700); output=staged/"job.plist"
            real_write=os.write; calls=[]
            def partial_then_fail(descriptor,payload):
                calls.append(len(payload))
                if len(calls)==1: return real_write(descriptor,payload[:17])
                raise OSError("bounded")
            with mock.patch.object(renderer.os,"write",side_effect=partial_then_fail):
                result=render(output,runtime,REVISION,runner=Runner())
            self.assertGreaterEqual(len(calls),2)
            self.assertEqual((result["plist_created"],result["commit_state"]),(False,"PRE_PUBLISH"))
            self.assertFalse(output.exists())
            self.assertEqual(list(staged.glob(".job.plist.candidate-*")),[])

    def test_postpublish_validation_failure_is_durable_and_preserves_target(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); runtime=root/"runtime"; staged=root/"staged"
            runtime.mkdir(mode=0o700); staged.mkdir(mode=0o700); output=staged/"job.plist"
            with mock.patch.object(renderer,"_valid_payload",side_effect=[True,True,False]):
                result=render(output,runtime,REVISION,runner=Runner())
            self.assertEqual((result["success"],result["outcome"],result["plist_created"],
                              result["commit_state"],result["durability_confirmed"]),
                             (False,"PLIST_PUBLISHED_VALIDATION_FAILED",True,"DURABLE",True))
            self.assertTrue(output.exists())

    def test_concurrent_render_publishes_once_without_candidate_cross_cleanup(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); runtime=root/"runtime"; staged=root/"staged"
            runtime.mkdir(mode=0o700); staged.mkdir(mode=0o700); output=staged/"job.plist"
            barrier=threading.Barrier(2); results=[]
            def invoke(): barrier.wait(); results.append(render(output,runtime,REVISION,runner=Runner()))
            threads=[threading.Thread(target=invoke) for _ in range(2)]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            self.assertEqual(sum(result["success"] for result in results),1)
            self.assertEqual(sorted(result["outcome"] for result in results),
                             ["PLIST_ALREADY_EXISTS","PLIST_RENDERED"])
            self.assertEqual(list(staged.glob(".job.plist.candidate-*")),[])

    def test_result_contract_rejects_contradictions(self):
        for arguments in ({"success":True,"outcome":"X"},
                          {"success":True,"outcome":"X","commit_state":"PUBLISHED"},
                          {"success":True,"outcome":"X","commit_state":"DURABLE",
                           "error_class":"X"}):
            with self.subTest(arguments=arguments),self.assertRaises(ValueError):
                renderer._result(**arguments)

    def test_installed_plist_is_safe_and_does_not_imply_activation(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); runtime=root/"runtime"; staged=root/"staged"
            active_directory=root/"Library/LaunchAgents"
            runtime.mkdir(mode=0o700); staged.mkdir(mode=0o700)
            active_directory.mkdir(parents=True)
            rendered=staged/"scheduler.plist"
            result=render(rendered,runtime,REVISION,runner=Runner())
            active=active_directory/"com.flop-agent-intelligence.engagement-scheduler.plist"
            active.write_bytes(rendered.read_bytes()); active.chmod(0o600)

            metadata=os.lstat(active); value=plistlib.loads(active.read_bytes())
            self.assertTrue(active.is_file()); self.assertFalse(active.is_symlink())
            self.assertEqual(metadata.st_uid,os.geteuid())
            self.assertEqual(metadata.st_mode&0o777,0o600)
            self.assertEqual(value["Label"],"com.flop-agent-intelligence.engagement-scheduler")
            self.assertEqual((value["StartInterval"],value["RunAtLoad"]),(3600,False))
            self.assertNotIn("KeepAlive",value)
            self.assertEqual((result["installed"],result["loaded"]),(False,False))
            self.assertEqual((result["collector_invocations"],result["network_requests"]),(0,0))

    def test_renderer_revision_tree_and_path_checks_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); runtime=root/"runtime"; staged=root/"staged"
            runtime.mkdir(mode=0o700); staged.mkdir(mode=0o700)
            for revision,runner,outcome in (("bad",Runner(),"CODE_REVISION_MISMATCH"),
                (REVISION,Runner(revision="0"*40),"CODE_REVISION_MISMATCH"),
                (REVISION,Runner(dirty=True),"CODE_TREE_DIRTY")):
                result=render(staged/f"{outcome}-{revision[:3]}.plist",runtime,revision,runner=runner)
                self.assertEqual(result["outcome"],outcome)
            unsafe=root/"unsafe"; unsafe.mkdir(); unsafe.chmod(0o777)
            self.assertEqual(render(unsafe/"job.plist",runtime,REVISION,runner=Runner())["outcome"],
                             "CODE_PATH_UNSAFE")
            staged.chmod(0o755)
            self.assertEqual(render(staged/"public.plist",runtime,REVISION,runner=Runner())["outcome"],
                             "CODE_PATH_UNSAFE")

    def test_renderer_source_has_no_activation_surface(self):
        source=Path(renderer.__file__).read_text()
        for forbidden in ("launchctl","bootstrap","kickstart","scheduler_enabled","run-once","urllib","requests."):
            self.assertNotIn(forbidden,source)


if __name__=="__main__": unittest.main()
