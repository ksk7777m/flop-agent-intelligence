import plistlib, subprocess, tempfile, unittest
from pathlib import Path

from scripts import render_engagement_launchagent as renderer


REVISION="647a823d186c2cba0075b1387e3ee02a898078b3"


def completed(stdout=b"",returncode=0,stderr=b""):
    return subprocess.CompletedProcess([],returncode,stdout,stderr)


class Runner:
    def __init__(self,revision=REVISION,dirty=False): self.revision=revision; self.dirty=dirty
    def __call__(self,command,cwd,timeout):
        if command[1:3]==["rev-parse","HEAD"]: return completed((self.revision+"\n").encode())
        if command[1:3]==["diff-index","--quiet"]: return completed(returncode=1 if self.dirty else 0)
        raise AssertionError(command)


class EngagementActivationTests(unittest.TestCase):
    def test_private_plist_render_is_exact_unloaded_and_exclusive(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); runtime=root/"runtime-root"; staged=root/"staged"
            runtime.mkdir(mode=0o700); staged.mkdir(mode=0o700); output=staged/"scheduler.plist"
            result=renderer.render(output,runtime,REVISION,runner=Runner())
            self.assertEqual(result,{"success":True,"outcome":"PLIST_RENDERED","plist_created":True,
                "installed":False,"loaded":False,"network_requests":0,"collector_invocations":0})
            self.assertEqual(output.stat().st_mode&0o777,0o600)
            value=plistlib.loads(output.read_bytes()); arguments=value["ProgramArguments"]
            self.assertEqual(arguments,["/usr/bin/python3","-I",str(renderer.LAUNCHER),
                "--expected-revision",REVISION,"--runtime-root",str(runtime)])
            self.assertEqual((value["StartInterval"],value["RunAtLoad"]),(3600,False))
            self.assertNotIn("KeepAlive",value); self.assertNotIn(b"APPROVED_",output.read_bytes())
            before=output.read_bytes(); again=renderer.render(output,runtime,REVISION,runner=Runner())
            self.assertEqual(again["outcome"],"PLIST_ALREADY_EXISTS")
            self.assertEqual(output.read_bytes(),before)

    def test_renderer_revision_tree_and_path_checks_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve(); runtime=root/"runtime"; staged=root/"staged"
            runtime.mkdir(mode=0o700); staged.mkdir(mode=0o700)
            for revision,runner,outcome in (("bad",Runner(),"CODE_REVISION_MISMATCH"),
                (REVISION,Runner(revision="0"*40),"CODE_REVISION_MISMATCH"),
                (REVISION,Runner(dirty=True),"CODE_TREE_DIRTY")):
                result=renderer.render(staged/f"{outcome}-{revision[:3]}.plist",runtime,revision,runner=runner)
                self.assertEqual(result["outcome"],outcome)
            unsafe=root/"unsafe"; unsafe.mkdir(); unsafe.chmod(0o777)
            self.assertEqual(renderer.render(unsafe/"job.plist",runtime,REVISION,runner=Runner())["outcome"],
                             "CODE_PATH_UNSAFE")
            staged.chmod(0o755)
            self.assertEqual(renderer.render(staged/"public.plist",runtime,REVISION,runner=Runner())["outcome"],
                             "CODE_PATH_UNSAFE")

    def test_renderer_source_has_no_activation_surface(self):
        source=Path(renderer.__file__).read_text()
        for forbidden in ("launchctl","bootstrap","kickstart","scheduler_enabled","run-once","urllib","requests."):
            self.assertNotIn(forbidden,source)


if __name__=="__main__": unittest.main()
