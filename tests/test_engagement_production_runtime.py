import json, os, stat, tempfile, unittest
from pathlib import Path
from unittest import mock

from scripts import engagement_scheduler_launcher as launcher
from scripts import provision_engagement_runtime as provisioner

REVISION="1"*40


class EngagementProductionRuntimeTests(unittest.TestCase):
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
            root=Path(folder).resolve(); python=root/"python/bin/python3"; python.parent.mkdir(parents=True)
            python.symlink_to("/Library/Developer/CommandLineTools/usr/bin/python3")
            value={"schema":launcher.RUNTIME_SCHEMA,"runtime_version":launcher.RUNTIME_VERSION,
                "project_revision":REVISION,"python":"python/bin/python3","python_version":"3.9.6",
                "dependency_lock":"requirements-engagement-production.txt",
                "dependency_lock_sha256":"0"*64,"packages":launcher.RUNTIME_PACKAGES,"wheels":{},
                "created_at":"2026-09-02T00:00:00Z"}
            manifest=root/"production-runtime.json"
            manifest.write_text(json.dumps(value)); manifest.chmod(0o600)
            self.assertEqual(launcher.validate_runtime(root,"2"*40),"CODE_REVISION_MISMATCH")
            self.assertEqual(launcher.validate_runtime(root,REVISION),"PRODUCTION_INTERPRETER_MISMATCH")
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

    def test_provisioner_has_no_network_activation_or_collection_surface(self):
        source=Path(provisioner.__file__).read_text()
        for forbidden in ("urllib","requests.","curl","launchctl","bootstrap","kickstart",
                          "run-once","--confirm","scheduler_enabled"):
            self.assertNotIn(forbidden,source)


if __name__=="__main__": unittest.main()
