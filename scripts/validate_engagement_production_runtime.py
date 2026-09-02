#!/usr/bin/env python3
"""Required offline real-runtime validation for Engagement Approval A/B."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parent))
from provision_engagement_runtime import STATE_FILES, provision, verify_wheelhouse
from engagement_runtime_contract import resolve_account_home, trusted_production_runtime_root

CODE_ROOT=Path(__file__).resolve().parents[1]

def _hash(path: Path) -> str: return hashlib.sha256(path.read_bytes()).hexdigest()

def validate(source_runtime: Path,wheelhouse: Path,expected_revision: str) -> dict[str,object]:
    source_runtime=source_runtime.absolute(); wheelhouse=wheelhouse.absolute()
    try: account_home=resolve_account_home()
    except Exception: account_home=None
    if account_home is None:
        return {"success":False,"outcome":"PRODUCTION_ACCOUNT_HOME_INVALID",
                "network_requests":0,"collector_invocations":0}
    try: trusted_root=trusted_production_runtime_root()
    except Exception: trusted_root=None
    if trusted_root is None or source_runtime!=trusted_root:
        return {"success":False,"outcome":"PRODUCTION_RUNTIME_ROOT_INVALID",
                "network_requests":0,"collector_invocations":0}
    engagement=source_runtime/"runtime/engagement"
    try:
        if not verify_wheelhouse(wheelhouse): raise OSError
        for name in STATE_FILES:
            metadata=(engagement/name).lstat()
            if (not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
                    or metadata.st_uid!=os.getuid() or stat.S_IMODE(metadata.st_mode)!=0o600):
                raise OSError
    except OSError:
        return {"success":False,"outcome":"TEST_ENVIRONMENT_MISSING",
                "network_requests":0,"collector_invocations":0}
    with tempfile.TemporaryDirectory(prefix="flop-runtime-validation-") as folder:
        root=Path(folder).resolve(); root.chmod(0o700)
        target=root/"runtime/engagement"; target.mkdir(parents=True,mode=0o700)
        for name in STATE_FILES:
            shutil.copyfile(engagement/name,target/name); (target/name).chmod(0o600)
        before={name:_hash(target/name) for name in STATE_FILES}
        result=provision(root,wheelhouse,expected_revision)
        after={name:_hash(target/name) for name in STATE_FILES}
        if not result.get("success") or before!=after:
            return {"success":False,"outcome":"PRODUCTION_RUNTIME_VALIDATION_FAILED",
                    "network_requests":0,"collector_invocations":0}
        manifest=json.loads((Path(str(result["generation"]))/"production-runtime.json").read_text())
        if (manifest.get("readiness")!="READY" or manifest.get("project_revision")!=expected_revision):
            return {"success":False,"outcome":"PRODUCTION_RUNTIME_VALIDATION_FAILED",
                    "network_requests":0,"collector_invocations":0}
        return {"success":True,"outcome":"PRODUCTION_RUNTIME_VALIDATION_PASSED",
                "network_requests":0,"collector_invocations":0,"isolated":True,
                "state_preserved":True,"wheel_count":len(manifest["wheels"])}

def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-runtime",type=Path,required=True)
    parser.add_argument("--wheelhouse",type=Path,required=True)
    parser.add_argument("--expected-revision",required=True)
    args=parser.parse_args(); result=validate(args.source_runtime,args.wheelhouse,args.expected_revision)
    print(json.dumps(result,sort_keys=True,separators=(",",":")))
    if not result["success"]: raise SystemExit(1)

if __name__=="__main__": main()
