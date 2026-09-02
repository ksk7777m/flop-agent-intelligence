#!/usr/bin/env python3
"""Provision the Engagement Python runtime from a verified local wheelhouse."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

CODE_ROOT = Path(__file__).resolve().parents[1]
BASE_PYTHON = Path("/usr/bin/python3")
GIT = Path("/usr/bin/git")
LOCK = CODE_ROOT / "requirements-engagement-production.txt"
RUNTIME_SCHEMA = "engagement-production-runtime-v1"
RUNTIME_VERSION = "0.1.0"
PRODUCTION_ELIGIBLE = "PRODUCTION_ELIGIBLE"
PREVIEW_ONLY = "PREVIEW_ONLY_FEATURE_REVISION"
WHEELS = {
    "attrs-25.4.0-py3-none-any.whl":"adcf7e2a1fb3b36ac48d97835bb6d8ade15b8dcce26aba8bf1d14847b57a3373",
    "cffi-2.0.0-cp39-cp39-macosx_11_0_arm64.whl":"de8dad4425a6ca6e4e5e297b27b5c824ecc7581910bf9aee86cb6835e6812aa7",
    "cryptography-46.0.5-cp38-abi3-macosx_10_9_universal2.whl":"4108d4c09fbbf2789d0c926eb4152ae1760d5a2d97612b92d508d96c861e4d31",
    "jsonschema-4.25.1-py3-none-any.whl":"3fba0169e345c7175110351d456342c364814cfcf3b964ba4587f22915230a63",
    "jsonschema_specifications-2025.9.1-py3-none-any.whl":"98802fee3a11ee76ecaca44429fda8a41bff98b00a0f2838151b113f210cc6fe",
    "pycparser-2.23-py3-none-any.whl":"e5c6e8d3fbad53479cab09ac03729e0a9faf2bee3db8208a550daf5af81a5934",
    "referencing-0.36.2-py3-none-any.whl":"e8699adbbf8b5c7de96d8ffa0eb5c158b3beafce084968e2ea8bb08c6794dcd0",
    "rpds_py-0.27.1-cp39-cp39-macosx_11_0_arm64.whl":"1fea2b1a922c47c51fd07d656324531adc787e415c8b116530a1d29c0516c62d",
    "typing_extensions-4.15.0-py3-none-any.whl":"f0fa19c6845758ab08074a0cfa8b7aecb71c999ca73d62883bc25cc018c4e548",
}
PACKAGES = {"attrs":"25.4.0","cffi":"2.0.0","cryptography":"46.0.5",
    "jsonschema":"4.25.1","jsonschema-specifications":"2025.9.1","pycparser":"2.23",
    "referencing":"0.36.2","rpds-py":"0.27.1","typing-extensions":"4.15.0"}
SAFE_ENV = {"PATH":"/usr/bin:/bin","LC_ALL":"C","TMPDIR":"/tmp",
            "PYTHONDONTWRITEBYTECODE":"1","PIP_DISABLE_PIP_VERSION_CHECK":"1"}

def _result(success: bool, outcome: str, **extra: object) -> dict[str, object]:
    return {"success":success,"outcome":outcome,"network_requests":0,
            "collector_invocations":0,**extra}

def _private_dir(path: Path, create: bool=False) -> bool:
    try: metadata=path.lstat()
    except FileNotFoundError:
        if not create: return False
        path.mkdir(mode=0o700,parents=False); metadata=path.lstat()
    return (stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_uid==os.getuid() and stat.S_IMODE(metadata.st_mode)==0o700
            and path.resolve()==path.absolute())

def _hash(path: Path) -> str:
    digest=hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda:stream.read(1024*1024),b""): digest.update(block)
    return digest.hexdigest()

def verify_wheelhouse(path: Path) -> bool:
    if not _private_dir(path): return False
    try: children=list(path.iterdir())
    except OSError: return False
    if {item.name for item in children} != set(WHEELS): return False
    for item in children:
        try: metadata=item.lstat()
        except OSError: return False
        if (not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid!=os.getuid() or stat.S_IMODE(metadata.st_mode)!=0o600
                or _hash(item)!=WHEELS[item.name]): return False
    return True

def _git(command: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run([str(GIT),*command],cwd=CODE_ROOT,env=SAFE_ENV,
                          capture_output=True,check=False)

def repository_eligibility(expected: str, approved_main_revision: str | None=None,
                           verified_origin_revision: str | None=None) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}",expected): return "PRODUCTION_INELIGIBLE_REVISION"
    head=_git(["rev-parse","HEAD"]); dirty=_git(["diff-index","--quiet","HEAD","--"])
    untracked=_git(["ls-files","--others","--exclude-standard"])
    if (head.returncode or head.stderr or head.stdout.decode("ascii").strip()!=expected
            or dirty.returncode or untracked.returncode or untracked.stdout):
        return "PRODUCTION_INELIGIBLE_REVISION"
    branch=_git(["symbolic-ref","--short","HEAD"])
    if branch.returncode or branch.stdout.decode("ascii").strip()!="main": return PREVIEW_ONLY
    origin=_git(["rev-parse","refs/remotes/origin/main"])
    if (not approved_main_revision or not verified_origin_revision
            or approved_main_revision!=expected or verified_origin_revision!=expected
            or origin.returncode or origin.stdout.decode("ascii").strip()!=expected):
        return "PRODUCTION_INELIGIBLE_REVISION"
    return PRODUCTION_ELIGIBLE

def provision(runtime_root: Path, source_wheelhouse: Path, expected_revision: str,
              *, production: bool=False, approved_main_revision: str | None=None,
              verified_origin_revision: str | None=None) -> dict[str, object]:
    runtime_root=runtime_root.absolute(); source_wheelhouse=source_wheelhouse.absolute()
    eligibility=repository_eligibility(expected_revision,approved_main_revision,
                                       verified_origin_revision)
    if eligibility=="PRODUCTION_INELIGIBLE_REVISION":
        return _result(False,eligibility,eligibility=eligibility)
    if production and eligibility!=PRODUCTION_ELIGIBLE:
        return _result(False,"PRODUCTION_REVISION_NOT_ELIGIBLE",eligibility=eligibility)
    if not _private_dir(runtime_root): return _result(False,"RUNTIME_ROOT_UNSAFE")
    if not verify_wheelhouse(source_wheelhouse): return _result(False,"WHEELHOUSE_INVALID")
    generations=runtime_root/"generations"
    if not generations.exists(): generations.mkdir(mode=0o700)
    if not _private_dir(generations): return _result(False,"RUNTIME_ROOT_UNSAFE")
    generation=generations/expected_revision
    if generation.exists() or generation.is_symlink():
        return _result(False,"PRODUCTION_RUNTIME_ALREADY_EXISTS",eligibility=eligibility)
    candidate=Path(tempfile.mkdtemp(prefix=f".{expected_revision}.candidate-",dir=generations))
    candidate.chmod(0o700)
    python_dir=candidate/"python"; wheelhouse=candidate/"wheelhouse"
    manifest=candidate/"production-runtime.json"
    try:
        wheelhouse.mkdir(mode=0o700)
        for name in sorted(WHEELS):
            destination=wheelhouse/name
            shutil.copyfile(source_wheelhouse/name,destination,follow_symlinks=False)
            destination.chmod(0o600)
        if not verify_wheelhouse(wheelhouse): raise RuntimeError("wheelhouse verification")
        created=subprocess.run([str(BASE_PYTHON),"-m","venv",str(python_dir)],
            env=SAFE_ENV,capture_output=True,check=False)
        if created.returncode: raise RuntimeError("venv creation")
        interpreter=python_dir/"bin/python3"
        installed=subprocess.run([str(interpreter),"-I","-m","pip","install","--no-index",
            "--find-links",str(wheelhouse),"--require-hashes","--no-deps","-r",str(LOCK)],
            env=SAFE_ENV,capture_output=True,check=False)
        if installed.returncode: raise RuntimeError("offline install")
        probe="""import importlib.metadata as m,json,site,sys
mods=['jsonschema','cryptography']
print(json.dumps({'isolated':sys.flags.isolated,'user_site':site.ENABLE_USER_SITE,
'prefix':sys.prefix,'packages':{p:m.version(p) for p in %r},
'origins':{n:__import__(n).__file__ for n in mods}}))""" % sorted(PACKAGES)
        checked=subprocess.run([str(interpreter),"-I","-c",probe],env=SAFE_ENV,
                               capture_output=True,check=False)
        if checked.returncode or checked.stderr: raise RuntimeError("import verification")
        value=json.loads(checked.stdout)
        if (value.get("isolated")!=1 or value.get("user_site") is not False
                or value.get("packages")!=PACKAGES
                or not all(Path(origin).is_relative_to(python_dir) for origin in value["origins"].values())):
            raise RuntimeError("runtime verification")
        payload={"schema":RUNTIME_SCHEMA,"runtime_version":RUNTIME_VERSION,
            "project_revision":expected_revision,"python":"python/bin/python3",
            "python_version":"3.9.6","dependency_lock":"requirements-engagement-production.txt",
            "dependency_lock_sha256":_hash(LOCK),"packages":PACKAGES,"wheels":WHEELS,
            "project_root":str(CODE_ROOT),"eligibility":eligibility,
            "previous_generations":sorted(item.name for item in generations.iterdir()
                if item.is_dir() and not item.name.startswith(".")),
            "created_at":datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")}
        descriptor=os.open(manifest,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        try:
            data=(json.dumps(payload,sort_keys=True,separators=(",",":"))+"\n").encode()
            os.write(descriptor,data); os.fsync(descriptor)
        finally: os.close(descriptor)
        directory=os.open(candidate,os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
        os.replace(candidate,generation); candidate=None
        directory=os.open(generations,os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
        return _result(True,"PRODUCTION_RUNTIME_READY",python=str(generation/"python/bin/python3"),
                       generation=str(generation),project_revision=expected_revision,
                       wheel_count=len(WHEELS),eligibility=eligibility)
    except (OSError,RuntimeError,ValueError,json.JSONDecodeError):
        return _result(False,"RUNTIME_REPROVISION_FAILED",eligibility=eligibility)
    finally:
        if candidate is not None and candidate.exists(): shutil.rmtree(candidate)

def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root",required=True,type=Path)
    parser.add_argument("--wheelhouse",required=True,type=Path)
    parser.add_argument("--expected-revision",required=True)
    parser.add_argument("--production",action="store_true")
    parser.add_argument("--approved-main-revision")
    parser.add_argument("--verified-origin-revision")
    args=parser.parse_args()
    result=provision(args.runtime_root,args.wheelhouse,args.expected_revision,
        production=args.production,approved_main_revision=args.approved_main_revision,
        verified_origin_revision=args.verified_origin_revision)
    print(json.dumps(result,sort_keys=True,separators=(",",":")))
    if not result["success"]: raise SystemExit(1)

if __name__=="__main__": main()
