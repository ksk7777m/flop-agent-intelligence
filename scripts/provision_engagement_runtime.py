#!/usr/bin/env python3
"""Provision the Engagement Python runtime from a verified local wheelhouse."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parent))
from engagement_runtime_contract import production_runtime_root, validate_scheduler_status_result

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
STATE_FILES=("scheduler-state.json","scheduler-state.lock","history.jsonl","history.jsonl.lock")

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

def _runtime_data_snapshot(runtime_root: Path) -> dict[str,str]:
    engagement=runtime_root/"runtime/engagement"
    return {name:_hash(engagement/name) for name in STATE_FILES}

def _trusted_chain(link: Path,approved: Path) -> str | None:
    try:
        for ancestor in (Path("/"),Path("/Library"),Path("/Library/Developer"),approved):
            item=ancestor.lstat()
            if (not stat.S_ISDIR(item.st_mode) or stat.S_ISLNK(item.st_mode)
                    or item.st_uid!=0 or stat.S_IMODE(item.st_mode)&0o022
                    or ancestor.resolve()!=ancestor.absolute()): return None
        for _ in range(8):
            link=Path(os.path.abspath(link))
            if not link.is_relative_to(approved): return None
            current=approved
            for part in link.relative_to(approved).parts[:-1]:
                current=current/part; item=current.lstat()
                if (not stat.S_ISDIR(item.st_mode) or item.st_uid!=0
                        or stat.S_IMODE(item.st_mode)&0o022): return None
            item=link.lstat()
            if item.st_uid!=0 or stat.S_IMODE(item.st_mode)&0o022: return None
            if not stat.S_ISLNK(item.st_mode):
                return str(link) if stat.S_ISREG(item.st_mode) else None
            target=Path(os.readlink(link)); link=target if target.is_absolute() else link.parent/target
    except (OSError,RuntimeError): return None
    return None

def _trusted_interpreter(interpreter: Path) -> str | None:
    try:
        metadata=interpreter.lstat()
        if (not stat.S_ISLNK(metadata.st_mode)
                or os.readlink(interpreter)!="/Library/Developer/CommandLineTools/usr/bin/python3"):
            return None
    except OSError: return None
    return _trusted_chain(Path("/Library/Developer/CommandLineTools/usr/bin/python3"),
                          Path("/Library/Developer/CommandLineTools"))

def _valid_origins(value: object,python_dir: Path,source: Path) -> bool:
    try:
        return (isinstance(value,dict)
            and (value.get("isolated"),value.get("no_user_site"),value.get("ignore_environment"))==(1,1,1)
            and Path(value["jsonschema"]).resolve().is_relative_to(python_dir)
            and Path(value["cryptography"]).resolve().is_relative_to(python_dir)
            and Path(value["flop_agent"]).resolve().is_relative_to(source))
    except (KeyError,TypeError,OSError,RuntimeError): return False

@contextmanager
def _publication_lock(generations: Path, timeout: float=5.0):
    path=generations/".publication.lock"
    descriptor=os.open(path,os.O_CREAT|os.O_RDWR|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0),0o600)
    try:
        metadata=os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=os.getuid()
                or stat.S_IMODE(metadata.st_mode)!=0o600): raise OSError
        deadline=time.monotonic()+timeout
        while True:
            try: fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB); break
            except BlockingIOError:
                if time.monotonic()>=deadline: raise TimeoutError
                time.sleep(0.01)
        try: yield
        finally: fcntl.flock(descriptor,fcntl.LOCK_UN)
    finally: os.close(descriptor)

def _publish_generation(candidate: Path,generation: Path,generations: Path) -> bool:
    """Exclusively publish candidate; never replace an existing generation."""
    with _publication_lock(generations):
        if generation.exists() or generation.is_symlink(): return False
        os.rename(candidate,generation)
        directory=os.open(generations,os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
        return True

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
    trusted_root=production_runtime_root() if production else runtime_root
    if trusted_root is None or runtime_root!=trusted_root:
        return _result(False,"RUNTIME_ROOT_UNSAFE",eligibility=eligibility)
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
        interpreter_realpath=_trusted_interpreter(interpreter)
        if interpreter_realpath is None: raise RuntimeError("interpreter trust")
        before=_runtime_data_snapshot(runtime_root)
        source=CODE_ROOT/"src"; scheduler=CODE_ROOT/"scripts/engagement_scheduler.py"
        origin_probe=("import json,sys;"+f"sys.path.insert(0,{str(source)!r});"
            "import cryptography,jsonschema,flop_agent.engagement_history as f;"
            "print(json.dumps({'isolated':sys.flags.isolated,'no_user_site':sys.flags.no_user_site,"
            "'ignore_environment':sys.flags.ignore_environment,'jsonschema':jsonschema.__file__,"
            "'cryptography':cryptography.__file__,'flop_agent':f.__file__}))")
        origins=subprocess.run([str(interpreter),"-I","-c",origin_probe],env=SAFE_ENV,
                               capture_output=True,check=False)
        if origins.returncode or origins.stderr: raise RuntimeError("origin verification")
        origin_value=json.loads(origins.stdout)
        if not _valid_origins(origin_value,python_dir,source):
            raise RuntimeError("origin verification")
        entry=("import runpy,sys;"+f"sys.path.insert(0,{str(source)!r});"
            +f"sys.argv[0]={str(scheduler)!r};"
            +f"runpy.run_path({str(scheduler)!r},run_name='__main__')")
        status=subprocess.run([str(interpreter),"-I","-c",entry,"status","--root",str(runtime_root)],
                              cwd=CODE_ROOT,env=SAFE_ENV,capture_output=True,check=False,timeout=10)
        try: status_value=json.loads(status.stdout)
        except (UnicodeDecodeError,json.JSONDecodeError): raise RuntimeError("status verification") from None
        if (status.returncode or status.stderr or validate_scheduler_status_result(status_value) is None
                or _runtime_data_snapshot(runtime_root)!=before):
            raise RuntimeError("PRODUCTION_SCHEDULER_STATUS_INVALID")
        payload={"schema":RUNTIME_SCHEMA,"runtime_version":RUNTIME_VERSION,
            "project_revision":expected_revision,"python":"python/bin/python3",
            "python_version":"3.9.6","dependency_lock":"requirements-engagement-production.txt",
            "dependency_lock_sha256":_hash(LOCK),"packages":PACKAGES,"wheels":WHEELS,
            "project_root":str(CODE_ROOT),"eligibility":eligibility,
            "approved_main_revision":approved_main_revision,
            "verified_origin_revision":verified_origin_revision,
            "interpreter_realpath":interpreter_realpath,"readiness":"READY",
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
        if not _publish_generation(candidate,generation,generations):
            return _result(False,"PRODUCTION_RUNTIME_ALREADY_EXISTS",eligibility=eligibility)
        candidate=None
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
