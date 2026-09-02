#!/usr/bin/env python3
"""Pinned, offline-preflight launcher for a future Engagement LaunchAgent."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0,str(Path(__file__).resolve().parent))
from engagement_runtime_contract import validate_scheduler_status_result

CODE_ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_RUNTIME_ROOT = (Path.home()/"Library/Application Support/flop-agent-intelligence/production-runtime").absolute()
GIT = Path("/usr/bin/git")
SCHEDULER = CODE_ROOT / "scripts/engagement_scheduler.py"
COLLECTOR = CODE_ROOT / "scripts/collect_engagement.py"
SCHEDULER_MODULE = CODE_ROOT / "src/flop_agent/engagement_scheduler.py"
LABEL = "com.flop-agent-intelligence.engagement-scheduler"
MAX_COMMAND_OUTPUT = 64 * 1024
MAX_LOG_BYTES = 1024 * 1024
LOG_GENERATIONS = 3
RUNTIME_SCHEMA = "engagement-production-runtime-v1"
RUNTIME_VERSION = "0.1.0"
RUNTIME_PACKAGES = {"attrs":"25.4.0","cffi":"2.0.0","cryptography":"46.0.5",
    "jsonschema":"4.25.1","jsonschema-specifications":"2025.9.1","pycparser":"2.23",
    "referencing":"0.36.2","rpds-py":"0.27.1","typing-extensions":"4.15.0"}
RUNTIME_WHEELS = {
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
RUNTIME_STATE_FILES = ("scheduler-state.json","scheduler-state.lock",
                       "history.jsonl","history.jsonl.lock")
PRELOG_KEYS = {"timestamp","stage","error_class","approved_revision","runtime_version"}
LOG_KEYS = {"timestamp","outcome","circuit_state","requests_24h","collector_invocations"}
LOG_OUTCOMES = {"PREFLIGHT_READY","OK_DISABLED","OK_SCHEDULER_INVOKED",
                "LAUNCHER_INTERNAL_ERROR","LOG_UNAVAILABLE"}
CIRCUIT_STATES = {"READY_DISABLED","READY","DEGRADED","CIRCUIT_OPEN",None}
SAFE_ENV = {"PATH":"/usr/bin:/bin", "LC_ALL":"C", "TMPDIR":"/tmp",
            "PYTHONDONTWRITEBYTECODE":"1"}
SCHEDULER_OUTCOMES = {
    "SCHEDULER_DISABLED", "SCHEDULER_READY", "SCHEDULER_MIN_INTERVAL",
    "SCHEDULER_NOT_BEFORE",
    "SCHEDULER_DAILY_BUDGET_EXCEEDED", "SCHEDULER_CIRCUIT_OPEN",
    "SCHEDULER_RUN_ALREADY_ACTIVE", "SCHEDULER_COLLECTION_SUCCEEDED",
    "SCHEDULER_COLLECTION_FAILED", "SCHEDULER_RECOVERED_INTERRUPTED_RUN",
    "SCHEDULER_STATE_MISSING", "SCHEDULER_STATE_INVALID", "SCHEDULER_STATE_PATH_UNSAFE",
    "SCHEDULER_STATE_PERMISSIONS", "SCHEDULER_STATE_LOCK_FAILED",
    "SCHEDULER_RESULT_INVALID",
}

Runner = Callable[[list[str], Path, int], subprocess.CompletedProcess[bytes]]


def _trusted_directory(path: Path, *, private: bool) -> bool:
    try: metadata=path.lstat()
    except OSError: return False
    mode=stat.S_IMODE(metadata.st_mode)
    return (stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_uid==os.getuid() and path.resolve()==path.absolute()
            and (mode==0o700 if private else not mode&0o022))


def _runtime_directories_trusted(runtime_root: Path,generation: Path,
                                 expected_revision: str,require_production: bool) -> bool:
    generations=runtime_root/"generations"
    python_dir=generation/"python"; wheelhouse=generation/"wheelhouse"
    return ((not require_production or runtime_root==PRODUCTION_RUNTIME_ROOT)
            and generation.name==expected_revision and generation.parent==generations
            and _trusted_directory(runtime_root,private=True)
            and _trusted_directory(generations,private=True)
            and _trusted_directory(generation,private=True)
            and _trusted_directory(python_dir,private=False)
            and _trusted_directory(wheelhouse,private=True))


def _trusted_os_chain(link: Path,*,approved: Path=Path("/Library/Developer/CommandLineTools"),
                      ancestors: tuple[Path,...] | None=None,expected_owner: int=0) -> str | None:
    try:
        ancestors=ancestors or (Path("/"),Path("/Library"),Path("/Library/Developer"),approved)
        for ancestor in ancestors:
            item=ancestor.lstat()
            if (not stat.S_ISDIR(item.st_mode) or stat.S_ISLNK(item.st_mode)
                    or item.st_uid!=expected_owner or stat.S_IMODE(item.st_mode)&0o022
                    or ancestor.resolve()!=ancestor.absolute()): return None
        for _ in range(8):
            link=Path(os.path.abspath(link))
            if not link.is_relative_to(approved): return None
            current=approved
            for part in link.relative_to(approved).parts[:-1]:
                current=current/part; item=current.lstat()
                if (not stat.S_ISDIR(item.st_mode) or stat.S_ISLNK(item.st_mode)
                        or item.st_uid!=expected_owner or stat.S_IMODE(item.st_mode)&0o022): return None
            item=link.lstat()
            if item.st_uid!=expected_owner or stat.S_IMODE(item.st_mode)&0o022: return None
            if not stat.S_ISLNK(item.st_mode):
                return str(link) if stat.S_ISREG(item.st_mode) else None
            target=Path(os.readlink(link)); link=target if target.is_absolute() else link.parent/target
    except (OSError,RuntimeError): return None
    return None


def _manifest_contract_valid(value: object,resolved_python: Path) -> bool:
    required={"schema","runtime_version","project_revision","python","python_version",
              "dependency_lock","dependency_lock_sha256","packages","wheels","created_at",
              "project_root","eligibility","previous_generations","readiness",
              "approved_main_revision","verified_origin_revision","interpreter_realpath"}
    return (isinstance(value,dict) and set(value)==required
            and value.get("schema")==RUNTIME_SCHEMA and value.get("runtime_version")==RUNTIME_VERSION
            and value.get("python")=="python/bin/python3" and value.get("python_version")=="3.9.6"
            and value.get("dependency_lock")=="requirements-engagement-production.txt"
            and value.get("packages")==RUNTIME_PACKAGES
            and value.get("wheels")==RUNTIME_WHEELS and value.get("project_root")==str(CODE_ROOT)
            and value.get("readiness")=="READY"
            and value.get("interpreter_realpath")==str(resolved_python))


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")


def _result(outcome: str, *, success: bool = False, scheduler_invoked: bool = False,
            scheduler_outcome: str | None = None, collector_invocations: int = 0,
            circuit_state: str | None = None, log_persisted: bool | None = None,
            log_error_class: str | None = None) -> dict[str, Any]:
    return {"success":success,"outcome":outcome,"scheduler_invoked":scheduler_invoked,
            "scheduler_outcome":scheduler_outcome,
            "collector_invocations":collector_invocations,"network_requests":collector_invocations,
            "circuit_state":circuit_state,"log_persisted":log_persisted,
            "log_error_class":log_error_class}


def _run(command: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command,cwd=cwd,env=SAFE_ENV,capture_output=True,check=False,timeout=timeout)


def _scheduler_command(action: str, runtime_root: Path) -> list[str]:
    isolated_entry=("import runpy,sys;"
               f"sys.path.insert(0,{str(CODE_ROOT / 'src')!r});"
               f"sys.argv[0]={str(SCHEDULER)!r};"
               f"runpy.run_path({str(SCHEDULER)!r},run_name='__main__')")
    return [str(Path(os.path.abspath(sys.executable))),"-I","-c",isolated_entry,action,"--root",str(runtime_root)]


def validate_runtime(runtime_root: Path, expected_revision: str, *,
                     require_production: bool=False) -> str | None:
    """Return a stable failure class, or None for the bound private runtime."""
    generation=(runtime_root/"generations"/expected_revision).absolute()
    manifest=generation/"production-runtime.json"
    expected_python=generation/"python/bin/python3"
    if not _runtime_directories_trusted(runtime_root,generation,expected_revision,require_production):
        return "PRODUCTION_RUNTIME_NOT_READY"
    try:
        metadata=manifest.lstat(); python_metadata=expected_python.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid!=os.getuid() or stat.S_IMODE(metadata.st_mode)!=0o600):
            return "PRODUCTION_RUNTIME_NOT_READY"
        resolved_python=expected_python.resolve(); resolved_metadata=resolved_python.lstat()
        if (not stat.S_ISLNK(python_metadata.st_mode)
                or os.readlink(expected_python)!="/Library/Developer/CommandLineTools/usr/bin/python3"
                or not stat.S_ISREG(resolved_metadata.st_mode) or resolved_metadata.st_uid!=0):
            return "PRODUCTION_RUNTIME_NOT_READY"
        trusted_realpath=_trusted_os_chain(Path("/Library/Developer/CommandLineTools/usr/bin/python3"))
        if trusted_realpath is None or trusted_realpath!=str(resolved_python):
            return "PRODUCTION_RUNTIME_NOT_READY"
        value=json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError,RuntimeError,UnicodeDecodeError,json.JSONDecodeError):
        return "PRODUCTION_RUNTIME_NOT_READY"
    if not _manifest_contract_valid(value,resolved_python):
        return "PRODUCTION_RUNTIME_NOT_READY"
    try:
        lock=CODE_ROOT/str(value["dependency_lock"])
        if (not _safe_regular(lock,CODE_ROOT)
                or hashlib.sha256(lock.read_bytes()).hexdigest()!=value["dependency_lock_sha256"]):
            return "PRODUCTION_RUNTIME_NOT_READY"
    except (OSError,TypeError): return "PRODUCTION_RUNTIME_NOT_READY"
    if value.get("project_revision")!=expected_revision: return "CODE_REVISION_MISMATCH"
    if require_production:
        if (value.get("eligibility")!="PRODUCTION_ELIGIBLE"
                or value.get("approved_main_revision")!=expected_revision
                or value.get("verified_origin_revision")!=expected_revision):
            return "PRODUCTION_RUNTIME_NOT_READY"
        commands=([str(GIT),"symbolic-ref","--short","HEAD"],
                  [str(GIT),"rev-parse","HEAD"],
                  [str(GIT),"rev-parse","refs/remotes/origin/main"],
                  [str(GIT),"diff-index","--quiet","HEAD","--"],
                  [str(GIT),"ls-files","--others","--exclude-standard","-z"],
                  [str(GIT),"ls-files","--others","--ignored","--exclude-standard",
                   "-z","--","scripts","src"])
        checks=tuple(subprocess.run(command,cwd=CODE_ROOT,env=SAFE_ENV,capture_output=True,
                                    check=False) for command in commands)
        if (checks[0].returncode or checks[0].stdout!=b"main\n" or checks[0].stderr
                or checks[1].returncode or checks[1].stdout.decode("ascii").strip()!=expected_revision
                or checks[1].stderr
                or checks[2].returncode or checks[2].stdout.decode("ascii").strip()!=expected_revision
                or checks[2].stderr or checks[3].returncode
                or checks[4].returncode or checks[4].stderr or checks[4].stdout
                or checks[5].returncode or checks[5].stderr
                or _ignored_code_present(checks[5].stdout,CODE_ROOT)):
            return "PRODUCTION_RUNTIME_NOT_READY"
    actual=Path(os.path.abspath(sys.executable))
    if actual!=expected_python: return "PRODUCTION_INTERPRETER_MISMATCH"
    try:
        import importlib.metadata as metadata_api
        import cryptography
        import jsonschema
        import flop_agent.engagement_history as engagement_history
        site_root=generation/"python"
        for package,version in RUNTIME_PACKAGES.items():
            distribution=metadata_api.distribution(package)
            if (distribution.version!=version
                    or not Path(distribution.locate_file("")).resolve().is_relative_to(site_root)):
                return "PRODUCTION_DEPENDENCY_MISSING"
        if (not Path(jsonschema.__file__).resolve().is_relative_to(site_root)
                or not Path(cryptography.__file__).resolve().is_relative_to(site_root)
                or not Path(engagement_history.__file__).resolve().is_relative_to(CODE_ROOT/"src")):
            return "PRODUCTION_DEPENDENCY_MISSING"
    except (metadata_api.PackageNotFoundError,ImportError,OSError,RuntimeError,TypeError):
        return "PRODUCTION_DEPENDENCY_MISSING"
    if require_production:
        engagement=runtime_root/"runtime/engagement"
        try:
            before={name:hashlib.sha256((engagement/name).read_bytes()).digest()
                    for name in RUNTIME_STATE_FILES}
            status=subprocess.run(_scheduler_command("status",runtime_root),cwd=CODE_ROOT,
                                  env=SAFE_ENV,capture_output=True,check=False,timeout=10)
            state=_bounded_json(status)
            after={name:hashlib.sha256((engagement/name).read_bytes()).digest()
                   for name in RUNTIME_STATE_FILES}
        except (OSError,subprocess.SubprocessError):
            return "PRODUCTION_RUNTIME_NOT_READY"
        if (status.returncode or validate_scheduler_status_result(state) is None or before!=after):
            return "PRODUCTION_RUNTIME_NOT_READY"
    return None


def _ignored_code_present(output: bytes, code_root: Path) -> bool:
    try: names=output.decode("utf-8").split("\0")
    except UnicodeDecodeError: return True
    dangerous={".py",".pyc",".pyo",".so",".dylib"}
    for name in filter(None,names):
        path=Path(name)
        if (path.is_absolute() or ".." in path.parts or "__pycache__" in path.parts
                or path.suffix.lower() in dangerous):
            return True
        try:
            metadata=os.lstat(code_root/path)
            if stat.S_ISREG(metadata.st_mode) and metadata.st_mode&0o111: return True
        except OSError: return True
    return False


def _validated_scheduler_result(value: object, returncode: int) -> dict[str, Any] | None:
    if not isinstance(value,dict) or type(value.get("success")) is not bool:
        return None
    allowed_keys={"success","allowed","outcome","overlap_active","circuit_state",
        "scheduler_enabled","last_attempt_at","last_success_at","consecutive_failures",
        "not_before_at",
        "last_error_class","normal_interval_minutes","minimum_interval_minutes",
        "next_eligible_at","requests_24h","collector_invocations","error_class"}
    if not set(value)<=allowed_keys or returncode!=(0 if value["success"] else 1): return None
    outcome=value.get("outcome"); invocations=value.get("collector_invocations")
    circuit=value.get("circuit_state")
    if type(invocations) is not int or invocations not in {0,1}: return None
    precollector={"SCHEDULER_DISABLED","SCHEDULER_NOT_BEFORE","SCHEDULER_MIN_INTERVAL",
        "SCHEDULER_DAILY_BUDGET_EXCEEDED","SCHEDULER_RUN_ALREADY_ACTIVE",
        "SCHEDULER_STATE_MISSING","SCHEDULER_STATE_INVALID","SCHEDULER_STATE_PATH_UNSAFE",
        "SCHEDULER_STATE_PERMISSIONS","SCHEDULER_STATE_LOCK_FAILED"}
    valid=(
        outcome=="SCHEDULER_COLLECTION_SUCCEEDED" and value["success"] and invocations==1
        and circuit=="READY"
        or outcome=="SCHEDULER_COLLECTION_FAILED" and not value["success"] and invocations==1
        and circuit in {"DEGRADED","CIRCUIT_OPEN"}
        or outcome=="SCHEDULER_CIRCUIT_OPEN" and not value["success"] and invocations==0
        and circuit=="CIRCUIT_OPEN"
        or outcome=="SCHEDULER_RECOVERED_INTERRUPTED_RUN" and not value["success"]
        and invocations==0 and circuit in {"DEGRADED","CIRCUIT_OPEN"}
        or outcome in precollector and not value["success"] and invocations==0
        and circuit in CIRCUIT_STATES)
    return value if valid else None


def _safe_regular(path: Path, root: Path) -> bool:
    try:
        absolute=path.absolute(); metadata=os.lstat(absolute)
        return (absolute.is_relative_to(root.absolute()) and stat.S_ISREG(metadata.st_mode)
                and not stat.S_ISLNK(metadata.st_mode) and absolute.resolve()==absolute)
    except (OSError,RuntimeError):
        return False


def _code_paths_safe(code_root: Path) -> bool:
    try:
        metadata=os.lstat(code_root.absolute())
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode): return False
    except OSError: return False
    required=(Path(__file__).absolute(),SCHEDULER,COLLECTOR,SCHEDULER_MODULE)
    expected_launcher=code_root/"scripts/engagement_scheduler_launcher.py"
    return (Path(__file__).absolute()==expected_launcher.absolute()
            and all(_safe_regular(path,code_root) for path in required)
            and GIT.is_absolute() and _safe_regular(GIT,Path("/")))


def _bounded_json(completed: subprocess.CompletedProcess[bytes]) -> dict[str, Any] | None:
    if len(completed.stdout)>MAX_COMMAND_OUTPUT or completed.stderr:
        return None
    try: value=json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError,json.JSONDecodeError): return None
    return value if isinstance(value,dict) else None


def _safe_directory(path: Path, *, create: bool) -> None:
    try: metadata=path.lstat()
    except FileNotFoundError:
        if not create: raise OSError
        os.mkdir(path,0o700); metadata=path.lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid!=os.getuid() or stat.S_IMODE(metadata.st_mode)&0o022):
        raise OSError


def _safe_log_file(path: Path) -> None:
    if not path.exists() and not path.is_symlink(): return
    metadata=path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid!=os.getuid() or stat.S_IMODE(metadata.st_mode)!=0o600):
        raise OSError


@contextmanager
def _log_lock(path: Path):
    flags=os.O_CREAT|os.O_RDWR|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0)
    descriptor=os.open(path,flags,0o600)
    try:
        metadata=os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode)!=0o600: raise OSError
        fcntl.flock(descriptor,fcntl.LOCK_EX)
        try: yield
        finally: fcntl.flock(descriptor,fcntl.LOCK_UN)
    finally: os.close(descriptor)


def append_log(runtime_root: Path, record: dict[str, Any]) -> None:
    if (not isinstance(record,dict) or not set(record)<=LOG_KEYS
            or set(record)-{"requests_24h","collector_invocations"}!={"timestamp","outcome","circuit_state"}
            or not isinstance(record["timestamp"],str) or len(record["timestamp"])!=20
            or record["outcome"] not in LOG_OUTCOMES or record["circuit_state"] not in CIRCUIT_STATES):
        raise OSError
    for field in ("requests_24h","collector_invocations"):
        if field in record and (type(record[field]) is not int or not 0<=record[field]<=24): raise OSError
    engagement=runtime_root/"runtime/engagement"
    _safe_directory(runtime_root,create=False)
    _safe_directory(runtime_root/"runtime",create=False)
    _safe_directory(engagement,create=False)
    directory=engagement/"launcher-logs"
    _safe_directory(directory,create=True)
    lock=directory/"launcher.log.lock"
    payload=(json.dumps(record,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n").encode()
    if len(payload)>4096: raise OSError
    with _log_lock(lock):
        paths=[directory/"launcher.jsonl"]+[directory/f"launcher.jsonl.{i}"
                for i in range(1,LOG_GENERATIONS)]
        for path in paths: _safe_log_file(path)
        current=paths[0]
        size=current.stat().st_size if current.exists() else 0
        if size+len(payload)>MAX_LOG_BYTES:
            for index in range(LOG_GENERATIONS-1,0,-1):
                source=paths[index-1]; destination=paths[index]
                if source.exists(): os.replace(source,destination)
        flags=os.O_CREAT|os.O_APPEND|os.O_WRONLY|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0)
        descriptor=os.open(current,flags,0o600)
        try:
            metadata=os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode)!=0o600: raise OSError
            written=0
            while written<len(payload):
                count=os.write(descriptor,payload[written:])
                if count<=0: raise OSError
                written+=count
            os.fsync(descriptor)
        finally: os.close(descriptor)


def append_prelog(runtime_root: Path, stage: str, error_class: str,
                  approved_revision: str) -> None:
    record={"timestamp":_utc_stamp(),"stage":stage,"error_class":error_class,
            "approved_revision":approved_revision,"runtime_version":RUNTIME_VERSION}
    if set(record)!=PRELOG_KEYS or not re.fullmatch(r"[A-Z_]+",error_class): raise OSError
    engagement=runtime_root/"runtime/engagement"
    _safe_directory(runtime_root,create=False); _safe_directory(runtime_root/"runtime",create=False)
    _safe_directory(engagement,create=False)
    directory=engagement/"launcher-logs"; _safe_directory(directory,create=True)
    path=directory/"launcher-preflight.jsonl"; _safe_log_file(path)
    payload=(json.dumps(record,sort_keys=True,separators=(",",":"))+"\n").encode()
    flags=os.O_CREAT|os.O_APPEND|os.O_WRONLY|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0)
    descriptor=os.open(path,flags,0o600)
    try:
        metadata=os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode)!=0o600: raise OSError
        if metadata.st_size+len(payload)>MAX_LOG_BYTES:
            os.ftruncate(descriptor,0); os.lseek(descriptor,0,os.SEEK_SET)
        os.write(descriptor,payload); os.fsync(descriptor)
    finally: os.close(descriptor)


def _preflight_failure(runtime_root: Path, expected_revision: str, outcome: str,
                       stage: str) -> dict[str, Any]:
    try: append_prelog(runtime_root,stage,outcome,expected_revision)
    except OSError: pass
    return _result(outcome)


def launch(runtime_root: Path, expected_revision: str, *, runner: Runner = _run,
           code_root: Path = CODE_ROOT) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{40}",expected_revision):
        return _preflight_failure(runtime_root,expected_revision,"CODE_REVISION_MISMATCH","REVISION")
    if code_root!=CODE_ROOT or not _code_paths_safe(code_root):
        return _preflight_failure(runtime_root,expected_revision,"CODE_PATH_UNSAFE","CODE_PATH")
    runtime_error=validate_runtime(runtime_root,expected_revision,require_production=True)
    if runtime_error:
        return _preflight_failure(runtime_root,expected_revision,runtime_error,"RUNTIME")
    try:
        revision=runner([str(GIT),"rev-parse","HEAD"],code_root,5)
        if (revision.returncode!=0 or revision.stderr or len(revision.stdout)>64
                or revision.stdout.decode("ascii").strip()!=expected_revision):
            return _preflight_failure(runtime_root,expected_revision,"CODE_REVISION_MISMATCH","REVISION")
        clean=runner([str(GIT),"diff-index","--quiet","HEAD","--"],code_root,5)
        if clean.returncode!=0: return _preflight_failure(runtime_root,expected_revision,"CODE_TREE_DIRTY","CODE_TREE")
        untracked=runner([str(GIT),"ls-files","--others","--exclude-standard","-z"],code_root,5)
        if untracked.returncode!=0 or untracked.stderr or untracked.stdout:
            return _preflight_failure(runtime_root,expected_revision,"CODE_TREE_DIRTY","CODE_TREE")
        ignored_code=runner([str(GIT),"ls-files","--others","--ignored","--exclude-standard",
                             "-z","--","scripts","src"],code_root,5)
        if (ignored_code.returncode!=0 or ignored_code.stderr
                or _ignored_code_present(ignored_code.stdout,code_root)):
            return _preflight_failure(runtime_root,expected_revision,"CODE_TREE_DIRTY","CODE_TREE")
        status=runner(_scheduler_command("status",runtime_root),code_root,10)
        raw_state=_bounded_json(status); state=validate_scheduler_status_result(raw_state)
        if state is None:
            outcome="STATE_MISSING" if raw_state and raw_state.get("outcome")=="SCHEDULER_STATE_MISSING" else "STATE_INVALID"
            return _result(outcome)
        append_log(runtime_root,{"timestamp":_utc_stamp(),"outcome":"PREFLIGHT_READY",
                   "circuit_state":state.get("circuit_state"),"requests_24h":state.get("requests_24h")})
    except (OSError,subprocess.SubprocessError,UnicodeDecodeError):
        return _result("LOG_UNAVAILABLE",log_persisted=False,
                       log_error_class="LOG_UNAVAILABLE") if 'state' in locals() else _result("LAUNCHER_INTERNAL_ERROR")
    command=_scheduler_command("run-once",runtime_root)
    try: completed=runner(command,code_root,40)
    except (OSError,subprocess.SubprocessError):
        return _result("LAUNCHER_INTERNAL_ERROR",scheduler_invoked=True,
                       scheduler_outcome="SCHEDULER_RESULT_INVALID")
    value=_validated_scheduler_result(_bounded_json(completed),completed.returncode)
    if not value: result=_result("LAUNCHER_INTERNAL_ERROR",scheduler_invoked=True,
                                 scheduler_outcome="SCHEDULER_RESULT_INVALID",log_persisted=True)
    else:
        invocations=value["collector_invocations"]
        scheduler_outcome=value.get("outcome")
        disabled=(value.get("outcome")=="SCHEDULER_DISABLED" and invocations==0)
        result=_result("OK_DISABLED" if disabled else "OK_SCHEDULER_INVOKED",
                       success=disabled or value.get("success") is True,scheduler_invoked=True,
                       scheduler_outcome=scheduler_outcome,collector_invocations=invocations,
                       circuit_state=value.get("circuit_state"),log_persisted=True)
    try:
        append_log(runtime_root,{"timestamp":_utc_stamp(),"outcome":result["outcome"],
                   "circuit_state":result["circuit_state"],
                   "collector_invocations":result["collector_invocations"]})
    except OSError:
        return {**result,"success":False,"log_persisted":False,
                "log_error_class":"LOG_UNAVAILABLE"}
    return result


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-revision",required=True)
    parser.add_argument("--runtime-root",type=Path,required=True)
    args=parser.parse_args()
    result=launch(Path(os.path.abspath(args.runtime_root)),args.expected_revision)
    print(json.dumps(result,sort_keys=True,separators=(",",":")))
    if not result["success"]: raise SystemExit(1)


if __name__=="__main__": main()
