#!/usr/bin/env python3
"""Pinned, offline-preflight launcher for a future Engagement LaunchAgent."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import stat
import subprocess
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

CODE_ROOT = Path(__file__).resolve().parents[1]
PYTHON = Path("/usr/bin/python3")
GIT = Path("/usr/bin/git")
SCHEDULER = CODE_ROOT / "scripts/engagement_scheduler.py"
COLLECTOR = CODE_ROOT / "scripts/collect_engagement.py"
SCHEDULER_MODULE = CODE_ROOT / "src/flop_agent/engagement_scheduler.py"
LABEL = "com.flop-agent-intelligence.engagement-scheduler"
MAX_COMMAND_OUTPUT = 64 * 1024
MAX_LOG_BYTES = 1024 * 1024
LOG_GENERATIONS = 3
LOG_KEYS = {"timestamp","outcome","circuit_state","requests_24h","collector_invocations"}
LOG_OUTCOMES = {"PREFLIGHT_READY","OK_DISABLED","OK_SCHEDULER_INVOKED",
                "LAUNCHER_INTERNAL_ERROR","LOG_UNAVAILABLE"}
CIRCUIT_STATES = {"READY_DISABLED","READY","DEGRADED","CIRCUIT_OPEN",None}
SAFE_ENV = {"PATH":"/usr/bin:/bin", "LC_ALL":"C", "TMPDIR":"/tmp",
            "PYTHONDONTWRITEBYTECODE":"1"}
SCHEDULER_OUTCOMES = {
    "SCHEDULER_DISABLED", "SCHEDULER_READY", "SCHEDULER_MIN_INTERVAL",
    "SCHEDULER_DAILY_BUDGET_EXCEEDED", "SCHEDULER_CIRCUIT_OPEN",
    "SCHEDULER_RUN_ALREADY_ACTIVE", "SCHEDULER_COLLECTION_SUCCEEDED",
    "SCHEDULER_COLLECTION_FAILED", "SCHEDULER_RECOVERED_INTERRUPTED_RUN",
    "SCHEDULER_STATE_MISSING", "SCHEDULER_STATE_INVALID", "SCHEDULER_STATE_PATH_UNSAFE",
    "SCHEDULER_STATE_PERMISSIONS", "SCHEDULER_STATE_LOCK_FAILED",
    "SCHEDULER_RESULT_INVALID",
}

Runner = Callable[[list[str], Path, int], subprocess.CompletedProcess[bytes]]


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
    return [str(PYTHON),"-I","-c",isolated_entry,action,"--root",str(runtime_root)]


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
        "last_error_class","normal_interval_minutes","minimum_interval_minutes",
        "next_eligible_at","requests_24h","collector_invocations","error_class"}
    if not set(value)<=allowed_keys or returncode!=(0 if value["success"] else 1): return None
    outcome=value.get("outcome"); invocations=value.get("collector_invocations")
    circuit=value.get("circuit_state")
    if type(invocations) is not int or invocations not in {0,1}: return None
    precollector={"SCHEDULER_DISABLED","SCHEDULER_MIN_INTERVAL",
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
            and PYTHON.is_absolute() and GIT.is_absolute()
            and _safe_regular(PYTHON,Path("/")) and _safe_regular(GIT,Path("/")))


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


def launch(runtime_root: Path, expected_revision: str, *, runner: Runner = _run,
           code_root: Path = CODE_ROOT) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{40}",expected_revision): return _result("CODE_REVISION_MISMATCH")
    if code_root!=CODE_ROOT or not _code_paths_safe(code_root): return _result("CODE_PATH_UNSAFE")
    try:
        revision=runner([str(GIT),"rev-parse","HEAD"],code_root,5)
        if (revision.returncode!=0 or revision.stderr or len(revision.stdout)>64
                or revision.stdout.decode("ascii").strip()!=expected_revision):
            return _result("CODE_REVISION_MISMATCH")
        clean=runner([str(GIT),"diff-index","--quiet","HEAD","--"],code_root,5)
        if clean.returncode!=0: return _result("CODE_TREE_DIRTY")
        untracked=runner([str(GIT),"ls-files","--others","--exclude-standard","-z"],code_root,5)
        if untracked.returncode!=0 or untracked.stderr or untracked.stdout:
            return _result("CODE_TREE_DIRTY")
        ignored_code=runner([str(GIT),"ls-files","--others","--ignored","--exclude-standard",
                             "-z","--","scripts","src"],code_root,5)
        if (ignored_code.returncode!=0 or ignored_code.stderr
                or _ignored_code_present(ignored_code.stdout,code_root)):
            return _result("CODE_TREE_DIRTY")
        status=runner(_scheduler_command("status",runtime_root),code_root,10)
        state=_bounded_json(status)
        if not state or state.get("success") is not True:
            outcome="STATE_MISSING" if state and state.get("outcome")=="SCHEDULER_STATE_MISSING" else "STATE_INVALID"
            return _result(outcome)
        if (state.get("circuit_state") not in CIRCUIT_STATES-{None}
                or type(state.get("requests_24h")) is not int
                or not 0<=state["requests_24h"]<=24):
            return _result("STATE_INVALID")
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
