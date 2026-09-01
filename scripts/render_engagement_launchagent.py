#!/usr/bin/env python3
"""Render an unloaded private Engagement LaunchAgent plist after offline trust checks."""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

CODE_ROOT=Path(__file__).resolve().parents[1]
GIT=Path("/usr/bin/git")
TEMPLATE=CODE_ROOT/"launchd/com.flop-agent-intelligence.engagement-scheduler.plist.template"
LAUNCHER=CODE_ROOT/"scripts/engagement_scheduler_launcher.py"
SAFE_ENV={"PATH":"/usr/bin:/bin","LC_ALL":"C","TMPDIR":"/tmp"}
Runner=Callable[[list[str],Path,int],subprocess.CompletedProcess[bytes]]
COMMIT_STATES={"PRE_PUBLISH","PUBLISHED","DURABLE"}


def _run(command: list[str],cwd: Path,timeout: int) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command,cwd=cwd,env=SAFE_ENV,capture_output=True,check=False,timeout=timeout)


def _safe_file(path: Path,root: Path) -> bool:
    try: metadata=os.lstat(path)
    except OSError: return False
    return (path.is_absolute() and path.is_relative_to(root) and stat.S_ISREG(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode) and path.resolve()==path)


def _safe_directory(path: Path, *, private: bool = False) -> bool:
    try: metadata=os.lstat(path)
    except OSError: return False
    mode=stat.S_IMODE(metadata.st_mode)
    safe_mode=mode==0o700 if private else not mode&0o022
    return (path.is_absolute() and stat.S_ISDIR(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode) and metadata.st_uid==os.getuid()
            and safe_mode and path.resolve()==path)


def _result(*,success: bool,outcome: str,commit_state: str="PRE_PUBLISH",
            error_class: str | None=None) -> dict[str,object]:
    if commit_state not in COMMIT_STATES: raise ValueError("invalid plist commit state")
    created=commit_state!="PRE_PUBLISH"; durable=commit_state=="DURABLE"
    if not success and error_class is None: error_class=outcome
    if success!=(durable and error_class is None):
        raise ValueError("contradictory plist result")
    return {"success":success,"outcome":outcome,"error_class":error_class,
            "plist_created":created,"commit_state":commit_state,
            "durability_confirmed":durable,"installed":False,"loaded":False,
            "network_requests":0,"collector_invocations":0}


def _valid_payload(payload: bytes,expected_revision: str,runtime_root: Path) -> bool:
    try: value=plistlib.loads(payload)
    except plistlib.InvalidFileException: return False
    arguments=["/usr/bin/python3","-I",str(LAUNCHER),"--expected-revision",
               expected_revision,"--runtime-root",str(runtime_root)]
    keys={"Label","ProgramArguments","StartInterval","RunAtLoad",
          "StandardOutPath","StandardErrorPath"}
    if (not isinstance(value,dict) or set(value)!=keys
            or value.get("Label")!="com.flop-agent-intelligence.engagement-scheduler"
            or value.get("ProgramArguments")!=arguments
            or value.get("StartInterval")!=3600 or value.get("RunAtLoad") is not False
            or value.get("StandardOutPath")!="/dev/null"
            or value.get("StandardErrorPath")!="/dev/null"):
        return False
    def strings(item: object):
        if isinstance(item,str): yield item
        elif isinstance(item,list):
            for child in item: yield from strings(child)
        elif isinstance(item,dict):
            for key,child in item.items(): yield key; yield from strings(child)
    return not any(re.search(r"<[^<>]+>",item) for item in strings(value))


def render(output: Path,runtime_root: Path,expected_revision: str,*,runner: Runner=_run,
           code_root: Path=CODE_ROOT) -> dict[str,object]:
    output=output.absolute(); runtime_root=runtime_root.absolute()
    active=(Path.home()/"Library/LaunchAgents").absolute()
    if not re.fullmatch(r"[0-9a-f]{40}",expected_revision):
        return _result(success=False,outcome="CODE_REVISION_MISMATCH")
    if (output.parent==active or code_root!=CODE_ROOT or not _safe_directory(code_root)
            or not _safe_directory(runtime_root,private=True)
            or not _safe_file(TEMPLATE,code_root) or not _safe_file(LAUNCHER,code_root)
            or not _safe_directory(output.parent,private=True)):
        return _result(success=False,outcome="CODE_PATH_UNSAFE")
    if output.exists() or output.is_symlink():
        return _result(success=False,outcome="PLIST_ALREADY_EXISTS")
    candidate: Path | None=None; descriptor=-1; published=False
    try:
        revision=runner([str(GIT),"rev-parse","HEAD"],code_root,5)
        dirty=runner([str(GIT),"diff-index","--quiet","HEAD","--"],code_root,5)
        if (revision.returncode or revision.stderr or len(revision.stdout)>64
                or revision.stdout.decode("ascii").strip()!=expected_revision):
            return _result(success=False,outcome="CODE_REVISION_MISMATCH")
        if dirty.returncode: return _result(success=False,outcome="CODE_TREE_DIRTY")
        value=plistlib.loads(TEMPLATE.read_bytes())
        arguments=value.get("ProgramArguments")
        expected=["/usr/bin/python3","-I","<APPROVED_REPOSITORY_ROOT>/scripts/engagement_scheduler_launcher.py",
                  "--expected-revision","<APPROVED_GIT_REVISION>","--runtime-root","<PRIVATE_RUNTIME_ROOT>"]
        if arguments!=expected: return _result(success=False,outcome="PLIST_RENDER_INVALID")
        value["ProgramArguments"]=["/usr/bin/python3","-I",str(LAUNCHER),"--expected-revision",
                                   expected_revision,"--runtime-root",str(runtime_root)]
        payload=plistlib.dumps(value,fmt=plistlib.FMT_XML,sort_keys=True)
        if not _valid_payload(payload,expected_revision,runtime_root):
            return _result(success=False,outcome="PLIST_RENDER_INVALID")
        descriptor,name=tempfile.mkstemp(prefix=f".{output.name}.candidate-",dir=output.parent)
        candidate=Path(name)
        metadata=os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode)!=0o600:
            raise OSError("unsafe candidate")
        written=0
        while written<len(payload):
            count=os.write(descriptor,payload[written:])
            if count<=0: raise OSError("short candidate write")
            written+=count
        os.fsync(descriptor); os.close(descriptor); descriptor=-1
        candidate_payload=candidate.read_bytes()
        if candidate_payload!=payload or not _valid_payload(candidate_payload,expected_revision,runtime_root):
            return _result(success=False,outcome="PLIST_CANDIDATE_INVALID")
        try: os.link(candidate,output,follow_symlinks=False)
        except FileExistsError:
            return _result(success=False,outcome="PLIST_ALREADY_EXISTS")
        published=True
        candidate.unlink(); candidate=None
        directory=os.open(output.parent,os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
        try: visible=output.read_bytes()
        except OSError:
            return _result(success=False,outcome="PLIST_PUBLISHED_VALIDATION_FAILED",
                           commit_state="DURABLE")
        if visible!=payload or not _valid_payload(visible,expected_revision,runtime_root):
            return _result(success=False,outcome="PLIST_PUBLISHED_VALIDATION_FAILED",
                           commit_state="DURABLE")
        return _result(success=True,outcome="PLIST_RENDERED",commit_state="DURABLE")
    except (OSError,UnicodeDecodeError,plistlib.InvalidFileException,subprocess.SubprocessError):
        return _result(success=False,outcome=("PLIST_COMMITTED_NOT_DURABLE" if published
                                              else "PLIST_RENDER_FAILED"),
                       commit_state="PUBLISHED" if published else "PRE_PUBLISH")
    finally:
        if descriptor>=0: os.close(descriptor)
        if candidate is not None:
            try: candidate.unlink(missing_ok=True)
            except OSError: pass


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--runtime-root",type=Path,required=True)
    parser.add_argument("--expected-revision",required=True)
    args=parser.parse_args()
    result=render(args.output,args.runtime_root,args.expected_revision)
    print(json.dumps(result,sort_keys=True,separators=(",",":")))
    if not result["success"]: raise SystemExit(1)


if __name__=="__main__": main()
