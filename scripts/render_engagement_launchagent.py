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
from pathlib import Path
from typing import Callable

CODE_ROOT=Path(__file__).resolve().parents[1]
GIT=Path("/usr/bin/git")
TEMPLATE=CODE_ROOT/"launchd/com.flop-agent-intelligence.engagement-scheduler.plist.template"
LAUNCHER=CODE_ROOT/"scripts/engagement_scheduler_launcher.py"
SAFE_ENV={"PATH":"/usr/bin:/bin","LC_ALL":"C","TMPDIR":"/tmp"}
Runner=Callable[[list[str],Path,int],subprocess.CompletedProcess[bytes]]


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


def render(output: Path,runtime_root: Path,expected_revision: str,*,runner: Runner=_run,
           code_root: Path=CODE_ROOT) -> dict[str,object]:
    base={"success":False,"outcome":"PLIST_RENDER_INVALID","plist_created":False,
          "installed":False,"loaded":False,"network_requests":0,"collector_invocations":0}
    output=output.absolute(); runtime_root=runtime_root.absolute()
    active=(Path.home()/"Library/LaunchAgents").absolute()
    if not re.fullmatch(r"[0-9a-f]{40}",expected_revision): return {**base,"outcome":"CODE_REVISION_MISMATCH"}
    if (output.parent==active or code_root!=CODE_ROOT or not _safe_directory(code_root)
            or not _safe_directory(runtime_root,private=True)
            or not _safe_file(TEMPLATE,code_root) or not _safe_file(LAUNCHER,code_root)
            or not _safe_directory(output.parent,private=True)):
        return {**base,"outcome":"CODE_PATH_UNSAFE"}
    if output.exists() or output.is_symlink(): return {**base,"outcome":"PLIST_ALREADY_EXISTS"}
    try:
        revision=runner([str(GIT),"rev-parse","HEAD"],code_root,5)
        dirty=runner([str(GIT),"diff-index","--quiet","HEAD","--"],code_root,5)
        if (revision.returncode or revision.stderr or len(revision.stdout)>64
                or revision.stdout.decode("ascii").strip()!=expected_revision):
            return {**base,"outcome":"CODE_REVISION_MISMATCH"}
        if dirty.returncode: return {**base,"outcome":"CODE_TREE_DIRTY"}
        value=plistlib.loads(TEMPLATE.read_bytes())
        arguments=value.get("ProgramArguments")
        expected=["/usr/bin/python3","-I","<APPROVED_REPOSITORY_ROOT>/scripts/engagement_scheduler_launcher.py",
                  "--expected-revision","<APPROVED_GIT_REVISION>","--runtime-root","<PRIVATE_RUNTIME_ROOT>"]
        if arguments!=expected: return base
        value["ProgramArguments"]=["/usr/bin/python3","-I",str(LAUNCHER),"--expected-revision",
                                   expected_revision,"--runtime-root",str(runtime_root)]
        payload=plistlib.dumps(value,fmt=plistlib.FMT_XML,sort_keys=True)
        if b"<APPROVED_" in payload or b"<PRIVATE_" in payload: return base
        descriptor=os.open(output,os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,"O_NOFOLLOW",0),0o600)
        try:
            written=0
            while written<len(payload):
                count=os.write(descriptor,payload[written:])
                if count<=0: raise OSError
                written+=count
            os.fsync(descriptor)
        finally: os.close(descriptor)
        directory=os.open(output.parent,os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    except (OSError,UnicodeDecodeError,plistlib.InvalidFileException,subprocess.SubprocessError):
        created=output.exists() and not output.is_symlink()
        return {**base,"outcome":"PLIST_COMMITTED_NOT_DURABLE" if created else "PLIST_RENDER_FAILED",
                "plist_created":created}
    return {**base,"success":True,"outcome":"PLIST_RENDERED","plist_created":True}


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
