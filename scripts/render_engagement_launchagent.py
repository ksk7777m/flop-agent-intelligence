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
RUNTIME_SCHEMA="engagement-production-runtime-v1"
PRODUCTION_ELIGIBLE="PRODUCTION_ELIGIBLE"
PREVIEW_ONLY="PREVIEW_ONLY_FEATURE_REVISION"


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
            error_class: str | None=None,eligibility: str="PRODUCTION_INELIGIBLE_REVISION",
            installable: bool=False,artifact_format: str | None=None) -> dict[str,object]:
    if commit_state not in COMMIT_STATES: raise ValueError("invalid plist commit state")
    created=commit_state!="PRE_PUBLISH"; durable=commit_state=="DURABLE"
    if not success and error_class is None: error_class=outcome
    if success!=(durable and error_class is None):
        raise ValueError("contradictory plist result")
    return {"success":success,"outcome":outcome,"error_class":error_class,
            "plist_created":created,"commit_state":commit_state,
            "durability_confirmed":durable,"installed":False,"loaded":False,
            "network_requests":0,"collector_invocations":0,"eligibility":eligibility,
            "installable":installable,"artifact_format":artifact_format}


def _valid_payload(payload: bytes,expected_revision: str,runtime_root: Path) -> bool:
    try: value=plistlib.loads(payload)
    except plistlib.InvalidFileException: return False
    arguments=[str(runtime_root/"generations"/expected_revision/"python/bin/python3"),"-I",str(LAUNCHER),"--expected-revision",
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


def _runtime_ready(runtime_root: Path, expected_revision: str, code_root: Path,
                   require_production: bool) -> bool:
    generation=runtime_root/"generations"/expected_revision
    manifest=generation/"production-runtime.json"; interpreter=generation/"python/bin/python3"
    try:
        metadata=manifest.lstat(); python_metadata=interpreter.lstat()
        value=json.loads(manifest.read_text(encoding="utf-8"))
        structural=(stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_uid==os.getuid() and stat.S_IMODE(metadata.st_mode)==0o600
            and stat.S_ISLNK(python_metadata.st_mode)
            and os.readlink(interpreter)=="/Library/Developer/CommandLineTools/usr/bin/python3"
            and stat.S_ISREG(interpreter.resolve().lstat().st_mode)
            and interpreter.resolve().lstat().st_uid==0
            and value.get("schema")==RUNTIME_SCHEMA
            and value.get("project_revision")==expected_revision
            and value.get("python")=="python/bin/python3"
            and value.get("project_root")==str(code_root))
        if not structural: return False
        entry=("import json,sys;"+f"sys.path.insert(0,{str(code_root/'scripts')!r});"
               "import engagement_scheduler_launcher as l;"
               f"print(json.dumps(l.validate_runtime(__import__('pathlib').Path({str(runtime_root)!r}),{expected_revision!r},require_production={require_production!r})))")
        checked=subprocess.run([str(interpreter),"-I","-c",entry],cwd=code_root,env=SAFE_ENV,
                               capture_output=True,check=False,timeout=10)
        return checked.returncode==0 and not checked.stderr and checked.stdout==b"null\n"
    except (OSError,RuntimeError,UnicodeDecodeError,json.JSONDecodeError): return False


def render(output: Path,runtime_root: Path,expected_revision: str,*,runner: Runner=_run,
           code_root: Path=CODE_ROOT,production: bool=False,
           approved_main_revision: str | None=None,
           verified_origin_revision: str | None=None) -> dict[str,object]:
    output=output.absolute(); runtime_root=runtime_root.absolute()
    active=(Path.home()/"Library/LaunchAgents").absolute()
    if not re.fullmatch(r"[0-9a-f]{40}",expected_revision):
        return _result(success=False,outcome="CODE_REVISION_MISMATCH")
    if (output.parent==active or code_root!=CODE_ROOT or not _safe_directory(code_root)
            or not _safe_directory(runtime_root,private=True)
            or not _safe_file(TEMPLATE,code_root) or not _safe_file(LAUNCHER,code_root)
            or not _safe_directory(output.parent,private=True)):
        return _result(success=False,outcome="CODE_PATH_UNSAFE")
    if not _runtime_ready(runtime_root,expected_revision,code_root,production):
        return _result(success=False,outcome="PRODUCTION_RUNTIME_NOT_READY")
    if output.exists() or output.is_symlink():
        return _result(success=False,outcome="PLIST_ALREADY_EXISTS")
    candidate: Path | None=None; descriptor=-1; published=False
    try:
        revision=runner([str(GIT),"rev-parse","HEAD"],code_root,5)
        dirty=runner([str(GIT),"diff-index","--quiet","HEAD","--"],code_root,5)
        untracked=runner([str(GIT),"ls-files","--others","--exclude-standard","-z"],code_root,5)
        if (revision.returncode or revision.stderr or len(revision.stdout)>64
                or revision.stdout.decode("ascii").strip()!=expected_revision):
            return _result(success=False,outcome="CODE_REVISION_MISMATCH")
        if (dirty.returncode or untracked.returncode or untracked.stderr or untracked.stdout):
            return _result(success=False,outcome="CODE_TREE_DIRTY")
        branch=runner([str(GIT),"symbolic-ref","--short","HEAD"],code_root,5)
        origin=runner([str(GIT),"rev-parse","refs/remotes/origin/main"],code_root,5)
        is_main=(branch.returncode==0 and not branch.stderr
                 and branch.stdout.decode("ascii").strip()=="main")
        eligible=(is_main and approved_main_revision==expected_revision
            and verified_origin_revision==expected_revision and origin.returncode==0
            and not origin.stderr and origin.stdout.decode("ascii").strip()==expected_revision)
        eligibility=PRODUCTION_ELIGIBLE if eligible else (PREVIEW_ONLY if not is_main
            else "PRODUCTION_INELIGIBLE_REVISION")
        if production and not eligible:
            return _result(success=False,outcome="PRODUCTION_REVISION_NOT_ELIGIBLE",
                           eligibility=eligibility)
        if not production:
            if output.suffix!=".json": return _result(success=False,outcome="PREVIEW_PATH_INVALID",
                                                       eligibility=eligibility)
            preview={"schema":"engagement-launchagent-preview-v1","installability":"NON_INSTALLABLE",
                "eligibility":eligibility,"label":"com.flop-agent-intelligence.engagement-scheduler",
                "start_interval":3600,"run_at_load":False,"keep_alive":False,
                "interpreter":str(runtime_root/"generations"/expected_revision/"python/bin/python3"),
                "launcher":str(LAUNCHER),"revision":expected_revision,"runtime_root":str(runtime_root)}
            payload=(json.dumps(preview,sort_keys=True,separators=(",",":"))+"\n").encode()
            validator=lambda data: json.loads(data).get("installability")=="NON_INSTALLABLE"
            outcome="PLIST_PREVIEW_RENDERED"; artifact_format="NON_INSTALLABLE_JSON"
        else:
            if output.suffix!=".plist": return _result(success=False,outcome="PLIST_PATH_INVALID",
                                                        eligibility=eligibility)
            artifact_format="PLIST"; outcome="PLIST_RENDERED"
        value=plistlib.loads(TEMPLATE.read_bytes())
        arguments=value.get("ProgramArguments")
        expected=["<IMMUTABLE_RUNTIME_GENERATION>/python/bin/python3","-I","<APPROVED_REPOSITORY_ROOT>/scripts/engagement_scheduler_launcher.py",
                  "--expected-revision","<APPROVED_GIT_REVISION>","--runtime-root","<PRIVATE_RUNTIME_ROOT>"]
        if arguments!=expected: return _result(success=False,outcome="PLIST_RENDER_INVALID")
        value["ProgramArguments"]=[str(runtime_root/"generations"/expected_revision/"python/bin/python3"),"-I",str(LAUNCHER),"--expected-revision",
                                   expected_revision,"--runtime-root",str(runtime_root)]
        if production:
            payload=plistlib.dumps(value,fmt=plistlib.FMT_XML,sort_keys=True)
            validator=lambda data:_valid_payload(data,expected_revision,runtime_root)
            if not validator(payload): return _result(success=False,outcome="PLIST_RENDER_INVALID",
                eligibility=eligibility)
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
        if candidate_payload!=payload or not validator(candidate_payload):
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
        if visible!=payload or not validator(visible):
            return _result(success=False,outcome="PLIST_PUBLISHED_VALIDATION_FAILED",
                           commit_state="DURABLE")
        return _result(success=True,outcome=outcome,commit_state="DURABLE",
                       eligibility=eligibility,installable=production,
                       artifact_format=artifact_format)
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
    parser.add_argument("--production",action="store_true")
    parser.add_argument("--approved-main-revision")
    parser.add_argument("--verified-origin-revision")
    args=parser.parse_args()
    result=render(args.output,args.runtime_root,args.expected_revision,production=args.production,
        approved_main_revision=args.approved_main_revision,
        verified_origin_revision=args.verified_origin_revision)
    print(json.dumps(result,sort_keys=True,separators=(",",":")))
    if not result["success"]: raise SystemExit(1)


if __name__=="__main__": main()
