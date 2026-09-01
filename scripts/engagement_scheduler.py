#!/usr/bin/env python3
"""Manage the disabled-by-default local Engagement scheduler policy."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from flop_agent.engagement_scheduler import FAILURE_CLASSES, approve_reset, dry_run, evaluate, load_state, run_once


def _collector(root: Path) -> dict:
    command = [sys.executable, str(root / "scripts/collect_engagement.py"), "--root", str(root)]
    try:
        completed = subprocess.run(command, cwd=root, capture_output=True, timeout=35, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {"success":False,"error_class":"WORKER_CRASHED"}
    if len(completed.stdout) > 512 * 1024:
        return {"success":False,"error_class":"WORKER_PROTOCOL_ERROR"}
    try: result = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"success":False,"error_class":"WORKER_PROTOCOL_ERROR"}
    if not isinstance(result, dict) or type(result.get("success")) is not bool:
        return {"success":False,"error_class":"WORKER_PROTOCOL_ERROR"}
    error = result.get("error_class") or result.get("cleanup_error")
    if error in FAILURE_CLASSES: return {"success":False,"error_class":error}
    if result["success"] and error is None and completed.returncode == 0:
        return {"success":True,"error_class":None}
    return {"success":False,"error_class":error if error in FAILURE_CLASSES else "VALIDATION_FAILED"}


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command",choices=("status","dry-run","run-once","approve-reset"))
    parser.add_argument("--root",type=Path,default=Path(__file__).resolve().parents[1])
    args=parser.parse_args(); root=args.root.resolve()
    state_path=root/"runtime/engagement/scheduler-state.json"
    lock_path=root/"runtime/engagement/scheduler-state.lock"
    if args.command == "status":
        try: result={"success":True,**evaluate(load_state(state_path))}
        except Exception as error: result={"success":False,"outcome":getattr(error,"code","SCHEDULER_STATE_INVALID")}
    elif args.command == "dry-run": result=dry_run(state_path,lock_path)
    elif args.command == "approve-reset": result=approve_reset(state_path,lock_path)
    else: result=run_once(state_path,lock_path,lambda:_collector(root))
    print(json.dumps(result,indent=2))
    if result.get("success") is False and args.command not in {"status","dry-run"}: raise SystemExit(1)


if __name__ == "__main__": main()
