#!/usr/bin/env python3
"""Manage the disabled-by-default local Engagement scheduler policy."""

from __future__ import annotations

import argparse
import json
import math
import os
import stat
import subprocess
import sys
from pathlib import Path

from flop_agent.engagement_scheduler import FAILURE_CLASSES, approve_reset, dry_run, evaluate, load_state, run_once

CODE_ROOT = Path(__file__).resolve().parents[1]
REVIEWED_COLLECTOR = CODE_ROOT / "scripts/collect_engagement.py"
RESULT_KEYS = {
    "ok", "success", "sample", "commit_state", "preview_state", "cleanup_state",
    "deadline_cleanup_overrun", "error_class", "durability_warning", "preview_warning",
    "cleanup_error", "network_diagnostics",
}
FAILURE_RESULT_KEYS = (RESULT_KEYS - {"ok", "sample"}) | {"collector_version", "git_revision"}
DIAGNOSTIC_KEYS = {
    "failure_stage", "total_elapsed_seconds", "open_elapsed_seconds", "body_elapsed_seconds",
    "http_status", "response_bytes", "configured_socket_timeout", "configured_total_deadline",
}


def _valid_diagnostics(value: object, *, success: bool) -> bool:
    if not isinstance(value, dict) or set(value) != DIAGNOSTIC_KEYS:
        return False
    if value["failure_stage"] not in {None, "HTTP_OPEN", "HTTP_BODY"}:
        return False
    for name in ("total_elapsed_seconds", "open_elapsed_seconds", "body_elapsed_seconds"):
        number = value[name]
        if number is not None and (type(number) not in (int, float) or not math.isfinite(number) or not 0 <= number <= 30.01):
            return False
    for name in ("configured_socket_timeout", "configured_total_deadline"):
        number = value[name]
        if type(number) not in (int, float) or not math.isfinite(number) or not 0 < number <= 30:
            return False
    status = value["http_status"]
    size = value["response_bytes"]
    if status is not None and (type(status) is not int or not 100 <= status <= 599): return False
    if size is not None and (type(size) is not int or not 0 <= size <= 2 * 1024 * 1024): return False
    if success:
        total, opened, body = (value[name] for name in ("total_elapsed_seconds", "open_elapsed_seconds", "body_elapsed_seconds"))
        return (value["failure_stage"] is None and all(item is not None for item in (total, opened, body, status, size))
                and 200 <= status < 300 and total + .01 >= opened + body)
    return True


def _validated_result(result: object, returncode: int) -> dict:
    invalid = {"success":False, "error_class":"COLLECTOR_RESULT_INVALID"}
    if not isinstance(result, dict) or type(result.get("success")) is not bool:
        return invalid
    success = result["success"]
    expected_keys = RESULT_KEYS if success else FAILURE_RESULT_KEYS
    if set(result) != expected_keys or type(result.get("deadline_cleanup_overrun")) is not bool:
        return invalid
    diagnostics = result.get("network_diagnostics")
    if diagnostics is not None and not _valid_diagnostics(diagnostics, success=success):
        return invalid
    if success:
        if (returncode != 0 or result.get("ok") is not True or not isinstance(result.get("sample"), dict)
                or result.get("error_class") is not None):
            return invalid
        if result.get("commit_state") != "DURABLE" or result.get("durability_warning") is not None:
            if (result.get("commit_state") == "COMMITTED"
                    and result.get("durability_warning") == "POST_COMMIT_DURABILITY_WARNING"):
                return {"success":False, "error_class":"COLLECTOR_RESULT_NOT_DURABLE"}
            return invalid
        if result.get("preview_state") != "UPDATED" or result.get("preview_warning") is not None:
            return {"success":False, "error_class":"COLLECTOR_PREVIEW_FAILED"}
        if result.get("cleanup_state") != "COMPLETED" or result.get("cleanup_error") is not None:
            error = result.get("cleanup_error")
            return {"success":False, "error_class":error if error in FAILURE_CLASSES else "COLLECTOR_RESULT_INVALID"}
        if result["deadline_cleanup_overrun"] or diagnostics is None:
            return {"success":False, "error_class":"TOTAL_DEADLINE_EXCEEDED" if result["deadline_cleanup_overrun"] else "COLLECTOR_RESULT_INVALID"}
        return {"success":True, "error_class":None}
    if (returncode == 0 or result.get("commit_state") != "PRE_COMMIT"
            or result.get("preview_state") != "NOT_ATTEMPTED" or result.get("preview_warning") is not None
            or result.get("durability_warning") is not None or result.get("cleanup_state") != "COMPLETED"
            or result.get("cleanup_error") is not None or result["deadline_cleanup_overrun"]
            or result.get("collector_version") != "0.1.0"
            or result.get("git_revision") is not None):
        return invalid
    error = result.get("error_class")
    if error in {"HTTP_OPEN_TIMEOUT", "HTTP_OPEN_FAILED", "HTTP_BODY_TIMEOUT", "HTTP_BODY_FAILED"}:
        expected_stage = "HTTP_OPEN" if error.startswith("HTTP_OPEN") else "HTTP_BODY"
        if diagnostics is None or diagnostics["failure_stage"] != expected_stage:
            return invalid
    return {"success":False, "error_class":error if error in FAILURE_CLASSES else "COLLECTOR_RESULT_INVALID"}


def _collector(root: Path) -> dict:
    try:
        collector = REVIEWED_COLLECTOR.resolve(strict=True)
        expected = (CODE_ROOT / "scripts/collect_engagement.py").absolute()
        metadata = os.lstat(expected)
        if collector != expected or stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            return {"success":False,"error_class":"COLLECTOR_RESULT_INVALID"}
    except (OSError, RuntimeError):
        return {"success":False,"error_class":"COLLECTOR_RESULT_INVALID"}
    command = [sys.executable, str(collector), "--root", str(root)]
    try:
        completed = subprocess.run(command, cwd=root, capture_output=True, timeout=35, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {"success":False,"error_class":"WORKER_CRASHED"}
    if len(completed.stdout) > 512 * 1024:
        return {"success":False,"error_class":"WORKER_PROTOCOL_ERROR"}
    try: result = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"success":False,"error_class":"WORKER_PROTOCOL_ERROR"}
    return _validated_result(result, completed.returncode)


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
