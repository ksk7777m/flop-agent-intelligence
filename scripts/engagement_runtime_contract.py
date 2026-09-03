"""Strict shared contracts for the Engagement production runtime."""

from __future__ import annotations

import os
import pwd
import stat
import sys
from pathlib import Path
from typing import Any

RUNTIME_SUFFIX = Path("Library/Application Support/flop-agent-intelligence/production-runtime")


def resolve_trusted_project_src(code_root: Path) -> Path | None:
    """Resolve this checkout's canonical, non-writable project import root."""
    expected_root=Path(__file__).resolve().parents[1]
    root=code_root.absolute(); source=root/"src"; package=source/"flop_agent"
    initializer=package/"__init__.py"
    try:
        if root!=expected_root or root.resolve()!=root: return None
        for path in (root,source,package):
            metadata=path.lstat()
            if (not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
                    or metadata.st_uid!=os.getuid() or stat.S_IMODE(metadata.st_mode)&0o022
                    or path.resolve()!=path.absolute()):
                return None
        metadata=initializer.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid!=os.getuid() or stat.S_IMODE(metadata.st_mode)&0o022
                or initializer.resolve()!=initializer.absolute()
                or not initializer.is_relative_to(source)):
            return None
    except (OSError,RuntimeError):
        return None
    return source


def install_trusted_project_import_path(code_root: Path) -> Path:
    """Install the validated repository source path ahead of all import sources."""
    source=resolve_trusted_project_src(code_root)
    if source is None: raise RuntimeError("trusted project source unavailable")
    value=str(source)
    sys.path[:]=[entry for entry in sys.path if entry!=value]
    sys.path.insert(0,value)
    return source


def resolve_account_home() -> Path | None:
    """Resolve a non-escalated user's trusted home without environment input."""
    uid=os.getuid()
    try:
        if os.geteuid()!=uid: return None
        raw=pwd.getpwuid(uid).pw_dir
        home=Path(raw)
        if not raw or not home.is_absolute() or home.resolve()!=home.absolute(): return None
        parents=list(home.parents)
        chain=[Path("/"),*reversed(parents[:-1]),home]
        for index,path in enumerate(chain):
            metadata=path.lstat()
            if (not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
                    or metadata.st_uid not in {0,uid} or stat.S_IMODE(metadata.st_mode)&0o022):
                return None
            if index==len(chain)-1 and metadata.st_uid!=uid: return None
        return home
    except (KeyError,OSError,RuntimeError,TypeError):
        return None


def production_runtime_root() -> Path | None:
    home=resolve_account_home()
    return None if home is None else (home/RUNTIME_SUFFIX).absolute()


def trusted_production_runtime_root() -> Path | None:
    """Return the existing private production root, or fail closed."""
    root=production_runtime_root()
    if root is None: return None
    try: metadata=root.lstat()
    except OSError: return None
    return root if (stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_uid==os.getuid() and stat.S_IMODE(metadata.st_mode)==0o700
        and root.resolve()==root.absolute()) else None

STATUS_KEYS = {
    "success", "allowed", "outcome", "overlap_active", "circuit_state",
    "scheduler_enabled", "run_in_progress", "last_attempt_at", "last_success_at",
    "not_before_at", "consecutive_failures", "last_error_class",
    "normal_interval_minutes", "minimum_interval_minutes", "next_eligible_at",
    "requests_24h",
}
READY_OUTCOMES = {
    "SCHEDULER_READY", "SCHEDULER_NOT_BEFORE", "SCHEDULER_MIN_INTERVAL",
    "SCHEDULER_DAILY_BUDGET_EXCEEDED",
}


def validate_scheduler_status_result(value: object) -> dict[str, Any] | None:
    """Return the exact, coherent armed-status result, otherwise fail closed."""
    if not isinstance(value, dict) or set(value) != STATUS_KEYS:
        return None
    outcome=value.get("outcome")
    if (value.get("success") is not True or outcome not in READY_OUTCOMES
            or value.get("allowed") is not (outcome == "SCHEDULER_READY")
            or value.get("overlap_active") is not False
            or value.get("scheduler_enabled") is not True
            or value.get("run_in_progress") is not False
            or value.get("circuit_state") != "READY"
            or type(value.get("consecutive_failures")) is not int
            or value["consecutive_failures"] != 0
            or value.get("last_error_class") is not None
            or type(value.get("normal_interval_minutes")) is not int
            or value["normal_interval_minutes"] < 30
            or type(value.get("minimum_interval_minutes")) is not int
            or value["minimum_interval_minutes"] != 30
            or type(value.get("requests_24h")) is not int
            or not 0 <= value["requests_24h"] <= 24
            or not isinstance(value.get("next_eligible_at"), str)):
        return None
    for field in ("last_attempt_at", "last_success_at", "not_before_at"):
        if value[field] is not None and not isinstance(value[field], str):
            return None
    return value
