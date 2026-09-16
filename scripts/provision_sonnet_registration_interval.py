#!/usr/bin/env python3
"""Precheck or explicitly provision the fixed attended-registration child."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from engagement_runtime_contract import (
    install_trusted_project_import_path,
    trusted_production_runtime_root,
)


CODE_ROOT = Path(__file__).resolve().parents[1]


def _emit(status: str) -> None:
    try:
        print(json.dumps({"status": status}, separators=(",", ":")), flush=True)
    except (OSError, UnicodeError):
        pass


def main() -> int:
    apply = len(sys.argv) == 2 and sys.argv[1] == "--apply"
    if len(sys.argv) != 1 and not apply:
        _emit("REGISTRATION_INTERVAL_ARGUMENT_INVALID")
        return 2
    try:
        install_trusted_project_import_path(CODE_ROOT)
        from flop_agent.sonnet_attended_registration import (  # noqa: PLC0415
            provision_registration_interval,
        )
        root = trusted_production_runtime_root()
        if root is None:
            _emit("REGISTRATION_INTERVAL_ROOT_INVALID")
            return 1
        status = provision_registration_interval(
            private_runtime_root=root, apply=apply)
        _emit(status)
        return 0 if status in {
            "REGISTRATION_INTERVAL_PROVISIONING_REQUIRED",
            "REGISTRATION_INTERVAL_READY", "REGISTRATION_INTERVAL_PROVISIONED",
        } else 1
    except Exception as error:
        code = getattr(error, "code", "REGISTRATION_INTERVAL_INTERNAL_FAILURE")
        allowed = {
            "REGISTRATION_INTERVAL_ROOT_INVALID",
            "REGISTRATION_INTERVAL_CHILD_INVALID",
            "REGISTRATION_INTERVAL_RACE",
        }
        _emit(code if code in allowed else "REGISTRATION_INTERVAL_INTERNAL_FAILURE")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
