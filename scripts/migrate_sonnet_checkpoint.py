#!/usr/bin/env python3
"""Dedicated one-shot Sonnet checkpoint migration entry point.

With no arguments this performs read-only preparation.  ``--apply`` is the
only write mode and requires a separate human authorization at execution time.
"""

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
    print(json.dumps({"status": status}, separators=(",", ":")), flush=True)


def main() -> int:
    apply = len(sys.argv) == 2 and sys.argv[1] == "--apply"
    if len(sys.argv) != 1 and not apply:
        _emit("LEGACY_MIGRATION_ARGUMENT_INVALID")
        return 2
    try:
        install_trusted_project_import_path(CODE_ROOT)
        from flop_agent.sonnet_checkpoint_migration import (  # noqa: PLC0415
            MigrationError,
            _apply_prepared_migration,
            _prepare_migration_at_fixed_root,
        )
    except Exception:
        _emit("LEGACY_MIGRATION_INTERNAL_FAILURE")
        return 1
    try:
        root = trusted_production_runtime_root()
        if root is None:
            _emit("LEGACY_MIGRATION_ROOT_INVALID")
            return 1
        plan = _prepare_migration_at_fixed_root(root)
        if not apply:
            _emit(plan.status)
            return 0
        result = _apply_prepared_migration(plan)
        _emit(result["status"])
        return 0
    except MigrationError as error:
        _emit(error.code)
        return 1
    except Exception:
        _emit("LEGACY_MIGRATION_INTERNAL_FAILURE")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
