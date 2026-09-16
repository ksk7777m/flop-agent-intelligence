#!/usr/bin/env python3
"""Dedicated one-shot Sonnet checkpoint migration entry point.

With no arguments this performs read-only preparation.  ``--seal-review``
durably fixes one reviewed private target, and ``--apply`` accepts only that
sealed target.  Each write mode requires separate human authorization.
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
    try:
        print(json.dumps({"status": status}, separators=(",", ":")), flush=True)
    except (OSError, UnicodeError):
        # Output failure must not expose a traceback containing private paths.
        pass


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) == 2 else None
    if len(sys.argv) != 1 and mode not in {"--seal-review", "--apply"}:
        _emit("LEGACY_MIGRATION_ARGUMENT_INVALID")
        return 2
    try:
        install_trusted_project_import_path(CODE_ROOT)
        from flop_agent.sonnet_checkpoint_migration import (  # noqa: PLC0415
            MigrationError,
            _apply_prepared_migration,
            _load_sealed_migration_at_fixed_root,
            _prepare_migration_at_fixed_root,
            _seal_migration_review,
        )
    except Exception:
        _emit("LEGACY_MIGRATION_INTERNAL_FAILURE")
        return 1
    try:
        root = trusted_production_runtime_root()
        if root is None:
            _emit("LEGACY_MIGRATION_ROOT_INVALID")
            return 1
        if mode == "--apply":
            plan = _load_sealed_migration_at_fixed_root(root)
            result = _apply_prepared_migration(plan)
            _emit(result["status"])
            return 0
        plan = _prepare_migration_at_fixed_root(root)
        if mode is None:
            _emit(plan.status)
            return 0
        result = _seal_migration_review(plan)
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
