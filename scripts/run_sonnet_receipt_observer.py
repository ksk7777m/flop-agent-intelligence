#!/usr/bin/env python3
"""Foreground-only launcher for the fixed GET-only Sonnet receipt supervisor."""

from __future__ import annotations

import json
import signal
import sys
import threading
from pathlib import Path
from typing import Any, Callable, Mapping

from engagement_runtime_contract import (
    install_trusted_project_import_path,
    trusted_production_runtime_root,
)


CODE_ROOT = Path(__file__).resolve().parents[1]
POLL_SECONDS = 0.2


def _emit(value: str | Mapping[str, Any]) -> None:
    payload = {"status": value} if type(value) is str else dict(value)
    print(json.dumps(payload, separators=(",", ":")), flush=True)


def _run_foreground(handle: object, stop_requested: threading.Event,
                    emit: Callable[[str | Mapping[str, Any]], None]) -> int:
    ready_emitted = False
    stop_forwarded = False
    while True:
        if stop_requested.is_set() and not stop_forwarded:
            handle.stop()
            stop_forwarded = True
        if not ready_emitted and handle.wait_until_ready(POLL_SECONDS):
            if handle.is_running():
                emit("OBSERVER_READY")
                ready_emitted = True
        terminal = handle.wait_for_terminal(0)
        if terminal is not None:
            projection = getattr(handle, "terminal_projection", lambda: None)()
            emit(projection or terminal)
            return 0 if terminal in {
                "OBSERVER_ACCEPTED", "OBSERVER_REJECTED",
                "OBSERVER_STOPPED", "OBSERVER_TIMEOUT",
            } else 1


def main() -> int:
    # No command-line configuration is accepted; all bindings remain local-only.
    if len(sys.argv) != 1:
        _emit("OBSERVER_REVIEW_REQUIRED")
        return 2
    stop_requested = threading.Event()
    previous: dict[int, object] = {}
    handle = None

    def request_stop(_signum: int, _frame: object) -> None:
        stop_requested.set()

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, request_stop)
        install_trusted_project_import_path(CODE_ROOT)
        from flop_agent.sonnet_receipt_supervisor import (  # noqa: PLC0415
            build_production_receipt_supervisor,
            safe_start_failure_projection,
        )
        root = trusted_production_runtime_root()
        if root is None:
            _emit("OBSERVER_REVIEW_REQUIRED")
            return 1
        _emit("OBSERVER_STARTING")
        handle = build_production_receipt_supervisor(
            private_runtime_root=root).start(stop_requested=stop_requested)
        return _run_foreground(handle, stop_requested, _emit)
    except Exception as error:
        if handle is not None:
            handle.stop()
            handle.wait_for_terminal(2)
        try:
            _emit(safe_start_failure_projection(error))
        except Exception:
            _emit({
                "status": "OBSERVER_REVIEW_REQUIRED",
                "failure_category": "READ_INTERNAL_FAILURE",
                "failure_phase": "BOOTSTRAP",
                "retryable": False,
                "observed_at": None,
                "read_attempt_count": 0,
            })
        return 1
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    raise SystemExit(main())
