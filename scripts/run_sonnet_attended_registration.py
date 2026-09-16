#!/usr/bin/env python3
"""Foreground attended runner for one fixed Sonnet writer registration."""

from __future__ import annotations

import json
import select
import signal
import sys
import threading
from pathlib import Path

from engagement_runtime_contract import (
    install_trusted_project_import_path,
    trusted_production_runtime_root,
)


CODE_ROOT = Path(__file__).resolve().parents[1]
POLL_SECONDS = 0.2


def _emit(status: str) -> None:
    try:
        print(json.dumps({"status": status}, separators=(",", ":")), flush=True)
    except (OSError, UnicodeError):
        pass


def main() -> int:
    if len(sys.argv) != 1:
        _emit("ATTENDED_REGISTRATION_ARGUMENT_INVALID")
        return 2
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        _emit("ATTENDED_REGISTRATION_INTERACTIVE_TTY_REQUIRED")
        return 1
    stop = threading.Event()
    previous: dict[int, object] = {}
    session = None

    def request_stop(_signum: int, _frame: object) -> None:
        stop.set()
        if session is not None:
            session.stop()

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, request_stop)
        install_trusted_project_import_path(CODE_ROOT)
        from flop_agent.sonnet_attended_registration import (  # noqa: PLC0415
            APPROVAL_COMMAND,
            AttendedRegistrationError,
            begin_attended_registration,
            issue_local_approval,
        )
        root = trusted_production_runtime_root()
        if root is None:
            _emit("ATTENDED_REGISTRATION_REVIEW_REQUIRED")
            return 1
        session = begin_attended_registration(private_runtime_root=root)
        approval_requested = False
        registration_executed = False
        while not stop.is_set():
            if (not approval_requested and not registration_executed
                    and session.wait_until_ready(POLL_SECONDS)):
                if not session.is_running():
                    break
                _emit("OBSERVER_READY")
                _emit("REGISTRATION_APPROVAL_REQUIRED")
                approval_requested = True
            if approval_requested:
                readable, _writable, _errors = select.select(
                    [sys.stdin], [], [], POLL_SECONDS)
                if readable:
                    command = sys.stdin.readline(256)
                    if command != APPROVAL_COMMAND + "\n":
                        raise AttendedRegistrationError("HUMAN_APPROVAL_REQUIRED")
                    artifact = issue_local_approval(command.rstrip("\n"))
                    result = session.execute_approved_registration(artifact)
                    _emit(str(result["status"]))
                    approval_requested = False
                    registration_executed = True
            terminal = session.wait_for_terminal(0)
            if terminal is not None:
                _emit(terminal)
                return 0 if terminal in {
                    "OBSERVER_ACCEPTED", "OBSERVER_REJECTED", "OBSERVER_STOPPED",
                    "OBSERVER_TIMEOUT",
                } else 1
        if session is not None:
            session.stop()
            session.wait_for_terminal(21)
        _emit("OBSERVER_STOPPED")
        return 0
    except Exception as error:
        if session is not None:
            session.stop()
            try:
                session.wait_for_terminal(21)
            except Exception:
                pass
        code = getattr(error, "code", "ATTENDED_REGISTRATION_INTERNAL_FAILURE")
        allowed = {
            "HUMAN_APPROVAL_REQUIRED", "REGISTRATION_ALREADY_STARTED",
            "OBSERVER_NOT_READY", "OBSERVER_NOT_LIVE",
            "REGISTRATION_SESSION_ALREADY_USED",
            "RECEIPT_RECONCILIATION_UNAVAILABLE",
            "RECEIPT_RECONCILIATION_FAILED",
        }
        _emit(code if code in allowed else "ATTENDED_REGISTRATION_REVIEW_REQUIRED")
        return 1
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    raise SystemExit(main())
