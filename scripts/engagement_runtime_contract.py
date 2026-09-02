"""Strict shared contracts for the Engagement production runtime."""

from __future__ import annotations

from typing import Any

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
