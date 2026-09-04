"""Read-only readiness checks for official FLOP/Technocore surfaces."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict
from urllib.parse import urlparse

from .remote_content_policy import ReviewedSourceId, read_configured_endpoint


OFFICIAL_SPECS = {
    "README.md": ReviewedSourceId.TECHNOCORE_README,
    "SECURITY.md": ReviewedSourceId.TECHNOCORE_SECURITY,
    "patterns.md": ReviewedSourceId.TECHNOCORE_PATTERNS,
    "llms.txt": ReviewedSourceId.TECHNOCORE_LLMS,
    "skill.md": ReviewedSourceId.TECHNOCORE_SKILL,
}
READINESS_ENDPOINTS = {
    "technocore": ReviewedSourceId.TECHNOCORE_HEALTH,
    "did_note": ReviewedSourceId.TECHNOCORE_DID_NOTE,
    "public_repo": ReviewedSourceId.PUBLIC_REPOSITORY_API,
    "official_repo": ReviewedSourceId.TECHNOCORE_REPOSITORY_API,
}
SCHEMAS = {
    "readiness.json": "flop-readiness-v1",
    "signals.json": "flop-signals-v1",
    "health.json": "flop-health-v1",
    "evidence.json": "flop-evidence-v1",
    "maintenance.json": "flop-maintenance-v1",
    "monitor.json": "flop-public-monitor-status-v1",
    "capacity_evidence.json": "technocore-capacity-evidence-v1",
    "teaser.json": "flop-teaser-monitor-v1",
    "testnet_adapter.json": "flop-testnet-adapter-status-v0",
    "technocore_compatibility.json": "technocore-compatibility-manifest-v1",
}


def fetch_bytes(source_id: ReviewedSourceId) -> bytes:
    return read_configured_endpoint(source_id)


def validate_dashboard_data(data_dir: Path) -> None:
    for filename, schema in SCHEMAS.items():
        value = json.loads((data_dir / filename).read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("schema") != schema:
            raise ValueError(f"{filename}: invalid schema")
    readiness = json.loads((data_dir / "readiness.json").read_text(encoding="utf-8"))
    allowed = {"READY", "VERIFIED", "LIVE", "RETIRED", "PENDING", "SUBMITTED", "NOT ANNOUNCED", "REVIEW REQUIRED", "ERROR"}
    for item in readiness["items"]:
        if item["status"] not in allowed:
            raise ValueError(f"unknown readiness status: {item['status']}")
    for path in data_dir.glob("*.json"):
        content = path.read_text(encoding="utf-8")
        if "/Users/" in content or "private_key" in content or "seed_b64" in content:
            raise ValueError(f"{path.name}: private material marker found")
        for value in _walk_json(json.loads(content)):
            if isinstance(value, str) and value.startswith(("http://", "https://")):
                parsed = urlparse(value)
                if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
                    raise ValueError(f"{path.name}: unsafe public URL")


def _walk_json(value: Any):
    if isinstance(value, dict):
        for nested in value.values():
            yield from _walk_json(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk_json(nested)
    else:
        yield value


def compare_spec_hashes(
    expected: Dict[str, str], fetcher: Callable[[str], bytes] = fetch_bytes,
) -> Dict[str, Dict[str, str]]:
    results: Dict[str, Dict[str, str]] = {}
    for name, source_id in OFFICIAL_SPECS.items():
        actual = hashlib.sha256(fetcher(source_id)).hexdigest()
        baseline = expected.get(name)
        results[name] = {
            "sha256": actual,
            "status": "UNCHANGED" if baseline == actual else "OFFICIAL_SPEC_CHANGED",
            "review": "NONE" if baseline == actual else "REVIEW_REQUIRED",
        }
    return results


def run_readiness_check(root: Path, fetcher: Callable[[str], bytes] = fetch_bytes) -> Dict[str, Any]:
    validate_dashboard_data(root / "data")
    expected = json.loads((root / "data" / "spec_hashes.json").read_text(encoding="utf-8"))["hashes"]
    checks: Dict[str, Dict[str, Any]] = {}
    for name, source_id in READINESS_ENDPOINTS.items():
        try:
            body = fetcher(source_id)
            checks[name] = {"status": "READY", "bytes": len(body)}
        except Exception as error:
            checks[name] = {"status": "ERROR", "error": type(error).__name__}
    checks["mailbox"] = {"status": "MIGRATION_PENDING", "read_only": True}
    specs = compare_spec_hashes(expected, fetcher)
    return {
        "schema": "flop-readiness-check-v1",
        "read_only": True,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "official_specs": specs,
        "status": "REVIEW_REQUIRED" if any(x["review"] == "REVIEW_REQUIRED" for x in specs.values()) else "READY",
    }
