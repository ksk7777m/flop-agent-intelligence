"""Fail when public onboarding surfaces expose unsafe capabilities or locators."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_FILES = [
    ROOT / "AI_ONBOARDING.md",
    ROOT / "ai-onboarding.json",
    ROOT / "llms.txt",
    ROOT / "index.html",
    ROOT / "dashboard.js",
    ROOT / "openapi.json",
    ROOT / "docs" / "KV_OBSERVATORY.md",
    ROOT / "docs" / "OBSERVATORY_API.md",
    *sorted((ROOT / "api" / "kv").glob("*.json")),
    *sorted((ROOT / "prompts").glob("*.md")),
]

FORBIDDEN_PATTERNS = {
    "local filesystem path": re.compile(r"(?:/Users/|/home/|[A-Za-z]:\\\\Users\\\\)"),
    "private Technocore locator": re.compile(r"(?<![A-Za-z0-9_-])(?:[a-z0-9]+-)*(?:mb-)?p-[A-Za-z0-9_-]+", re.IGNORECASE),
    "PEM private key": re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"),
    "credential-bearing URL": re.compile(r"https?://[^\s/@:]+:[^\s/@]+@"),
    "Technocore write route": re.compile(r"technocore\.chat/(?:say|say-signed|set|note|claim)(?:/|\b)", re.IGNORECASE),
    "wallet seed material": re.compile(r"(?:seed phrase|wallet private key|mnemonic)\s*[:=]\s*\S+", re.IGNORECASE),
}

RAW_FIELDS = {"raw_value", "value_raw", "note_value", "response_body", "message_body"}


def scan() -> list[str]:
    findings: list[str] = []
    for path in PUBLIC_FILES:
        text = path.read_text(encoding="utf-8")
        for label, pattern in FORBIDDEN_PATTERNS.items():
            if pattern.search(text):
                findings.append(f"{path.relative_to(ROOT)}: {label}")

    openapi = json.loads((ROOT / "openapi.json").read_text(encoding="utf-8"))
    for route, operations in openapi.get("paths", {}).items():
        unsafe = set(operations) - {"get", "parameters", "summary", "description"}
        if unsafe:
            findings.append(f"openapi.json: non-GET operation at {route}: {sorted(unsafe)}")

    for path in sorted((ROOT / "api").rglob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        def visit(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key.lower() in RAW_FIELDS:
                        findings.append(f"{path.relative_to(ROOT)}: raw-value-shaped public field {key}")
                    visit(child)
            elif isinstance(value, list):
                for child in value: visit(child)
            elif (path.parent.name == "kv" and isinstance(value, str)
                  and re.search(r"https?://", value) and value != "https://technocore.chat"):
                findings.append(f"{path.relative_to(ROOT)}: note-derived or unexpected URL in public API")
        visit(payload)

    tracked = {str(path.relative_to(ROOT)) for path in ROOT.rglob("*") if path.is_file()}
    for name in tracked:
        if re.search(r"\.(?:sqlite3?|db)(?:-(?:wal|shm))?$|-(?:wal|shm)$", name, re.IGNORECASE):
            findings.append(f"{name}: runtime database artifact in public tree")

    manifest = json.loads((ROOT / "ai-onboarding.json").read_text(encoding="utf-8"))
    if manifest.get("mode") != "read-only":
        findings.append("ai-onboarding.json: mode is not read-only")
    return findings


if __name__ == "__main__":
    failures = scan()
    if failures:
        raise SystemExit("Public-safety scan failed:\n- " + "\n- ".join(failures))
    print(f"Public-safety scan passed ({len(PUBLIC_FILES)} files, GET-only OpenAPI).")
