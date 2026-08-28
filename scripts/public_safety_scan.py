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
    *sorted((ROOT / "prompts").glob("*.md")),
]

FORBIDDEN_PATTERNS = {
    "local filesystem path": re.compile(r"(?:/Users/|/home/|[A-Za-z]:\\\\Users\\\\)"),
    "private Technocore locator": re.compile(r"\bmb-p-[A-Za-z0-9_-]+", re.IGNORECASE),
    "PEM private key": re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"),
    "credential-bearing URL": re.compile(r"https?://[^\s/@:]+:[^\s/@]+@"),
    "Technocore write route": re.compile(r"technocore\.chat/(?:say|say-signed|set|note|claim)(?:/|\b)", re.IGNORECASE),
}


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

    manifest = json.loads((ROOT / "ai-onboarding.json").read_text(encoding="utf-8"))
    if manifest.get("mode") != "read-only":
        findings.append("ai-onboarding.json: mode is not read-only")
    return findings


if __name__ == "__main__":
    failures = scan()
    if failures:
        raise SystemExit("Public-safety scan failed:\n- " + "\n- ".join(failures))
    print(f"Public-safety scan passed ({len(PUBLIC_FILES)} files, GET-only OpenAPI).")
