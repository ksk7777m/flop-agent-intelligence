#!/usr/bin/env python3
"""Conservative public-tree scan that deliberately never opens secrets/."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", ".venv", "__pycache__", "secrets", "receipts", "build", "dist"}
SKIP_FILES = {".DS_Store"}
TEXT_SUFFIXES = {"", ".md", ".py", ".json", ".jsonl", ".toml", ".txt", ".gitignore"}
RULES = {
    "private_key_block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "personal_path": re.compile(r"/(?:Users|home)/[^/\s]+/"),
    "github_token": re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    "generic_secret_assignment": re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|secret|password|cookie)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"
    ),
}


def scan() -> dict:
    findings = []
    scanned = 0
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        if any(part in SKIP_DIRS for part in relative.parts) or path.name in SKIP_FILES or not path.is_file():
            continue
        if path.suffix not in TEXT_SUFFIXES:
            continue
        scanned += 1
        text = path.read_text(encoding="utf-8", errors="replace")
        for name, pattern in RULES.items():
            for match in pattern.finditer(text):
                findings.append({"rule": name, "file": str(relative), "line": text.count("\n", 0, match.start()) + 1})
    return {"public_safe": not findings, "files_scanned": scanned, "findings": findings, "excluded": sorted(SKIP_DIRS)}


if __name__ == "__main__":
    result = scan()
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["public_safe"] else 1)

