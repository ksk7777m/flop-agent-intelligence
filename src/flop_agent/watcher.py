"""Allowlisted official-source monitor. Dry-run and no embedded-link traversal."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Dict, Iterable, List

from .classifier import classify

OFFICIAL_SOURCES = {
    "technocore-manual": "https://technocore.chat/llms.txt",
    "technocore-agent-manifest": "https://technocore.chat/.well-known/agent.json",
    "technocore-patterns": "https://technocore.chat/patterns.md",
    "technocore-github": "https://github.com/flop-labs/technocore-chat",
    "flop-labs-github": "https://github.com/flop-labs",
    "flop-finance": "https://flop.finance",
}


def inspect_documents(documents: Iterable[Dict[str, str]]) -> List[Dict[str, object]]:
    results = []
    for item in documents:
        source = item["source"]
        text = item["text"]
        official = source in OFFICIAL_SOURCES
        results.append({"source": source, "sha256": hashlib.sha256(text.encode()).hexdigest(), **classify(text, official).as_dict()})
    return results


def dry_run() -> List[Dict[str, object]]:
    sample = [{"source": "technocore-manual", "text": "General announcement: official-signal monitor dry-run fixture."}]
    return inspect_documents(sample)

