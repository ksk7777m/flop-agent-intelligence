"""Allowlisted official-source monitor. Dry-run and no embedded-link traversal."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Dict, Iterable, List

from .classifier import classify
from .remote_content_policy import ReviewedSourceId

OFFICIAL_SOURCES = {
    "technocore-manual": ReviewedSourceId.TECHNOCORE_LLMS,
    "technocore-agent-manifest": ReviewedSourceId.TECHNOCORE_AGENT_MANIFEST,
    "technocore-patterns": ReviewedSourceId.TECHNOCORE_PATTERNS_HOSTED,
    "flop-finance": ReviewedSourceId.FLOP_FINANCE,
}


def inspect_documents(documents: Iterable[Dict[str, str]]) -> List[Dict[str, object]]:
    results = []
    for item in documents:
        source = item["source"]
        text = item["text"]
        source_id = OFFICIAL_SOURCES.get(source)
        results.append({"source": source, "sha256": hashlib.sha256(text.encode()).hexdigest(), **classify(text, source_id).as_dict()})
    return results


def dry_run() -> List[Dict[str, object]]:
    sample = [{"source": "technocore-manual", "text": "General announcement: official-signal monitor dry-run fixture."}]
    return inspect_documents(sample)
