"""Read-only FLOP readiness monitor with explicit trust and drift boundaries."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List

from .classifier import classify
from .receipt import read_receipt, verify_receipt
from .readiness import OFFICIAL_SPECS


VERSION = "flop-readiness-health-monitor-v1"
TEASER_URL = "https://flop.finance/teaser/"
DID = "did:key:z6MkkTuFggpkYcZ61zGxej2Ae7Lf6MHk3AbsYASULYTqiqXy"
DID_NOTE_VALUE = (
    f"{DID} x25519:a-EbwHNshrhf00Aqq4P7xrZ8Cqmncxr3HW_wTSOoXW0 "
    "name:FLOP-Agent-Intelligence-and-Safety-Layer "
    "repo:https://github.com/ksk7777m/flop-agent-intelligence"
)
DID_NOTE_HASH = "f1f0f6a3dbf73e9a42841959aa1af1e43347018f710cdd036f9b4951c77e26f9"
MAILBOX = None
X25519_PUBLIC = "a-EbwHNshrhf00Aqq4P7xrZ8Cqmncxr3HW_wTSOoXW0"
KNOWN_MAILBOX_SEQ = 1

ENDPOINTS = {
    "technocore": "https://technocore.chat/healthz",
    "did_note": "https://technocore.chat/kv/did-4e/1df29904c79a56",
    "contribution": "https://technocore.chat/r/lobby?since=929749&limit=1&format=json",
    "repo": "https://api.github.com/repos/ksk7777m/flop-agent-intelligence",
    "original_commit": "https://api.github.com/repos/ksk7777m/flop-agent-intelligence/commits/e388c6fd549de2931c40f1647dc1540a78b5c920",
    "dashboard_commit": "https://api.github.com/repos/ksk7777m/flop-agent-intelligence/commits/1fdc4b014a24bb7bcaf9ca0c0851959dcdef3bc7",
    "dashboard": "https://ksk7777m.github.io/flop-agent-intelligence/",
    "public_evidence": "https://ksk7777m.github.io/flop-agent-intelligence/data/evidence.json",
    "official_repo": "https://api.github.com/repos/flop-labs/technocore-chat",
    "flop_site": "https://flop.finance/",
    "teaser": TEASER_URL,
    "x_official": "https://x.com/flop_labs",
    "x_evidence": "https://x.com/Giappone_Medici/status/2092613806434218126",
    "capacity_manifest": "https://technocore.chat/.well-known/agent.json",
    "rooms_summary": "https://technocore.chat/rooms?limit=1&format=json",
}
ALLOWED_URLS = set(ENDPOINTS.values()) | set(OFFICIAL_SPECS.values())
SENSITIVE_TERMS = {
    "testnet", "faucet", "did task", "did-gated", "reward", "snapshot",
    "eligibility", "claim", "contract", "deadline", "security", "upgrade",
}

class _VisibleText(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hidden = 0
        self.parts: List[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in {"script", "style"}:
            self.hidden += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self.hidden:
            self.hidden -= 1

    def handle_data(self, data: str) -> None:
        if not self.hidden:
            self.parts.append(data)


class _TeaserHTML(HTMLParser):
    """Collect visible text, heading-scoped text and links without following them."""

    def __init__(self) -> None:
        super().__init__()
        self.hidden = 0
        self.heading_tag: str | None = None
        self.heading_parts: List[str] = []
        self.section = "document"
        self.parts: List[str] = []
        self.sections: Dict[str, List[str]] = {self.section: []}
        self.links: List[Dict[str, str]] = []
        self.current_link: Dict[str, str] | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in {"script", "style"}:
            self.hidden += 1
        elif tag in {"h1", "h2", "h3", "h4"} and not self.hidden:
            self.heading_tag = tag
            self.heading_parts = []
        elif tag == "a" and not self.hidden:
            href = dict(attrs).get("href")
            if href:
                self.current_link = {"href": href, "text": ""}
                self.links.append(self.current_link)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self.hidden:
            self.hidden -= 1
        elif tag == self.heading_tag:
            heading = re.sub(r"\s+", " ", " ".join(self.heading_parts)).strip()
            if heading:
                self.section = heading
                self.sections.setdefault(heading, [])
            self.heading_tag = None
        elif tag == "a":
            self.current_link = None

    def handle_data(self, data: str) -> None:
        if self.hidden:
            return
        self.parts.append(data)
        self.sections.setdefault(self.section, []).append(data)
        if self.heading_tag:
            self.heading_parts.append(data)
        if self.current_link is not None:
            self.current_link["text"] += data


def normalize_official_signal(raw: bytes) -> bytes:
    parser = _VisibleText()
    parser.feed(raw.decode("utf-8", errors="replace"))
    return re.sub(r"\s+", " ", " ".join(parser.parts)).strip().lower().encode()


def extract_teaser_snapshot(raw: bytes) -> Dict[str, Any]:
    parser = _TeaserHTML()
    parser.feed(raw.decode("utf-8", errors="replace"))
    normalized = re.sub(r"\s+", " ", " ".join(parser.parts)).strip()
    lower = normalized.lower()
    section_hashes = {
        name: hashlib.sha256(re.sub(r"\s+", " ", " ".join(parts)).strip().lower().encode()).hexdigest()
        for name, parts in parser.sections.items()
        if re.sub(r"\s+", " ", " ".join(parts)).strip()
    }
    links = [{"href": item["href"], "text": re.sub(r"\s+", " ", item["text"]).strip()} for item in parser.links]
    yellow_links = [item for item in links if "yellow paper" in (item["text"] + " " + item["href"]).lower()]
    faucet_links = [item for item in links if "faucet" in (item["text"] + " " + item["href"]).lower()]
    inference_links = [item for item in links if "inference" in (item["text"] + " " + item["href"]).lower()]
    contract_addresses = sorted(set(re.findall(r"\b0x[a-fA-F0-9]{40}\b", normalized)))
    testnet_match = re.search(r"testnet is planned for (q[1-4] \d{4})", lower)
    mainnet_match = re.search(r"mainnet to follow in (q[1-4] \d{4})", lower)
    signals = {
        "spec_status": "OFFICIAL_DRAFT" if any(term in lower for term in ("figures are provisional", "yet to be finalised", "planned for")) else "CONFIRMED",
        "testnet": testnet_match.group(1).strip() if testnet_match else ("MENTIONED" if "testnet" in lower else "NOT_ANNOUNCED"),
        "mainnet": mainnet_match.group(1).strip() if mainnet_match else ("MENTIONED" if "mainnet" in lower else "NOT_ANNOUNCED"),
        "genesis_airdrop": "DRAFT" if "genesis airdrop" in lower else "NOT_ANNOUNCED",
        "agent_allocation": "up to 1,200,000,000 (7.0%)" if "up to 1,200,000,000 (7.0%)" in lower else "MENTIONED" if "agents" in lower else "NOT_ANNOUNCED",
        "miner_allocation": "up to 1,200,000,000 (7.0%)" if "up to 1,200,000,000 (7.0%)" in lower else "MENTIONED" if "miners" in lower else "NOT_ANNOUNCED",
        "validator_allocation": "305,505,000 (1.8%)" if "305,505,000 (1.8%)" in lower else "MENTIONED" if "validators" in lower else "NOT_ANNOUNCED",
        "reserve_incentives": "794,495,000 (4.6%)" if "794,495,000 (4.6%)" in lower else "MENTIONED" if "reserve" in lower else "NOT_ANNOUNCED",
        "faucet": "CONFIRMED_ENDPOINT" if faucet_links else "OFFICIAL_DRAFT_MENTION" if "faucet" in lower else "NOT_ANNOUNCED",
        "inference": "CONFIRMED_ENDPOINT" if inference_links else "OFFICIAL_DRAFT_MENTION" if "inference" in lower else "NOT_ANNOUNCED",
        "did_tasks": "MENTIONED" if "did-gated" in lower or "did task" in lower else "NONE",
        "unlock_mechanics": "DRAFT" if "unlocks 1 airdropped" in lower else "NOT_ANNOUNCED",
        "prizes": "DRAFT" if "prizes" in lower else "NOT_ANNOUNCED",
        "snapshot": "MENTIONED" if "snapshot" in lower else "NOT_ANNOUNCED",
        "eligibility": "MENTIONED" if "eligibility" in lower else "NOT_ANNOUNCED",
        "claim": "DRAFT_MECHANIC" if "claim a test-token faucet" in lower else "NOT_ANNOUNCED",
        "yellow_paper": "CONFIRMED_LINK" if yellow_links else "DRAFT_REFERENCE" if "yellow paper" in lower else "NOT_ANNOUNCED",
        "contract_address": contract_addresses,
    }
    return {
        "source": TEASER_URL,
        "source_tier": "TIER_1_OFFICIAL",
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "normalized_text_sha256": hashlib.sha256(normalized.lower().encode()).hexdigest(),
        "section_hashes": section_hashes,
        "signals": signals,
    }


def evaluate_teaser(raw: bytes, baseline: Dict[str, Any]) -> Dict[str, Any]:
    current = extract_teaser_snapshot(raw)
    if current["normalized_text_sha256"] == baseline.get("normalized_text_sha256"):
        return _result("READY", "UNCHANGED", classification="INFO", spec_status=current["signals"]["spec_status"], **current)
    old_signals = baseline.get("signals", {})
    changed = [
        {"field": field, "old": old_signals.get(field), "new": value}
        for field, value in current["signals"].items() if old_signals.get(field) != value
    ]
    changed_sections = sorted(
        name for name, digest in current["section_hashes"].items()
        if baseline.get("section_hashes", {}).get(name) != digest
    )
    detail = "CRITICAL_NEW_OFFICIAL_SPEC" if current["signals"]["yellow_paper"] == "CONFIRMED_LINK" and old_signals.get("yellow_paper") != "CONFIRMED_LINK" else "OFFICIAL_TEASER_CHANGED"
    return _result(
        "REVIEW_REQUIRED", detail, classification="CRITICAL" if detail.startswith("CRITICAL") else "REVIEW_REQUIRED",
        spec_status=current["signals"]["spec_status"], semantic_diff=changed,
        changed_sections=changed_sections, **current,
    )


def classify_source_failure(consecutive_failures: int) -> Dict[str, Any]:
    if consecutive_failures >= 2:
        return _result("REVIEW_REQUIRED", "Official source unavailable for two or more consecutive checks")
    return _result("UNKNOWN", "Official source temporarily unavailable")


def fetch_bytes(url: str) -> bytes:
    if url not in ALLOWED_URLS:
        raise ValueError("URL is not in the monitor allowlist")
    request = urllib.request.Request(url, headers={"User-Agent": "flop-readiness-monitor/1"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.read()


def _result(status: str, detail: str, **extra: Any) -> Dict[str, Any]:
    return {"status": status, "detail": detail, **extra}


def evaluate_did_note(body: bytes) -> Dict[str, Any]:
    text = body.decode("utf-8", errors="replace")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    value = next((line for line in reversed(lines) if line.startswith("did:key:")), "")
    digest = hashlib.sha256(value.encode()).hexdigest()
    expected_parts = (DID, "repo:https://github.com/ksk7777m/flop-agent-intelligence", f"x25519:{X25519_PUBLIC}")
    if digest != DID_NOTE_HASH or value != DID_NOTE_VALUE or "mailbox:" in value or not all(part in value for part in expected_parts):
        return _result("REVIEW_REQUIRED", "DID Note missing or changed", sha256=digest)
    return _result("READY", "Expected DID, repository and X25519 key match; mailbox omitted", sha256=digest)


def evaluate_mailbox(body: bytes) -> Dict[str, Any]:
    try:
        room = json.loads(body)
        messages = room["messages"]
    except (KeyError, TypeError, json.JSONDecodeError):
        return _result("ERROR", "Mailbox response is not valid JSON")
    known = [m for m in messages if m.get("seq") == KNOWN_MAILBOX_SEQ and m.get("from") == DID]
    if not known:
        return _result("REVIEW_REQUIRED", "Known signed readiness message is unavailable")
    newer = [m for m in messages if isinstance(m.get("seq"), int) and m["seq"] > KNOWN_MAILBOX_SEQ]
    unsafe = []
    for message in newer:
        # Message bodies remain inert data. Classification performs no fetch or execution.
        outcome = classify(str(message.get("text", "")), official=False)
        if outcome.security_review_required:
            unsafe.append(message.get("seq"))
    if newer:
        return _result(
            "REVIEW_REQUIRED", "NEW_MAILBOX_MESSAGE", new_message_count=len(newer),
            unsafe_message_seqs=unsafe, last_seq=max(m["seq"] for m in newer),
        )
    return _result("READY", "Known signed message present; no new messages", last_seq=KNOWN_MAILBOX_SEQ)


def classify_live_record(body: bytes, historical_seq: int = 929750) -> Dict[str, Any]:
    try:
        room = json.loads(body)
        first_seq = room.get("first_seq")
        messages = room.get("messages", [])
    except (TypeError, json.JSONDecodeError):
        return _result("UNKNOWN", "Room response is invalid")
    match = next((m for m in messages if m.get("seq") == historical_seq), None)
    if match:
        if match.get("from") != DID:
            return _result("INVALID", "Historical seq has unexpected DID", first_seq=first_seq)
        return _result("LIVE", "Historical signed record remains in the live ring", first_seq=first_seq)
    if isinstance(first_seq, int) and first_seq > historical_seq:
        return _result("EVICTED_EXPECTED", "Historical seq is below current first_seq", first_seq=first_seq)
    if isinstance(first_seq, int) and first_seq <= historical_seq:
        return _result("UNEXPECTED_MISSING", "Historical seq should still be inside the live ring boundary", first_seq=first_seq)
    return _result("UNKNOWN", "Live ring boundary is unavailable", first_seq=first_seq)


def evaluate_capacity_contract(manifest_body: bytes, rooms_body: bytes, observed_rejection_cap: int = 10240) -> Dict[str, Any]:
    try:
        manifest = json.loads(manifest_body)
        rooms = json.loads(rooms_body)
        advertised = int(manifest["limits"]["rooms"])
        runtime = int(rooms["capacity"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return _result("UNKNOWN", "Capacity contract could not be parsed")
    if advertised == runtime:
        return _result(
            "CONSISTENT", "Configured runtime cap matches the current official manifest",
            documented_default=5120, advertised_cap=advertised, runtime_cap=runtime,
            observed_rejection_cap=observed_rejection_cap,
            runtime_changed_since_observation=runtime != observed_rejection_cap,
        )
    return _result(
        "DIVERGED", "SPEC_RUNTIME_DIVERGENCE", documented_default=5120,
        advertised_cap=advertised, runtime_cap=runtime,
        observed_rejection_cap=observed_rejection_cap, classification="REVIEW_REQUIRED",
    )


def evaluate_engagement_aggregates(rooms_body: bytes) -> Dict[str, Any]:
    try:
        value = json.loads(rooms_body)
        engagement = value["engagement"]
    except (KeyError, TypeError, json.JSONDecodeError):
        return _result("UNKNOWN", "Engagement aggregates unavailable")
    metrics = {
        key: engagement.get(key)
        for key in ("zero_response_share", "nick_diversity", "windowed_note_to_message_ratio")
    }
    if not any(metric is not None for metric in metrics.values()):
        return _result("UNKNOWN", "Engagement aggregate window is empty", metrics=metrics)
    return _result(
        "READY",
        "Technocore engagement health metrics; not confirmed FLOP airdrop scoring",
        metrics=metrics,
    )


def detect_signal_delta(previous: bytes, current: bytes) -> Dict[str, Any]:
    normalized = lambda raw: re.sub(r"\s+", " ", raw.decode("utf-8", errors="replace")).strip().lower()
    before, after = normalized(previous), normalized(current)
    if before == after:
        return _result("READY", "NO ACTIONABLE CHANGE", delta_count=0)
    added_terms = sorted(term for term in SENSITIVE_TERMS if term in after and term not in before)
    if added_terms:
        return _result("REVIEW_REQUIRED", "Potential actionable official signal changed", delta_count=len(added_terms), terms=added_terms)
    return _result("CHANGED", "Non-actionable or formatting/source change", delta_count=0)


def detect_signal_terms(previous_terms: Iterable[str], current: bytes) -> Dict[str, Any]:
    text = normalize_official_signal(current).decode()
    before = set(previous_terms)
    now = {term for term in SENSITIVE_TERMS if term in text}
    added = sorted(now - before)
    if added:
        return _result("REVIEW_REQUIRED", "Potential actionable official signal changed", delta_count=len(added), terms=added)
    return _result("CHANGED", "Official source changed without a new monitored term", delta_count=0)


def assess_freshness(checked_at: str, now: datetime | None = None) -> str:
    checked = datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
    current = now or datetime.now(timezone.utc)
    hours = (current - checked).total_seconds() / 3600
    return "FRESH" if hours < 24 else "AGING" if hours <= 48 else "STALE"


def _safe_fetch(name: str, fetcher: Callable[[str], bytes]) -> tuple[bytes | None, Dict[str, Any]]:
    try:
        body = fetcher(ENDPOINTS[name])
        return body, _result("READY", "Endpoint reachable", bytes=len(body))
    except Exception as error:
        return None, _result("UNKNOWN", "Endpoint temporarily unavailable", error=type(error).__name__)


def _local_evidence(root: Path) -> Dict[str, Any]:
    expected = [
        ("original", root / "receipts/flop-agent-intelligence-e388c6fd.receipt.json", "854b3442645b0dcaeae9d87646e0144fd48f659ef0a72208135eddaa37b279b2"),
        ("dashboard", root / "receipts/flop-readiness-dashboard-v1-1fdc4b0.receipt.json", "433737734c148e9351bf405252b8aa78ac0e923320366980fe26a97aabb67e70"),
    ]
    details = {}
    for name, path, fingerprint in expected:
        try:
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            verified = verify_receipt(read_receipt(path))["status"] == "VALID"
            details[name] = actual == fingerprint and verified
        except Exception:
            details[name] = False
    try:
        from .identity import verify_message
        records = [json.loads(line) for line in (root / "data/activity.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        contribution = next(item for item in reversed(records) if item.get("room") == "lobby" and item.get("seq") == 929750)
        verify_message(contribution["did"], contribution["signature"], "lobby", int(contribution["nonce"]), contribution["text_after_sweep"])
        details["contribution_signature"] = contribution["did"] == DID
    except Exception:
        details["contribution_signature"] = False
    return _result("READY" if all(details.values()) else "ERROR", "Local receipts and contribution signature verified" if all(details.values()) else "Receipt verification failed", receipts=details)


def _public_evidence(root: Path, bodies: Dict[str, bytes]) -> Dict[str, Any]:
    details: Dict[str, bool] = {}
    try:
        public = json.loads(bodies["public_evidence"])
        details["repository"] = public.get("repository") == "https://github.com/ksk7777m/flop-agent-intelligence"
        details["original_commit"] = public.get("original_public_commit") == "e388c6fd549de2931c40f1647dc1540a78b5c920"
        details["receipt_fingerprint"] = public.get("receipt_sha256") == "854b3442645b0dcaeae9d87646e0144fd48f659ef0a72208135eddaa37b279b2"
        details["historical_status"] = public.get("historical_evidence_status") == "VERIFIED_OFFCHAIN"
        details["commit_reachable"] = "original_commit" in bodies
        from .identity import verify_message
        records = [json.loads(line) for line in (root / "data/activity.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        contribution = next(item for item in reversed(records) if item.get("room") == "lobby" and item.get("seq") == 929750)
        verify_message(contribution["did"], contribution["signature"], "lobby", int(contribution["nonce"]), contribution["text_after_sweep"])
        details["contribution_signature"] = contribution["did"] == DID
    except Exception:
        details["parse_or_signature"] = False
    valid = bool(details) and all(details.values())
    return _result(
        "READY" if valid else "ERROR",
        "Public commit, receipt metadata and contribution signature verified" if valid else "Public evidence verification failed",
        evidence=details,
        mode="public",
    )


def run_monitor(root: Path, fetcher: Callable[[str], bytes] = fetch_bytes, evidence_mode: str = "local") -> Dict[str, Any]:
    checked_at = datetime.now(timezone.utc).isoformat()
    checks: Dict[str, Dict[str, Any]] = {}
    bodies: Dict[str, bytes] = {}
    for name in ENDPOINTS:
        body, checks[name] = _safe_fetch(name, fetcher)
        if body is not None:
            bodies[name] = body
    if "did_note" in bodies:
        checks["did_note"] = evaluate_did_note(bodies["did_note"])
    checks["mailbox"] = _result("READY", "MIGRATION_PENDING; no mailbox endpoint advertised or fetched")
    if "repo" in bodies:
        try:
            repo = json.loads(bodies["repo"])
            checks["repo"] = _result(
                "READY" if repo.get("private") is False and repo.get("default_branch") == "main" else "REVIEW_REQUIRED",
                "Public repository and main default branch verified",
            )
        except json.JSONDecodeError:
            checks["repo"] = _result("ERROR", "Repository metadata is invalid")
    if "dashboard" in bodies and b"FLOP Agent Readiness Dashboard" not in bodies["dashboard"]:
        checks["dashboard"] = _result("REVIEW_REQUIRED", "Dashboard content marker missing")
    if "flop_site" in bodies and b"https://x.com/flop_labs" not in bodies["flop_site"]:
        checks["flop_site"] = _result("REVIEW_REQUIRED", "Official @flop_labs link missing")
    if "capacity_manifest" in bodies and "rooms_summary" in bodies:
        capacity = evaluate_capacity_contract(bodies["capacity_manifest"], bodies["rooms_summary"])
        checks["capacity_contract"] = _result(
            "READY" if capacity["status"] == "CONSISTENT" else "REVIEW_REQUIRED",
            capacity["detail"], capacity_status=capacity["status"],
            **{key: value for key, value in capacity.items() if key not in {"status", "detail"}},
        )
    else:
        checks["capacity_contract"] = _result("UNKNOWN", "Capacity sources unavailable", capacity_status="UNKNOWN")
    if "rooms_summary" in bodies:
        checks["engagement"] = evaluate_engagement_aggregates(bodies["rooms_summary"])
        try:
            room_summary = json.loads(bodies["rooms_summary"])
            total, capacity = int(room_summary["total"]), int(room_summary["capacity"])
            checks["mailbox_migration"] = _result(
                "READY", "MAILBOX_MIGRATION_POSSIBLE" if total < capacity else "MIGRATION_PENDING",
                room_count=total, room_limit=capacity, available_capacity=max(0, capacity - total), probe_performed=False,
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            checks["mailbox_migration"] = _result("UNKNOWN", "Room availability could not be derived", probe_performed=False)
    else:
        checks["engagement"] = _result("UNKNOWN", "Engagement aggregates unavailable")
        checks["mailbox_migration"] = _result("UNKNOWN", "Room availability unavailable", probe_performed=False)
    live_record = classify_live_record(bodies["contribution"]) if "contribution" in bodies else _result("UNKNOWN", "Contribution endpoint unavailable")
    if evidence_mode not in {"local", "public"}:
        raise ValueError("evidence_mode must be local or public")
    evidence = _public_evidence(root, bodies) if evidence_mode == "public" else _local_evidence(root)
    checks["receipts"] = evidence
    historical_status = "VERIFIED_OFFCHAIN" if evidence["status"] == "READY" else "INVALID"
    if live_record["status"] == "LIVE" and evidence["status"] == "READY":
        checks["contribution"] = _result("READY", "Historical contribution verified live", live_record_status="LIVE", historical_evidence_status="VERIFIED_LIVE", first_seq=live_record.get("first_seq"))
    elif live_record["status"] == "EVICTED_EXPECTED" and evidence["status"] == "READY":
        checks["contribution"] = _result("READY", "Expected ring eviction; historical evidence remains verified", live_record_status="EVICTED_EXPECTED", historical_evidence_status=historical_status, first_seq=live_record.get("first_seq"))
    else:
        checks["contribution"] = _result("REVIEW_REQUIRED", live_record["detail"], live_record_status=live_record["status"], historical_evidence_status=historical_status, first_seq=live_record.get("first_seq"))

    baselines = json.loads((root / "data/monitor_baseline.json").read_text(encoding="utf-8"))
    if "teaser" in bodies:
        checks["teaser"] = evaluate_teaser(bodies["teaser"], baselines["teaser"])
    else:
        checks["teaser"] = classify_source_failure(1)
    spec_results = {}
    for name, url in OFFICIAL_SPECS.items():
        try:
            actual = hashlib.sha256(fetcher(url)).hexdigest()
            expected = baselines["official_specs"][name]
            spec_results[name] = _result(
                "READY" if actual == expected else "REVIEW_REQUIRED",
                "UNCHANGED" if actual == expected else "OFFICIAL_SPEC_CHANGED",
                previous_hash=expected, current_hash=actual,
                changed_sections=[] if actual == expected else ["Semantic diff requires human review against the pinned revision"],
                security_relevance="NONE" if actual == expected else ("REVIEW_REQUIRED" if name in {"SECURITY.md", "llms.txt", "patterns.md"} else "UNKNOWN"),
                action_relevance="NONE" if actual == expected else "REVIEW_REQUIRED",
            )
        except Exception as error:
            spec_results[name] = _result("ERROR", "Specification unavailable", error=type(error).__name__)

    signals = _result("READY", "NO ACTIONABLE CHANGE", delta_count=0)
    if "flop_site" in bodies:
        actual_hash = hashlib.sha256(normalize_official_signal(bodies["flop_site"])).hexdigest()
        if actual_hash != baselines["flop_site_sha256"]:
            signals = detect_signal_terms(baselines["flop_site_terms"], bodies["flop_site"])

    statuses = [item["status"] for item in checks.values()] + [item["status"] for item in spec_results.values()] + [signals["status"]]
    if "REVIEW_REQUIRED" in statuses:
        overall = "REVIEW_REQUIRED"
    elif "ERROR" in statuses:
        overall = "ERROR"
    elif "UNKNOWN" in statuses:
        overall = "DEGRADED"
    elif "CHANGED" in statuses:
        overall = "CHANGED"
    else:
        overall = "READY"
    meaningful = any(item.get("detail") in {"OFFICIAL_SPEC_CHANGED", "DID Note missing or changed", "Receipt verification failed"} for item in list(checks.values()) + list(spec_results.values()))
    meaningful = meaningful or any(
        checks.get(name, {}).get("status") in {"REVIEW_REQUIRED", "ERROR"}
        for name in ("did_note", "mailbox", "repo", "dashboard", "contribution", "receipts", "capacity_contract")
    )
    if signals["status"] == "REVIEW_REQUIRED" or checks["teaser"]["status"] == "REVIEW_REQUIRED":
        meaningful = True
    return {
        "schema": VERSION, "checked_at": checked_at, "monitor_version": "1",
        "overall_status": overall, "freshness": assess_freshness(checked_at),
        "checks": checks, "official_specs": spec_results, "official_signals": signals,
        "signal_delta_count": signals.get("delta_count", 0),
        "meaningful_change": meaningful, "errors": [k for k, v in checks.items() if v["status"] == "ERROR"],
        "warnings": [k for k, v in checks.items() if v["status"] in {"CHANGED", "REVIEW_REQUIRED"}],
        "evidence_mode": evidence_mode, "external_writes_performed": 0,
    }


def save_run(root: Path, record: Dict[str, Any]) -> None:
    runtime = root / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    latest = runtime / "latest-health.json"
    latest.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    with (runtime / "health-monitor.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, separators=(",", ":")) + "\n")


def exit_code(record: Dict[str, Any]) -> int:
    if record["meaningful_change"]:
        return 3
    return {"READY": 0, "REVIEW_REQUIRED": 1, "CHANGED": 1, "DEGRADED": 1, "ERROR": 2}.get(record["overall_status"], 2)
