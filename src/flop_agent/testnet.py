"""Fail-closed FLOP testnet readiness adapter.

V0 is deliberately fixture-only. It contains no network client, wallet key
handling, transaction signing, token operation, or live execution path.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Mapping
from urllib.parse import urlparse


SCHEMA = "flop-testnet-config-v0"
RECEIPT_SCHEMA = "flop-testnet-activity-receipt-v0"
TOKEN = "FLOP"
PLACEHOLDER_WALLET = "0xTEST_WALLET_PLACEHOLDER"


class LiveActionDisabled(PermissionError):
    """Raised for every action that could mutate a live network or wallet."""


class TestnetState(str, Enum):
    NOT_ANNOUNCED = "NOT_ANNOUNCED"
    OFFICIAL_DRAFT = "OFFICIAL_DRAFT"
    SIGNAL_DETECTED = "SIGNAL_DETECTED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    CONFIG_READY = "CONFIG_READY"
    FAUCET_DETECTED = "FAUCET_DETECTED"
    CLAIM_REQUIRES_APPROVAL = "CLAIM_REQUIRES_APPROVAL"
    TOKEN_BALANCE_READY = "TOKEN_BALANCE_READY"
    INFERENCE_ENDPOINT_DETECTED = "INFERENCE_ENDPOINT_DETECTED"
    INFERENCE_REQUIRES_APPROVAL = "INFERENCE_REQUIRES_APPROVAL"
    RESULT_RECEIVED = "RESULT_RECEIVED"
    EVIDENCE_VERIFIED = "EVIDENCE_VERIFIED"
    ERROR = "ERROR"


TRANSITIONS = {
    TestnetState.NOT_ANNOUNCED: {"official_draft": TestnetState.OFFICIAL_DRAFT},
    TestnetState.OFFICIAL_DRAFT: {"official_signal": TestnetState.SIGNAL_DETECTED},
    TestnetState.SIGNAL_DETECTED: {"review": TestnetState.REVIEW_REQUIRED},
    TestnetState.REVIEW_REQUIRED: {"config_verified": TestnetState.CONFIG_READY},
    TestnetState.CONFIG_READY: {"faucet_verified": TestnetState.FAUCET_DETECTED},
    TestnetState.FAUCET_DETECTED: {"preview_claim": TestnetState.CLAIM_REQUIRES_APPROVAL},
    TestnetState.CLAIM_REQUIRES_APPROVAL: {"fixture_balance": TestnetState.TOKEN_BALANCE_READY},
    TestnetState.TOKEN_BALANCE_READY: {"inference_verified": TestnetState.INFERENCE_ENDPOINT_DETECTED},
    TestnetState.INFERENCE_ENDPOINT_DETECTED: {"preview_inference": TestnetState.INFERENCE_REQUIRES_APPROVAL},
    TestnetState.INFERENCE_REQUIRES_APPROVAL: {"fixture_result": TestnetState.RESULT_RECEIVED},
    TestnetState.RESULT_RECEIVED: {"receipt_verified": TestnetState.EVIDENCE_VERIFIED},
}


def transition(state: TestnetState, event: str) -> TestnetState:
    try:
        return TRANSITIONS[state][event]
    except KeyError as error:
        raise ValueError(f"transition not allowed: {state.value} + {event}") from error


def empty_config() -> Dict[str, Any]:
    return {
        "schema": SCHEMA,
        "network_name": None,
        "chain_id": None,
        "rpc_url": None,
        "explorer_url": None,
        "faucet_url": None,
        "inference_api_url": None,
        "token_symbol": TOKEN,
        "token_contract": None,
        "source_url": None,
        "source_tier": None,
        "spec_status": None,
        "verified_at": None,
        "activation_status": "DO_NOT_ACTIVATE",
    }


def classify_source(url: str | None) -> str:
    if not url:
        return "UNVERIFIED"
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        return "UNVERIFIED"
    host, path = (parsed.hostname or "").lower(), parsed.path.lower()
    if host in {"flop.finance", "www.flop.finance", "technocore.chat"}:
        return "TIER_1_OFFICIAL"
    if host == "github.com" and path.startswith("/flop-labs/"):
        return "TIER_1_OFFICIAL"
    if host == "raw.githubusercontent.com" and path.startswith("/flop-labs/"):
        return "TIER_1_OFFICIAL"
    if host in {"x.com", "twitter.com"} and path.startswith("/flop_labs"):
        return "TIER_1_OFFICIAL"
    if host in {"x.com", "twitter.com"} and path.startswith("/cryptohayes"):
        return "REVIEW_REQUIRED"
    return "UNVERIFIED"


def validate_config(config: Mapping[str, Any]) -> Dict[str, Any]:
    source_class = classify_source(config.get("source_url"))
    required_provenance = all(config.get(key) for key in ("source_url", "source_tier", "verified_at"))
    populated = any(config.get(key) is not None for key in ("network_name", "chain_id", "rpc_url", "faucet_url", "inference_api_url", "token_contract"))
    if populated and (source_class != "TIER_1_OFFICIAL" or not required_provenance):
        return {"status": "REVIEW_REQUIRED", "reason": "UNVERIFIED_CONFIGURATION_SOURCE", "activation": "DO_NOT_ACTIVATE"}
    if config.get("token_contract") and not re.fullmatch(r"0x[a-fA-F0-9]{40}", str(config["token_contract"])):
        return {"status": "REVIEW_REQUIRED", "reason": "UNVERIFIED_CONTRACT", "activation": "DO_NOT_ACTIVATE"}
    return {
        "status": "READY" if populated else "OFFICIAL_DRAFT",
        "reason": "CONFIG_CANDIDATE_REQUIRES_HUMAN_REVIEW" if populated else "NO_OPERATIONAL_ENDPOINTS",
        "activation": "DO_NOT_ACTIVATE",
    }


def configuration_candidate(signal: Mapping[str, Any]) -> Dict[str, Any]:
    candidate = empty_config()
    for key in candidate:
        if key in signal and key not in {"activation_status", "schema"}:
            candidate[key] = signal[key]
    candidate["activation_status"] = "REVIEW_REQUIRED"
    candidate["handoff"] = "DETECT_VERIFY_REVIEW_PREPARE"
    return candidate


SECURITY_PATTERNS = {
    "seed": re.compile(r"\b(seed|seed phrase|mnemonic)\b", re.I),
    "private_key": re.compile(r"\b(private key|secret key)\b", re.I),
    "wallet_connect": re.compile(r"\b(connect (?:your )?wallet|wallet connect)\b", re.I),
}


def classify_instruction(text: str, endpoint: str | None = None) -> Dict[str, Any]:
    risks = sorted(name for name, pattern in SECURITY_PATTERNS.items() if pattern.search(text))
    if risks:
        return {"status": "CRITICAL_SECURITY_RISK", "risks": risks, "connection_prohibited": True}
    if endpoint and classify_source(endpoint) != "TIER_1_OFFICIAL":
        return {"status": "UNVERIFIED_ENDPOINT", "risks": ["unknown_endpoint"], "connection_prohibited": True}
    return {"status": "READ_ONLY", "risks": [], "connection_prohibited": False}


@dataclass(frozen=True)
class ApprovalEnvelope:
    action: str
    status: str = "PENDING"
    approved_by: str | None = None
    approved_at: str | None = None


class FaucetAdapter:
    def __init__(self, config: Mapping[str, Any]):
        self.config = dict(config)

    def detect(self) -> Dict[str, Any]:
        endpoint = self.config.get("faucet_url")
        return {"status": "FAUCET_DETECTED" if endpoint else "NOT_AVAILABLE", "endpoint": endpoint}

    def validate_source(self) -> str:
        return classify_source(self.config.get("source_url"))

    def preview_claim(self) -> Dict[str, Any]:
        endpoint = self.config.get("faucet_url")
        safety = classify_instruction("faucet claim preview", endpoint)
        return {
            "mode": "DRY_RUN",
            "state": "CLAIM_REQUIRES_APPROVAL" if endpoint and safety["status"] == "READ_ONLY" else "REVIEW_REQUIRED",
            "endpoint": endpoint,
            "network": self.config.get("network_name"),
            "wallet": PLACEHOLDER_WALLET,
            "token": TOKEN,
            "request_method": None,
            "official_source": self.config.get("source_url"),
            "known_risks": safety["risks"],
            "live_action": "DISABLED",
        }

    def claim(self, approval: ApprovalEnvelope | None = None) -> None:
        del approval
        raise LiveActionDisabled("Faucet claims are FORBIDDEN_V0 even with approval")


class WalletProvider:
    def address(self) -> None:
        return None

    def sign(self, payload: bytes, approval: ApprovalEnvelope | None = None) -> None:
        del payload, approval
        raise LiveActionDisabled("Wallet signing is FORBIDDEN_V0")


class BalanceAdapter:
    def read_fixture(self, fixture: Mapping[str, Any]) -> Dict[str, Any]:
        return {
            "wallet": fixture.get("wallet", PLACEHOLDER_WALLET),
            "token": fixture.get("token", TOKEN),
            "balance": str(fixture.get("balance", "0")),
            "network": fixture.get("network"),
            "source": "fixture",
            "fixture": True,
        }


class InferenceAdapter:
    def __init__(self, config: Mapping[str, Any]):
        self.config = dict(config)

    def discover(self) -> Dict[str, Any]:
        endpoint = self.config.get("inference_api_url")
        return {"status": "INFERENCE_ENDPOINT_DETECTED" if endpoint else "NOT_AVAILABLE", "endpoint": endpoint}

    def quote(self, request: Mapping[str, Any], fixture: Mapping[str, Any]) -> Dict[str, Any]:
        return {
            "request_id": request.get("request_id"),
            "model": fixture.get("model"),
            "provider": fixture.get("provider"),
            "estimated_flop_cost": str(fixture.get("estimated_flop_cost", "0")),
            "network": fixture.get("network"),
            "source_url": fixture.get("source_url"),
            "approval_status": "NOT_APPROVED",
            "fixture": True,
        }

    def preview(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        return {
            "mode": "DRY_RUN",
            "state": "INFERENCE_REQUIRES_APPROVAL",
            "request_id": request.get("request_id"),
            "model": request.get("model"),
            "provider": request.get("provider"),
            "prompt_hash": request.get("prompt_hash"),
            "prompt_stored": False,
            "estimated_flop_cost": request.get("estimated_flop_cost"),
            "live_action": "DISABLED",
        }

    def execute(self, request: Mapping[str, Any], approval: ApprovalEnvelope | None = None) -> None:
        del request, approval
        raise LiveActionDisabled("Inference execution is FORBIDDEN_V0 even with approval")


def inference_request(request_id: str = "dryrun-001", prompt: str | None = None) -> Dict[str, Any]:
    return {
        "request_id": request_id,
        "model": None,
        "provider": None,
        "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest() if prompt is not None else None,
        "estimated_flop_cost": None,
        "network": None,
        "source_url": None,
        "approval_status": "NOT_APPROVED",
    }


def spend_record(fixture: Mapping[str, Any]) -> Dict[str, Any]:
    try:
        requested = Decimal(str(fixture["requested_cost_flop"]))
        actual = Decimal(str(fixture["actual_cost_flop"]))
    except (KeyError, InvalidOperation) as error:
        raise ValueError("invalid FLOP cost fixture") from error
    verified = bool(fixture.get("verified")) and requested == actual
    return {
        "event_id": fixture.get("event_id"), "timestamp": fixture.get("timestamp"),
        "wallet": fixture.get("wallet", PLACEHOLDER_WALLET), "provider": fixture.get("provider"),
        "model": fixture.get("model"), "requested_cost_flop": format(requested, "f"),
        "actual_cost_flop": format(actual, "f"), "cost_match": requested == actual,
        "tx_hash": fixture.get("tx_hash"), "result_hash": fixture.get("result_hash"),
        "source": "fixture", "fixture": True, "verified": verified, "airdrop_score": "UNKNOWN",
    }


def _canonical_receipt(receipt: Mapping[str, Any]) -> bytes:
    payload = {key: value for key, value in receipt.items() if key != "integrity_sha256"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def create_fixture_receipt(activity: Mapping[str, Any], generated_at: str | None = None) -> Dict[str, Any]:
    receipt = {
        "schema": RECEIPT_SCHEMA, "activity_type": activity.get("activity_type", "inference"),
        "network": activity.get("network", "fixture"), "request_hash": activity.get("request_hash"),
        "result_hash": activity.get("result_hash"), "cost_flop": str(activity.get("cost_flop", "0")),
        "tx_hash": None, "source_url": activity.get("source_url"), "git_commit": activity.get("git_commit"),
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(), "fixture": True,
        "live_action": False, "integrity_algorithm": "SHA-256 (integrity only; not authorship)",
    }
    receipt["integrity_sha256"] = hashlib.sha256(_canonical_receipt(receipt)).hexdigest()
    return receipt


def verify_testnet_receipt(receipt: Mapping[str, Any]) -> Dict[str, Any]:
    expected = hashlib.sha256(_canonical_receipt(receipt)).hexdigest()
    valid = receipt.get("schema") == RECEIPT_SCHEMA and receipt.get("fixture") is True and receipt.get("live_action") is False and receipt.get("tx_hash") is None and receipt.get("integrity_sha256") == expected
    return {"status": "VALID_FIXTURE" if valid else "INVALID", "fixture": receipt.get("fixture") is True}


ACTIVATION_FIELDS = (
    "network_name", "chain_id", "rpc_url", "explorer_url", "faucet_url", "inference_api_url",
    "wallet_requirements", "token_symbol", "token_contract", "security_review", "human_approval",
)


def activation_checklist(config: Mapping[str, Any]) -> Dict[str, Any]:
    missing = [field for field in ACTIVATION_FIELDS if not config.get(field)]
    return {"status": "DO_NOT_ACTIVATE" if missing else "REVIEW_REQUIRED", "missing": missing, "auto_activate": False}


def load_fixture(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def current_status() -> Dict[str, str]:
    return {
        "Testnet": "OFFICIAL_DRAFT / NOT LIVE", "Faucet": "NOT AVAILABLE",
        "Inference": "NOT AVAILABLE", "Wallet": "NOT CONFIGURED", "Live actions": "DISABLED",
        "Dry-run": "READY", "Evidence": "READY", "Official monitor": "ACTIVE",
    }
