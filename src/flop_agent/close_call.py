"""close-1 draft verifier and offline accounting; never an activation issuer.

The official package does not specify launch-record signing bytes or a pinned
FLOP Labs launch key. No caller-provided DID or boolean can fill that gap.
Room names, signatures and arithmetic alone never establish official authority.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from decimal import localcontext
from pathlib import Path

from ._offline_reference import load_reference
from .message_verification import sweep_text, verify_message
from .wire_evidence import parse_nonce

SPEC_COMMIT = "0ae6b063107b77e3a6cb794186fdd341a947e5e1"
_ROOT = Path(__file__).resolve().parents[2] / "vendor/official_sources/2026-10-02/close-call"
_fold = load_reference("close_call")
_MANIFEST_HASH = "bae09812e25eb6f1369c611f24964f7ea0acafddfc45301a16f33f941296dafa"
_CONTEST_HASH = "f2c08c1388fe7f29b13be01cf4655dcf2f2178aa2df92edac5841d5a021da831"
_RULES_HASH = "3dc13bfc482707d44a1a26db080364a96b38f0ae16516e345ccd314e183d5a7f"


class CloseCallError(ValueError):
    pass


def _object(raw):
    if type(raw) is not bytes or len(raw) > 2 * 1024 * 1024:
        raise CloseCallError("DOCUMENT_SIZE_INVALID")
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise CloseCallError("DUPLICATE_JSON_KEY")
            value[key] = item
        return value
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise CloseCallError("DOCUMENT_INVALID") from None
    if type(value) is not dict:
        raise CloseCallError("DOCUMENT_INVALID")
    return value


def verify_package(contest: bytes, manifest: bytes, rules: bytes):
    config = _object(contest)
    if config.get("contest_id") != "close-1":
        raise CloseCallError("CONTEST_ID_MISMATCH")
    for raw, expected in ((contest, _CONTEST_HASH), (manifest, _MANIFEST_HASH), (rules, _RULES_HASH)):
        if hashlib.sha256(raw).hexdigest() != expected:
            raise CloseCallError("PACKAGE_HASH_MISMATCH")
    # Only this pinned package is supported. Manifest URL fields are inert.
    return config


def activation_status(*, launch_record=None, now=None):
    config = verify_package(*((_ROOT / name).read_bytes()
                              for name in ("contest.json", "manifest.json", "close-call-game.md")))
    instant = now or datetime.now(timezone.utc)
    if not isinstance(instant, datetime) or instant.tzinfo is None:
        raise CloseCallError("TIME_INVALID")
    opening = datetime.fromisoformat(config["opening"].replace("Z", "+00:00"))
    lock = datetime.fromisoformat(config["lock"].replace("Z", "+00:00"))
    return {
        "contest_id": "close-1", "official_launch_verified": False,
        "launch_record": "ABSENT_IN_REVIEWED_REPOSITORY" if launch_record is None
                         else "UNVERIFIED_UNSUPPORTED_LAUNCH_FORMAT",
        "blocker": "OFFICIAL_LAUNCH_SCHEMA_AND_AUTHORITY_REQUIRED",
        "time_window_open": opening <= instant < lock,
        "mode": "DRAFT_VERIFIER_ONLY", "dry_run": True, "live_write": "DISABLED",
    }


def verify_candidate_records(records, *, expected_referee):
    """Check a proposed referee's signatures, NOT that it is FLOP Labs' referee.

    Caller supplies a bounded offline sequence. Sequence/timestamp metadata are
    unsigned; completeness and official referee authority remain unproven.
    """
    if type(records) is not list or not 1 <= len(records) <= 10000:
        raise CloseCallError("RECORD_BOUND_INVALID")
    config = verify_package(*((_ROOT / name).read_bytes()
                              for name in ("contest.json", "manifest.json", "close-call-game.md")))
    rooms = dict(zip(("flow", "state", "price", "positions", "pnl"), config["rooms"]["referee"]))
    last_nonce, seen, seed_seen = {}, set(), False
    for record in records:
        if (type(record) is not dict or any(type(record.get(k)) is not str
                for k in ("room", "from", "nonce", "sig", "text"))):
            raise CloseCallError("RECORD_INVALID")
        room = record["room"]
        if room not in rooms.values() or record["from"] != expected_referee:
            raise CloseCallError("REFEREE_OR_ROOM_MISMATCH")
        try:
            nonce = int(parse_nonce(record["nonce"]).decimal)
            if (record["text"] != sweep_text(record["text"])
                    or re.fullmatch(r"[A-Za-z0-9_-]{85}[AQgw]", record["sig"]) is None):
                raise ValueError()
            verify_message(expected_referee, record["sig"], room, record["nonce"], record["text"])
        except Exception:
            raise CloseCallError("SIGNATURE_INVALID") from None
        identity = (room, record["nonce"])
        if identity in seen or nonce <= last_nonce.get(room, 0):
            raise CloseCallError("REPLAYED_RECORD")
        seen.add(identity); last_nonce[room] = nonce
        body = _object(record["text"].encode("utf-8"))
        kind = body.get("t")
        if kind in {"seed", "final"}:
            if body.get("season") != "close-1" or room != rooms["price"]:
                raise CloseCallError("CONTEST_OR_ROOM_MISMATCH")
            if _fold.amount(body.get("price")) is None:
                raise CloseCallError("PRICE_INVALID")
            if kind == "seed":
                if seed_seen or body.get("package") != _MANIFEST_HASH:
                    raise CloseCallError("SEED_PACKAGE_MISMATCH")
                if body.get("rooms") != config["rooms"]["referee"]:
                    raise CloseCallError("ROOM_MAPPING_MISMATCH")
                if _fold.amount(body.get("price")) is None:
                    raise CloseCallError("SEED_PRICE_INVALID")
                seed_seen = True
        elif kind not in rooms or rooms[kind] != room:
            raise CloseCallError("RECORD_KIND_MISMATCH")
        else:
            if type(body.get("n")) is not int or not 1 <= body["n"] <= config["lock_sweep"]:
                raise CloseCallError("SWEEP_INVALID")
            if type(body.get("file")) is not str or not re.fullmatch(r"[0-9a-f]{64}", body["file"]):
                raise CloseCallError("SWEEP_HASH_INVALID")
    if not seed_seen:
        raise CloseCallError("SIGNED_SEED_REQUIRED")
    return {"signatures": "VERIFIED_FOR_CANDIDATE_KEY", "seed_package": "MATCHED",
            "official_launch_verified": False, "history_complete": False,
            "records_checked": len(records), "dry_run": True, "live_write": "DISABLED"}


def replay_signed_archive(seed, flows, archives, *, expected_referee):
    """Hash-bind full archive bytes to signed flow records; reject redactions.

    Archive format is documented at the configured official archive README.
    This authenticates a candidate key's statements, not launch authority or
    original counterparties' signatures (which the archive does not contain).
    """
    if type(flows) is not list or type(archives) is not list or len(flows) != len(archives):
        raise CloseCallError("ARCHIVE_BINDING_INVALID")
    evidence = verify_candidate_records([seed] + flows, expected_referee=expected_referee)
    seed_body = _object(seed["text"].encode())
    if seed_body.get("t") != "seed":
        raise CloseCallError("SIGNED_SEED_REQUIRED")
    config = _object((_ROOT / "contest.json").read_bytes())
    fold, results = _fold.Fold(config), []
    fold.seed(seed_body["price"])
    with localcontext() as context:
        context.prec = 60
        for expected_n, (flow, raw) in enumerate(zip(flows, archives), 1):
            body = _object(flow["text"].encode())
            if (body.get("t") != "flow" or body.get("n") != expected_n
                    or type(raw) is not bytes or len(raw) > 2 * 1024 * 1024
                    or hashlib.sha256(raw).hexdigest() != body.get("file")):
                raise CloseCallError("ARCHIVE_HASH_OR_GAP_MISMATCH")
            archive = _object(raw)
            if set(archive) != {"input", "output"} or type(archive["input"]) is not dict:
                raise CloseCallError("ARCHIVE_SHAPE_INVALID")
            event = archive["input"]
            if (event.get("t") != "sweep" or event.get("n") != expected_n
                    or type(event.get("owners")) is not list or type(event.get("trades")) is not list
                    or any(type(t) is not dict or "redacted" in t for t in event["trades"])):
                raise CloseCallError("ARCHIVE_REDACTED_OR_INVALID")
            try:
                result = fold.sweep(expected_n, event.get("ref"), event.get("close"),
                                    event["owners"], event["trades"])
            except Exception:
                raise CloseCallError("ARCHIVE_FOLD_INVALID") from None
            if result != archive["output"]:
                raise CloseCallError("ARCHIVE_OUTPUT_MISMATCH")
            results.append(result)
    return {**evidence, "archive": "FULL_BYTES_HASH_BOUND_TO_CANDIDATE_SIGNATURES",
            "counterparty_signatures": "NOT_AVAILABLE_IN_ARCHIVE", "sweeps": results,
            "balances": {key: str(account.cash) for key, account in fold.accounts.items()},
            "positions": {key: str(account.position) for key, account in fold.accounts.items()}}


def replay_draft(events: bytes):
    """Reconstruct sample/local accounting only; input is NOT authoritative."""
    if type(events) is not bytes or len(events) > 2 * 1024 * 1024:
        raise CloseCallError("EVENT_BOUND_INVALID")
    config = verify_package(*((_ROOT / name).read_bytes()
                              for name in ("contest.json", "manifest.json", "close-call-game.md")))
    fold, sweeps, final = _fold.Fold(config), [], None
    try:
        with localcontext() as context:
            context.prec = 60
            for line in events.splitlines():
                if not line.strip():
                    continue
                event = _object(line)
                if final is not None:
                    raise ValueError()
                if event.get("t") == "seed":
                    fold.seed(event.get("px"))
                elif event.get("t") == "sweep":
                    if not isinstance(event.get("owners"), list) or not isinstance(event.get("trades"), list):
                        raise ValueError()
                    sweeps.append(fold.sweep(event.get("n"), event.get("ref"), event.get("close"),
                                             event["owners"], event["trades"]))
                elif event.get("t") == "final" and fold.global_px is not None:
                    final = fold.final(event.get("px"))
                else:
                    raise ValueError()
    except Exception:
        raise CloseCallError("DRAFT_FOLD_INVALID") from None
    return {"status": "UNAUTHENTICATED_DRAFT_REPLAY", "official_launch_verified": False,
            "dry_run": True, "live_write": "DISABLED", "sweeps": sweeps, "final": final,
            "balances": {key: str(account.cash) for key, account in fold.accounts.items()},
            "positions": {key: str(account.position) for key, account in fold.accounts.items()}}
