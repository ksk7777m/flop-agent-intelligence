"""D-0505/D-0511 draft byte conformance, NOT settlement or signature authority.

FLOP uses sr25519, unlike Technocore's Ed25519 lane. This module deliberately
does not claim signature verification; no sr25519 verifier is installed here.
"""
from __future__ import annotations

import hashlib
from types import MappingProxyType

from ._offline_reference import load_reference

_wire = load_reference("yellowpaper")
SPEC_COMMIT = "3c97bbc8d6ba68cf2ea003ab88bc154aafdf105e"
VERSION_REGISTRY = MappingProxyType({
    "yellowpaper_wire_version": "flop-wire-v1", "receipt_version": 1,
    "leaf_versions": (0, 1, 2, 3), "transcript_version": "FCC4",
    "replay_domain_version": 1, "spec_commit": SPEC_COMMIT,
    "authority": "OFFICIAL_NORMATIVE_DRAFT", "live_action_enabled": False,
})


def _uint(value, bits):
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError("UNSIGNED_INTEGER_INVALID")
    return value


def _hash(value):
    if type(value) is not bytes or len(value) != 32:
        raise ValueError("HASH_INVALID")
    return value


def require_profile(profile):
    if profile != "flop-wire-v1":
        raise ValueError("UNKNOWN_WIRE_VERSION")


def channel_id(genesis, agent, miner, nonce, *, profile="flop-wire-v1"):
    require_profile(profile)
    return _wire.channel_id_v1(_hash(genesis), _hash(agent), _hash(miner), _uint(nonce, 64))


def task_hash(genesis, agent, nonce, model, payload, commit, *, profile="flop-wire-v1"):
    require_profile(profile)
    return _wire.task_hash_v1(_hash(genesis), _hash(agent), _uint(nonce, 64),
                              _hash(model), _hash(payload), _hash(commit))


def leaf_hash(version, **fields):
    if type(version) is not int or version not in (0, 1, 2, 3):
        raise ValueError("UNKNOWN_LEAF_VERSION")
    for name in ("channel_id", "h_in", "h_out", "decode_policy_hash", "ids_hash", "toploc_commitment_hash"):
        _hash(fields[name])
    for name, bits in (("turn_index", 32), ("g_n", 128), ("miner_recv_ms", 64),
                       ("miner_done_ms", 64), ("latency_ms", 64)):
        _uint(fields[name], bits)
    return _wire.transcript_leaf(_wire.TranscriptLeafVersion(version), **fields)


def decode_transcript(raw, *, expected_channel, policy_hash, legacy_mode=False,
                      profile="flop-wire-v1"):
    require_profile(profile)
    _hash(expected_channel)
    if type(legacy_mode) is not bool or (policy_hash is None and not legacy_mode):
        raise ValueError("EXPLICIT_LEGACY_MODE_REQUIRED")
    if policy_hash is not None:
        _hash(policy_hash)
    if type(raw) is not bytes or len(raw) > 2 * 1024 * 1024:
        raise ValueError("TRANSCRIPT_SIZE_INVALID")
    channel, turns = _wire.decode_transcript_blob(raw)
    if channel != expected_channel:
        raise ValueError("CHANNEL_MISMATCH")
    indices = set()
    for turn in turns:
        if turn.turn_index in indices:
            raise ValueError("DUPLICATE_TURN")
        indices.add(turn.turn_index)
        if policy_hash is not None and (turn.leaf_version < 2 or turn.decode_policy_hash != policy_hash):
            raise ValueError("DECODE_POLICY_MISMATCH")
    return channel, turns


def encode_transcript(channel, turns):
    # Re-decode for canonical structure only; channel-policy validation is separate.
    raw = _wire.encode_transcript_blob(_hash(channel), turns)
    _wire.decode_transcript_blob(raw)
    return raw


def derive_payable(*, path, escrow, turn_count, aggregate_gn,
                   base_per_turn, rate_g, contract_payment=None):
    for value in (escrow, turn_count, aggregate_gn, base_per_turn, rate_g):
        _uint(value, 128)
    if path not in {"settle", "force_settle"}:
        raise ValueError("UNKNOWN_SETTLEMENT_PATH")
    if contract_payment is not None:
        result = _uint(contract_payment, 128)
    elif path == "settle":
        result = escrow
    else:
        result = _uint(base_per_turn * turn_count + rate_g * aggregate_gn, 128)
    if result > escrow:
        raise ValueError("TARIFF_EXCEEDS_ESCROW")
    return result


def receipt_preimage(channel, root, aggregate_gn, payable, *, wire_profile=1,
                     legacy_mode=False):
    _hash(channel); _hash(root); _uint(aggregate_gn, 128); _uint(payable, 128)
    if type(wire_profile) is int and wire_profile == 1:
        return _wire.receipt_message_v1(channel, root, aggregate_gn, payable)
    if wire_profile is None and legacy_mode is True:
        return _wire.legacy_receipt_message(channel, root, aggregate_gn, payable)
    raise ValueError("UNKNOWN_RECEIPT_VERSION_OR_CUTOFF")


def check_receipt(raw, *, channel, root, aggregate_gn, state, wire_profile=1):
    payable = derive_payable(aggregate_gn=aggregate_gn, **state)
    if raw != receipt_preimage(channel, root, aggregate_gn, payable, wire_profile=wire_profile):
        raise ValueError("RECEIPT_BINDING_MISMATCH")
    return {"bytes_conformant": True, "signature": "NOT_VERIFIED_SR25519",
            "payable": payable, "live_action_enabled": False}


def check_merkle_path(leaf, path, root):
    _hash(leaf); _hash(root)
    if type(path) is not list or len(path) > 64:
        raise ValueError("PATH_BOUND_INVALID")
    for sibling, is_left in path:
        _hash(sibling)
        if type(is_left) is not bool:
            raise ValueError("PATH_ORIENTATION_INVALID")
    if _wire.root_from_path(leaf, path) != root:
        raise ValueError("MERKLE_PATH_MISMATCH")
    return True


def decode_compact(raw):
    value, end = _wire.decode_compact_u32(raw)
    if end != len(raw):
        raise ValueError("TRAILING_COMPACT_BYTES")
    return value


def encode_compact(value):
    return _wire.compact_u32(_uint(value, 32))


def decode_policy_hash(raw):
    """Validate the explicit F.1 SCALE structure before hashing its exact bytes."""
    if type(raw) is not bytes or len(raw) > 256:
        raise ValueError("DECODE_POLICY_INVALID")
    offset = 0
    def take(size):
        nonlocal offset
        value = raw[offset:offset + size]
        offset += size
        if len(value) != size:
            raise ValueError("DECODE_POLICY_TRUNCATED")
        return value
    if take(2) != b"\x01\x00":
        raise ValueError("UNKNOWN_POLICY_VERSION")
    tag = take(1)[0]
    if tag > 4:
        raise ValueError("UNKNOWN_POLICY_CLASS")
    if tag == 4:
        take(2)
    take(32)  # tokenizer hash
    take(26)  # four u32s, u16 beam width, u64 seed
    take(32)  # stop conditions
    transform = take(1)[0]
    if transform not in (0, 1):
        raise ValueError("UNKNOWN_OUTPUT_TRANSFORM")
    if transform == 1:
        take(32)
    take(32)  # class policy
    if offset != len(raw):
        raise ValueError("DECODE_POLICY_TRAILING_BYTES")
    return hashlib.sha256(b"FLOP_DECODE_POLICY_HASH_V1" + raw).digest()
