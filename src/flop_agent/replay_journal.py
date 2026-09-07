"""Unprivileged Replay client facade backed by a local helper process."""
from __future__ import annotations

import json
import secrets
import socket
import struct
import subprocess
import sys
from dataclasses import asdict, dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

PROTOCOL_VERSION="replay-ipc-v1"
MAX_REQUEST_BYTES=16_384
MAX_RESPONSE_BYTES=32_768
ACTION_SCHEMA_VERSION="replay-action-v1"
POLICY_VERSION="local-replay-side-effect-policy-v2"

class ReplaySafetyError(ValueError):
    def __init__(self,code:str,field:str,reason:str):
        super().__init__(f"{code}: {field}: {reason}");self.code=code
        self.metadata=MappingProxyType({"field":field,"reason":reason})

class ReplayState(str,Enum):
    OBSERVED="OBSERVED"; VALIDATED="VALIDATED"; REJECTED="REJECTED"
    REPLAY_IDENTITY_CONFLICT="REPLAY_IDENTITY_CONFLICT"; EFFECT_RESERVED="EFFECT_RESERVED"
    EFFECT_ATTEMPTED="EFFECT_ATTEMPTED"; EFFECT_CONFIRMED="EFFECT_CONFIRMED"
    EFFECT_FAILED_SAFE="EFFECT_FAILED_SAFE"; EFFECT_OUTCOME_UNKNOWN="EFFECT_OUTCOME_UNKNOWN"

class RetryClassification(str,Enum):
    SAFE_TO_RETRY="SAFE_TO_RETRY"; DO_NOT_RETRY="DO_NOT_RETRY"
    RECONCILIATION_REQUIRED="RECONCILIATION_REQUIRED"; HUMAN_REVIEW_REQUIRED="HUMAN_REVIEW_REQUIRED"

class EffectClass(str,Enum):
    FAUCET_CLAIM="FAUCET_CLAIM"; INFERENCE_SPEND="INFERENCE_SPEND"; PAYMENT="PAYMENT"
    AGENT_TASK="AGENT_TASK"; REPUTATION_CREDIT="REPUTATION_CREDIT"

class ConfirmationEvidenceType(str,Enum):
    LOCAL_NO_EFFECT_PROOF="LOCAL_NO_EFFECT_PROOF"; FAUCET_RESULT="FAUCET_RESULT"
    INFERENCE_RESULT="INFERENCE_RESULT"; RAIL_FINALITY="RAIL_FINALITY"
    READ_BACK_CONFIRMATION="READ_BACK_CONFIRMATION"; AGENT_TASK_RECEIPT="AGENT_TASK_RECEIPT"
    REPUTATION_RECEIPT="REPUTATION_RECEIPT"

@dataclass(frozen=True)
class CanonicalAction:
    actor_did:str; action_class:str; context:str; nonce:str
    signed_payload_sha256:str; signing_bytes_sha256:str; target:str; schema_version:str

def _recv_exact(channel:socket.socket,size:int)->bytes:
    chunks=[];remaining=size
    while remaining:
        chunk=channel.recv(remaining)
        if not chunk:raise ReplaySafetyError("IPC_TRUNCATED","response","complete framed response required")
        chunks.append(chunk);remaining-=len(chunk)
    return b"".join(chunks)

def _invoke(command:str,action:CanonicalAction)->Mapping[str,Any]|str:
    if type(action) is not CanonicalAction:raise ReplaySafetyError("ACTION_INVALID","action","exact canonical action required")
    parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
    parent.settimeout(10)
    token=secrets.token_hex(32);request_id=secrets.token_hex(16)
    request={"version":PROTOCOL_VERSION,"request_id":request_id,"auth":token,"command":command,"policy_version":POLICY_VERSION,"action":asdict(action)}
    encoded=json.dumps(request,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    if len(encoded)>MAX_REQUEST_BYTES:raise ReplaySafetyError("IPC_REQUEST_TOO_LARGE","request","bounded request required")
    process=None
    try:
        process=subprocess.Popen(
            [sys.executable,"-m","flop_agent.replay_store_helper","--serve-fd",str(child.fileno()),"--auth",token],
            pass_fds=(child.fileno(),),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True,
        )
        child.close();parent.sendall(struct.pack("!I",len(encoded))+encoded)
        size=struct.unpack("!I",_recv_exact(parent,4))[0]
        if size>MAX_RESPONSE_BYTES:raise ReplaySafetyError("IPC_RESPONSE_TOO_LARGE","response","bounded response required")
        response=json.loads(_recv_exact(parent,size).decode("utf-8"))
        if type(response) is not dict or set(response)!={"version","request_id","ok","result","error"} or response.get("version")!=PROTOCOL_VERSION or response.get("request_id")!=request_id:
            raise ReplaySafetyError("IPC_RESPONSE_INVALID","response","canonical response required")
        if response["ok"] is not True:
            error=response.get("error")
            if type(error) is not dict or set(error)!={"code","field","reason"}:raise ReplaySafetyError("IPC_RESPONSE_INVALID","response","safe error required")
            raise ReplaySafetyError(str(error["code"]),str(error["field"]),str(error["reason"]))
        result=response["result"]
        return result if command=="REPLAY_ID" else MappingProxyType(result)
    finally:
        parent.close();child.close()
        if process is not None:
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.wait()

def _build_facade():
    invoke=_invoke
    def observe(action:CanonicalAction)->Mapping[str,Any]:return invoke("OBSERVE",action)  # type: ignore[return-value]
    def inspect_action(action:CanonicalAction)->Mapping[str,Any]:return invoke("INSPECT",action)  # type: ignore[return-value]
    def replay_id(action:CanonicalAction)->str:return invoke("REPLAY_ID",action)  # type: ignore[return-value]
    return observe,inspect_action,replay_id

observe_action,inspect_action,canonical_replay_id=_build_facade()
del _build_facade
del _invoke

__all__=("CanonicalAction","ConfirmationEvidenceType","EffectClass","ReplaySafetyError","ReplayState","RetryClassification","canonical_replay_id","inspect_action","observe_action")
