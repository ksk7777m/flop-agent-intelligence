"""Unprivileged Replay client facade backed by a reviewed local helper."""
from __future__ import annotations

import hashlib,json,secrets,socket,struct,subprocess,sys
from dataclasses import asdict,dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any,Mapping

PROTOCOL_VERSION="replay-ipc-v1";MAX_REQUEST_BYTES=16_384;MAX_RESPONSE_BYTES=32_768
ACTION_SCHEMA_VERSION="replay-action-v1";POLICY_VERSION="local-replay-side-effect-policy-v2"

class ReplaySafetyError(ValueError):
    def __init__(self,code:str,field:str,reason:str):
        super().__init__(f"{code}: {field}: {reason}");self.code=code;self.metadata=MappingProxyType({"field":field,"reason":reason})
class ReplayState(str,Enum):
    OBSERVED="OBSERVED";VALIDATED="VALIDATED";REJECTED="REJECTED";REPLAY_IDENTITY_CONFLICT="REPLAY_IDENTITY_CONFLICT";EFFECT_RESERVED="EFFECT_RESERVED";EFFECT_ATTEMPTED="EFFECT_ATTEMPTED";EFFECT_CONFIRMED="EFFECT_CONFIRMED";EFFECT_FAILED_SAFE="EFFECT_FAILED_SAFE";EFFECT_OUTCOME_UNKNOWN="EFFECT_OUTCOME_UNKNOWN"
class RetryClassification(str,Enum):
    SAFE_TO_RETRY="SAFE_TO_RETRY";DO_NOT_RETRY="DO_NOT_RETRY";RECONCILIATION_REQUIRED="RECONCILIATION_REQUIRED";HUMAN_REVIEW_REQUIRED="HUMAN_REVIEW_REQUIRED"
class EffectClass(str,Enum):
    FAUCET_CLAIM="FAUCET_CLAIM";INFERENCE_SPEND="INFERENCE_SPEND";PAYMENT="PAYMENT";AGENT_TASK="AGENT_TASK";REPUTATION_CREDIT="REPUTATION_CREDIT"
class ConfirmationEvidenceType(str,Enum):
    LOCAL_NO_EFFECT_PROOF="LOCAL_NO_EFFECT_PROOF";FAUCET_RESULT="FAUCET_RESULT";INFERENCE_RESULT="INFERENCE_RESULT";RAIL_FINALITY="RAIL_FINALITY";READ_BACK_CONFIRMATION="READ_BACK_CONFIRMATION";AGENT_TASK_RECEIPT="AGENT_TASK_RECEIPT";REPUTATION_RECEIPT="REPUTATION_RECEIPT"
@dataclass(frozen=True)
class CanonicalAction:
    actor_did:str;action_class:str;context:str;nonce:str;signed_payload_sha256:str;signing_bytes_sha256:str;target:str;schema_version:str

def _build_facade():
    jsonm,pack,unpack=json,struct.pack,struct.unpack
    socketpair,af_unix,sock_stream,shutdown_write=socket.socketpair,socket.AF_UNIX,socket.SOCK_STREAM,socket.SHUT_WR
    popen,devnull,timeout_error=subprocess.Popen,subprocess.DEVNULL,subprocess.TimeoutExpired
    executable=str(Path(sys.executable).resolve());repo=Path(__file__).resolve().parents[2];helper=repo/"libexec"/"flop_replay_store_helper"
    expected="b9bdc2607d1853346f3f0c2b319c016446810b10b5ce493682c8afbdfee0f18c"
    if not helper.is_absolute() or not helper.is_file() or helper.is_symlink() or hashlib.sha256(helper.read_bytes()).hexdigest()!=expected:raise ReplaySafetyError("HELPER_PROVENANCE_INVALID","helper","reviewed helper artifact required")
    environment=MappingProxyType({"PATH":"/usr/bin:/bin","PYTHONNOUSERSITE":"1","LC_ALL":"C"})
    action_type,error_type,proxy=CanonicalAction,ReplaySafetyError,MappingProxyType
    version,policy,max_request,max_response=PROTOCOL_VERSION,POLICY_VERSION,MAX_REQUEST_BYTES,MAX_RESPONSE_BYTES
    to_dict,token_hex=asdict,secrets.token_hex
    def recv_exact(channel:socket.socket,size:int)->bytes:
        chunks=[];remaining=size
        while remaining:
            chunk=channel.recv(remaining)
            if not chunk:raise error_type("IPC_TRUNCATED","response","complete framed response required")
            chunks.append(chunk);remaining-=len(chunk)
        return b"".join(chunks)
    def invoke(command:str,action:CanonicalAction)->Mapping[str,Any]|str:
        if type(action) is not action_type:raise error_type("ACTION_INVALID","action","exact canonical action required")
        parent,child=socketpair(af_unix,sock_stream);parent.settimeout(10);request_id=token_hex(16);process=None;return_code=None
        try:
            process=popen([executable,"-I","-S",str(helper),"--serve-fd",str(child.fileno())],pass_fds=(child.fileno(),),stdin=devnull,stdout=devnull,stderr=devnull,close_fds=True,cwd=str(repo),env=dict(environment))
            child.close();auth=recv_exact(parent,64).decode("ascii")
            request={"version":version,"request_id":request_id,"auth":auth,"command":command,"policy_version":policy,"action":to_dict(action)}
            encoded=jsonm.dumps(request,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
            if len(encoded)>max_request:raise error_type("IPC_REQUEST_TOO_LARGE","request","bounded request required")
            parent.sendall(pack("!I",len(encoded))+encoded);parent.shutdown(shutdown_write)
            size=unpack("!I",recv_exact(parent,4))[0]
            if size>max_response:raise error_type("IPC_RESPONSE_TOO_LARGE","response","bounded response required")
            response=jsonm.loads(recv_exact(parent,size).decode("utf-8"))
            if type(response) is not dict or set(response)!={"version","request_id","ok","result","error"} or response.get("version")!=version or response.get("request_id")!=request_id:raise error_type("IPC_RESPONSE_INVALID","response","canonical response required")
            if response["ok"] is not True:
                error=response.get("error")
                if type(error) is not dict or set(error)!={"code","field","reason"}:raise error_type("IPC_RESPONSE_INVALID","response","safe error required")
                raise error_type(str(error["code"]),str(error["field"]),str(error["reason"]))
            result=response["result"]
        finally:
            parent.close();child.close()
            if process is not None:
                try:return_code=process.wait(timeout=10)
                except timeout_error:process.kill();process.wait();raise error_type("IPC_HELPER_TIMEOUT","helper","helper failed closed")
        if return_code!=0:raise error_type("IPC_HELPER_FAILED","helper","helper failed closed")
        return result if command=="REPLAY_ID" else proxy(result)
    def observe(action:CanonicalAction)->Mapping[str,Any]:return invoke("OBSERVE",action)  # type: ignore[return-value]
    def inspect_action(action:CanonicalAction)->Mapping[str,Any]:return invoke("INSPECT",action)  # type: ignore[return-value]
    def replay_id(action:CanonicalAction)->str:return invoke("REPLAY_ID",action)  # type: ignore[return-value]
    return observe,inspect_action,replay_id

observe_action,inspect_action,canonical_replay_id=_build_facade();del _build_facade
__all__=("CanonicalAction","ConfirmationEvidenceType","EffectClass","ReplaySafetyError","ReplayState","RetryClassification","canonical_replay_id","inspect_action","observe_action")
