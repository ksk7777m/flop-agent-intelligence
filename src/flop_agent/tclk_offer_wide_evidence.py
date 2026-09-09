"""Offline offer-wide acquisition, cursor integrity, and completeness boundary."""
from __future__ import annotations
import hashlib, hmac, json, sys, types
from pathlib import Path
from typing import Any, Mapping
from jsonschema import Draft202012Validator
from .tclk_accept_preflight import _parse
from .tclk_offer_global_winner import assess_offer_global_winner
from .tclk_schema_evidence import COMMIT, SCHEMA_SHA256, SPEC_SHA256
from .tclk_transcript_boundary import MAX_TRANSCRIPT_BYTES, assess_tclk_transcript

SCHEMA="tclk-offer-wide-evidence-v1";DOMAIN="TCLK_OFFER_WIDE_EVIDENCE\x00V1"
POLICY="tclk-offer-wide-evidence-policy-v1";MAX_METADATA_BYTES=4096
ROOT=Path(__file__).resolve().parents[2];RESULT_SCHEMA=ROOT/"schemas/tclk-offer-wide-evidence.v1.json"
SOURCE_TYPES=frozenset({"DIRECT_EXPORT","MCP_PAGE","PROVIDED_EXPORT","LOCAL_ARCHIVE","UNKNOWN_SOURCE"})
SOURCE_FIELDS=frozenset({"source_type","generation","first_seq","last_seq","truncated","lower_boundary","upper_boundary"})
CHECKPOINT_FIELDS=frozenset({"generation","last_delivered_seq"})
STAGES=("INPUT_BOUNDS","SOURCE_METADATA","SOURCE_AUTHENTICITY","RAW_SOURCE_INTEGRITY",
 "TRANSCRIPT_VALIDATION","SIGNER_VERIFICATION","CURSOR_INTEGRITY","GENERATION_CONTINUITY",
 "SEQUENCE_CONTINUITY","LOWER_BOUNDARY","UPPER_BOUNDARY","TRUNCATION","GAP_CLASSIFICATION",
 "OFFER_WIDE_COMPLETENESS","CHRONOLOGY_AUTHORITY","WINNER_AUTHORITY","READINESS","AUTHORIZATION")

class _Error(ValueError):
 def __init__(self,code:str):super().__init__(code);self.code=code
def _canon(v:Any)->bytes:return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")
def _hash(v:bytes)->str:return hashlib.sha256(v).hexdigest()
def _identity(v:Any)->dict[str,Any]:return {"byte_length":len(v),"sha256":_hash(v)} if type(v) is bytes else {"byte_length":None,"sha256":"UNAVAILABLE"}
def _stages()->list[dict[str,Any]]:
 fixed={2:"UNKNOWN",3:"UNKNOWN",14:"NOT_AUTHORITATIVE",15:"BLOCKED",16:"BLOCKED",17:"BLOCKED"}
 return [{"ordinal":i+1,"stage_id":n,"state":fixed.get(i,"NOT_EVALUATED")} for i,n in enumerate(STAGES)]
def _base(o:Any,t:Any,s:Any,c:Any)->dict[str,Any]:
 return {"schema":SCHEMA,"domain":DOMAIN,"content_label":"PUBLIC_MINIMIZED_EVIDENCE","artifact_id":"",
  "policy_identity":{"policy_revision":POLICY,"tclk_commit":COMMIT,"schema_sha256":SCHEMA_SHA256,"spec_sha256":SPEC_SHA256,
   "winner_policy":"tclk-offer-global-winner-policy-v1","transcript_policy":"tclk-transcript-boundary-policy-v1"},
  "input_evidence":{"offer":_identity(o),"transcript":_identity(t),"source":_identity(s),"checkpoint":_identity(c),"hash_role":"LINKABLE_FINGERPRINT_NOT_AUTHORITY"},
  "stages":_stages(),"errors":[],"source":{"type":"NOT_EVALUATED","acceptance":"NOT_EVALUATED","authentication":"UNKNOWN","integrity":"UNKNOWN"},
  "cursor":{"integrity":"NOT_EVALUATED","generation":"NOT_EVALUATED","continuity":"NOT_EVALUATED","resync":"NOT_EVALUATED"},
  "gap":"NOT_EVALUATED","retention":"NOT_CONFIRMED","completeness":"COMPLETENESS_NOT_ESTABLISHED",
  "record_count":0,"quarantined_count":0,"signed_records":"NOT_EVALUATED",
  "metadata":{"classification":"OBSERVED_METADATA_NOT_SIGNED_FACT","ordering":"CHRONOLOGY_OBSERVED_NOT_AUTHORITATIVE"},
  "winner":"GLOBAL_WINNER_UNRESOLVED","race_loss":"NOT_ISSUED","lock":"NOT_VERIFIED","settlement":"NOT_VERIFIED",
  "compatibility":"COMPATIBILITY_REVIEW_REQUIRED","ready_to_act":False,"authorized_to_act":False,"live_action_enabled":False,
  "production_api":{"classification":"SAFE_PURE_VALIDATOR","network":"NONE","side_effect":"NONE","authority":"NONE","complete_issuance_reachable":False,"winner_issuance_reachable":False}}
def _seal(r:dict[str,Any])->Mapping[str,Any]:
 r["artifact_id"]=_hash(_canon({"domain":DOMAIN,**{k:v for k,v in r.items() if k!="artifact_id"}}));_validate(r);return r
def _validate(v:Any)->None:
 try:
  schema=json.loads(RESULT_SCHEMA.read_bytes());Draft202012Validator.check_schema(schema);Draft202012Validator(schema).validate(v)
 except Exception:raise _Error("RESULT_SCHEMA_INVALID") from None
 expected=_hash(_canon({"domain":DOMAIN,**{k:x for k,x in v.items() if k!="artifact_id"}}))
 if not hmac.compare_digest(v["artifact_id"],expected):raise _Error("ARTIFACT_IDENTITY_MISMATCH")
 if v["winner"]!="GLOBAL_WINNER_UNRESOLVED" or v["race_loss"]!="NOT_ISSUED" or v["ready_to_act"] is not False or v["authorized_to_act"] is not False:raise _Error("AUTHORITY_ESCALATION_REJECTED")
def _document(raw:bytes,fields:frozenset[str])->Mapping[str,Any]:
 try:v=_parse(raw)
 except Exception:raise _Error("ARTIFACT_INVALID") from None
 if set(v)!=fields:raise _Error("ARTIFACT_INVALID")
 return v
def assess_offer_wide_evidence(offer_bytes:bytes,transcript_bytes:bytes,source_metadata_bytes:bytes,checkpoint_bytes:bytes)->Mapping[str,Any]:
 r=_base(offer_bytes,transcript_bytes,source_metadata_bytes,checkpoint_bytes);st=r["stages"]
 def mark(i:int,x:str)->None:st[i]["state"]=x
 if any(type(x) is not bytes for x in (offer_bytes,transcript_bytes,source_metadata_bytes,checkpoint_bytes)):
  r["errors"]=["INPUT_TYPE_INVALID"];return _seal(r)
 if len(transcript_bytes)>MAX_TRANSCRIPT_BYTES or len(source_metadata_bytes)>MAX_METADATA_BYTES or len(checkpoint_bytes)>MAX_METADATA_BYTES:
  r["errors"]=["INPUT_LIMIT_EXCEEDED"];return _seal(r)
 mark(0,"VERIFIED")
 try:source=_document(source_metadata_bytes,SOURCE_FIELDS);checkpoint=_document(checkpoint_bytes,CHECKPOINT_FIELDS)
 except _Error as e:r["errors"]=[e.code];return _seal(r)
 if source.get("source_type") not in SOURCE_TYPES or not isinstance(source.get("generation"),str) or not source["generation"] or any(type(source.get(k)) is not bool for k in ("truncated","lower_boundary","upper_boundary")) or any(type(source.get(k)) is not int or not 0<=source[k]<=9007199254740991 for k in ("first_seq","last_seq")) or source["first_seq"]>source["last_seq"]:
  r["errors"]=["SOURCE_METADATA_INVALID"];return _seal(r)
 if not isinstance(checkpoint.get("generation"),str) or not checkpoint["generation"] or type(checkpoint.get("last_delivered_seq")) is not int or not 0<=checkpoint["last_delivered_seq"]<=9007199254740991:
  r["errors"]=["CURSOR_INTEGRITY_FAILED"];return _seal(r)
 mark(1,"VERIFIED");r["source"]={"type":source["source_type"],"acceptance":"OFFER_WIDE_SOURCE_PARTIAL","authentication":"UNKNOWN","integrity":"UNKNOWN"}
 tr=assess_tclk_transcript(transcript_bytes);win=assess_offer_global_winner(offer_bytes,transcript_bytes)
 r["record_count"]=tr["record_count"];r["quarantined_count"]=1 if tr["errors"] else 0
 valid=not tr["errors"] and tr["record_count"]>0;mark(4,"VERIFIED" if valid else "FAILED")
 signed=valid and all(x["signature"]=="VERIFIED" for x in tr["frame_evidence"]);r["signed_records"]="VERIFIED" if signed else "NOT_VERIFIED";mark(5,"VERIFIED" if signed else "FAILED")
 mark(6,"VERIFIED");r["cursor"]["integrity"]="VERIFIED"
 if source["generation"]!=checkpoint["generation"]:
  r["errors"]=["GENERATION_MISMATCH"];r["cursor"].update(generation="MISMATCH",continuity="BLOCKED",resync="RESYNC_REQUIRED");r["gap"]="GENERATION_MISMATCH";mark(7,"FAILED");return _seal(r)
 r["cursor"]["generation"]="MATCH";mark(7,"VERIFIED")
 expected=checkpoint["last_delivered_seq"]+1
 if source["first_seq"]>expected:r["gap"]="GAP_UNRESOLVED";r["cursor"].update(continuity="GAP",resync="RESYNC_REQUIRED");mark(8,"FAILED")
 elif source["first_seq"]<expected:r["gap"]="CURSOR_OVERLAP_UNRESOLVED";r["cursor"].update(continuity="NON_MONOTONIC",resync="RESYNC_REQUIRED");mark(8,"FAILED")
 else:r["gap"]="NO_INTERNAL_GAP_OBSERVED";r["cursor"].update(continuity="CONTIGUOUS",resync="NOT_REQUIRED_BY_LOCAL_CHECK");mark(8,"VERIFIED")
 mark(9,"OBSERVED" if source["lower_boundary"] else "UNKNOWN");mark(10,"OBSERVED" if source["upper_boundary"] else "UNKNOWN");mark(11,"FAILED" if source["truncated"] else "NOT_OBSERVED");mark(12,"UNRESOLVED" if r["gap"]!="NO_INTERNAL_GAP_OBSERVED" else "NO_GAP_OBSERVED")
 # Metadata bytes are caller-provided, never authenticated source authority.
 if source["truncated"] or source["source_type"] in {"MCP_PAGE","PROVIDED_EXPORT","UNKNOWN_SOURCE"}:r["source"]["acceptance"]="OFFER_WIDE_SOURCE_PARTIAL"
 elif valid:r["source"]["acceptance"]="OFFER_WIDE_SOURCE_UNAUTHENTICATED"
 mark(13,"NOT_ESTABLISHED");r["completeness"]="COMPLETENESS_NOT_ESTABLISHED"
 if win["winner"]!="GLOBAL_WINNER_UNRESOLVED":raise _Error("WINNER_BOUNDARY_FAILED")
 return _seal(r)
__all__=["assess_offer_wide_evidence"]
class _Sealed(types.ModuleType):
 _protected=frozenset({"SCHEMA","DOMAIN","POLICY","ROOT","RESULT_SCHEMA","SOURCE_TYPES","SOURCE_FIELDS","CHECKPOINT_FIELDS","STAGES","MAX_METADATA_BYTES","MAX_TRANSCRIPT_BYTES","assess_offer_global_winner","assess_tclk_transcript","_parse","_validate","_document","_seal","assess_offer_wide_evidence","__all__"})
 def __setattr__(self,n:str,v:Any)->None:
  if n in self._protected and n in self.__dict__:raise AttributeError("offer-wide evidence dependencies are sealed")
  super().__setattr__(n,v)
sys.modules[__name__].__class__=_Sealed
