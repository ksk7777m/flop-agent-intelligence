"""Offline issuance boundary for attested offer-wide completeness."""
from __future__ import annotations
import hashlib, hmac, json, sys, types
from pathlib import Path
from typing import Any, Mapping
from jsonschema import Draft202012Validator
from .tclk_accept_preflight import MAX_INPUT_BYTES as MAX_OFFER_BYTES
from .tclk_offer_wide_evidence import MAX_METADATA_BYTES, MAX_TRANSCRIPT_BYTES, assess_offer_wide_evidence
from .tclk_offer_global_winner import assess_offer_global_winner
from .tclk_transcript_boundary import MAX_RECORD_BYTES, MAX_RECORDS, _strict_object
from .tclk_source_attestation import MAX_ARTIFACT_BYTES, MAX_REPLAY_BYTES, verify_source_attestation

ROOT=Path(__file__).resolve().parents[2]
RESULT_SCHEMA=ROOT/"schemas/tclk-offer-wide-completeness.v1.json"
SCHEMA="tclk-offer-wide-completeness-v1";DOMAIN="TCLK_OFFER_WIDE_COMPLETENESS\x00V1";POLICY="tclk-offer-wide-completeness-policy-v1"
STAGES=("INPUT_BOUNDS","SOURCE_ATTESTATION","SOURCE_SCOPE","GENERATION","CURSOR","LOWER_BOUNDARY","UPPER_BOUNDARY","GAP","TRUNCATION","MALFORMED_SCOPE","RETENTION","ARTIFACT_CONFLICT","COMPLETENESS_ISSUANCE","WINNER_BOUNDARY")
class _ResourceLimit(ValueError):pass

def _canon(v:Any)->bytes:return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")
def _hash(v:bytes)->str:return hashlib.sha256(v).hexdigest()
def _parse(raw:bytes)->Any:
 v=json.loads(raw)
 if _canon(v)!=raw:raise ValueError
 return v
def _base(values:tuple[Any,...])->dict[str,Any]:
 return {"schema":SCHEMA,"domain":DOMAIN,"content_label":"PUBLIC_MINIMIZED_EVIDENCE","artifact_id":"","policy_revision":POLICY,
  "input_byte_lengths":[len(v) if type(v) is bytes else None for v in values],"input_commitments":{"offer_sha256":_hash(values[0]) if type(values[0]) is bytes else "UNAVAILABLE","transcript_sha256":_hash(values[1]) if type(values[1]) is bytes else "UNAVAILABLE","role":"LINKABLE_FINGERPRINT_NOT_WINNER_AUTHORITY"},"stages":[{"ordinal":i+1,"stage_id":n,"state":"NOT_EVALUATED"} for i,n in enumerate(STAGES)],"errors":[],
  "source_attestation":"SOURCE_ATTESTATION_INVALID","source_scope":"SOURCE_SCOPE_INSUFFICIENT","generation":"GENERATION_UNRESOLVED","cursor":"CURSOR_INTEGRITY_FAILED","lower_boundary":"LOWER_BOUNDARY_UNRESOLVED","upper_boundary":"UPPER_BOUNDARY_UNRESOLVED","gap":"GAP_UNRESOLVED","truncation":"TRUNCATION_UNRESOLVED","malformed":"MALFORMED_SCOPE_IMPACT_UNRESOLVED","retention":"RETENTION_UNRESOLVED","artifact_conflict":"SOURCE_CONFLICT_UNRESOLVED","completeness":"COMPLETENESS_NOT_ESTABLISHED",
  "record_count":0,"winner":"GLOBAL_WINNER_UNRESOLVED","race_loss":"NOT_ISSUED","chronology":"CHRONOLOGY_OBSERVED_NOT_AUTHORITATIVE","lock":"NOT_VERIFIED","settlement":"NOT_VERIFIED","ready_to_act":False,"authorized_to_act":False,"live_action_enabled":False,
  "production_api":{"classification":"SAFE_PURE_VALIDATOR","network":"NONE","technocore":"NONE","remote_mcp":"NONE","signer":"NONE","wallet":"NONE","settlement":"NONE","completeness_issuance_reachable":True,"winner_issuance_reachable":False}}
def _seal(r:dict[str,Any])->Mapping[str,Any]:
 r["artifact_id"]=_hash(_canon({k:v for k,v in r.items() if k!="artifact_id"}));_validate(r);return r
def _stop(r:dict[str,Any],code:str)->Mapping[str,Any]:r["errors"]=[code];return _seal(r)
def _records(raw:bytes)->list[dict[str,Any]]:
 rows=[]
 for line in raw.splitlines():
  if not line:continue
  if len(rows)>=MAX_RECORDS or len(line)>MAX_RECORD_BYTES:raise _ResourceLimit
  try:item=_strict_object(line)
  except Exception as e:
   if getattr(e,"code","") in {"RECORD_TOO_LARGE","MEMBER_LIMIT_EXCEEDED"}:raise _ResourceLimit from None
   raise
  if _canon(item)!=line:raise ValueError
  if not isinstance(item,dict) or type(item.get("seq")) is not int or not 0<=item["seq"]<=9007199254740991 or not isinstance(item.get("generation"),str):raise ValueError
  rows.append(item)
 return rows

def _assess(offer:bytes,transcript:bytes,descriptor:bytes,context:bytes,attestation:bytes,checkpoint:bytes,replay:bytes,attestation_verifier:Any,wide_assessor:Any,winner_assessor:Any)->Mapping[str,Any]:
 r=_base((offer,transcript,descriptor,context,attestation,checkpoint,replay));s=r["stages"]
 if any(type(x) is not bytes for x in (offer,transcript,descriptor,context,attestation,checkpoint,replay)):return _stop(r,"INPUT_TYPE_INVALID")
 if len(offer)>MAX_OFFER_BYTES or len(transcript)>MAX_TRANSCRIPT_BYTES or len(descriptor)>MAX_METADATA_BYTES or len(context)>MAX_METADATA_BYTES or len(attestation)>MAX_ARTIFACT_BYTES or len(checkpoint)>MAX_METADATA_BYTES or len(replay)>MAX_REPLAY_BYTES:return _stop(r,"INPUT_LIMIT_EXCEEDED")
 s[0]["state"]="VERIFIED"
 if not attestation:return _stop(r,"SOURCE_ATTESTATION_REQUIRED")
 attested=attestation_verifier(transcript,descriptor,context,attestation,replay)
 if attested.get("source_attestation")!="SOURCE_ATTESTATION_VERIFIED":return _stop(r,"SOURCE_ATTESTATION_INVALID")
 r["source_attestation"]="SOURCE_ATTESTATION_VERIFIED";s[1]["state"]="VERIFIED"
 try:ctx=_parse(context);cp=_parse(checkpoint)
 except Exception:return _stop(r,"MALFORMED_SCOPE_IMPACT_UNRESOLVED")
 try:rows=_records(transcript)
 except _ResourceLimit:return _stop(r,"INPUT_LIMIT_EXCEEDED")
 except Exception:return _stop(r,"MALFORMED_SCOPE_IMPACT_UNRESOLVED")
 if ctx.get("acquisition_scope")!="OFFER_WIDE" or ctx.get("source_type") not in {"DIRECT_EXPORT","LOCAL_ARCHIVE"} or not hmac.compare_digest(ctx.get("offer_sha256",""),_hash(offer)):
  return _stop(r,"SOURCE_SCOPE_INSUFFICIENT")
 r["source_scope"]="OFFER_WIDE_SCOPE_VERIFIED";s[2]["state"]="VERIFIED"
 generation=ctx.get("generation")
 if not isinstance(cp,dict) or set(cp)!={"generation","last_delivered_seq"}:return _stop(r,"CURSOR_INTEGRITY_FAILED")
 if cp.get("generation")!=generation or any(row.get("generation")!=generation for row in rows):return _stop(r,"GENERATION_MISMATCH")
 r["generation"]="GENERATION_VERIFIED";s[3]["state"]="VERIFIED"
 if type(cp.get("last_delivered_seq")) is not int or not 0<=cp["last_delivered_seq"]<=9007199254740991:return _stop(r,"CURSOR_INTEGRITY_FAILED")
 r["cursor"]="CURSOR_INTEGRITY_VERIFIED";s[4]["state"]="VERIFIED"
 if ctx.get("lower_boundary") is not True:return _stop(r,"LOWER_BOUNDARY_UNRESOLVED")
 r["lower_boundary"]="LOWER_BOUNDARY_VERIFIED";s[5]["state"]="VERIFIED"
 if ctx.get("upper_boundary") is not True:return _stop(r,"UPPER_BOUNDARY_UNRESOLVED")
 r["upper_boundary"]="UPPER_BOUNDARY_VERIFIED";s[6]["state"]="VERIFIED"
 if not rows or [x["seq"] for x in rows]!=list(range(ctx.get("first_seq",-1),ctx.get("high_water_seq",-1)+1)) or ctx["first_seq"]!=cp["last_delivered_seq"]+1:
  return _stop(r,"GAP_UNRESOLVED")
 r["gap"]="NO_GAP_VERIFIED";s[7]["state"]="VERIFIED"
 if ctx.get("truncated") is not False or ctx.get("dropped_count")!=0 or ctx.get("bounded_page") is not False:return _stop(r,"TRUNCATION_DETECTED")
 r["truncation"]="NO_TRUNCATION_ATTESTED";s[8]["state"]="VERIFIED"
 source=_canon({"source_type":ctx["source_type"],"generation":generation,"first_seq":ctx["first_seq"],"last_seq":ctx["high_water_seq"],"truncated":False,"lower_boundary":True,"upper_boundary":True})
 wide=wide_assessor(offer,transcript,source,checkpoint);winner=winner_assessor(offer,transcript);r["record_count"]=wide.get("record_count",0)
 if wide.get("errors") or wide.get("quarantined_count")!=0 or wide.get("signed_records")!="VERIFIED" or winner.get("errors") or any(x.get("eligibility")!="LOCAL_ACCEPT_ELIGIBLE" for x in winner.get("candidates",[])):return _stop(r,"MALFORMED_SCOPE_IMPACT_UNRESOLVED")
 r["malformed"]="NO_MALFORMED_SCOPE_IMPACT";s[9]["state"]="VERIFIED"
 if ctx.get("retention_loss") is not False:return _stop(r,"RETENTION_LOSS_CONFIRMED")
 r["retention"]="NO_RETENTION_LOSS_ATTESTED";s[10]["state"]="VERIFIED"
 if ctx.get("artifact_set_status")!="NO_CONFLICTS":return _stop(r,"SOURCE_CONFLICT_UNRESOLVED")
 r["artifact_conflict"]="NO_SOURCE_CONFLICT_ATTESTED";s[11]["state"]="VERIFIED"
 r["completeness"]="OFFER_WIDE_COMPLETENESS_VERIFIED";s[12]["state"]="VERIFIED";s[13]["state"]="BLOCKED"
 return _seal(r)

def _build(verifier:Any,wide:Any,winner:Any)->Any:
 def assess_offer_wide_completeness(offer_bytes:bytes,transcript_bytes:bytes,source_descriptor_bytes:bytes,acquisition_context_bytes:bytes,attestation_bytes:bytes,checkpoint_bytes:bytes,replay_ledger_bytes:bytes)->Mapping[str,Any]:
  return _assess(offer_bytes,transcript_bytes,source_descriptor_bytes,acquisition_context_bytes,attestation_bytes,checkpoint_bytes,replay_ledger_bytes,verifier,wide,winner)
 return assess_offer_wide_completeness
assess_offer_wide_completeness=_build(verify_source_attestation,assess_offer_wide_evidence,assess_offer_global_winner)

def _validate(v:Any)->None:
 try:
  schema=json.loads(RESULT_SCHEMA.read_bytes());Draft202012Validator.check_schema(schema);Draft202012Validator(schema).validate(v)
 except Exception:raise ValueError("RESULT_SCHEMA_INVALID") from None
 expected=_hash(_canon({k:x for k,x in v.items() if k!="artifact_id"}))
 if not hmac.compare_digest(v["artifact_id"],expected):raise ValueError("ARTIFACT_IDENTITY_MISMATCH")
 commitments=v["input_commitments"]
 if set(commitments)!={"offer_sha256","transcript_sha256","role"} or commitments["role"]!="LINKABLE_FINGERPRINT_NOT_WINNER_AUTHORITY":raise ValueError("INPUT_COMMITMENT_INVALID")
 complete=v["completeness"]=="OFFER_WIDE_COMPLETENESS_VERIFIED"
 gates=(v["source_attestation"]=="SOURCE_ATTESTATION_VERIFIED",v["source_scope"]=="OFFER_WIDE_SCOPE_VERIFIED",v["generation"]=="GENERATION_VERIFIED",v["cursor"]=="CURSOR_INTEGRITY_VERIFIED",v["lower_boundary"]=="LOWER_BOUNDARY_VERIFIED",v["upper_boundary"]=="UPPER_BOUNDARY_VERIFIED",v["gap"]=="NO_GAP_VERIFIED",v["truncation"]=="NO_TRUNCATION_ATTESTED",v["malformed"]=="NO_MALFORMED_SCOPE_IMPACT",v["retention"]=="NO_RETENTION_LOSS_ATTESTED",v["artifact_conflict"]=="NO_SOURCE_CONFLICT_ATTESTED")
 if complete != (not v["errors"] and all(gates)):raise ValueError("COMPLETENESS_STATE_CONTRADICTION")
 if complete and ([x["state"] for x in v["stages"][:13]]!=["VERIFIED"]*13 or v["stages"][13]["state"]!="BLOCKED"):raise ValueError("COMPLETENESS_STATE_CONTRADICTION")
 if not complete and v["stages"][12]["state"]!="NOT_EVALUATED":raise ValueError("COMPLETENESS_STATE_CONTRADICTION")
 if v["winner"]!="GLOBAL_WINNER_UNRESOLVED" or v["race_loss"]!="NOT_ISSUED" or v["lock"]!="NOT_VERIFIED" or v["settlement"]!="NOT_VERIFIED" or v["ready_to_act"] is not False or v["authorized_to_act"] is not False or v["live_action_enabled"] is not False:raise ValueError("AUTHORITY_ESCALATION_REJECTED")
 for i,(item,name) in enumerate(zip(v["stages"],STAGES),1):
  if type(item["ordinal"]) is not int or item["ordinal"]!=i or item["stage_id"]!=name:raise ValueError("STAGE_GRAMMAR_INVALID")

__all__=["assess_offer_wide_completeness"]
class _Sealed(types.ModuleType):
 _protected=frozenset({"RESULT_SCHEMA","SCHEMA","DOMAIN","POLICY","STAGES","assess_offer_wide_completeness","_assess","_build","_validate","__all__"})
 def __setattr__(self,n:str,v:Any)->None:
  if n in self._protected and n in self.__dict__:raise AttributeError("offer-wide completeness dependencies are sealed")
  super().__setattr__(n,v)
sys.modules[__name__].__class__=_Sealed
