"""Offline authenticated coordination-winner issuance boundary."""
from __future__ import annotations
import base64,hashlib,hmac,json,sys,time,types
from pathlib import Path
from typing import Any,Mapping
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator
from .tclk_accept_preflight import MAX_INPUT_BYTES as MAX_OFFER_BYTES
from .tclk_offer_global_winner import MAX_CANDIDATES,MAX_TRANSCRIPT_BYTES,assess_offer_global_winner
from .tclk_offer_wide_completeness import _validate as validate_completeness

ROOT=Path(__file__).resolve().parents[2];MANIFEST=ROOT/"data/tclk_winner_authorities.json";POLICY_FILE=ROOT/"data/tclk_winner_policy.json";RESULT_SCHEMA=ROOT/"schemas/tclk-authenticated-winner.v1.json"
MANIFEST_SHA256="7b9f2e8f28192b8699080c93ec63eb435fef36f1cb5f271a4bf4a0832f37781c";POLICY_SHA256="4016a20c4c5ae385915260cea52e5b151a6d8fabbea827279ac6855de316e2bf"
SCHEMA="tclk-authenticated-winner-v1";POLICY="tclk-authenticated-winner-policy-v1";CHRONOLOGY_DOMAIN=b"TCLK_CHRONOLOGY_AUTHORITY\x00V1|";WINNER_DOMAIN=b"TCLK_WINNER_AUTHORITY\x00V1|"
MAX_ARTIFACT_BYTES=16384;MAX_REPLAY_BYTES=65536
AUTH_FIELDS=frozenset({"authority_id","authority_version","key_id","public_key_b64url","policy_id","policy_version"})
CHRON_FIELDS=frozenset({"version","authority_id","authority_version","key_id","policy_id","policy_version","offer_sha256","candidate_set_sha256","ordered_candidates","unique","issued_at","expires_at","nonce","signature"})
WIN_FIELDS=frozenset({"version","authority_id","authority_version","key_id","policy_id","policy_version","policy_sha256","offer_sha256","candidate_set_sha256","completeness_sha256","chronology_sha256","winner_commitment","decision_nonce","issued_at","expires_at","signature"})
STAGES=("INPUT_BOUNDS","ARTIFACT_SCHEMA","COMPLETENESS","CANDIDATE_SET","AUTHORITY_LOOKUP","POLICY","CHRONOLOGY_AUTHORITY","SIGNATURES","DIGEST_BINDING","UNIQUENESS","FRESHNESS_REPLAY","WINNER_ISSUANCE","LOCK_SETTLEMENT_BOUNDARY")
def _canon(v:Any)->bytes:return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")
def _hash(v:bytes)->str:return hashlib.sha256(v).hexdigest()
def _parse(v:bytes)->Any:
 x=json.loads(v)
 if _canon(x)!=v:raise ValueError
 return x
def _b64(v:str)->bytes:
 if not isinstance(v,str) or not v or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in v):raise ValueError
 x=base64.urlsafe_b64decode(v+"="*(-len(v)%4))
 if base64.urlsafe_b64encode(x).decode().rstrip("=")!=v:raise ValueError
 return x
def _token(v:Any)->bool:return isinstance(v,str) and 0<len(v)<=128 and v.isascii() and all(c.isalnum() or c in "._:-" for c in v)
def _uint(v:Any)->bool:return type(v) is int and 0<=v<=9007199254740991
def _digest(v:Any)->bool:return isinstance(v,str) and len(v)==64 and all(c in "0123456789abcdef" for c in v)
def _base(vals:tuple[Any,...])->dict[str,Any]:return {"schema":SCHEMA,"content_label":"PUBLIC_MINIMIZED_EVIDENCE","artifact_id":"","policy_revision":POLICY,"input_byte_lengths":[len(x) if type(x) is bytes else None for x in vals],"stages":[{"ordinal":i+1,"stage_id":n,"state":"NOT_EVALUATED"} for i,n in enumerate(STAGES)],"errors":[],"completeness":"COMPLETENESS_NOT_VERIFIED","candidate_set":"CANDIDATE_SET_UNRESOLVED","winner_authority":"WINNER_AUTHORITY_UNVERIFIED","policy":"POLICY_UNVERIFIED","chronology":"CHRONOLOGY_AUTHORITY_MISSING","uniqueness":"WINNER_UNRESOLVED","winner":"GLOBAL_WINNER_UNRESOLVED","winner_commitment":"","candidate_count":0,"replay":"NOT_EVALUATED","race_loss":"NOT_ISSUED","lock":"NOT_VERIFIED","settlement":"NOT_VERIFIED","ready_to_act":False,"authorized_to_act":False,"live_action_enabled":False,"production_api":{"classification":"SAFE_PURE_VALIDATOR","network":"NONE","technocore":"NONE","remote_mcp":"NONE","signer":"NONE","wallet":"NONE","settlement":"NONE","winner_issuance_reachable":True,"race_loss_reachable":False}}
def _seal(r:dict[str,Any])->Mapping[str,Any]:r["artifact_id"]=_hash(_canon({k:v for k,v in r.items() if k!="artifact_id"}));_validate(r);return r
def _stop(r:dict[str,Any],code:str)->Mapping[str,Any]:r["errors"]=[code];return _seal(r)
def _manifest(raw:bytes)->dict[str,Any]:
 v=_parse(raw[:-1] if raw.endswith(b"\n") else raw)
 if not isinstance(v,dict) or set(v)!={"schema","policy_revision","authorities"} or v["schema"]!="tclk-winner-authorities-v1" or v["policy_revision"]!=POLICY or not isinstance(v["authorities"],list):raise ValueError
 ids=set();keys=set()
 for x in v["authorities"]:
  if not isinstance(x,dict) or set(x)!=AUTH_FIELDS or not all(_token(x[k]) for k in ("authority_id","authority_version","key_id","policy_id","policy_version")) or len(_b64(x["public_key_b64url"]))!=32 or x["authority_id"] in ids or x["key_id"] in keys:raise ValueError
  ids.add(x["authority_id"]);keys.add(x["key_id"])
 return v
def _signed_ok(value:dict[str,Any],key:bytes,domain:bytes)->bool:
 try:
  sig=_b64(value["signature"])
  if len(sig)!=64:return False
  Ed25519PublicKey.from_public_bytes(key).verify(sig,domain+_canon({k:v for k,v in value.items() if k!="signature"}));return True
 except Exception:return False
def _assess(offer:bytes,transcript:bytes,completeness_raw:bytes,chronology_raw:bytes,winner_raw:bytes,replay_raw:bytes,manifest_raw:bytes,policy_raw:bytes,now:int,winner_assessor:Any)->Mapping[str,Any]:
 r=_base((offer,transcript,completeness_raw,chronology_raw,winner_raw,replay_raw));s=r["stages"]
 if any(type(x) is not bytes for x in (offer,transcript,completeness_raw,chronology_raw,winner_raw,replay_raw)) or type(now) is not int:return _stop(r,"INPUT_TYPE_INVALID")
 if len(offer)>MAX_OFFER_BYTES or len(transcript)>MAX_TRANSCRIPT_BYTES or any(len(x)>MAX_ARTIFACT_BYTES for x in (completeness_raw,chronology_raw,winner_raw)) or len(replay_raw)>MAX_REPLAY_BYTES:return _stop(r,"INPUT_LIMIT_EXCEEDED")
 s[0]["state"]="VERIFIED"
 try:complete=_parse(completeness_raw);chron=_parse(chronology_raw);decision=_parse(winner_raw);replays=_parse(replay_raw)
 except Exception:return _stop(r,"ARTIFACT_SCHEMA_INVALID")
 if not isinstance(chron,dict) or set(chron)!=CHRON_FIELDS or not isinstance(decision,dict) or set(decision)!=WIN_FIELDS:return _stop(r,"ARTIFACT_SCHEMA_INVALID")
 chron_tokens=("authority_id","authority_version","key_id","policy_id","policy_version","nonce");decision_tokens=("authority_id","authority_version","key_id","policy_id","policy_version","decision_nonce")
 if chron.get("version")!="tclk-chronology-attestation-v1" or not all(_token(chron.get(k)) for k in chron_tokens) or any(not _digest(chron.get(k)) for k in ("offer_sha256","candidate_set_sha256")) or not isinstance(chron.get("ordered_candidates"),list) or len(chron["ordered_candidates"])>MAX_CANDIDATES or any(not _digest(x) for x in chron["ordered_candidates"]) or type(chron.get("unique")) is not bool or any(not _uint(chron.get(k)) for k in ("issued_at","expires_at")) or chron["issued_at"]>chron["expires_at"] or decision.get("version")!="tclk-winner-decision-v1" or not all(_token(decision.get(k)) for k in decision_tokens) or any(not _digest(decision.get(k)) for k in ("policy_sha256","offer_sha256","candidate_set_sha256","completeness_sha256","chronology_sha256","winner_commitment")) or any(not _uint(decision.get(k)) for k in ("issued_at","expires_at")) or decision["issued_at"]>decision["expires_at"]:return _stop(r,"ARTIFACT_SCHEMA_INVALID")
 s[1]["state"]="VERIFIED"
 try:validate_completeness(complete)
 except Exception:return _stop(r,"COMPLETENESS_INVALID")
 if complete.get("completeness")!="OFFER_WIDE_COMPLETENESS_VERIFIED" or complete.get("input_commitments",{}).get("offer_sha256")!=_hash(offer) or complete.get("input_commitments",{}).get("transcript_sha256")!=_hash(transcript):return _stop(r,"COMPLETENESS_INVALID")
 r["completeness"]="OFFER_WIDE_COMPLETENESS_VERIFIED";s[2]["state"]="VERIFIED"
 view=winner_assessor(offer,transcript);candidates=view.get("candidates",[])
 if view.get("errors") or not candidates or len(candidates)>MAX_CANDIDATES or any(x.get("eligibility")!="LOCAL_ACCEPT_ELIGIBLE" for x in candidates):return _stop(r,"CANDIDATE_SET_INVALID")
 ids=[x["candidate_identity"] for x in candidates]
 if len(set(ids))!=len(ids):return _stop(r,"CANDIDATE_SET_CONFLICT")
 candidate_set_sha=_hash(_canon(sorted(ids)));r["candidate_count"]=len(ids);r["candidate_set"]="OFFER_GLOBAL_CANDIDATE_SET_VERIFIED";s[3]["state"]="VERIFIED"
 try:m=_manifest(manifest_raw)
 except Exception:return _stop(r,"WINNER_AUTHORITY_MANIFEST_INVALID")
 matches=[x for x in m["authorities"] if x["authority_id"]==decision.get("authority_id") and x["authority_version"]==decision.get("authority_version") and x["key_id"]==decision.get("key_id")]
 if len(matches)!=1:return _stop(r,"WINNER_AUTHORITY_UNKNOWN")
 authority=matches[0];s[4]["state"]="VERIFIED"
 try:policy=_parse(policy_raw[:-1] if policy_raw.endswith(b"\n") else policy_raw)
 except Exception:return _stop(r,"WINNER_POLICY_INVALID")
 if _hash(policy_raw)!=POLICY_SHA256 or set(policy)!={"schema","algorithm","candidate_set_order","chronology_order","policy_id","policy_version","tie_rule"} or policy!={"schema":"tclk-winner-policy-v1","algorithm":"SEALED_CHRONOLOGY_FIRST_V1","candidate_set_order":"LEXICOGRAPHIC_COMMITMENT_SET_ONLY","chronology_order":"AUTHORITY_ATTESTED_ONLY","policy_id":"tclk-winner-selection","policy_version":"1","tie_rule":"UNRESOLVED"} or authority["policy_id"]!=policy["policy_id"] or authority["policy_version"]!=policy["policy_version"]:return _stop(r,"WINNER_POLICY_INVALID")
 if decision.get("policy_id")!=policy["policy_id"] or decision.get("policy_version")!=policy["policy_version"] or chron.get("policy_id")!=policy["policy_id"] or chron.get("policy_version")!=policy["policy_version"]:return _stop(r,"WINNER_POLICY_MISMATCH")
 r["policy"]="PINNED_POLICY_VERIFIED";s[5]["state"]="VERIFIED"
 if any(chron.get(k)!=decision.get(k) for k in ("authority_id","authority_version","key_id")) or chron["authority_id"]!=authority["authority_id"]:return _stop(r,"CHRONOLOGY_AUTHORITY_INVALID")
 s[6]["state"]="VERIFIED";key=_b64(authority["public_key_b64url"])
 if not _signed_ok(chron,key,CHRONOLOGY_DOMAIN) or not _signed_ok(decision,key,WINNER_DOMAIN):return _stop(r,"WINNER_SIGNATURE_INVALID")
 r["winner_authority"]="WINNER_AUTHORITY_VERIFIED";s[7]["state"]="VERIFIED"
 if decision["offer_sha256"]!=_hash(offer) or chron["offer_sha256"]!=_hash(offer) or decision["candidate_set_sha256"]!=candidate_set_sha or chron["candidate_set_sha256"]!=candidate_set_sha or decision["completeness_sha256"]!=_hash(completeness_raw) or decision["chronology_sha256"]!=_hash(chronology_raw) or decision["policy_sha256"]!=POLICY_SHA256:return _stop(r,"WINNER_DIGEST_MISMATCH")
 s[8]["state"]="VERIFIED"
 if chron["unique"] is not True or len(chron["ordered_candidates"])!=len(ids) or len(set(chron["ordered_candidates"]))!=len(ids) or set(chron["ordered_candidates"])!=set(ids) or not chron["ordered_candidates"] or decision["winner_commitment"]!=chron["ordered_candidates"][0] or decision["winner_commitment"] not in ids:return _stop(r,"WINNER_AMBIGUOUS")
 r["uniqueness"]="UNIQUE_WINNER_VERIFIED";s[9]["state"]="VERIFIED"
 replay_id=_hash(_canon({"authority_id":decision["authority_id"],"decision_nonce":decision["decision_nonce"],"offer_sha256":decision["offer_sha256"],"candidate_set_sha256":candidate_set_sha,"policy_sha256":POLICY_SHA256}))
 if not isinstance(replays,list) or any(not _digest(x) for x in replays):return _stop(r,"WINNER_REPLAY_INVALID")
 if replay_id in replays:return _stop(r,"WINNER_REPLAY_DETECTED")
 if now<chron["issued_at"] or now>chron["expires_at"] or now<decision["issued_at"] or now>decision["expires_at"]:return _stop(r,"WINNER_AUTHORITY_EXPIRED")
 r["replay"]="UNSEEN_IN_PROVIDED_LEDGER";s[10]["state"]="VERIFIED"
 r["chronology"]="AUTHENTICATED_CHRONOLOGY_VERIFIED";r["winner"]="OFFER_GLOBAL_WINNER_VERIFIED";r["winner_commitment"]=decision["winner_commitment"];s[11]["state"]="VERIFIED";s[12]["state"]="BLOCKED";return _seal(r)
def _build(manifest_path:Path,manifest_hash:str,policy_path:Path,policy_hash:str,clock:Any,assessor:Any)->Any:
 def assess_authenticated_winner(offer_bytes:bytes,transcript_bytes:bytes,completeness_artifact_bytes:bytes,chronology_attestation_bytes:bytes,winner_attestation_bytes:bytes,replay_ledger_bytes:bytes)->Mapping[str,Any]:
  try:
   m=manifest_path.read_bytes();p=policy_path.read_bytes()
   if _hash(m)!=manifest_hash:m=b""
   if _hash(p)!=policy_hash:p=b""
  except Exception:m=b"";p=b""
  return _assess(offer_bytes,transcript_bytes,completeness_artifact_bytes,chronology_attestation_bytes,winner_attestation_bytes,replay_ledger_bytes,m,p,int(clock()),assessor)
 return assess_authenticated_winner
assess_authenticated_winner=_build(MANIFEST,MANIFEST_SHA256,POLICY_FILE,POLICY_SHA256,time.time,assess_offer_global_winner)
def _validate(v:Any)->None:
 try:s=json.loads(RESULT_SCHEMA.read_bytes());Draft202012Validator.check_schema(s);Draft202012Validator(s).validate(v)
 except Exception:raise ValueError("RESULT_SCHEMA_INVALID") from None
 if v["artifact_id"]!=_hash(_canon({k:x for k,x in v.items() if k!="artifact_id"})):raise ValueError("ARTIFACT_IDENTITY_MISMATCH")
 won=v["winner"]=="OFFER_GLOBAL_WINNER_VERIFIED";gates=(v["completeness"]=="OFFER_WIDE_COMPLETENESS_VERIFIED",v["candidate_set"]=="OFFER_GLOBAL_CANDIDATE_SET_VERIFIED",v["winner_authority"]=="WINNER_AUTHORITY_VERIFIED",v["policy"]=="PINNED_POLICY_VERIFIED",v["chronology"]=="AUTHENTICATED_CHRONOLOGY_VERIFIED",v["uniqueness"]=="UNIQUE_WINNER_VERIFIED",len(v["winner_commitment"])==64,v["replay"]=="UNSEEN_IN_PROVIDED_LEDGER")
 if won!=(not v["errors"] and all(gates)) or v["race_loss"]!="NOT_ISSUED" or v["lock"]!="NOT_VERIFIED" or v["settlement"]!="NOT_VERIFIED" or v["ready_to_act"] is not False or v["authorized_to_act"] is not False or v["live_action_enabled"] is not False:raise ValueError("WINNER_STATE_CONTRADICTION")
 if won and ([x["state"] for x in v["stages"][:12]]!=["VERIFIED"]*12 or v["stages"][12]["state"]!="BLOCKED"):raise ValueError("WINNER_STATE_CONTRADICTION")
 if not won and v["stages"][11]["state"]!="NOT_EVALUATED":raise ValueError("WINNER_STATE_CONTRADICTION")
 for i,(x,n) in enumerate(zip(v["stages"],STAGES),1):
  if type(x["ordinal"]) is not int or x["ordinal"]!=i or x["stage_id"]!=n:raise ValueError("STAGE_GRAMMAR_INVALID")
__all__=["assess_authenticated_winner"]
class _Sealed(types.ModuleType):
 _protected=frozenset({"MANIFEST","POLICY_FILE","MANIFEST_SHA256","POLICY_SHA256","SCHEMA","POLICY","CHRONOLOGY_DOMAIN","WINNER_DOMAIN","assess_authenticated_winner","_assess","_validate","__all__"})
 def __setattr__(self,n:str,v:Any)->None:
  if n in self._protected and n in self.__dict__:raise AttributeError("winner authority dependencies are sealed")
  super().__setattr__(n,v)
sys.modules[__name__].__class__=_Sealed
