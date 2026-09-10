"""Offline-only KOL program, referral, and attribution evidence readiness."""
from __future__ import annotations
import hashlib,json
from pathlib import Path
from typing import Any,Mapping
from jsonschema import Draft202012Validator

ROOT=Path(__file__).resolve().parents[2];BASELINE=ROOT/"data/flop_kol_program_baseline.json";AUTHORITIES=ROOT/"data/flop_kol_authorities.json";RESULT_SCHEMA=ROOT/"schemas/flop-kol-referral-readiness.v1.json"
BASELINE_SHA256="ca7696ae7cce7b106ec58d6e46573f0a99d229486cb699e9fd2946e1d0eccc68";AUTHORITIES_SHA256="a4d9231ae5ccc3be1f310f5b204746d1f4c3aefdc803d378de60982b3a2f1083"
SCHEMA="flop-kol-referral-readiness-v1";POLICY="flop-kol-referral-readiness-policy-v1";MAX_INPUT_BYTES=65536;MAX_PROGRAMS=32;MAX_REFERRALS=64
OFFICIAL=frozenset({"FLOP_LABS_OFFICIAL","REVIEWED_OFFICIAL_STATEMENT"});UNTRUSTED=frozenset({"TECHNOCORE_USER_CONTENT","COMMUNITY_SIGNED","X_COMMUNITY_POST","SEARCH_RESULT","AGGREGATOR","UNOFFICIAL_GITHUB","LOOKALIKE_DOMAIN","SHORTENED_URL","THIRD_PARTY_REFERRAL","USER_OFFICIAL_LABEL"})
PROGRAM_FIELDS=frozenset({"source_class","source_id","source_document_sha256","program_id","announcement_version","rules_version","rules_sha256","details","leaderboard","source_nonce"})
REFERRAL_FIELDS=frozenset({"source_class","source_id","source_document_sha256","program_id","announcement_version","rules_version","rules_sha256","referrer_sha256","referral_link_sha256","domain_endpoint_sha256","issued_context_sha256","issued_at","expires_at","source_nonce"})
AUTH_FIELDS=frozenset({"source_class","source_id","source_document_sha256","program_id","announcement_version","rules_version","rules_sha256","referrals"})
AUTH_REF_FIELDS=frozenset({"referrer_sha256","referral_link_sha256","domain_endpoint_sha256","issued_context_sha256","issued_at","expires_at"})
ATTR_FIELDS=frozenset({"program_id","rules_sha256","referral_link_sha256","wallet_identity_sha256","wallet_creation_event_sha256","network_usage_sha256","event_source_sha256","event_timestamp_sha256","evidence_nonce","self_referral_claimed"})
def _canon(v:Any)->bytes:return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")
def _hash(v:bytes)->str:return hashlib.sha256(v).hexdigest()
def _digest(v:Any)->bool:return isinstance(v,str) and len(v)==64 and all(c in "0123456789abcdef" for c in v)
def _token(v:Any)->bool:return isinstance(v,str) and 0<len(v)<=128 and v.isascii() and all(c.isalnum() or c in "._:-" for c in v)
def _uint(v:Any)->bool:return type(v) is int and 0<=v<=9007199254740991
def _parse(raw:bytes)->Any:
 payload=raw[:-1] if raw.endswith(b"\n") else raw;value=json.loads(payload)
 if _canon(value)!=payload:raise ValueError
 return value
def _base(pc:int,rc:int)->dict[str,Any]:return {"schema":SCHEMA,"content_label":"PUBLIC_MINIMIZED_EVIDENCE","artifact_id":"","policy_revision":POLICY,"reviewed_as_of":"2026-09-10","program":"KOL_PROGRAM_ANNOUNCED","program_details":"KOL_PROGRAM_DETAILS_PENDING","referral":"REFERRAL_LINK_NOT_ISSUED","leaderboard":"LEADERBOARD_NOT_PUBLISHED","attribution":"ATTRIBUTION_NOT_ESTABLISHED","wallet_creation":"WALLET_CREATION_NOT_OBSERVED","network_usage":"NETWORK_USAGE_NOT_OBSERVED","flop_help_metric":"UNRESOLVED","lottery_rule_status":"DETAILS_PENDING","reward_formula":"UNRESOLVED","ranking_formula":"UNRESOLVED","airdrop_attribution_effect":"UNRESOLVED","self_referral_policy":"UNRESOLVED","sybil_policy":"UNRESOLVED","program_candidate_count":pc,"referral_candidate_count":rc,"errors":[],"attributed_user_verified":False,"network_usage_verified":False,"rank_verified":False,"reward_verified":False,"lottery_eligibility_verified":False,"agent_airdrop_eligible":False,"authorized_to_register":False,"authorized_to_open_referral":False,"authorized_to_create_wallet":False,"authorized_to_track_user":False,"authorized_to_claim":False,"ready_to_act":False,"authorized_to_act":False,"live_action_enabled":False,"production_api":{"classification":"SAFE_PURE_OFFLINE_VALIDATOR","network":"NONE","http":"NONE","x":"NONE","technocore":"NONE","remote_mcp":"NONE","browser":"NONE","analytics":"NONE","wallet":"NONE","signer":"NONE","referral_action":"NONE","claim":"NONE"}}
def _seal(result:dict[str,Any])->Mapping[str,Any]:result["artifact_id"]=_hash(_canon({k:v for k,v in result.items() if k!="artifact_id"}));validate_kol_projection(result);return result
def _stop(result:dict[str,Any],code:str)->Mapping[str,Any]:result["errors"]=[code];return _seal(result)
def _valid_program(value:Any)->bool:
 if not isinstance(value,dict) or set(value)!=PROGRAM_FIELDS or value["source_class"] not in OFFICIAL|UNTRUSTED:return False
 return all(_token(value[k]) for k in ("source_id","program_id","announcement_version","source_nonce")) and _digest(value["source_document_sha256"]) and (value["rules_version"] is None or _token(value["rules_version"])) and (value["rules_sha256"] is None or _digest(value["rules_sha256"])) and value["details"] in {"PENDING","PUBLISHED"} and value["leaderboard"] in {"NOT_PUBLISHED","CANDIDATE","PUBLISHED"} and ((value["rules_version"] is None)==(value["rules_sha256"] is None))
def _valid_referral(value:Any)->bool:
 return isinstance(value,dict) and set(value)==REFERRAL_FIELDS and value["source_class"] in OFFICIAL|UNTRUSTED and all(_token(value[k]) for k in ("source_id","program_id","announcement_version","rules_version","source_nonce")) and all(_digest(value[k]) for k in ("source_document_sha256","rules_sha256","referrer_sha256","referral_link_sha256","domain_endpoint_sha256","issued_context_sha256")) and _uint(value["issued_at"]) and _uint(value["expires_at"]) and value["issued_at"]<=value["expires_at"]
def _valid_attribution(value:Any)->bool:
 if value=={}:return True
 return isinstance(value,dict) and set(value)==ATTR_FIELDS and all(_token(value[k]) for k in ("program_id","evidence_nonce")) and all(value[k] is None or _digest(value[k]) for k in ("rules_sha256","referral_link_sha256","wallet_identity_sha256","wallet_creation_event_sha256","network_usage_sha256","event_source_sha256","event_timestamp_sha256")) and type(value["self_referral_claimed"]) is bool
def _manifest(value:Any)->list[dict[str,Any]]:
 if not isinstance(value,dict) or set(value)!={"schema","authorities"} or value["schema"]!="flop-kol-authorities-v1" or not isinstance(value["authorities"],list):raise ValueError
 for item in value["authorities"]:
  if not isinstance(item,dict) or set(item)!=AUTH_FIELDS or item["source_class"] not in OFFICIAL or not all(_token(item[k]) for k in ("source_id","program_id","announcement_version","rules_version")) or not all(_digest(item[k]) for k in ("source_document_sha256","rules_sha256")) or not isinstance(item["referrals"],list):raise ValueError
  for ref in item["referrals"]:
   if not isinstance(ref,dict) or set(ref)!=AUTH_REF_FIELDS or not all(_digest(ref[k]) for k in AUTH_REF_FIELDS if k.endswith("sha256")) or not _uint(ref["issued_at"]) or not _uint(ref["expires_at"]) or ref["issued_at"]>ref["expires_at"]:raise ValueError
 return value["authorities"]
def _assess(program_raw:bytes,referral_raw:bytes,attribution_raw:bytes,baseline_raw:bytes,authorities_raw:bytes)->Mapping[str,Any]:
 result=_base(0,0)
 if any(type(x) is not bytes for x in (program_raw,referral_raw,attribution_raw,baseline_raw,authorities_raw)):return _stop(result,"INPUT_TYPE_INVALID")
 if any(len(x)>MAX_INPUT_BYTES for x in (program_raw,referral_raw,attribution_raw,baseline_raw,authorities_raw)):return _stop(result,"INPUT_LIMIT_EXCEEDED")
 try:programs=_parse(program_raw);referrals=_parse(referral_raw);attribution=_parse(attribution_raw);baseline=_parse(baseline_raw);manifest=_parse(authorities_raw)
 except Exception:return _stop(result,"ARTIFACT_SCHEMA_INVALID")
 if not isinstance(programs,list) or len(programs)>MAX_PROGRAMS or any(not _valid_program(x) for x in programs) or not isinstance(referrals,list) or len(referrals)>MAX_REFERRALS or any(not _valid_referral(x) for x in referrals) or not _valid_attribution(attribution):return _stop(result,"ARTIFACT_SCHEMA_INVALID")
 result["program_candidate_count"]=len(programs);result["referral_candidate_count"]=len(referrals)
 if baseline.get("schema")!="flop-kol-program-baseline-v1" or baseline.get("program",{}).get("details")!="PENDING" or baseline.get("policy",{}).get("reward_formula")!="UNRESOLVED":return _stop(result,"ARTIFACT_SCHEMA_INVALID")
 try:authorities=_manifest(manifest)
 except Exception:return _stop(result,"ARTIFACT_SCHEMA_INVALID")
 nonces=[(x["source_class"],x["source_id"],x["source_nonce"]) for x in programs+referrals]
 if len(set(nonces))!=len(nonces):return _stop(result,"REPLAY_CANDIDATE")
 def authority_for(value:dict[str,Any])->list[dict[str,Any]]:
  return [a for a in authorities if all(value[k]==a[k] for k in ("source_class","source_id","source_document_sha256","program_id","announcement_version","rules_version","rules_sha256"))]
 if programs:
  if any(x["source_class"] in UNTRUSTED or not authority_for(x) for x in programs):return _stop(result,"SOURCE_UNVERIFIED")
  rules={(x["program_id"],x["rules_version"],x["rules_sha256"]) for x in programs}
  if len(rules)>1:result["program"]="KOL_PROGRAM_CONFLICT";return _stop(result,"PROGRAM_CONFLICT")
  current=programs[0]
  if current["details"]!="PUBLISHED" or current["rules_sha256"] is None:return _stop(result,"PROGRAM_RULES_REQUIRED")
  result["program"]="KOL_PROGRAM_READY_FOR_HUMAN_REVIEW";result["program_details"]="KOL_PROGRAM_DETAILS_VERIFIED"
  if current["leaderboard"]=="CANDIDATE":result["leaderboard"]="LEADERBOARD_CANDIDATE"
  elif current["leaderboard"]=="PUBLISHED":result["leaderboard"]="LEADERBOARD_OFFICIAL_SOURCE_VERIFIED"
 verified_refs=[]
 if referrals:
  result["referral"]="REFERRAL_LINK_CANDIDATE"
  for ref in referrals:
   matches=authority_for(ref)
   if ref["source_class"] in UNTRUSTED or len(matches)!=1:continue
   binding={k:ref[k] for k in AUTH_REF_FIELDS}
   if binding not in matches[0]["referrals"]:continue
   verified_refs.append(ref)
  if len(verified_refs)!=len(referrals):return _stop(result,"SOURCE_BINDING_MISMATCH" if any(authority_for(x) for x in referrals) else "SOURCE_UNVERIFIED")
  identities={(x["referral_link_sha256"],x["domain_endpoint_sha256"],x["referrer_sha256"],x["rules_sha256"]) for x in verified_refs}
  if len(identities)>1:result["referral"]="REFERRAL_LINK_CONFLICT";return _stop(result,"REFERRAL_CONFLICT")
  if result["program"]!="KOL_PROGRAM_READY_FOR_HUMAN_REVIEW":result["referral"]="REFERRAL_LINK_SOURCE_VERIFIED";return _stop(result,"PROGRAM_RULES_REQUIRED")
  result["referral"]="REFERRAL_LINK_READY_FOR_HUMAN_REVIEW"
 if attribution!={}:
  if result["referral"]!="REFERRAL_LINK_READY_FOR_HUMAN_REVIEW":return _stop(result,"REFERRAL_REQUIRED")
  ref=verified_refs[0]
  if attribution["program_id"]!=ref["program_id"] or attribution["rules_sha256"]!=ref["rules_sha256"] or attribution["referral_link_sha256"]!=ref["referral_link_sha256"]:result["attribution"]="ATTRIBUTION_CONFLICT";return _stop(result,"ATTRIBUTION_RULE_MISMATCH")
  if attribution["wallet_identity_sha256"] is None or attribution["wallet_creation_event_sha256"] is None:return _stop(result,"WALLET_EVIDENCE_REQUIRED")
  result["wallet_creation"]="WALLET_CREATION_EVIDENCE_COMMITTED"
  if attribution["network_usage_sha256"] is None or attribution["event_source_sha256"] is None or attribution["event_timestamp_sha256"] is None:return _stop(result,"NETWORK_USAGE_EVIDENCE_REQUIRED")
  result["network_usage"]="NETWORK_USAGE_EVIDENCE_COMMITTED"
  if attribution["self_referral_claimed"]:result["attribution"]="ATTRIBUTION_RULES_UNRESOLVED";return _stop(result,"PROGRAM_RULES_REQUIRED")
  result["attribution"]="ATTRIBUTION_EVIDENCE_READY"
 return _seal(result)
def assess_kol_referral_readiness(program_candidates_bytes:bytes,referral_candidates_bytes:bytes,attribution_evidence_bytes:bytes)->Mapping[str,Any]:
 try:
  baseline=BASELINE.read_bytes();authorities=AUTHORITIES.read_bytes()
  if _hash(baseline)!=BASELINE_SHA256:baseline=b""
  if _hash(authorities)!=AUTHORITIES_SHA256:authorities=b""
 except Exception:baseline=b"";authorities=b""
 return _assess(program_candidates_bytes,referral_candidates_bytes,attribution_evidence_bytes,baseline,authorities)
def validate_kol_projection(value:Any)->None:
 try:schema=json.loads(RESULT_SCHEMA.read_bytes());Draft202012Validator.check_schema(schema);Draft202012Validator(schema).validate(value)
 except Exception:raise ValueError("RESULT_SCHEMA_INVALID") from None
 if value["artifact_id"]!=_hash(_canon({k:v for k,v in value.items() if k!="artifact_id"})):raise ValueError("ARTIFACT_IDENTITY_MISMATCH")
 false_fields=("attributed_user_verified","network_usage_verified","rank_verified","reward_verified","lottery_eligibility_verified","agent_airdrop_eligible","authorized_to_register","authorized_to_open_referral","authorized_to_create_wallet","authorized_to_track_user","authorized_to_claim","ready_to_act","authorized_to_act","live_action_enabled")
 if any(value[x] is not False for x in false_fields):raise ValueError("ACTION_BOUNDARY_VIOLATION")
 if value["program_details"]=="KOL_PROGRAM_DETAILS_PENDING" and value["leaderboard"]=="LEADERBOARD_OFFICIAL_SOURCE_VERIFIED":raise ValueError("PROGRAM_STATE_CONTRADICTION")
 if value["program"]=="KOL_PROGRAM_READY_FOR_HUMAN_REVIEW" and value["program_details"]!="KOL_PROGRAM_DETAILS_VERIFIED":raise ValueError("PROGRAM_STATE_CONTRADICTION")
 if value["referral"]=="REFERRAL_LINK_READY_FOR_HUMAN_REVIEW" and value["program"]!="KOL_PROGRAM_READY_FOR_HUMAN_REVIEW":raise ValueError("REFERRAL_STATE_CONTRADICTION")
 if value["attribution"]=="ATTRIBUTION_EVIDENCE_READY" and (value["referral"]!="REFERRAL_LINK_READY_FOR_HUMAN_REVIEW" or value["wallet_creation"]!="WALLET_CREATION_EVIDENCE_COMMITTED" or value["network_usage"]!="NETWORK_USAGE_EVIDENCE_COMMITTED"):raise ValueError("ATTRIBUTION_STATE_CONTRADICTION")
__all__=["assess_kol_referral_readiness","validate_kol_projection"]
