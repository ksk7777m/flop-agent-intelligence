"""Offline settlement-rail maturity and FLOP conformance boundary."""
from __future__ import annotations
import hashlib,json,re
from pathlib import Path
from jsonschema import Draft202012Validator

ROOT=Path(__file__).resolve().parents[2];BASELINE=ROOT/"data/settlement_rail_baseline.json";AUTHORITIES=ROOT/"data/settlement_rail_authorities.json";RESULT_SCHEMA=ROOT/"schemas/settlement-rail-maturity.v1.json"
SCHEMA="settlement-rail-maturity-v1";POLICY="settlement-rail-maturity-policy-v1";MAX_BYTES=65536;MAX_RAILS=32;MAX_OBSERVATIONS=64;MAX_DEPTH=6
BASELINE_SHA256="6c4e55508676814bbeaedbd37b0290ba7e61b6c7d6ba0bf810967a68c29a9abf";AUTHORITIES_SHA256="9ac853065c0a1dc9d9e7df7d10022275577d0b95ef51aa84253484a4bf34ea19"
RAIL_FIELDS=frozenset({"rail_id","rail_type","implementation_version","source_class","source_id","source_sha256","code_sha256","source_status","audit_state","deployment_state","network_sha256","asset_class","asset_sha256"})
OBS_FIELDS=frozenset({"rail_id","rail_identity_sha256","network_sha256","asset_sha256","deployment_sha256","transaction_sha256","lock_state","terminal_state","locked_max","actual_settlement","timestamp_sha256","finality_state","yellow_paper_version","yellow_paper_sha256","timelock_policy_verified","safety_margin_verified","cross_chain_margin_verified","contract_identity_verified","source_provenance_verified"})
AUTH_FIELDS=RAIL_FIELDS|frozenset({"rail_identity_sha256","observations"})
OFFICIAL=frozenset({"TCLK_RELEASE","FLOP_REVIEWED_SOURCE"});UNTRUSTED=frozenset({"TECHNOCORE_USER_CONTENT","COMMUNITY_POST","SEARCH_RESULT","AGGREGATOR","UNOFFICIAL_GITHUB","CALLER_OFFICIAL_LABEL"})
HEX=re.compile(r"^[0-9a-f]{64}$");TOKEN=re.compile(r"^[A-Za-z0-9._:-]{1,128}$");DECIMAL=re.compile(r"^(?:0|[1-9][0-9]{0,18})$")
def _canon(v):return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")
def _hash(v):return hashlib.sha256(v).hexdigest()
def _depth(v):
 if not isinstance(v,(dict,list)):return 0
 return 1+max((_depth(x) for x in (v.values() if isinstance(v,dict) else v)),default=0)
def _parse(raw):
 if type(raw) is not bytes or len(raw)>MAX_BYTES:raise ValueError
 payload=raw[:-1] if raw.endswith(b"\n") else raw;v=json.loads(payload)
 if _depth(v)>MAX_DEPTH or _canon(v)!=payload:raise ValueError
 return v
def _token(v):return isinstance(v,str) and TOKEN.fullmatch(v) is not None
def _digest(v):return isinstance(v,str) and HEX.fullmatch(v) is not None
def _decimal(v):return isinstance(v,str) and DECIMAL.fullmatch(v) is not None
def _valid_rail(v):
 return isinstance(v,dict) and set(v)==RAIL_FIELDS and v["rail_type"] in {"PAPER","MEMORY","EVM_HASH","POINT_LOCK"} and v["source_class"] in OFFICIAL|UNTRUSTED and all(_token(v[k]) for k in ("rail_id","implementation_version","source_id")) and _digest(v["source_sha256"]) and (v["code_sha256"] is None or _digest(v["code_sha256"])) and v["source_status"] in {"RELEASED","PR_OPEN_UNMERGED","REFERENCE_ONLY"} and v["audit_state"] in {"NOT_AUDITED","REFERENCE_ONLY","INTERNAL_TESTED","EXTERNAL_REVIEWED","FORMALLY_AUDITED"} and v["deployment_state"] in {"NOT_DEPLOYED","MOCK_ONLY","DEVNET_DEPLOYED","TESTNET_DEPLOYED","MAINNET_DEPLOYED"} and (v["network_sha256"] is None or _digest(v["network_sha256"])) and v["asset_class"] in {"TEST_TOKEN","MAINNET_ASSET","UNVERIFIED_ASSET","THIRD_PARTY_ASSET"} and (v["asset_sha256"] is None or _digest(v["asset_sha256"]))
def _valid_observation(v):
 return isinstance(v,dict) and set(v)==OBS_FIELDS and all(_token(v[k]) for k in ("rail_id","yellow_paper_version")) and all(v[k] is None or _digest(v[k]) for k in ("rail_identity_sha256","network_sha256","asset_sha256","deployment_sha256","transaction_sha256","timestamp_sha256","yellow_paper_sha256")) and v["lock_state"] in {"NOT_OBSERVED","LOCK_OBSERVED"} and v["terminal_state"] in {"NOT_OBSERVED","CLAIM_OBSERVED","REFUND_OBSERVED","CONFLICT"} and (v["locked_max"] is None or _decimal(v["locked_max"])) and (v["actual_settlement"] is None or _decimal(v["actual_settlement"])) and v["finality_state"] in {"UNRESOLVED","OBSERVED_NOT_FINAL","FINALITY_VERIFIED"} and all(type(v[k]) is bool for k in ("timelock_policy_verified","safety_margin_verified","cross_chain_margin_verified","contract_identity_verified","source_provenance_verified"))
def _base(rc=0,oc=0):return {"schema":SCHEMA,"content_label":"PUBLIC_MINIMIZED_EVIDENCE","artifact_id":"","policy_revision":POLICY,"reviewed_as_of":"2026-09-10","tclk_protocol":"ALPHA_V0_1_0","paper_rail":"PAPER_ONLY","memory_rail":"REFERENCE_IMPLEMENTATION","evm_hash_rail":"UNMERGED_BINDING","point_lock":"EXPERIMENTAL_UNAUDITED","deployment":"NO_VALUE_BEARING_DEPLOYMENT_CONFIRMED","audit":"NO_PRODUCTION_AUDIT_CONFIRMED","rail_observation":"NOT_VERIFIED","network_binding":"NOT_VERIFIED","asset_binding":"NOT_VERIFIED","flop_yellowpaper_conformance":"UNRESOLVED","settlement":"SETTLEMENT_UNVERIFIED","rail_candidate_count":rc,"observation_count":oc,"errors":[],"economic_value_verified":False,"real_funds":False,"value_bearing_verified":False,"settlement_verified":False,"ready_for_human_review":False,"authorized_to_lock":False,"authorized_to_claim":False,"authorized_to_refund":False,"authorized_to_send_value":False,"authorized_to_connect_wallet":False,"authorized_to_act":False,"production_api":{"classification":"SAFE_PURE_OFFLINE_VALIDATOR","network":"NONE","rpc":"NONE","technocore":"NONE","remote_mcp":"NONE","wallet":"NONE","signer":"NONE","transaction_builder":"NONE","contract_call":"NONE","faucet":"NONE","inference":"NONE","settlement_action":"NONE"}}
def _seal(r):r["artifact_id"]=_hash(_canon({k:v for k,v in r.items() if k!="artifact_id"}));validate_settlement_projection(r);return r
def _stop(r,c):r["errors"]=[c];return _seal(r)
def _assess(rails_raw,observations_raw,authorities_raw,baseline_raw):
 r=_base()
 if any(type(x) is not bytes for x in (rails_raw,observations_raw,authorities_raw,baseline_raw)):return _stop(r,"INPUT_TYPE_INVALID")
 if any(len(x)>MAX_BYTES for x in (rails_raw,observations_raw,authorities_raw,baseline_raw)):return _stop(r,"INPUT_LIMIT_EXCEEDED")
 try:rails=_parse(rails_raw);obs=_parse(observations_raw);manifest=_parse(authorities_raw);baseline=_parse(baseline_raw)
 except Exception:return _stop(r,"ARTIFACT_SCHEMA_INVALID")
 if not isinstance(rails,list) or len(rails)>MAX_RAILS or any(not _valid_rail(x) for x in rails) or not isinstance(obs,list) or len(obs)>MAX_OBSERVATIONS or any(not _valid_observation(x) for x in obs):return _stop(r,"ARTIFACT_SCHEMA_INVALID")
 r["rail_candidate_count"]=len(rails);r["observation_count"]=len(obs)
 if baseline.get("schema")!="settlement-rail-baseline-v1" or baseline.get("tclk",{}).get("value_bearing_rail")!="NONE_CONFIRMED":return _stop(r,"ARTIFACT_SCHEMA_INVALID")
 if not isinstance(manifest,dict) or set(manifest)!={"schema","authorities"} or manifest["schema"]!="settlement-rail-authorities-v1" or not isinstance(manifest["authorities"],list):return _stop(r,"ARTIFACT_SCHEMA_INVALID")
 if any(not isinstance(a,dict) or set(a)!=AUTH_FIELDS or not _digest(a["rail_identity_sha256"]) or not _valid_rail({k:a[k] for k in RAIL_FIELDS}) or not isinstance(a["observations"],list) or len(a["observations"])>MAX_OBSERVATIONS or any(not _valid_observation(x) for x in a["observations"]) for a in manifest["authorities"]):return _stop(r,"ARTIFACT_SCHEMA_INVALID")
 verified=[]
 for rail in rails:
  matches=[a for a in manifest["authorities"] if all(rail[k]==a[k] for k in RAIL_FIELDS)]
  if rail["source_class"] in UNTRUSTED or len(matches)!=1:return _stop(r,"SOURCE_UNVERIFIED")
  verified.append((rail,matches[0]))
 if obs:
  if not verified:return _stop(r,"RAIL_AUTHORITY_REQUIRED")
  for item in obs:
   matches=[(rail,a) for rail,a in verified if item["rail_id"]==rail["rail_id"] and item["rail_identity_sha256"]==a["rail_identity_sha256"] and item in a["observations"]]
   if len(matches)!=1:return _stop(r,"OBSERVATION_BINDING_MISMATCH")
   rail,_=matches[0]
   if item["network_sha256"]!=rail["network_sha256"] or item["asset_sha256"]!=rail["asset_sha256"]:return _stop(r,"OBSERVATION_UNVERIFIED")
   if item["actual_settlement"] is not None and item["locked_max"] is not None and int(item["actual_settlement"])>int(item["locked_max"]):return _stop(r,"AMOUNT_POLICY_VIOLATION")
  complete=all(all(item[k] is not None for k in ("rail_identity_sha256","network_sha256","asset_sha256","deployment_sha256","transaction_sha256","timestamp_sha256","yellow_paper_sha256","locked_max","actual_settlement")) and item["lock_state"]=="LOCK_OBSERVED" and item["terminal_state"] in {"CLAIM_OBSERVED","REFUND_OBSERVED"} and item["finality_state"]=="FINALITY_VERIFIED" and all(item[k] for k in ("timelock_policy_verified","safety_margin_verified","cross_chain_margin_verified","contract_identity_verified","source_provenance_verified")) for item in obs)
  r["rail_observation"]="EVIDENCE_PRESENT_UNVERIFIED";r["ready_for_human_review"]=complete
 return _seal(r)
def assess_settlement_rail_maturity(rail_artifacts_bytes:bytes,rail_observations_bytes:bytes):
 try:
  authorities=AUTHORITIES.read_bytes();baseline=BASELINE.read_bytes()
  if _hash(authorities)!=AUTHORITIES_SHA256 or _hash(baseline)!=BASELINE_SHA256:return _stop(_base(),"ARTIFACT_SCHEMA_INVALID")
  return _assess(rail_artifacts_bytes,rail_observations_bytes,authorities,baseline)
 except Exception:return _stop(_base(),"ARTIFACT_SCHEMA_INVALID")
def validate_settlement_projection(v):
 try:s=json.loads(RESULT_SCHEMA.read_bytes());Draft202012Validator.check_schema(s);Draft202012Validator(s).validate(v)
 except Exception:raise ValueError("RESULT_SCHEMA_INVALID") from None
 if v["artifact_id"]!=_hash(_canon({k:x for k,x in v.items() if k!="artifact_id"})):raise ValueError("ARTIFACT_IDENTITY_MISMATCH")
 if any(v[k] is not False for k in ("economic_value_verified","real_funds","value_bearing_verified","settlement_verified","authorized_to_lock","authorized_to_claim","authorized_to_refund","authorized_to_send_value","authorized_to_connect_wallet","authorized_to_act")):raise ValueError("ACTION_BOUNDARY_VIOLATION")
__all__=["assess_settlement_rail_maturity","validate_settlement_projection"]
