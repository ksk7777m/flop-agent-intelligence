"""Pure offline FLOP Testnet, Faucet, and inference readiness boundary."""
from __future__ import annotations
import hashlib,json
from pathlib import Path
from typing import Any,Mapping
from jsonschema import Draft202012Validator

ROOT=Path(__file__).resolve().parents[2]
BASELINE=ROOT/"data/flop_testnet_readiness_baseline.json";AUTHORITIES=ROOT/"data/flop_endpoint_authorities.json";RESULT_SCHEMA=ROOT/"schemas/flop-testnet-readiness.v1.json"
BASELINE_SHA256="acfc326612a5d7ac7a2422fe4f67c87f05fbfa64be96131cf5d66f7974301bde";AUTHORITIES_SHA256="8c8698fc364ec9dbd4c6959296456efb5939f24eb69dbb08e18640e0c9a4b767"
SCHEMA="flop-testnet-readiness-v1";POLICY="flop-testnet-readiness-policy-v1";MAX_INPUT_BYTES=65536;MAX_CANDIDATES=64
OFFICIAL=frozenset({"FLOP_YELLOW_PAPER","FLOP_FINANCE_DOCS","FLOP_LABS_MATERIAL"})
UNTRUSTED=frozenset({"TECHNOCORE_USER_CONTENT","COMMUNITY_SIGNED","SEARCH_RESULT","AGGREGATOR","UNOFFICIAL_GITHUB","LOOKALIKE_DOMAIN","THIRD_PARTY_REFERRAL"})
ENDPOINTS=("TESTNET","FAUCET","INFERENCE")
CANDIDATE_FIELDS=frozenset({"source_class","source_id","source_document_sha256","source_version","source_updated","endpoint_class","endpoint_sha256","network_identity_sha256","asset_class","asset_identity_sha256","published_status","spec_parameter_sha256","observation_nonce"})
AUTHORITY_FIELDS=frozenset({"source_class","source_id","source_document_sha256","source_version","source_updated","endpoints"})
AUTHORITY_ENDPOINT_FIELDS=frozenset({"endpoint_class","endpoint_sha256","network_identity_sha256","asset_class","asset_identity_sha256"})
INFERENCE_FIELDS=frozenset({"workload_id","agent_identity_sha256","network_session_sha256","request_sha256","result_sha256","model_task_id","compute_units","test_token_spend","provider_identity_sha256","receipt_sha256","timestamp_provenance_sha256","self_reported_usage","evidence_nonce"})
def _canon(v:Any)->bytes:return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")
def _hash(v:bytes)->str:return hashlib.sha256(v).hexdigest()
def _digest(v:Any)->bool:return isinstance(v,str) and len(v)==64 and all(c in "0123456789abcdef" for c in v)
def _token(v:Any,n:int=128)->bool:return isinstance(v,str) and 0<len(v)<=n and v.isascii() and all(c.isalnum() or c in "._:-" for c in v)
def _amount(v:Any)->bool:
 if not isinstance(v,str) or not v:return False
 left,dot,right=v.partition(".")
 return left.isdigit() and (left=="0" or not left.startswith("0")) and (not dot or bool(right) and right.isdigit())
def _parse(raw:bytes)->Any:
 payload=raw[:-1] if raw.endswith(b"\n") else raw;value=json.loads(payload)
 if _canon(value)!=payload:raise ValueError
 return value
def _base(count:int)->dict[str,Any]:return {"schema":SCHEMA,"content_label":"PUBLIC_MINIMIZED_EVIDENCE","artifact_id":"","policy_revision":POLICY,"reviewed_as_of":"2026-09-10","spec":"OFFICIAL_DRAFT_COMMITMENT_UNRESOLVED","testnet":"TESTNET_NOT_PUBLISHED","faucet":"FAUCET_NOT_PUBLISHED","inference":"INFERENCE_ENDPOINT_NOT_PUBLISHED","network_identity":"NETWORK_IDENTITY_UNVERIFIED","asset_identity":"UNVERIFIED_ASSET","endpoint_candidate_count":count,"inference_evidence":"INFERENCE_WORKLOAD_SCHEMA_READY","inference_executed":False,"useful_inference_verified":False,"spend_verified":False,"airdrop_eligibility_verified":False,"airdrop_rule_status":"PROVISIONAL","testnet_to_mainnet_conversion":"UNRESOLVED","agent_scoring":"UNRESOLVED","spend_to_unlock":"PROVISIONAL_OR_UNRESOLVED","errors":[],"claim_authorized":False,"inference_spend_authorized":False,"ready_to_act":False,"authorized_to_act":False,"live_action_enabled":False,"production_api":{"classification":"SAFE_PURE_OFFLINE_VALIDATOR","network":"NONE","http":"NONE","technocore":"NONE","remote_mcp":"NONE","signer":"NONE","wallet":"NONE","chain_rpc":"NONE","inference_rpc":"NONE","faucet_client":"NONE"}}
def _seal(result:dict[str,Any])->Mapping[str,Any]:
 result["artifact_id"]=_hash(_canon({k:v for k,v in result.items() if k!="artifact_id"}));validate_readiness_projection(result);return result
def _stop(result:dict[str,Any],code:str)->Mapping[str,Any]:result["errors"]=[code];return _seal(result)
def _manifest(value:Any)->list[dict[str,Any]]:
 if not isinstance(value,dict) or set(value)!={"schema","authorities"} or value["schema"]!="flop-endpoint-authorities-v1" or not isinstance(value["authorities"],list):raise ValueError
 seen=set()
 for item in value["authorities"]:
  if not isinstance(item,dict) or set(item)!=AUTHORITY_FIELDS or item["source_class"] not in OFFICIAL or not _token(item["source_id"]) or not _digest(item["source_document_sha256"]) or not _token(item["source_version"]) or not _token(item["source_updated"]) or not isinstance(item["endpoints"],list) or not item["endpoints"]:raise ValueError
  for endpoint in item["endpoints"]:
   if not isinstance(endpoint,dict) or set(endpoint)!=AUTHORITY_ENDPOINT_FIELDS or endpoint["endpoint_class"] not in ENDPOINTS or not _digest(endpoint["endpoint_sha256"]) or not _digest(endpoint["network_identity_sha256"]) or endpoint["asset_class"] not in {"TEST_TOKEN","MAINNET_ASSET","UNVERIFIED_ASSET","THIRD_PARTY_ASSET"} or (endpoint["asset_identity_sha256"] is not None and not _digest(endpoint["asset_identity_sha256"])):raise ValueError
  identity=(item["source_class"],item["source_id"],item["source_document_sha256"],item["source_version"])
  if identity in seen:raise ValueError
  seen.add(identity)
 return value["authorities"]
def _candidate(value:Any)->bool:
 return isinstance(value,dict) and set(value)==CANDIDATE_FIELDS and value["source_class"] in OFFICIAL|UNTRUSTED and _token(value["source_id"]) and _digest(value["source_document_sha256"]) and _token(value["source_version"]) and _token(value["source_updated"]) and value["endpoint_class"] in ENDPOINTS and _digest(value["endpoint_sha256"]) and _digest(value["network_identity_sha256"]) and value["asset_class"] in {"TEST_TOKEN","MAINNET_ASSET","UNVERIFIED_ASSET","THIRD_PARTY_ASSET"} and (value["asset_identity_sha256"] is None or _digest(value["asset_identity_sha256"])) and value["published_status"] in {"PUBLISHED","CANDIDATE","NOT_PUBLISHED"} and _digest(value["spec_parameter_sha256"]) and _token(value["observation_nonce"])
def _inference(value:Any)->bool:
 if value=={}:return True
 return isinstance(value,dict) and set(value)==INFERENCE_FIELDS and all(_digest(value[k]) for k in ("agent_identity_sha256","request_sha256","result_sha256","provider_identity_sha256","timestamp_provenance_sha256")) and all(value[k] is None or _digest(value[k]) for k in ("network_session_sha256","receipt_sha256")) and _token(value["workload_id"]) and _token(value["model_task_id"]) and _token(value["evidence_nonce"]) and _amount(value["compute_units"]) and _amount(value["test_token_spend"]) and type(value["self_reported_usage"]) is bool
def _assess(candidates_raw:bytes,inference_raw:bytes,request_raw:bytes,response_raw:bytes,baseline_raw:bytes,authorities_raw:bytes)->Mapping[str,Any]:
 result=_base(0)
 if any(type(x) is not bytes for x in (candidates_raw,inference_raw,request_raw,response_raw)):return _stop(result,"INPUT_TYPE_INVALID")
 if any(len(x)>MAX_INPUT_BYTES for x in (candidates_raw,inference_raw,request_raw,response_raw,baseline_raw,authorities_raw)):return _stop(result,"INPUT_LIMIT_EXCEEDED")
 try:candidates=_parse(candidates_raw);draft=_parse(inference_raw);baseline=_parse(baseline_raw);manifest=_parse(authorities_raw)
 except Exception:return _stop(result,"ARTIFACT_SCHEMA_INVALID")
 if not isinstance(candidates,list) or len(candidates)>MAX_CANDIDATES or any(not _candidate(x) for x in candidates) or not _inference(draft):return _stop(result,"ARTIFACT_SCHEMA_INVALID")
 result["endpoint_candidate_count"]=len(candidates)
 candidate_nonces=[(x["source_class"],x["source_id"],x["observation_nonce"]) for x in candidates]
 if len(set(candidate_nonces))!=len(candidate_nonces):return _stop(result,"REPLAY_CANDIDATE")
 if baseline.get("schema")!="flop-testnet-readiness-baseline-v1" or baseline.get("flop_spec",{}).get("version")!="v0.5.0" or baseline.get("flop_spec",{}).get("updated")!="2026-09-05" or baseline.get("technocore",{}).get("version")!="0.13.0":return _stop(result,"ARTIFACT_SCHEMA_INVALID")
 try:authorities=_manifest(manifest)
 except Exception:return _stop(result,"ARTIFACT_SCHEMA_INVALID")
 verified=[]
 for candidate in candidates:
  sources=[a for a in authorities if all(candidate[k]==a[k] for k in ("source_class","source_id","source_document_sha256","source_version","source_updated"))]
  match=[a for a in sources if any(all(candidate[k]==endpoint[k] for k in AUTHORITY_ENDPOINT_FIELDS) for endpoint in a["endpoints"])]
  if candidate["source_class"] in UNTRUSTED or len(match)!=1:continue
  verified.append(candidate)
 if candidates and len(verified)!=len(candidates):
  for kind,label in (("TESTNET","TESTNET_CANDIDATE"),("FAUCET","FAUCET_CANDIDATE"),("INFERENCE","INFERENCE_ENDPOINT_CANDIDATE")):
   if any(x["endpoint_class"]==kind for x in candidates):result[kind.lower()]=label
  same_source=any(any(candidate[k]==a[k] for k in ("source_class","source_id","source_version")) for candidate in candidates for a in authorities)
  return _stop(result,"SOURCE_BINDING_MISMATCH" if same_source else "SOURCE_UNVERIFIED")
 considered={kind:[x for x in verified if x["endpoint_class"]==kind and x["published_status"]!="NOT_PUBLISHED"] for kind in ENDPOINTS}
 groups={kind:[x for x in considered[kind] if x["published_status"]=="PUBLISHED"] for kind in ENDPOINTS}
 for kind,label in (("TESTNET","TESTNET_OFFICIAL_SOURCE_VERIFIED"),("FAUCET","FAUCET_OFFICIAL_SOURCE_VERIFIED"),("INFERENCE","INFERENCE_OFFICIAL_SOURCE_VERIFIED")):
  if any(x["endpoint_class"]==kind and x["published_status"]=="CANDIDATE" for x in verified):result[kind.lower()]=label
 if any(len({(x["endpoint_sha256"],x["network_identity_sha256"],x["asset_class"],x["asset_identity_sha256"]) for x in group})>1 for group in considered.values()):
  for kind,group in considered.items():
   if len({(x["endpoint_sha256"],x["network_identity_sha256"],x["asset_class"],x["asset_identity_sha256"]) for x in group})>1:result[kind.lower()]=kind+"_CONFLICT"
  return _stop(result,"ENDPOINT_CONFLICT")
 if len({x["spec_parameter_sha256"] for x in groups["TESTNET"]})>1:result["spec"]="SPEC_CONFLICT";return _stop(result,"SPEC_CONFLICT")
 network={x["network_identity_sha256"] for x in verified if x["published_status"]=="PUBLISHED"}
 if len(network)>1:return _stop(result,"NETWORK_BINDING_MISMATCH")
 if network:result["network_identity"]="NETWORK_IDENTITY_VERIFIED"
 if groups["TESTNET"]:result["spec"]="SPEC_SOURCE_VERIFIED"
 for endpoint in groups["TESTNET"]+groups["FAUCET"]:
  if endpoint["asset_class"]!="TEST_TOKEN" or endpoint["asset_identity_sha256"] is None:return _stop(result,"ASSET_UNVERIFIED")
 if groups["TESTNET"] or groups["FAUCET"]:result["asset_identity"]="TEST_TOKEN"
 if groups["FAUCET"]:
  if not groups["TESTNET"]:return _stop(result,"NETWORK_BINDING_MISMATCH")
 for kind,ready in (("TESTNET","TESTNET_READY_FOR_HUMAN_REVIEW"),("FAUCET","FAUCET_READY_FOR_HUMAN_REVIEW"),("INFERENCE","INFERENCE_READY_FOR_HUMAN_REVIEW")):
  if groups[kind]:result[kind.lower()]=ready
 if draft!={}:
  result["inference_evidence"]="INFERENCE_EVIDENCE_INCOMPLETE"
  if draft["request_sha256"]!=_hash(request_raw) or draft["result_sha256"]!=_hash(response_raw):return _stop(result,"INFERENCE_COMMITMENT_MISMATCH")
  if draft["test_token_spend"]!="0" and not draft["receipt_sha256"]:return _stop(result,"INFERENCE_RECEIPT_REQUIRED")
  if draft["self_reported_usage"]:return _stop(result,"INFERENCE_EVIDENCE_INVALID")
  if not groups["INFERENCE"] or draft["network_session_sha256"] is None:return _stop(result,"INFERENCE_NETWORK_PROVENANCE_REQUIRED")
  result["inference_evidence"]="INFERENCE_EVIDENCE_READY"
 return _seal(result)
def assess_testnet_readiness(endpoint_candidates_bytes:bytes,inference_evidence_bytes:bytes,request_bytes:bytes=b"",response_bytes:bytes=b"")->Mapping[str,Any]:
 try:
  baseline=BASELINE.read_bytes();authorities=AUTHORITIES.read_bytes()
  if _hash(baseline)!=BASELINE_SHA256:baseline=b""
  if _hash(authorities)!=AUTHORITIES_SHA256:authorities=b""
 except Exception:baseline=b"";authorities=b""
 return _assess(endpoint_candidates_bytes,inference_evidence_bytes,request_bytes,response_bytes,baseline,authorities)
def validate_readiness_projection(value:Any)->None:
 try:schema=json.loads(RESULT_SCHEMA.read_bytes());Draft202012Validator.check_schema(schema);Draft202012Validator(schema).validate(value)
 except Exception:raise ValueError("RESULT_SCHEMA_INVALID") from None
 if value["artifact_id"]!=_hash(_canon({k:v for k,v in value.items() if k!="artifact_id"})):raise ValueError("ARTIFACT_IDENTITY_MISMATCH")
 if any(value[x] is not False for x in ("inference_executed","useful_inference_verified","spend_verified","airdrop_eligibility_verified","claim_authorized","inference_spend_authorized","ready_to_act","authorized_to_act","live_action_enabled")):raise ValueError("ACTION_BOUNDARY_VIOLATION")
 if value["testnet"]=="TESTNET_READY_FOR_HUMAN_REVIEW" and (value["spec"]!="SPEC_SOURCE_VERIFIED" or value["network_identity"]!="NETWORK_IDENTITY_VERIFIED" or value["asset_identity"]!="TEST_TOKEN"):raise ValueError("READINESS_CONTRADICTION")
 if value["faucet"]=="FAUCET_READY_FOR_HUMAN_REVIEW" and value["testnet"]!="TESTNET_READY_FOR_HUMAN_REVIEW":raise ValueError("READINESS_CONTRADICTION")
 if value["inference_evidence"]=="INFERENCE_EVIDENCE_READY" and value["inference"]!="INFERENCE_READY_FOR_HUMAN_REVIEW":raise ValueError("READINESS_CONTRADICTION")
__all__=["assess_testnet_readiness","validate_readiness_projection"]
