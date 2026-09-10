"""Pure offline, signature-first delegation resolution."""
from __future__ import annotations
import base64,hashlib,json,re
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator
from .did_key import public_key_from_did

SCHEMA="delegation-signature-first-resolution-v1";DOMAIN=b"TECHNOCORE-DELEGATION-V1|"
MAX_NOTE_BYTES=262144;MAX_AUTHORITY_BYTES=65536;MAX_PRIOR_BYTES=16384;MAX_RECORD_BYTES=4096;MAX_RECORDS=128;MAX_DEPTH=6
REGISTRY_PATH=Path(__file__).resolve().parents[2]/"data/delegation_authorities.json"
RESULT_SCHEMA_PATH=Path(__file__).resolve().parents[2]/"schemas/delegation-signature-first-resolution.v1.json"
REGISTRY_SHA256="2349342406065b5a6b18383db16d3c6710243a75fb3d3f7b47ff6457b8d015ef"
RECORD_FIELDS=frozenset({"version","root_did","agent_did","scope","expires","nonce","signature"})
SCOPE=re.compile(r"^(?:\*|r:[A-Za-z0-9._-]{1,64}|kv:[A-Za-z0-9._-]{1,64})$");DECIMAL=re.compile(r"^(?:0|[1-9][0-9]{0,18})$")
def _canonical(value):return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")
def _hash(raw):return hashlib.sha256(raw).hexdigest()
def _depth(value):
 if not isinstance(value,(dict,list)):return 0
 return 1+max((_depth(x) for x in (value.values() if isinstance(value,dict) else value)),default=0)
def _parse(raw,limit):
 if type(raw) is not bytes or len(raw)>limit:raise ValueError
 payload=raw[:-1] if raw.endswith(b"\n") else raw;value=json.loads(payload)
 if _depth(value)>MAX_DEPTH or _canonical(value)!=payload:raise ValueError
 return value
def _b64(value):
 if not isinstance(value,str) or not re.fullmatch(r"[A-Za-z0-9_-]{86}",value):raise ValueError
 raw=base64.urlsafe_b64decode(value+"==")
 if len(raw)!=64:raise ValueError
 return raw
def _valid_record(value):
 return isinstance(value,dict) and set(value)==RECORD_FIELDS and value["version"]=="technocore-delegation-v1" and isinstance(value["root_did"],str) and isinstance(value["agent_did"],str) and value["root_did"]!=value["agent_did"] and isinstance(value["scope"],str) and SCOPE.fullmatch(value["scope"]) is not None and isinstance(value["expires"],str) and DECIMAL.fullmatch(value["expires"]) is not None and isinstance(value["nonce"],str) and DECIMAL.fullmatch(value["nonce"]) is not None and isinstance(value["signature"],str) and len(_canonical(value))<=MAX_RECORD_BYTES
def _base():return {"schema":SCHEMA,"content_label":"PUBLIC_MINIMIZED_EVIDENCE","artifact_id":"","resolution":"DELEGATION_NOT_ESTABLISHED","history_completeness":"DELEGATION_HISTORY_COMPLETENESS_NOT_ESTABLISHED","record_count":0,"valid_signature_count":0,"current_count":0,"superseded_count":0,"expired_count":0,"forged_count":0,"conflict_count":0,"records":[],"errors":[],"root_identity_verified":False,"delegation_signature_valid":False,"authorized_to_act":False,"wallet_action_authorized":False,"faucet_action_authorized":False,"inference_spend_authorized":False,"live_signing_authorized":False,"network_access_authorized":False,"production_api":{"classification":"SAFE_PURE_OFFLINE_VALIDATOR","technocore":"NONE","humans_ui":"NONE","remote_mcp":"NONE","network":"NONE","signer":"NONE","wallet":"NONE","claim":"NONE"}}
def _seal(result):result["artifact_id"]=_hash(_canonical({k:v for k,v in result.items() if k!="artifact_id"}));validate_delegation_projection(result);return result
def _stop(result,code):result["errors"]=[code];return _seal(result)
def _resolve(note_bytes,authority_bytes,prior_state_bytes):
 result=_base()
 if any(type(x) is not bytes for x in (note_bytes,authority_bytes,prior_state_bytes)):return _stop(result,"INPUT_TYPE_INVALID")
 if len(note_bytes)>MAX_NOTE_BYTES or len(authority_bytes)>MAX_AUTHORITY_BYTES or len(prior_state_bytes)>MAX_PRIOR_BYTES:return _stop(result,"INPUT_LIMIT_EXCEEDED")
 try:note=_parse(note_bytes,MAX_NOTE_BYTES);authority=_parse(authority_bytes,MAX_AUTHORITY_BYTES);prior=_parse(prior_state_bytes,MAX_PRIOR_BYTES)
 except Exception:return _stop(result,"ARTIFACT_SCHEMA_INVALID")
 if not isinstance(note,dict) or set(note)!={"schema","records"} or note["schema"]!="technocore-delegation-note-v1" or not isinstance(note["records"],list) or len(note["records"])>MAX_RECORDS:return _stop(result,"ARTIFACT_SCHEMA_INVALID")
 if not isinstance(authority,dict) or set(authority)!={"schema","evaluated_at","root_did_sha256"} or authority["schema"]!="delegation-root-authority-v1" or not isinstance(authority["evaluated_at"],str) or DECIMAL.fullmatch(authority["evaluated_at"]) is None or not isinstance(authority["root_did_sha256"],list) or len(authority["root_did_sha256"])>32 or any(not isinstance(x,str) or not re.fullmatch(r"[0-9a-f]{64}",x) for x in authority["root_did_sha256"]):return _stop(result,"ARTIFACT_SCHEMA_INVALID")
 if prior!={} and prior!={"schema":"delegation-prior-state-v1","history_completeness":"NOT_ESTABLISHED"}:return _stop(result,"ARTIFACT_SCHEMA_INVALID")
 now=int(authority["evaluated_at"]);parsed=[];seen=set()
 for item in note["records"]:
  if not _valid_record(item):return _stop(result,"ARTIFACT_SCHEMA_INVALID")
  raw=_canonical(item);rid=_hash(raw)
  if rid in seen:continue
  seen.add(rid);unsigned={k:v for k,v in item.items() if k!="signature"};root_ok=_hash(item["root_did"].encode()) in authority["root_did_sha256"];signature_ok=False
  try:Ed25519PublicKey.from_public_bytes(public_key_from_did(item["root_did"])).verify(_b64(item["signature"]),DOMAIN+_canonical(unsigned));signature_ok=True
  except (ValueError,InvalidSignature):pass
  state="DELEGATION_FORGED"
  if signature_ok and not root_ok:state="DELEGATION_ROOT_UNVERIFIED"
  elif signature_ok and int(item["expires"])<=now:state="DELEGATION_EXPIRED"
  elif signature_ok and root_ok:state="DELEGATION_VALID_CURRENT"
  parsed.append({"raw":item,"record_id":rid,"agent_id":_hash(item["agent_did"].encode()),"root_id":_hash(item["root_did"].encode()),"root_verified":root_ok,"signature_valid":signature_ok,"state":state,"valid_nonce_rank":None,"superseded_by":None})
 valid=[x for x in parsed if x["state"]=="DELEGATION_VALID_CURRENT"]
 for agent in {x["agent_id"] for x in valid}:
  group=[x for x in valid if x["agent_id"]==agent]
  if len({x["root_id"] for x in group})>1:
   for x in group:x["state"]="DELEGATION_CONFLICT"
   continue
  ordered=sorted({int(x["raw"]["nonce"]) for x in group});ranks={nonce:index+1 for index,nonce in enumerate(ordered)}
  for x in group:x["valid_nonce_rank"]=ranks[int(x["raw"]["nonce"])]
  highest=ordered[-1];top=[x for x in group if int(x["raw"]["nonce"])==highest];identities={_hash(_canonical({k:v for k,v in x["raw"].items() if k!="signature"})) for x in top}
  if len(identities)>1:
   for x in group:x["state"]="DELEGATION_CONFLICT";x["valid_nonce_rank"]=None
  else:
   winner=top[0]
   for x in group:
    if int(x["raw"]["nonce"])<highest:x["state"]="DELEGATION_SUPERSEDED";x["superseded_by"]=winner["record_id"]
 for x in parsed:result["records"].append({k:x[k] for k in ("record_id","agent_id","root_id","state","root_verified","signature_valid","valid_nonce_rank","superseded_by")})
 for field,state in (("current_count","DELEGATION_VALID_CURRENT"),("superseded_count","DELEGATION_SUPERSEDED"),("expired_count","DELEGATION_EXPIRED"),("forged_count","DELEGATION_FORGED"),("conflict_count","DELEGATION_CONFLICT")):result[field]=sum(x["state"]==state for x in parsed)
 result["record_count"]=len(parsed);result["valid_signature_count"]=sum(x["signature_valid"] for x in parsed);result["root_identity_verified"]=any(x["root_verified"] and x["signature_valid"] for x in parsed);result["delegation_signature_valid"]=any(x["signature_valid"] for x in parsed)
 if result["conflict_count"]:result["resolution"]="DELEGATION_CONFLICT"
 elif result["current_count"]:result["resolution"]="DELEGATION_VALID_CURRENT"
 elif result["expired_count"]:result["resolution"]="DELEGATION_EXPIRED"
 elif result["forged_count"]:result["resolution"]="DELEGATION_FORGED"
 elif parsed:result["resolution"]="DELEGATION_ROOT_UNVERIFIED"
 return _seal(result)
def resolve_delegations(note_bytes:bytes,root_authority_artifact_bytes:bytes,prior_delegation_state_bytes:bytes=b"{}"):
 try:
  registry_raw=REGISTRY_PATH.read_bytes()
  if _hash(registry_raw)!=REGISTRY_SHA256:raise ValueError
  registry=json.loads(registry_raw)
  if set(registry)!={"schema","approved_authority_artifact_sha256"} or registry["schema"]!="delegation-authority-registry-v1" or registry["approved_authority_artifact_sha256"]!=[]:raise ValueError
 except Exception:return _stop(_base(),"ROOT_AUTHORITY_UNAPPROVED")
 if type(root_authority_artifact_bytes) is not bytes or _hash(root_authority_artifact_bytes) not in registry.get("approved_authority_artifact_sha256",[]):return _stop(_base(),"ROOT_AUTHORITY_UNAPPROVED")
 return _resolve(note_bytes,root_authority_artifact_bytes,prior_delegation_state_bytes)
def validate_delegation_projection(value):
 try:schema=json.loads(RESULT_SCHEMA_PATH.read_bytes());Draft202012Validator.check_schema(schema);Draft202012Validator(schema).validate(value)
 except Exception:raise ValueError("RESULT_SCHEMA_INVALID") from None
 if value["artifact_id"]!=_hash(_canonical({k:v for k,v in value.items() if k!="artifact_id"})):raise ValueError("ARTIFACT_IDENTITY_MISMATCH")
 records=value["records"]
 expected={"record_count":len(records),"valid_signature_count":sum(x["signature_valid"] for x in records),"current_count":sum(x["state"]=="DELEGATION_VALID_CURRENT" for x in records),"superseded_count":sum(x["state"]=="DELEGATION_SUPERSEDED" for x in records),"expired_count":sum(x["state"]=="DELEGATION_EXPIRED" for x in records),"forged_count":sum(x["state"]=="DELEGATION_FORGED" for x in records),"conflict_count":sum(x["state"]=="DELEGATION_CONFLICT" for x in records)}
 if any(value[k]!=v for k,v in expected.items()):raise ValueError("DELEGATION_COUNT_MISMATCH")
 by_id={x["record_id"]:x for x in records}
 for record in records:
  if record["state"]=="DELEGATION_SUPERSEDED":
   target=by_id.get(record["superseded_by"])
   if target is None or target["state"]!="DELEGATION_VALID_CURRENT" or target["agent_id"]!=record["agent_id"] or target["root_id"]!=record["root_id"] or target["valid_nonce_rank"] is None or record["valid_nonce_rank"] is None or target["valid_nonce_rank"]<=record["valid_nonce_rank"]:raise ValueError("SUPERSESSION_EVIDENCE_INVALID")
  elif record["superseded_by"] is not None:raise ValueError("SUPERSESSION_EVIDENCE_INVALID")
 if any(value[x] is not False for x in ("authorized_to_act","wallet_action_authorized","faucet_action_authorized","inference_spend_authorized","live_signing_authorized","network_access_authorized")):raise ValueError("ACTION_BOUNDARY_VIOLATION")
__all__=["resolve_delegations","validate_delegation_projection"]
