import copy,hashlib,inspect,json,unittest
from pathlib import Path
from jsonschema import Draft202012Validator
import flop_agent.testnet_readiness as readiness

def canon(value):return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")
class TestnetReadinessTests(unittest.TestCase):
 def setUp(self):
  self.baseline=Path("data/flop_testnet_readiness_baseline.json").read_bytes();self.network="a"*64;self.asset="b"*64;self.request=b"PRIVATE PROMPT";self.response=b"PRIVATE RESPONSE"
  self.testnet=self.candidate("TESTNET","c"*64);self.faucet=self.candidate("FAUCET","d"*64);self.inference_endpoint=self.candidate("INFERENCE","e"*64)
  self.manifest=canon({"schema":"flop-endpoint-authorities-v1","authorities":[self.authority(self.testnet),self.authority(self.faucet),self.authority(self.inference_endpoint)]})
 def candidate(self,kind,endpoint,source_class="FLOP_YELLOW_PAPER",status="PUBLISHED",**changes):
  value={"source_class":source_class,"source_id":"official-source-"+kind.lower(),"source_document_sha256":hashlib.sha256(kind.encode()).hexdigest(),"source_version":"v0.5.0","source_updated":"2026-09-05","endpoint_class":kind,"endpoint_sha256":endpoint,"network_identity_sha256":self.network,"asset_class":"TEST_TOKEN","asset_identity_sha256":self.asset,"published_status":status,"spec_parameter_sha256":"f"*64,"observation_nonce":"1"};value.update(changes);return value
 def authority(self,candidate):
  return {"source_class":candidate["source_class"],"source_id":candidate["source_id"],"source_document_sha256":candidate["source_document_sha256"],"source_version":candidate["source_version"],"source_updated":candidate["source_updated"],"endpoints":[{k:candidate[k] for k in readiness.AUTHORITY_ENDPOINT_FIELDS}]}
 def draft(self,**changes):
  value={"workload_id":"fixture-workload","agent_identity_sha256":"1"*64,"network_session_sha256":"2"*64,"request_sha256":hashlib.sha256(self.request).hexdigest(),"result_sha256":hashlib.sha256(self.response).hexdigest(),"model_task_id":"fixture-task","compute_units":"10","test_token_spend":"2.5","provider_identity_sha256":"5"*64,"receipt_sha256":"6"*64,"timestamp_provenance_sha256":"7"*64,"self_reported_usage":False,"evidence_nonce":"9"};value.update(changes);return value
 def assess(self,candidates=None,draft=None,manifest=None):
  return readiness._assess(canon([] if candidates is None else candidates),canon({} if draft is None else draft),self.request,self.response,self.baseline,self.manifest if manifest is None else manifest)
 def test_production_empty_manifest_fails_closed_and_no_endpoint_is_safe(self):
  empty=readiness.assess_testnet_readiness(b"[]",b"{}");self.assertEqual(empty["testnet"],"TESTNET_NOT_PUBLISHED");self.assertEqual(empty["faucet"],"FAUCET_NOT_PUBLISHED");self.assertFalse(empty["ready_to_act"])
  result=readiness.assess_testnet_readiness(canon([self.testnet]),b"{}");self.assertEqual(result["errors"],["SOURCE_UNVERIFIED"]);self.assertEqual(result["testnet"],"TESTNET_CANDIDATE")
 def test_verified_sources_reach_human_review_only(self):
  result=self.assess([self.testnet,self.faucet,self.inference_endpoint],self.draft());self.assertEqual(result["spec"],"SPEC_SOURCE_VERIFIED");self.assertEqual(result["testnet"],"TESTNET_READY_FOR_HUMAN_REVIEW");self.assertEqual(result["faucet"],"FAUCET_READY_FOR_HUMAN_REVIEW");self.assertEqual(result["inference"],"INFERENCE_READY_FOR_HUMAN_REVIEW");self.assertEqual(result["inference_evidence"],"INFERENCE_EVIDENCE_READY");self.assertEqual(result["network_identity"],"NETWORK_IDENTITY_VERIFIED");self.assertEqual(result["asset_identity"],"TEST_TOKEN")
  for field in ("inference_executed","useful_inference_verified","spend_verified","airdrop_eligibility_verified","claim_authorized","inference_spend_authorized","ready_to_act","authorized_to_act","live_action_enabled"):self.assertFalse(result[field])
  Draft202012Validator(json.loads(Path("schemas/flop-testnet-readiness.v1.json").read_text())).validate(result)
 def test_community_search_lookalike_referral_and_forged_official_labels_fail(self):
  for source in readiness.UNTRUSTED:
   candidate=self.candidate("FAUCET","d"*64,source_class=source);self.assertEqual(self.assess([candidate],manifest=canon({"schema":"flop-endpoint-authorities-v1","authorities":[]}))["errors"],["SOURCE_UNVERIFIED"])
  forged=copy.deepcopy(self.testnet);forged["source_document_sha256"]="0"*64;self.assertEqual(self.assess([forged])["errors"],["SOURCE_BINDING_MISMATCH"])
 def test_endpoint_network_asset_and_spec_conflicts_fail_closed(self):
  injected=copy.deepcopy(self.testnet);injected["endpoint_sha256"]="0"*64;self.assertEqual(self.assess([injected])["errors"],["SOURCE_BINDING_MISMATCH"])
  other=copy.deepcopy(self.faucet);other["network_identity_sha256"]="9"*64;manifest=canon({"schema":"flop-endpoint-authorities-v1","authorities":[self.authority(self.testnet),self.authority(other)]});self.assertEqual(self.assess([self.testnet,other],manifest=manifest)["errors"],["NETWORK_BINDING_MISMATCH"])
  third=copy.deepcopy(self.faucet);third.update(asset_class="THIRD_PARTY_ASSET",asset_identity_sha256="8"*64);manifest=canon({"schema":"flop-endpoint-authorities-v1","authorities":[self.authority(self.testnet),self.authority(third)]});self.assertEqual(self.assess([self.testnet,third],manifest=manifest)["errors"],["ASSET_UNVERIFIED"])
  conflicting=copy.deepcopy(self.testnet);conflicting.update(source_id="official-source-other",source_document_sha256="8"*64,spec_parameter_sha256="7"*64);manifest=canon({"schema":"flop-endpoint-authorities-v1","authorities":[self.authority(self.testnet),self.authority(conflicting)]});result=self.assess([self.testnet,conflicting],manifest=manifest);self.assertEqual(result["spec"],"SPEC_CONFLICT");self.assertEqual(result["errors"],["SPEC_CONFLICT"])
 def test_candidate_status_does_not_become_action_ready(self):
  candidate=self.candidate("TESTNET","c"*64,status="CANDIDATE");manifest=canon({"schema":"flop-endpoint-authorities-v1","authorities":[self.authority(candidate)]});result=self.assess([candidate],manifest=manifest);self.assertEqual(result["testnet"],"TESTNET_OFFICIAL_SOURCE_VERIFIED");self.assertFalse(result["ready_to_act"])
  conflict=self.candidate("TESTNET","9"*64,status="CANDIDATE",source_id="official-source-other",source_document_sha256="8"*64,observation_nonce="2");manifest=canon({"schema":"flop-endpoint-authorities-v1","authorities":[self.authority(candidate),self.authority(conflict)]});self.assertEqual(self.assess([candidate,conflict],manifest=manifest)["errors"],["ENDPOINT_CONFLICT"])
 def test_inference_requires_receipt_network_and_non_self_reported_usage(self):
  endpoints=[self.testnet,self.inference_endpoint]
  self.assertEqual(self.assess(endpoints,self.draft(receipt_sha256=None))["errors"],["INFERENCE_RECEIPT_REQUIRED"])
  self.assertEqual(self.assess(endpoints,self.draft(network_session_sha256=None))["errors"],["INFERENCE_NETWORK_PROVENANCE_REQUIRED"])
  self.assertEqual(self.assess(endpoints,self.draft(self_reported_usage=True))["errors"],["INFERENCE_EVIDENCE_INVALID"])
  self.assertEqual(self.assess(endpoints,self.draft(request_sha256="0"*64))["errors"],["INFERENCE_COMMITMENT_MISMATCH"])
  self.assertEqual(self.assess(endpoints,self.draft(result_sha256="0"*64))["errors"],["INFERENCE_COMMITMENT_MISMATCH"])
 def test_duplicate_source_nonce_is_replay_candidate(self):
  self.assertEqual(self.assess([self.testnet,self.testnet])["errors"],["REPLAY_CANDIDATE"])
  for changes in ({"endpoint_sha256":"9"*64},{"network_identity_sha256":"9"*64},{"source_document_sha256":"9"*64}):
   replay={**self.testnet,**changes};self.assertEqual(self.assess([self.testnet,replay])["errors"],["REPLAY_CANDIDATE"])
 def test_raw_material_extra_fields_and_bool_nonce_are_rejected_without_echo(self):
  invalid=(True,False,1.0,9007199254740993,"1e3","0x10","+1"," 1","\N{ARABIC-INDIC DIGIT ONE}","01","1"*20,"1"*1000)
  attacks=({**self.testnet,"raw_url":"https://secret.invalid/?key=PRIVATE"},*({**self.testnet,"observation_nonce":nonce} for nonce in invalid))
  for attack in attacks:
   result=self.assess([attack]);self.assertEqual(result["errors"],["ARTIFACT_SCHEMA_INVALID"]);self.assertNotIn("PRIVATE",json.dumps(result));self.assertNotIn("secret.invalid",json.dumps(result))
  for change in ({"raw_prompt":"PRIVATE PROMPT"},{"raw_response":"PRIVATE RESPONSE"},*({"evidence_nonce":nonce} for nonce in invalid)):
   result=self.assess([self.testnet,self.inference_endpoint],{**self.draft(),**change});self.assertEqual(result["errors"],["ARTIFACT_SCHEMA_INVALID"]);self.assertNotIn("PRIVATE",json.dumps(result))
  for nonce in ("9007199254740991","9007199254740992","9007199254740993","9999999999999999999"):
   self.assertNotEqual(self.assess([{**self.testnet,"observation_nonce":nonce}])["errors"],["ARTIFACT_SCHEMA_INVALID"])
 def test_scoring_usefulness_settlement_and_claim_are_never_derived(self):
  result=self.assess([self.testnet,self.faucet,self.inference_endpoint],self.draft());rendered=json.dumps(result);self.assertEqual(result["agent_scoring"],"UNRESOLVED");self.assertEqual(result["airdrop_rule_status"],"PROVISIONAL");self.assertNotIn("USEFUL_INFERENCE_VERIFIED",rendered);self.assertNotIn("PRIVATE PROMPT",rendered);self.assertNotIn("PRIVATE RESPONSE",rendered);self.assertNotIn("settlement",rendered.lower())
 def test_schema_semantic_resource_and_reachability_boundaries(self):
  result=self.assess();validator=Draft202012Validator(json.loads(Path("schemas/flop-testnet-readiness.v1.json").read_text()));forged=copy.deepcopy(result);forged["ready_to_act"]=True;forged["artifact_id"]=readiness._hash(readiness._canon({k:v for k,v in forged.items() if k!="artifact_id"}))
  with self.assertRaises(Exception):readiness.validate_readiness_projection(forged)
  forged=copy.deepcopy(result);forged["testnet"]="TESTNET_READY_FOR_HUMAN_REVIEW";forged["artifact_id"]=readiness._hash(readiness._canon({k:v for k,v in forged.items() if k!="artifact_id"}));self.assertTrue(list(validator.iter_errors(forged)))
  with self.assertRaises(Exception):readiness.validate_readiness_projection(forged)
  self.assertEqual(readiness.assess_testnet_readiness(b"["+b" "*readiness.MAX_INPUT_BYTES,b"not-json")["errors"],["INPUT_LIMIT_EXCEEDED"])
  self.assertEqual(readiness._assess(b"[]",b"{}",b"",b"",b" "*(readiness.MAX_INPUT_BYTES+1),b"{}")["errors"],["INPUT_LIMIT_EXCEEDED"])
  source=inspect.getsource(readiness)
  for word in ("urlopen","requests.","socket.","subprocess.","PrivateKey","wallet_sdk","web3","post_signed"):self.assertNotIn(word,source)
 def test_pinned_baseline_manifest_schema_and_public_inventory(self):
  self.assertEqual(hashlib.sha256(self.baseline).hexdigest(),readiness.BASELINE_SHA256);self.assertEqual(hashlib.sha256(Path("data/flop_endpoint_authorities.json").read_bytes()).hexdigest(),readiness.AUTHORITIES_SHA256);self.assertEqual(json.loads(Path("data/flop_endpoint_authorities.json").read_text())["authorities"],[])
  baseline=json.loads(self.baseline);self.assertEqual(baseline["flop_spec"]["version"],"v0.5.0");self.assertEqual(baseline["technocore"]["version"],"0.13.0");self.assertEqual(baseline["endpoint_state"]["faucet"],"NOT_LIVE_CONFIRMED")
  index=json.loads(Path("schemas/index.json").read_text());self.assertIn("schemas/flop-testnet-readiness.v1.json",{x["path"] for x in index["schemas"]});compat=json.loads(Path("data/technocore_compatibility.json").read_text())["flop_testnet_readiness"];self.assertEqual(compat["authority_manifest"],"EMPTY_FAIL_CLOSED");self.assertEqual(compat["scoring"],"UNRESOLVED")
if __name__=="__main__":unittest.main()
