import copy,hashlib,inspect,json,unittest
from pathlib import Path
from jsonschema import Draft202012Validator
import flop_agent.settlement_rail_maturity as rail
def canon(v):return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")
class SettlementRailMaturityTests(unittest.TestCase):
 def setUp(self):
  self.base=Path("data/settlement_rail_baseline.json").read_bytes();self.paper=self.candidate("paper","PAPER",source_status="RELEASED");self.evm=self.candidate("evm-hash","EVM_HASH",source_status="PR_OPEN_UNMERGED",deployment_state="MOCK_ONLY",asset_class="TEST_TOKEN",network_sha256="4"*64);self.identity="9"*64
 def candidate(self,rail_id,rail_type,**changes):
  v={"rail_id":rail_id,"rail_type":rail_type,"implementation_version":"v0.1.0","source_class":"TCLK_RELEASE","source_id":"reviewed-tclk-source","source_sha256":"1"*64,"code_sha256":"2"*64,"source_status":"REFERENCE_ONLY","audit_state":"NOT_AUDITED","deployment_state":"NOT_DEPLOYED","network_sha256":None,"asset_class":"UNVERIFIED_ASSET"};v.update(changes);return v
 def authority(self,v):return {**v,"rail_identity_sha256":self.identity}
 def observation(self,**changes):
  v={"rail_id":"evm-hash","rail_identity_sha256":self.identity,"network_sha256":"4"*64,"deployment_sha256":"5"*64,"transaction_sha256":"6"*64,"lock_state":"LOCK_OBSERVED","terminal_state":"CLAIM_OBSERVED","locked_max":"100","actual_settlement":"80","timestamp_sha256":"7"*64,"finality_state":"FINALITY_VERIFIED","timelock_policy_verified":True,"safety_margin_verified":True,"cross_chain_margin_verified":True,"contract_identity_verified":True,"source_provenance_verified":True};v.update(changes);return v
 def assess(self,rails=None,obs=None,authorities=None):return rail._assess(canon([] if rails is None else rails),canon([] if obs is None else obs),canon({"schema":"settlement-rail-authorities-v1","authorities":[] if authorities is None else authorities}),self.base)
 def test_production_empty_authority_and_baseline_states(self):
  r=rail.assess_settlement_rail_maturity(b"[]",b"[]");self.assertEqual((r["paper_rail"],r["memory_rail"],r["evm_hash_rail"],r["point_lock"]),("PAPER_ONLY","REFERENCE_IMPLEMENTATION","UNMERGED_BINDING","EXPERIMENTAL_UNAUDITED"));self.assertFalse(r["economic_value_verified"]);self.assertEqual(json.loads(Path("data/settlement_rail_authorities.json").read_text())["authorities"],[])
  self.assertEqual(hashlib.sha256(self.base).hexdigest(),rail.BASELINE_SHA256);self.assertEqual(hashlib.sha256(Path("data/settlement_rail_authorities.json").read_bytes()).hexdigest(),rail.AUTHORITIES_SHA256)
  self.assertEqual(rail.assess_settlement_rail_maturity(canon([self.paper]),b"[]")["errors"],["SOURCE_UNVERIFIED"])
 def test_paper_mock_pr_and_transcript_claim_never_prove_value(self):
  for candidate in (self.paper,self.evm):
   r=self.assess([candidate],authorities=[self.authority(candidate)]);self.assertFalse(r["value_bearing_verified"]);self.assertFalse(r["settlement_verified"]);self.assertEqual(r["flop_yellowpaper_conformance"],"UNRESOLVED")
 def test_untrusted_sources_and_name_only_fail_closed(self):
  for source in rail.UNTRUSTED:
   v={**self.evm,"source_class":source};self.assertEqual(self.assess([v],authorities=[])["errors"],["SOURCE_UNVERIFIED"])
  self.assertEqual(self.assess([{**self.evm,"raw_contract":"PRIVATE"}])["errors"],["ARTIFACT_SCHEMA_INVALID"])
 def test_observation_exact_network_contract_source_and_asset_boundary(self):
  auth=self.authority(self.evm);valid=self.assess([self.evm],[self.observation()],[auth]);self.assertTrue(valid["ready_for_human_review"]);self.assertFalse(valid["settlement_verified"])
  for change in ({"network_sha256":"8"*64},{"rail_identity_sha256":"8"*64},{"contract_identity_verified":False},{"source_provenance_verified":False}):self.assertTrue(self.assess([self.evm],[self.observation(**change)],[auth])["errors"])
 def test_yellow_paper_gates_and_amount_policy_remain_unresolved(self):
  auth=self.authority(self.evm)
  for field in ("timelock_policy_verified","safety_margin_verified","cross_chain_margin_verified"):
   r=self.assess([self.evm],[self.observation(**{field:False})],[auth]);self.assertEqual(r["flop_yellowpaper_conformance"],"UNRESOLVED");self.assertFalse(r["settlement_verified"])
  self.assertEqual(self.assess([self.evm],[self.observation(actual_settlement="101")],[auth])["errors"],["AMOUNT_POLICY_VIOLATION"])
 def test_missing_finality_fake_deployment_and_asset_mismatch_never_promote(self):
  auth=self.authority(self.evm)
  for change in ({"finality_state":"UNRESOLVED"},{"deployment_sha256":None},{"terminal_state":"NOT_OBSERVED"}):self.assertFalse(self.assess([self.evm],[self.observation(**change)],[auth])["settlement_verified"])
  wrong={**self.evm,"asset_class":"THIRD_PARTY_ASSET"};self.assertEqual(self.assess([wrong],authorities=[auth])["errors"],["SOURCE_UNVERIFIED"])
 def test_privacy_resource_schema_and_action_reachability(self):
  for field in ("preimage","witness","wallet_address","rpc_credential","raw_signing_payload","transcript_valid"):
   attack={**self.observation(),field:"PRIVATE"};r=self.assess([self.evm],[attack],[self.authority(self.evm)]);self.assertEqual(r["errors"],["ARTIFACT_SCHEMA_INVALID"]);self.assertNotIn("PRIVATE",json.dumps(r))
  self.assertEqual(rail._assess(b" "*(rail.MAX_BYTES+1),b"[]",b"{}",self.base)["errors"],["INPUT_LIMIT_EXCEEDED"])
  result=self.assess();schema=json.loads(Path("schemas/settlement-rail-maturity.v1.json").read_text());Draft202012Validator.check_schema(schema);Draft202012Validator(schema).validate(result)
  forged=copy.deepcopy(result);forged["settlement_verified"]=True;forged["artifact_id"]=rail._hash(rail._canon({k:v for k,v in forged.items() if k!="artifact_id"}));
  with self.assertRaises(ValueError):rail.validate_settlement_projection(forged)
  for field in ("authorized_to_lock","authorized_to_claim","authorized_to_refund","authorized_to_send_value","authorized_to_connect_wallet","authorized_to_act"):self.assertFalse(result[field])
  source=inspect.getsource(rail)
  for word in ("requests.","urlopen","socket.","web3","PrivateKey","subprocess.","import technocore","playwright","selenium"):self.assertNotIn(word,source)
if __name__=="__main__":unittest.main()
