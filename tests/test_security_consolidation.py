import inspect,json,unittest
from pathlib import Path
from jsonschema import Draft202012Validator
from flop_agent import delegation_resolution as delegation
from flop_agent import kol_referral_readiness as kol
from flop_agent import settlement_rail_maturity as settlement
from flop_agent import tclk_authenticated_winner as winner
from flop_agent import tclk_source_attestation as source
from flop_agent import testnet_readiness as testnet

class SecurityConsolidationTests(unittest.TestCase):
 def test_closed_consolidation_artifact_and_current_assumptions(self):
  value=json.loads(Path("data/security_consolidation.json").read_text());schema=json.loads(Path("schemas/security-consolidation.v1.json").read_text());Draft202012Validator.check_schema(schema);Draft202012Validator(schema).validate(value);self.assertEqual(value["authority"]["production_authorities_total"],0);self.assertEqual(value["production_api"],"OFFLINE_ONLY")
 def test_all_production_authority_manifests_are_empty(self):
  paths=("tclk_source_authorities.json","tclk_winner_authorities.json","flop_endpoint_authorities.json","flop_kol_authorities.json","delegation_authorities.json","settlement_rail_authorities.json")
  for name in paths:
   value=json.loads((Path("data")/name).read_text());self.assertEqual(value.get("authorities",value.get("approved_authority_artifact_sha256")),[],name)
 def test_empty_authorities_fail_closed_across_packages(self):
  results=(source.verify_source_attestation(b"{}",b"{}",b"{}",b"{}",b"{}"),winner.assess_authenticated_winner(b"{}",b"{}",b"{}",b"{}",b"{}",b"{}"),testnet.assess_testnet_readiness(b"[]",b"[]"),kol.assess_kol_referral_readiness(b"[]",b"[]",b"{}"),delegation.resolve_delegations(b"{}",b"{}"),settlement.assess_settlement_rail_maturity(b"[]",b"[]"))
  for result in results:self.assertTrue(result.get("errors") or result.get("ready_to_act") is False or result.get("authorized_to_act") is False);self.assertIsNot(result.get("authorized_to_act",False),True)
 def test_no_action_projection_matrix(self):
  results=(testnet.assess_testnet_readiness(b"[]",b"[]"),kol.assess_kol_referral_readiness(b"[]",b"[]",b"{}"),delegation.resolve_delegations(b"{}",b"{}"),settlement.assess_settlement_rail_maturity(b"[]",b"[]"))
  for result in results:
   for key,value in result.items():
    if key.startswith("authorized_to_") or key=="live_action_enabled" or key.endswith("_action_authorized"):self.assertFalse(value,(key,result.get("schema")))
 def test_bool_lossless_and_unknown_field_matrix(self):
  self.assertFalse(kol._token(True));self.assertFalse(kol._uint(True));self.assertFalse(settlement._decimal(True));self.assertFalse(settlement._decimal(1.0))
  bad=json.dumps({"schema":"technocore-delegation-note-v1","records":[{"version":"technocore-delegation-v1","root_did":"x","agent_did":"y","scope":"*","expires":"200","nonce":True,"signature":"x"}]},sort_keys=True,separators=(",",":")).encode();self.assertEqual(delegation._resolve(bad,b'{"evaluated_at":"100","root_did_sha256":[],"schema":"delegation-root-authority-v1"}',b"{}")["errors"],["ARTIFACT_SCHEMA_INVALID"])
 def test_public_error_privacy_resource_gates_and_no_live_imports(self):
  marker="CROSS-PACKAGE-PRIVATE-MARKER";attack=json.dumps([{"raw_secret":marker}],separators=(",",":")).encode();results=(kol.assess_kol_referral_readiness(b"[]",attack,b"{}"),settlement.assess_settlement_rail_maturity(attack,b"[]"))
  for result in results:self.assertNotIn(marker,json.dumps(result));self.assertTrue(result["errors"])
  self.assertEqual(settlement.assess_settlement_rail_maturity(b" "*(settlement.MAX_BYTES+1),b"[]")["errors"],["INPUT_LIMIT_EXCEEDED"])
  modules=(source,winner,testnet,kol,delegation,settlement);forbidden=("requests.","urlopen","socket.","subprocess.","web3","playwright","selenium","PrivateKey")
  for module in modules:
   text=inspect.getsource(module)
   for token in forbidden:self.assertNotIn(token,text,module.__name__)
if __name__=="__main__":unittest.main()
