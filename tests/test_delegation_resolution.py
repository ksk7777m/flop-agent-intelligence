import base64,copy,hashlib,inspect,json,unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator
from flop_agent.identity import did_from_public_key
import flop_agent.delegation_resolution as delegation

def canon(v):return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")
def b64(v):return base64.urlsafe_b64encode(v).decode().rstrip("=")
class DelegationResolutionTests(unittest.TestCase):
 def setUp(self):
  self.root=Ed25519PrivateKey.from_private_bytes(bytes(range(32)));self.other=Ed25519PrivateKey.from_private_bytes(bytes(range(1,33)));self.root_did=did_from_public_key(self.root.public_key().public_bytes_raw());self.agent1=did_from_public_key(Ed25519PrivateKey.from_private_bytes(bytes(range(2,34))).public_key().public_bytes_raw());self.agent2=did_from_public_key(Ed25519PrivateKey.from_private_bytes(bytes(range(3,35))).public_key().public_bytes_raw());self.authority=canon({"schema":"delegation-root-authority-v1","evaluated_at":"100","root_did_sha256":[hashlib.sha256(self.root_did.encode()).hexdigest()]})
 def record(self,nonce="5",agent=None,scope="r:lobby",expires="200",key=None,root_did=None):
  value={"version":"technocore-delegation-v1","root_did":root_did or self.root_did,"agent_did":agent or self.agent1,"scope":scope,"expires":expires,"nonce":nonce};value["signature"]=b64((key or self.root).sign(delegation.DOMAIN+canon(value)));return value
 def assess(self,records):return delegation._resolve(canon({"schema":"technocore-delegation-note-v1","records":records}),self.authority,b"{}")
 def test_single_reissue_supersession_and_per_agent_isolation(self):
  result=self.assess([self.record("5"),self.record("9007199254740993"),self.record("7",agent=self.agent2)]);self.assertEqual(result["current_count"],2);self.assertEqual(result["superseded_count"],1);self.assertEqual(result["resolution"],"DELEGATION_VALID_CURRENT")
 def test_forged_high_low_and_same_nonce_never_rank(self):
  for forged in ("999","1","5"):
   bad=self.record(forged,key=self.other);result=self.assess([self.record("5"),bad]);self.assertEqual(result["current_count"],1);self.assertEqual(result["superseded_count"],0);self.assertEqual(result["forged_count"],1)
 def test_scope_mutation_wrong_root_and_unknown_scope_fail_closed(self):
  value=self.record();value["scope"]="kv:other";self.assertEqual(self.assess([value])["resolution"],"DELEGATION_FORGED")
  wrong=self.record(key=self.other);self.assertEqual(self.assess([wrong])["resolution"],"DELEGATION_FORGED")
  self.assertEqual(self.assess([{**self.record(),"scope":"wallet:*"}])["errors"],["ARTIFACT_SCHEMA_INVALID"])
 def test_nonce_and_expiry_canonical_decimal_grammar(self):
  for value in (True,False,1.0,"١","1e3","0x10","01","1"*20):
   self.assertEqual(self.assess([{**self.record(),"nonce":value}])["errors"],["ARTIFACT_SCHEMA_INVALID"])
  for value in (True,1.0,"Infinity","1e3","١","0x10","01","1"*20):
   self.assertEqual(self.assess([{**self.record(),"expires":value}])["errors"],["ARTIFACT_SCHEMA_INVALID"])
 def test_expiry_duplicate_and_history_completeness(self):
  expired=self.assess([self.record(expires="100")]);self.assertEqual(expired["resolution"],"DELEGATION_EXPIRED")
  same=self.record();duplicate=self.assess([same,copy.deepcopy(same)]);self.assertEqual(duplicate["record_count"],1);self.assertEqual(duplicate["history_completeness"],"DELEGATION_HISTORY_COMPLETENESS_NOT_ESTABLISHED")
 def test_equal_nonce_conflicting_scope_or_expiry_is_conflict(self):
  for other in (self.record(scope="kv:public"),self.record(expires="201")):
   result=self.assess([self.record(),other]);self.assertEqual(result["resolution"],"DELEGATION_CONFLICT");self.assertEqual(result["current_count"],0)
 def test_equal_nonce_conflicting_reviewed_root_binding_is_conflict(self):
  other_did=did_from_public_key(self.other.public_key().public_bytes_raw());authority=canon({"schema":"delegation-root-authority-v1","evaluated_at":"100","root_did_sha256":[hashlib.sha256(self.root_did.encode()).hexdigest(),hashlib.sha256(other_did.encode()).hexdigest()]});other=self.record(key=self.other,root_did=other_did)
  result=delegation._resolve(canon({"schema":"technocore-delegation-note-v1","records":[self.record(),other]}),authority,b"{}");self.assertEqual(result["resolution"],"DELEGATION_CONFLICT");self.assertEqual(result["conflict_count"],2)
 def test_root_identity_is_independent_and_production_registry_empty(self):
  unknown=canon({"schema":"delegation-root-authority-v1","evaluated_at":"100","root_did_sha256":[]});result=delegation._resolve(canon({"schema":"technocore-delegation-note-v1","records":[self.record()]}),unknown,b"{}");self.assertEqual(result["resolution"],"DELEGATION_ROOT_UNVERIFIED");self.assertTrue(result["delegation_signature_valid"]);self.assertFalse(result["root_identity_verified"])
  self.assertEqual(delegation.resolve_delegations(b"{}",self.authority)["errors"],["ROOT_AUTHORITY_UNAPPROVED"])
 def test_valid_delegation_never_authorizes_actions_or_exposes_raw_values(self):
  record=self.record(nonce="1234567890123456789");result=self.assess([record]);rendered=json.dumps(result)
  for field in ("authorized_to_act","wallet_action_authorized","faucet_action_authorized","inference_spend_authorized","live_signing_authorized","network_access_authorized"):self.assertFalse(result[field])
  for secret in (record["root_did"],record["agent_did"],record["scope"],record["nonce"],record["signature"]):self.assertNotIn(secret,rendered)
 def test_resources_schema_compatibility_and_no_reachability(self):
  self.assertEqual(delegation._resolve(b" "*(delegation.MAX_NOTE_BYTES+1),self.authority,b"{}")["errors"],["INPUT_LIMIT_EXCEEDED"])
  schema=json.loads(Path("schemas/delegation-signature-first-resolution.v1.json").read_text());Draft202012Validator.check_schema(schema);Draft202012Validator(schema).validate(self.assess([self.record()]))
  source=inspect.getsource(delegation)
  for word in ("requests.","urlopen","socket.","subprocess.","PrivateKey","web3","playwright","selenium","testnet_readiness","kol_referral") :self.assertNotIn(word,source)
  self.assertEqual(json.loads(Path("data/delegation_authorities.json").read_text())["approved_authority_artifact_sha256"],[])
  self.assertEqual(hashlib.sha256(Path("data/delegation_authorities.json").read_bytes()).hexdigest(),delegation.REGISTRY_SHA256)
if __name__=="__main__":unittest.main()
