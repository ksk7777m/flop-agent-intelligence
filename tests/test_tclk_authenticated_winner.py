import base64,copy,hashlib,inspect,json,unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator
import flop_agent.tclk_authenticated_winner as winner
from tests.test_tclk_offer_wide_completeness import OfferWideCompletenessTests,canonical

def b64(v):return base64.urlsafe_b64encode(v).decode().rstrip("=")
class AuthenticatedWinnerTests(unittest.TestCase):
 def setUp(self):
  fixture=OfferWideCompletenessTests(methodName="test_complete_attested_scope_issues_completeness_only");fixture.setUp();self.fixture=fixture;self.offer=fixture.offer_raw;self.transcript=fixture.transcript;self.completeness=canonical(fixture.assess());self.key=Ed25519PrivateKey.generate()
  self.manifest=canonical({"schema":"tclk-winner-authorities-v1","policy_revision":winner.POLICY,"authorities":[{"authority_id":"fixture-winner-authority","authority_version":"1","key_id":"fixture-winner-key","public_key_b64url":b64(self.key.public_key().public_bytes_raw()),"policy_id":"tclk-winner-selection","policy_version":"1"}]})
  self.policy=Path("data/tclk_winner_policy.json").read_bytes();self.view=winner.assess_offer_global_winner(self.offer,self.transcript);self.ids=[x["candidate_identity"] for x in self.view["candidates"]];self.set_sha=hashlib.sha256(canonical(sorted(self.ids))).hexdigest()
 def artifacts(self,order=None,unique=True,nonce="41",winner_id=None,chron_changes=None,decision_changes=None):
  chron={"version":"tclk-chronology-attestation-v1","authority_id":"fixture-winner-authority","authority_version":"1","key_id":"fixture-winner-key","policy_id":"tclk-winner-selection","policy_version":"1","offer_sha256":hashlib.sha256(self.offer).hexdigest(),"candidate_set_sha256":self.set_sha,"ordered_candidates":self.ids if order is None else order,"unique":unique,"issued_at":100,"expires_at":200,"nonce":nonce};chron.update(chron_changes or {});chron["signature"]=b64(self.key.sign(winner.CHRONOLOGY_DOMAIN+canonical(chron)));chron_raw=canonical(chron)
  decision={"version":"tclk-winner-decision-v1","authority_id":"fixture-winner-authority","authority_version":"1","key_id":"fixture-winner-key","policy_id":"tclk-winner-selection","policy_version":"1","policy_sha256":winner.POLICY_SHA256,"offer_sha256":hashlib.sha256(self.offer).hexdigest(),"candidate_set_sha256":self.set_sha,"completeness_sha256":hashlib.sha256(self.completeness).hexdigest(),"chronology_sha256":hashlib.sha256(chron_raw).hexdigest(),"winner_commitment":self.ids[0] if winner_id is None else winner_id,"decision_nonce":"51","issued_at":100,"expires_at":200};decision.update(decision_changes or {});decision["signature"]=b64(self.key.sign(winner.WINNER_DOMAIN+canonical(decision)));return chron_raw,canonical(decision)
 def assess(self,chron=None,decision=None,completeness=None,replay=b"[]",manifest=None,policy=None,now=150,offer=None,transcript=None):
  if chron is None or decision is None:chron,decision=self.artifacts()
  return winner._assess(self.offer if offer is None else offer,self.transcript if transcript is None else transcript,self.completeness if completeness is None else completeness,chron,decision,replay,self.manifest if manifest is None else manifest,self.policy if policy is None else policy,now,winner.assess_offer_global_winner)
 def test_complete_authoritative_unique_winner_issues_coordination_only(self):
  r=self.assess();self.assertEqual(r["winner"],"OFFER_GLOBAL_WINNER_VERIFIED");self.assertEqual(r["winner_commitment"],self.ids[0]);self.assertEqual(r["race_loss"],"NOT_ISSUED");self.assertEqual(r["lock"],"NOT_VERIFIED");self.assertEqual(r["settlement"],"NOT_VERIFIED");self.assertFalse(r["ready_to_act"]);Draft202012Validator(json.loads(Path("schemas/tclk-authenticated-winner.v1.json").read_text())).validate(r)
 def test_completeness_missing_invalid_and_cross_offer_rejected(self):
  for raw in (b"",b"{}",canonical({**json.loads(self.completeness),"completeness":"COMPLETENESS_NOT_ESTABLISHED"})):self.assertEqual(self.assess(completeness=raw)["winner"],"GLOBAL_WINNER_UNRESOLVED")
  changed=self.offer+b" ";self.assertEqual(self.assess(offer=changed)["errors"],["COMPLETENESS_INVALID"])
 def test_empty_production_unknown_wrong_key_policy_and_expiry(self):
  c,d=self.artifacts();self.assertEqual(winner.assess_authenticated_winner(self.offer,self.transcript,self.completeness,c,d,b"[]")["errors"],["WINNER_AUTHORITY_UNKNOWN"])
  self.assertEqual(self.assess(manifest=canonical({"schema":"tclk-winner-authorities-v1","policy_revision":winner.POLICY,"authorities":[]}))["errors"],["WINNER_AUTHORITY_UNKNOWN"])
  other=Ed25519PrivateKey.generate();m=json.loads(self.manifest);m["authorities"][0]["public_key_b64url"]=b64(other.public_key().public_bytes_raw());self.assertEqual(self.assess(manifest=canonical(m))["errors"],["WINNER_SIGNATURE_INVALID"])
  bad_policy=self.policy.replace(b"SEALED_CHRONOLOGY_FIRST_V1",b"RAW_ORDER_FIRST_UNSAFE");self.assertEqual(self.assess(policy=bad_policy)["errors"],["WINNER_POLICY_INVALID"]);self.assertEqual(self.assess(now=201)["errors"],["WINNER_AUTHORITY_EXPIRED"])
 def test_candidate_digest_injection_deletion_contract_and_duplicate(self):
  c,d=self.artifacts(decision_changes={"candidate_set_sha256":"0"*64});self.assertEqual(self.assess(c,d)["errors"],["WINNER_DIGEST_MISMATCH"])
  c,d=self.artifacts(order=self.ids[:1]);self.assertEqual(self.assess(c,d)["errors"],["WINNER_AMBIGUOUS"])
  c,d=self.artifacts(order=[self.ids[0],self.ids[0]]);self.assertEqual(self.assess(c,d)["errors"],["WINNER_AMBIGUOUS"])
  rows=copy.deepcopy(self.fixture.rows);rows[0]["sig"]="A"*86;self.assertEqual(self.assess(transcript=self.fixture.transcript.__class__(b"\n".join(canonical(x) for x in rows)+b"\n"))["errors"],["COMPLETENESS_INVALID"])
 def test_chronology_missing_digest_tie_raw_order_and_signature(self):
  c,d=self.artifacts(unique=False);self.assertEqual(self.assess(c,d)["errors"],["WINNER_AMBIGUOUS"])
  _,d=self.artifacts();self.assertEqual(self.assess(b"{}",d)["errors"],["ARTIFACT_SCHEMA_INVALID"])
  c,d=self.artifacts();v=json.loads(c);v["ordered_candidates"].reverse();self.assertEqual(self.assess(canonical(v),d)["errors"],["WINNER_SIGNATURE_INVALID"])
  c,d=self.artifacts(decision_changes={"chronology_sha256":"0"*64});self.assertEqual(self.assess(c,d)["errors"],["WINNER_DIGEST_MISMATCH"])
 def test_replay_conflicting_decision_nonce_bool_and_ambiguity(self):
  c,d=self.artifacts();r=self.assess(c,d);decision=json.loads(d);rid=hashlib.sha256(canonical({"authority_id":decision["authority_id"],"decision_nonce":decision["decision_nonce"],"offer_sha256":decision["offer_sha256"],"candidate_set_sha256":self.set_sha,"policy_sha256":winner.POLICY_SHA256})).hexdigest();self.assertEqual(self.assess(c,d,replay=canonical([rid]))["errors"],["WINNER_REPLAY_DETECTED"])
  c,d=self.artifacts(decision_changes={"decision_nonce":True});self.assertEqual(self.assess(c,d)["errors"],["ARTIFACT_SCHEMA_INVALID"])
  c,d=self.artifacts(winner_id=self.ids[1]);self.assertEqual(self.assess(c,d)["errors"],["WINNER_AMBIGUOUS"])
 def test_schema_privacy_reachability_and_escalation_rejection(self):
  r=self.assess()
  def leaves(v):
   if isinstance(v,str):yield v
   elif isinstance(v,dict):
    for child in v.values():yield from leaves(child)
   elif isinstance(v,list):
    for child in v:yield from leaves(child)
  projected=set(leaves(r))
  for raw in (self.fixture.rows[0]["from"],self.fixture.rows[0]["sig"],self.fixture.rows[0]["nonce"],self.fixture.rows[0]["room"],self.fixture.accepts[0]["statement"]):self.assertNotIn(raw,projected)
  forged=copy.deepcopy(r);forged["lock"]="VERIFIED";forged["artifact_id"]=winner._hash(winner._canon({k:v for k,v in forged.items() if k!="artifact_id"}));
  with self.assertRaises(Exception):winner._validate(forged)
  forged=copy.deepcopy(r);forged["stages"][0]["state"]="NOT_EVALUATED";forged["artifact_id"]=winner._hash(winner._canon({k:v for k,v in forged.items() if k!="artifact_id"}))
  with self.assertRaises(Exception):winner._validate(forged)
  source=inspect.getsource(winner)
  for word in ("urlopen","requests.","socket.","subprocess.","PrivateKey","post_signed"):self.assertNotIn(word,source)
  self.assertEqual(winner.__all__,["assess_authenticated_winner"])
 def test_manifest_policy_pins_indexes_and_inventory(self):
  self.assertEqual(json.loads(Path("data/tclk_winner_authorities.json").read_bytes())["authorities"],[]);self.assertEqual(hashlib.sha256(Path("data/tclk_winner_authorities.json").read_bytes()).hexdigest(),winner.MANIFEST_SHA256);self.assertEqual(hashlib.sha256(self.policy).hexdigest(),winner.POLICY_SHA256)
  index=json.loads(Path("schemas/index.json").read_text());self.assertIn("schemas/tclk-authenticated-winner.v1.json",{x["path"] for x in index["schemas"]});item=json.loads(Path("data/technocore_compatibility.json").read_text())["tclk_authenticated_winner"];self.assertEqual(item["race_loss"],"NOT_ISSUED")
if __name__=="__main__":unittest.main()
