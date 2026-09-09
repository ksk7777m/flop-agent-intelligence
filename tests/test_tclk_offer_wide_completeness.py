import base64, copy, hashlib, inspect, json, unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator
import flop_agent.tclk_offer_wide_completeness as complete
import flop_agent.tclk_source_attestation as att
from tests.test_tclk_offer_global_winner import canonical, record, transcript, vector, PAYEE_KEYS

def b64(v):return base64.urlsafe_b64encode(v).decode().rstrip("=")

class OfferWideCompletenessTests(unittest.TestCase):
 def setUp(self):
  self.key=Ed25519PrivateKey.generate();self.offer,self.accepts=vector();self.offer_raw=canonical(self.offer)
  self.rows=[record(self.accepts[0],PAYEE_KEYS[0],1),record(self.accepts[1],PAYEE_KEYS[1],2)];self.transcript=transcript(self.rows)
  self.descriptor=canonical({"source_type":"DIRECT_EXPORT","source_id":"tclk-offers","generation":"gen-1"})
  self.context_value={"source_type":"DIRECT_EXPORT","source_id":"tclk-offers","generation":"gen-1","acquisition_mode":"OFFLINE_IMPORT","acquired_at":100,"acquisition_scope":"OFFER_WIDE","offer_sha256":hashlib.sha256(self.offer_raw).hexdigest(),"first_seq":1,"high_water_seq":2,"lower_boundary":True,"upper_boundary":True,"truncated":False,"dropped_count":0,"bounded_page":False,"retention_loss":False,"artifact_set_status":"NO_CONFLICTS"}
  self.manifest=canonical({"schema":"tclk-source-authorities-v1","policy_revision":att.POLICY,"authorities":[{"authority_id":"fixture-authority","authority_version":"1","policy_id":att.POLICY,"key_id":"fixture-key","public_key_b64url":b64(self.key.public_key().public_bytes_raw()),"allowed_source_types":["DIRECT_EXPORT","LOCAL_ARCHIVE"],"allowed_source_ids":["tclk-offers"]}]})
  self.checkpoint=canonical({"generation":"gen-1","last_delivered_seq":0})
 def sealed(self,context=None,transcript_raw=None,descriptor=None,**artifact_changes):
  context_raw=canonical(self.context_value if context is None else context);evidence=self.transcript if transcript_raw is None else transcript_raw;desc=self.descriptor if descriptor is None else descriptor
  value={"version":att.ARTIFACT_VERSION,"authority_id":"fixture-authority","authority_version":"1","policy_id":att.POLICY,"key_id":"fixture-key","source_type":json.loads(desc)["source_type"],"source_binding_sha256":hashlib.sha256(desc).hexdigest(),"generation":json.loads(desc)["generation"],"acquired_at":json.loads(context_raw)["acquired_at"],"issued_at":110,"expires_at":200,"evidence_sha256":hashlib.sha256(evidence).hexdigest(),"context_sha256":hashlib.sha256(context_raw).hexdigest(),"attestation_nonce":"17"};value.update(artifact_changes);value["signature"]=b64(self.key.sign(att.DOMAIN+canonical(value)));return context_raw,canonical(value)
 def assess(self,context=None,transcript_raw=None,descriptor=None,checkpoint=None,replay=b"[]",attestation_raw=None,now=150):
  evidence=self.transcript if transcript_raw is None else transcript_raw;desc=self.descriptor if descriptor is None else descriptor
  context_raw,artifact=self.sealed(context,evidence,desc) if attestation_raw is None else (canonical(self.context_value if context is None else context),attestation_raw)
  verifier=lambda e,d,c,a,r:att._verify(e,d,c,a,r,self.manifest,now)
  return complete._assess(self.offer_raw,evidence,desc,context_raw,artifact,self.checkpoint if checkpoint is None else checkpoint,replay,verifier,complete.assess_offer_wide_evidence)
 def assert_blocked(self,r):
  self.assertEqual(r["winner"],"GLOBAL_WINNER_UNRESOLVED");self.assertEqual(r["race_loss"],"NOT_ISSUED");self.assertEqual(r["lock"],"NOT_VERIFIED");self.assertEqual(r["settlement"],"NOT_VERIFIED");self.assertFalse(r["ready_to_act"]);self.assertFalse(r["authorized_to_act"]);self.assertFalse(r["live_action_enabled"])
 def test_complete_attested_scope_issues_completeness_only(self):
  r=self.assess();self.assertEqual(r["completeness"],"OFFER_WIDE_COMPLETENESS_VERIFIED");self.assertEqual(r["record_count"],2);self.assertEqual(r["errors"],[]);self.assert_blocked(r);Draft202012Validator(json.loads(Path("schemas/tclk-offer-wide-completeness.v1.json").read_text())).validate(r)
 def test_no_invalid_expired_unknown_or_digest_mismatched_attestation(self):
  self.assertEqual(self.assess(attestation_raw=b"")["errors"],["SOURCE_ATTESTATION_REQUIRED"])
  _,artifact=self.sealed();v=json.loads(artifact);v["signature"]="A"*86;self.assertEqual(self.assess(attestation_raw=canonical(v))["errors"],["SOURCE_ATTESTATION_INVALID"])
  self.assertEqual(self.assess(now=201)["errors"],["SOURCE_ATTESTATION_INVALID"])
  self.assertEqual(complete.assess_offer_wide_completeness(self.offer_raw,self.transcript,self.descriptor,canonical(self.context_value),artifact,self.checkpoint,b"[]")["errors"],["SOURCE_ATTESTATION_INVALID"])
  self.assertEqual(self.assess(transcript_raw=self.transcript+b" ",attestation_raw=artifact)["errors"],["SOURCE_ATTESTATION_INVALID"])
 def test_scope_offer_room_and_source_type_fail_closed(self):
  cases=({"acquisition_scope":"PARTIAL"},{"offer_sha256":"0"*64},{"source_id":"other-room"},{"source_type":"MCP_PAGE"},{"bounded_page":True})
  for changes in cases:
   ctx={**self.context_value,**changes};desc=canonical({"source_type":ctx["source_type"],"source_id":ctx["source_id"],"generation":"gen-1"});r=self.assess(context=ctx,descriptor=desc)
   self.assertNotEqual(r["completeness"],"OFFER_WIDE_COMPLETENESS_VERIFIED")
 def test_lower_upper_truncation_retention_and_conflict(self):
  cases=(({"lower_boundary":False},"LOWER_BOUNDARY_UNRESOLVED"),({"upper_boundary":False},"UPPER_BOUNDARY_UNRESOLVED"),({"truncated":True},"TRUNCATION_DETECTED"),({"dropped_count":1},"TRUNCATION_DETECTED"),({"bounded_page":True},"TRUNCATION_DETECTED"),({"retention_loss":True},"RETENTION_LOSS_CONFIRMED"),({"artifact_set_status":"CONFLICT_UNRESOLVED"},"SOURCE_CONFLICT_UNRESOLVED"))
  for changes,code in cases:self.assertEqual(self.assess(context={**self.context_value,**changes})["errors"],[code])
 def test_gap_overlap_history_and_generation_fail_closed(self):
  one=transcript([self.rows[0]]);self.assertEqual(self.assess(transcript_raw=one,context={**self.context_value,"high_water_seq":2})["errors"],["GAP_UNRESOLVED"])
  overlap=canonical({"generation":"gen-1","last_delivered_seq":1});self.assertEqual(self.assess(checkpoint=overlap)["errors"],["GAP_UNRESOLVED"])
  rows=copy.deepcopy(self.rows);rows[1]["seq"]=3;raw=transcript(rows);self.assertEqual(self.assess(transcript_raw=raw,context={**self.context_value,"high_water_seq":3})["errors"],["GAP_UNRESOLVED"])
  rows=copy.deepcopy(self.rows);rows[1]["generation"]="gen-2";raw=transcript(rows);self.assertEqual(self.assess(transcript_raw=raw)["errors"],["GENERATION_MISMATCH"])
 def test_cursor_types_ranges_and_generation(self):
  cases=(({},"GENERATION_MISMATCH"),({"generation":"gen-2","last_delivered_seq":0},"GENERATION_MISMATCH"),({"generation":"gen-1","last_delivered_seq":True},"CURSOR_INTEGRITY_FAILED"),({"generation":"gen-1","last_delivered_seq":1.0},"CURSOR_INTEGRITY_FAILED"),({"generation":"gen-1","last_delivered_seq":-1},"CURSOR_INTEGRITY_FAILED"),({"generation":"gen-1","last_delivered_seq":9007199254740992},"CURSOR_INTEGRITY_FAILED"))
  for value,code in cases:self.assertEqual(self.assess(checkpoint=canonical(value))["errors"],[code])
 def test_malformed_record_signer_and_contract_block(self):
  self.assertEqual(self.assess(transcript_raw=self.transcript+b'{"bad":true}\n',context={**self.context_value,"high_water_seq":3})["errors"],["MALFORMED_SCOPE_IMPACT_UNRESOLVED"])
  rows=copy.deepcopy(self.rows);rows[0]["sig"]="A"*86;self.assertEqual(self.assess(transcript_raw=transcript(rows))["errors"],["MALFORMED_SCOPE_IMPACT_UNRESOLVED"])
  rows=copy.deepcopy(self.rows);frame=json.loads(rows[0]["text"].split(" ",1)[1]);frame["contract"]="0x"+"0"*64;rows[0]["text"]="tclk1 "+canonical(frame).decode();self.assertEqual(self.assess(transcript_raw=transcript(rows))["errors"],["MALFORMED_SCOPE_IMPACT_UNRESOLVED"])
 def test_schema_semantics_privacy_and_no_action_reachability(self):
  valid=self.assess()
  for field,value in (("source_attestation","SOURCE_ATTESTATION_INVALID"),("gap","GAP_UNRESOLVED"),("winner","OFFER_GLOBAL_WINNER_VERIFIED")):
   forged=copy.deepcopy(valid);forged[field]=value;forged["artifact_id"]=complete._hash(complete._canon({k:v for k,v in forged.items() if k!="artifact_id"}))
   with self.assertRaises(Exception):complete._validate(forged)
  def leaves(v):
   if isinstance(v,str):yield v
   elif isinstance(v,dict):
    for child in v.values():yield from leaves(child)
   elif isinstance(v,list):
    for child in v:yield from leaves(child)
  projected=set(leaves(valid))
  for value in (self.offer["id"],self.rows[0]["room"],self.rows[0]["sig"],self.rows[0]["nonce"],self.rows[0]["ts"]):self.assertNotIn(value,projected)
  source=inspect.getsource(complete)
  for word in ("urlopen","requests.","socket.","subprocess.","PrivateKey","post_signed"):self.assertNotIn(word,source)
  self.assertEqual(complete.__all__,["assess_offer_wide_completeness"])
  with self.assertRaises(AttributeError):complete.POLICY="x"
 def test_schema_index_compatibility_and_production_inventory(self):
  index=json.loads(Path("schemas/index.json").read_text());self.assertIn("schemas/tclk-offer-wide-completeness.v1.json",{x["path"] for x in index["schemas"]})
  manifest=json.loads(Path("data/technocore_compatibility.json").read_text());item=manifest["tclk_offer_wide_completeness"];self.assertEqual(item["classification"],"SAFE_PURE_VALIDATOR");self.assertEqual(item["winner"],"GLOBAL_WINNER_UNRESOLVED")
  inventory=Path("docs/TECHNOCORE_SAFETY_FOUNDATION.md").read_text();self.assertIn("offer-wide\n  completeness issuer",inventory);self.assertIn("`UNSAFE`: **0**",inventory)

if __name__=="__main__":unittest.main()
