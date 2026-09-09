import copy, inspect, json, unittest
from pathlib import Path
from jsonschema import Draft202012Validator
import flop_agent.tclk_offer_wide_evidence as evidence
from tests.test_tclk_offer_global_winner import canonical, record, transcript, vector, PAYEE_KEYS

def source(**changes):
 value={"source_type":"DIRECT_EXPORT","generation":"gen-1","first_seq":1,"last_seq":2,"truncated":False,"lower_boundary":True,"upper_boundary":True};value.update(changes);return canonical(value)
def checkpoint(**changes):
 value={"generation":"gen-1","last_delivered_seq":0};value.update(changes);return canonical(value)
def strings(value):
 if isinstance(value,str):yield value
 elif isinstance(value,dict):
  for child in value.values():yield from strings(child)
 elif isinstance(value,list):
  for child in value:yield from strings(child)
class OfferWideEvidenceTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.schema=json.loads(Path("schemas/tclk-offer-wide-evidence.v1.json").read_text());Draft202012Validator.check_schema(cls.schema)
  cls.offer,accepts=vector();cls.records=[record(accepts[0],PAYEE_KEYS[0],1),record(accepts[1],PAYEE_KEYS[1],2)]
 def assess(self,s=None,c=None,records=None):return evidence.assess_offer_wide_evidence(canonical(self.offer),transcript(self.records if records is None else records),source() if s is None else s,checkpoint() if c is None else c)
 def closed(self,r):
  Draft202012Validator(self.schema).validate(r);evidence._validate(r)
  self.assertEqual(r["winner"],"GLOBAL_WINNER_UNRESOLVED");self.assertEqual(r["race_loss"],"NOT_ISSUED");self.assertEqual(r["completeness"],"COMPLETENESS_NOT_ESTABLISHED");self.assertFalse(r["ready_to_act"]);self.assertFalse(r["authorized_to_act"])
  leaves=set(strings(r))
  for v in (self.records[0]["from"],self.records[0]["nonce"],self.records[0]["sig"],self.records[0]["ts"],self.records[0]["text"]):self.assertNotIn(v,leaves)
 def test_direct_complete_claim_remains_unauthenticated_and_winner_blocked(self):
  r=self.assess();self.assertEqual(r["source"]["acceptance"],"OFFER_WIDE_SOURCE_UNAUTHENTICATED");self.assertEqual(r["cursor"]["continuity"],"CONTIGUOUS");self.closed(r)
 def test_source_types_never_imply_complete(self):
  for kind in ("DIRECT_EXPORT","MCP_PAGE","PROVIDED_EXPORT","LOCAL_ARCHIVE","UNKNOWN_SOURCE"):
   r=self.assess(source(source_type=kind));self.assertEqual(r["completeness"],"COMPLETENESS_NOT_ESTABLISHED");self.closed(r)
  for raw in (source(source_type="DIRECT_EXPORT",lower_boundary=True,upper_boundary=True),source(source_type="PROVIDED_EXPORT",lower_boundary=True,upper_boundary=True)):
   self.assertNotEqual(self.assess(raw)["completeness"],"OFFER_WIDE_COMPLETENESS_VERIFIED")
  self.assertEqual(self.assess(source(source_type="FORGED_AUTHORITY"))["errors"],["SOURCE_METADATA_INVALID"])
  self.assertEqual(self.assess(canonical({"source_type":"DIRECT_EXPORT","authenticated":True}))["errors"],["ARTIFACT_INVALID"])
 def test_cursor_rejections(self):
  cases=[(b"", "ARTIFACT_INVALID"),(checkpoint(last_delivered_seq=-1),"CURSOR_INTEGRITY_FAILED"),(checkpoint(last_delivered_seq=True),"CURSOR_INTEGRITY_FAILED"),(checkpoint(last_delivered_seq=1.0),"ARTIFACT_INVALID"),(checkpoint(last_delivered_seq=9007199254740992),"ARTIFACT_INVALID"),(canonical({"generation":"gen-1","last_delivered_seq":0,"x":1}),"ARTIFACT_INVALID")]
  for c,code in cases:self.assertEqual(self.assess(c=c)["errors"],[code])
 def test_generation_mismatch_requires_resync(self):
  r=self.assess(c=checkpoint(generation="other"));self.assertEqual(r["errors"],["GENERATION_MISMATCH"]);self.assertEqual(r["cursor"]["resync"],"RESYNC_REQUIRED");self.closed(r)
 def test_gap_is_unresolved_not_retention_loss(self):
  r=self.assess(source(first_seq=4,last_seq=5));self.assertEqual(r["gap"],"GAP_UNRESOLVED");self.assertEqual(r["retention"],"NOT_CONFIRMED");self.closed(r)
 def test_overlap_and_truncation_partial(self):
  r=self.assess(source(first_seq=0,last_seq=2,truncated=True));self.assertEqual(r["gap"],"CURSOR_OVERLAP_UNRESOLVED");self.assertEqual(r["source"]["acceptance"],"OFFER_WIDE_SOURCE_PARTIAL");self.closed(r)
 def test_malformed_transcript_is_quarantined_and_not_complete(self):
  raw=transcript(self.records)+b'{"private":"must-not-leak"}\n';r=evidence.assess_offer_wide_evidence(canonical(self.offer),raw,source(),checkpoint());self.assertEqual(r["quarantined_count"],1);self.assertEqual(r["signed_records"],"NOT_VERIFIED");self.assertNotIn("must-not-leak",json.dumps(r));self.closed(r)
 def test_unsigned_mutations_and_multiple_accepts_never_issue_winner(self):
  for field,value in (("seq",8),("ts","2026-09-09T01:00:00Z"),("generation","other")):
   rows=copy.deepcopy(self.records);rows[0][field]=value;r=self.assess(records=rows);self.assertEqual(r["winner"],"GLOBAL_WINNER_UNRESOLVED")
 def test_closed_grammar_and_escalation_rejected(self):
  r=self.assess()
  for mutate in (lambda x:x.update(winner="OFFER_GLOBAL_WINNER_VERIFIED"),lambda x:x.update(completeness="OFFER_WIDE_COMPLETENESS_VERIFIED"),lambda x:x["stages"].reverse(),lambda x:x["stages"][0].update(ordinal=True),lambda x:x["stages"][0].update(state="FAILED"),lambda x:x["cursor"].update(resync="RESYNC_REQUIRED"),lambda x:x.update(extra=True)):
   forged=copy.deepcopy(r);mutate(forged)
   with self.assertRaises(Exception):Draft202012Validator(self.schema).validate(forged)
   with self.assertRaises(Exception):evidence._validate(forged)
 def test_limits_api_and_no_action_imports(self):
  r=evidence.assess_offer_wide_evidence(canonical(self.offer),b"x"*(evidence.MAX_TRANSCRIPT_BYTES+1),source(),checkpoint());self.assertEqual(r["errors"],["INPUT_LIMIT_EXCEEDED"])
  r=evidence.assess_offer_wide_evidence(b"x"*(evidence.MAX_OFFER_BYTES+1),transcript(self.records),source(),checkpoint());self.assertEqual(r["errors"],["INPUT_LIMIT_EXCEEDED"])
  self.assertEqual(list(inspect.signature(evidence.assess_offer_wide_evidence).parameters),["offer_bytes","transcript_bytes","source_metadata_bytes","checkpoint_bytes"]);self.assertEqual(evidence.__all__,["assess_offer_wide_evidence"])
  src=inspect.getsource(evidence)
  for word in ("urlopen","requests.","socket.","subprocess.","wallet","sign_message","post_signed"):self.assertNotIn(word,src)
  with self.assertRaises(AttributeError):evidence.POLICY="x"
 def test_schema_index_and_compatibility_inventory(self):
  index=json.loads(Path("schemas/index.json").read_text());self.assertIn("schemas/tclk-offer-wide-evidence.v1.json",{x["path"] for x in index["schemas"]})
  manifest=json.loads(Path("data/technocore_compatibility.json").read_text());item=manifest["tclk_offer_wide_evidence"];self.assertEqual(item["classification"],"SAFE_PURE_VALIDATOR");self.assertEqual(item["winner"],"GLOBAL_WINNER_UNRESOLVED")
if __name__=="__main__":unittest.main()
