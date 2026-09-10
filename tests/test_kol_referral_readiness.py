import copy,hashlib,inspect,json,unittest
from pathlib import Path
from jsonschema import Draft202012Validator
import flop_agent.kol_referral_readiness as kol

def canon(value):return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")
class KOLReferralReadinessTests(unittest.TestCase):
 def setUp(self):
  self.baseline=Path("data/flop_kol_program_baseline.json").read_bytes();self.source_hash="a"*64;self.rules_hash="b"*64;self.link_hash="c"*64
  self.program={"source_class":"FLOP_LABS_OFFICIAL","source_id":"official-kol-source","source_document_sha256":self.source_hash,"program_id":"kol-program","announcement_version":"announcement-v1","rules_version":"rules-v1","rules_sha256":self.rules_hash,"details":"PUBLISHED","leaderboard":"PUBLISHED","source_nonce":"1"}
  self.referral={"source_class":"FLOP_LABS_OFFICIAL","source_id":"official-kol-source","source_document_sha256":self.source_hash,"program_id":"kol-program","announcement_version":"announcement-v1","rules_version":"rules-v1","rules_sha256":self.rules_hash,"referrer_sha256":"d"*64,"referral_link_sha256":self.link_hash,"domain_endpoint_sha256":"e"*64,"issued_context_sha256":"f"*64,"issued_at":100,"expires_at":200,"source_nonce":"2"}
  self.authority={"source_class":"FLOP_LABS_OFFICIAL","source_id":"official-kol-source","source_document_sha256":self.source_hash,"program_id":"kol-program","announcement_version":"announcement-v1","rules_version":"rules-v1","rules_sha256":self.rules_hash,"details":"PUBLISHED","leaderboard":"PUBLISHED","referrals":[{k:self.referral[k] for k in kol.AUTH_REF_FIELDS}]}
  self.manifest=canon({"schema":"flop-kol-authorities-v1","authorities":[self.authority]})
 def evidence(self,**changes):
  value={"program_id":"kol-program","rules_sha256":self.rules_hash,"referral_link_sha256":self.link_hash,"wallet_identity_sha256":"1"*64,"wallet_creation_event_sha256":"2"*64,"network_usage_sha256":"3"*64,"event_source_sha256":"4"*64,"event_timestamp_sha256":"5"*64,"evidence_nonce":"3","self_referral_claimed":False};value.update(changes);return value
 def assess(self,programs=None,refs=None,evidence=None,manifest=None,baseline=None):
  return kol._assess(canon([] if programs is None else programs),canon([] if refs is None else refs),canon({} if evidence is None else evidence),self.baseline if baseline is None else baseline,self.manifest if manifest is None else manifest)
 def test_production_empty_manifest_and_baseline_are_fail_closed(self):
  baseline=kol.assess_kol_referral_readiness(b"[]",b"[]",b"{}");self.assertEqual(baseline["program"],"KOL_PROGRAM_ANNOUNCED");self.assertEqual(baseline["program_details"],"KOL_PROGRAM_DETAILS_PENDING");self.assertEqual(baseline["referral"],"REFERRAL_LINK_NOT_ISSUED");self.assertEqual(baseline["leaderboard"],"LEADERBOARD_NOT_PUBLISHED")
  result=kol.assess_kol_referral_readiness(canon([self.program]),canon([self.referral]),b"{}");self.assertEqual(result["errors"],["SOURCE_UNVERIFIED"]);self.assertFalse(result["authorized_to_register"])
 def test_valid_fixture_reaches_human_review_and_evidence_ready_only(self):
  result=self.assess([self.program],[self.referral],self.evidence());self.assertEqual(result["program"],"KOL_PROGRAM_READY_FOR_HUMAN_REVIEW");self.assertEqual(result["referral"],"REFERRAL_LINK_READY_FOR_HUMAN_REVIEW");self.assertEqual(result["leaderboard"],"LEADERBOARD_OFFICIAL_SOURCE_VERIFIED");self.assertEqual(result["attribution"],"ATTRIBUTION_EVIDENCE_READY")
  for field in ("attributed_user_verified","network_usage_verified","rank_verified","reward_verified","lottery_eligibility_verified","agent_airdrop_eligible","authorized_to_register","authorized_to_open_referral","authorized_to_create_wallet","authorized_to_track_user","authorized_to_claim","ready_to_act","authorized_to_act","live_action_enabled"):self.assertFalse(result[field])
  Draft202012Validator(json.loads(Path("schemas/flop-kol-referral-readiness.v1.json").read_text())).validate(result)
 def test_untrusted_official_looking_sources_never_verify(self):
  for source in kol.UNTRUSTED:
   program={**self.program,"source_class":source};result=self.assess([program],manifest=canon({"schema":"flop-kol-authorities-v1","authorities":[]}));self.assertEqual(result["errors"],["SOURCE_UNVERIFIED"])
 def test_source_and_referral_binding_mismatches_fail(self):
  for change in ({"source_document_sha256":"0"*64},{"rules_version":"rules-v2"},{"rules_sha256":"0"*64},{"details":"PENDING"},{"leaderboard":"CANDIDATE"}):self.assertEqual(self.assess([{**self.program,**change}])["errors"],["SOURCE_UNVERIFIED"])
  for change in ({"referral_link_sha256":"0"*64},{"domain_endpoint_sha256":"0"*64},{"referrer_sha256":"0"*64},{"issued_context_sha256":"0"*64},{"expires_at":201}):self.assertEqual(self.assess([self.program],[{**self.referral,**change}])["errors"],["SOURCE_BINDING_MISMATCH"])
 def test_referral_must_bind_to_selected_program_and_exact_issuance(self):
  other_ref={**self.referral,"program_id":"other-program","source_nonce":"4"};other_authority={**self.authority,"program_id":"other-program","referrals":[{k:other_ref[k] for k in kol.AUTH_REF_FIELDS}]};manifest=canon({"schema":"flop-kol-authorities-v1","authorities":[self.authority,other_authority]})
  self.assertEqual(self.assess([self.program],[other_ref],manifest=manifest)["errors"],["SOURCE_BINDING_MISMATCH"])
  later={**self.referral,"issued_at":101,"source_nonce":"5"};authority=copy.deepcopy(self.authority);authority["referrals"].append({k:later[k] for k in kol.AUTH_REF_FIELDS});manifest=canon({"schema":"flop-kol-authorities-v1","authorities":[authority]})
  self.assertEqual(self.assess([self.program],[self.referral,later],manifest=manifest)["errors"],["REFERRAL_CONFLICT"])
 def test_program_and_referral_conflicts_fail_closed(self):
  other={**self.program,"source_id":"official-other","source_document_sha256":"8"*64,"rules_sha256":"9"*64,"source_nonce":"4"};authority={**self.authority,"source_id":"official-other","source_document_sha256":"8"*64,"rules_sha256":"9"*64,"referrals":[]};manifest=canon({"schema":"flop-kol-authorities-v1","authorities":[self.authority,authority]});self.assertEqual(self.assess([self.program,other],manifest=manifest)["errors"],["PROGRAM_CONFLICT"])
  other_ref={**self.referral,"referral_link_sha256":"9"*64,"source_nonce":"5"};authority=copy.deepcopy(self.authority);authority["referrals"].append({k:other_ref[k] for k in kol.AUTH_REF_FIELDS});manifest=canon({"schema":"flop-kol-authorities-v1","authorities":[authority]});self.assertEqual(self.assess([self.program],[self.referral,other_ref],manifest=manifest)["errors"],["REFERRAL_CONFLICT"])
 def test_referral_is_not_attribution_and_missing_evidence_fails(self):
  link=self.assess([self.program],[self.referral]);self.assertEqual(link["attribution"],"ATTRIBUTION_NOT_ESTABLISHED")
  self.assertEqual(self.assess([self.program],[self.referral],self.evidence(wallet_creation_event_sha256=None))["errors"],["WALLET_EVIDENCE_REQUIRED"])
  self.assertEqual(self.assess([self.program],[self.referral],self.evidence(network_usage_sha256=None))["errors"],["NETWORK_USAGE_EVIDENCE_REQUIRED"])
  self.assertEqual(self.assess([self.program],[self.referral],self.evidence(rules_sha256="0"*64))["errors"],["ATTRIBUTION_RULE_MISMATCH"])
 def test_reward_lottery_self_referral_and_agent_airdrop_stay_unresolved(self):
  result=self.assess([self.program],[self.referral],self.evidence(self_referral_claimed=True));self.assertEqual(result["attribution"],"ATTRIBUTION_RULES_UNRESOLVED");self.assertEqual(result["reward_formula"],"UNRESOLVED");self.assertEqual(result["ranking_formula"],"UNRESOLVED");self.assertFalse(result["reward_verified"]);self.assertFalse(result["agent_airdrop_eligible"])
 def test_nonce_replay_bool_float_and_oversized_rejected(self):
  for change in ({"referral_link_sha256":"0"*64},{"announcement_version":"announcement-v2"},{"source_document_sha256":"0"*64}):self.assertEqual(self.assess([self.program],[self.referral,{**self.referral,**change}])["errors"],["REPLAY_CANDIDATE"])
  invalid=(True,False,1.0,9007199254740993,"1e3","0x10","+1"," 1","\N{ARABIC-INDIC DIGIT ONE}","01","1"*20,"1"*1000)
  for nonce in invalid:self.assertEqual(self.assess([{**self.program,"source_nonce":nonce}])["errors"],["ARTIFACT_SCHEMA_INVALID"])
  for nonce in invalid:self.assertEqual(self.assess([self.program],[{**self.referral,"source_nonce":nonce}])["errors"],["ARTIFACT_SCHEMA_INVALID"])
  for nonce in invalid:self.assertEqual(self.assess([self.program],[self.referral],self.evidence(evidence_nonce=nonce))["errors"],["ARTIFACT_SCHEMA_INVALID"])
  for nonce in ("9007199254740991","9007199254740992","9007199254740993","9999999999999999999"):
   self.assertNotEqual(self.assess([{**self.program,"source_nonce":nonce}])["errors"],["ARTIFACT_SCHEMA_INVALID"])
 def test_privacy_closed_inputs_resource_and_reachability(self):
  attacks=({**self.referral,"raw_url":"https://fake.invalid/r?ref=PRIVATE"},{**self.referral,"wallet_address":"PRIVATE"},{**self.referral,"referral_code":"PRIVATE"})
  for attack in attacks:
   result=self.assess([self.program],[attack]);rendered=json.dumps(result);self.assertEqual(result["errors"],["ARTIFACT_SCHEMA_INVALID"]);self.assertNotIn("PRIVATE",rendered);self.assertNotIn("fake.invalid",rendered)
  self.assertEqual(kol._assess(b"[]",b"[]",b"{}",b" "*(kol.MAX_INPUT_BYTES+1),b"{}")["errors"],["INPUT_LIMIT_EXCEEDED"])
  source=inspect.getsource(kol)
  for word in ("urlopen","requests.","socket.","subprocess.","PrivateKey","web3","playwright","selenium"):self.assertNotIn(word,source)
 def test_schema_semantics_pins_and_inventory(self):
  result=self.assess();forged=copy.deepcopy(result);forged["reward_verified"]=True;forged["artifact_id"]=kol._hash(kol._canon({k:v for k,v in forged.items() if k!="artifact_id"}))
  with self.assertRaises(Exception):kol.validate_kol_projection(forged)
  self.assertEqual(hashlib.sha256(self.baseline).hexdigest(),kol.BASELINE_SHA256);self.assertEqual(hashlib.sha256(Path("data/flop_kol_authorities.json").read_bytes()).hexdigest(),kol.AUTHORITIES_SHA256);self.assertEqual(json.loads(Path("data/flop_kol_authorities.json").read_text())["authorities"],[])
  baseline=json.loads(self.baseline);self.assertEqual(baseline["program"]["details"],"PENDING");self.assertEqual(baseline["leaderboard"]["publication"],"NOT_PUBLISHED_CONFIRMED");self.assertEqual(baseline["policy"]["flop_help_metric"],"UNRESOLVED")
  index=json.loads(Path("schemas/index.json").read_text());self.assertIn("schemas/flop-kol-referral-readiness.v1.json",{x["path"] for x in index["schemas"]});compat=json.loads(Path("data/technocore_compatibility.json").read_text())["flop_kol_referral_readiness"];self.assertEqual(compat["authority_manifest"],"EMPTY_FAIL_CLOSED")
if __name__=="__main__":unittest.main()
