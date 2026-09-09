import base64, copy, hashlib, inspect, json, unicodedata, unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator
import flop_agent.tclk_source_attestation as att


def canon(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
def b64(value): return base64.urlsafe_b64encode(value).decode().rstrip("=")


class SourceAttestationTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.evidence = b"opaque exact evidence\n"
        self.descriptor = canon({"source_type":"DIRECT_EXPORT","source_id":"reviewed-export-1","generation":"gen-7"})
        self.context = canon({"source_type":"DIRECT_EXPORT","source_id":"reviewed-export-1","generation":"gen-7","acquisition_mode":"OFFLINE_IMPORT","acquired_at":100,"acquisition_scope":"OFFER_WIDE","offer_sha256":"0"*64,"first_seq":1,"high_water_seq":2,"lower_boundary":True,"upper_boundary":True,"truncated":False,"dropped_count":0,"bounded_page":False,"retention_loss":False,"artifact_set_status":"NO_CONFLICTS"})
        self.manifest = canon({"schema":"tclk-source-authorities-v1","policy_revision":att.POLICY,"authorities":[{"authority_id":"fixture-authority","authority_version":"1","policy_id":att.POLICY,"key_id":"fixture-key","public_key_b64url":b64(self.key.public_key().public_bytes_raw()),"allowed_source_types":["DIRECT_EXPORT"],"allowed_source_ids":["reviewed-export-1"]}]})

    def artifact(self, **changes):
        value={"version":att.ARTIFACT_VERSION,"authority_id":"fixture-authority","authority_version":"1","policy_id":att.POLICY,"key_id":"fixture-key","source_type":"DIRECT_EXPORT","source_binding_sha256":hashlib.sha256(self.descriptor).hexdigest(),"generation":"gen-7","acquired_at":100,"issued_at":110,"expires_at":200,"evidence_sha256":hashlib.sha256(self.evidence).hexdigest(),"context_sha256":hashlib.sha256(self.context).hexdigest(),"attestation_nonce":"17"}
        value.update(changes); value["signature"]=b64(self.key.sign(att.DOMAIN+canon(value))); return canon(value)

    def verify(self, artifact=None, replay=b"[]", manifest=None, now=150, evidence=None, descriptor=None, context=None):
        return att._verify(self.evidence if evidence is None else evidence, self.descriptor if descriptor is None else descriptor, self.context if context is None else context, self.artifact() if artifact is None else artifact, replay, self.manifest if manifest is None else manifest, now)

    def test_valid_signature_exact_digests_generation_policy_and_nonce(self):
        result=self.verify(); self.assertEqual(result["source_attestation"],"SOURCE_ATTESTATION_VERIFIED"); self.assertEqual(result["source_authenticity"],"AUTHENTICATED_SOURCE"); self.assertEqual(result["replay"],"UNSEEN_IN_PROVIDED_LEDGER"); self.assertEqual([x["state"] for x in result["stages"]],["VERIFIED"]*9)
        Draft202012Validator(json.loads(Path("schemas/tclk-source-attestation.v1.json").read_text())).validate(result)

    def test_unknown_wrong_key_bad_signature_and_forged_labels(self):
        unknown=self.artifact(authority_id="trusted-by-caller"); self.assertEqual(self.verify(unknown)["errors"],["SOURCE_ATTESTATION_UNKNOWN_AUTHORITY"])
        self.assertEqual(self.verify(self.artifact(authority_version="0"))["errors"],["SOURCE_ATTESTATION_UNKNOWN_AUTHORITY"])
        self.assertEqual(self.verify(self.artifact(key_id="other-key"))["errors"],["SOURCE_ATTESTATION_UNKNOWN_AUTHORITY"])
        self.assertEqual(self.verify(self.artifact(policy_id="older-policy"))["errors"],["SOURCE_ATTESTATION_CANONICAL_INVALID"])
        other=Ed25519PrivateKey.generate(); wrong=canon({"schema":"tclk-source-authorities-v1","policy_revision":att.POLICY,"authorities":[{"authority_id":"fixture-authority","authority_version":"1","policy_id":att.POLICY,"key_id":"fixture-key","public_key_b64url":b64(other.public_key().public_bytes_raw()),"allowed_source_types":["DIRECT_EXPORT"],"allowed_source_ids":["reviewed-export-1"]}]})
        self.assertEqual(self.verify(manifest=wrong)["errors"],["SOURCE_ATTESTATION_SIGNATURE_INVALID"])
        value=json.loads(self.artifact()); value["signature"]="A"*86; self.assertEqual(self.verify(canon(value))["errors"],["SOURCE_ATTESTATION_SIGNATURE_INVALID"])
        self.assertEqual(att.verify_source_attestation(self.evidence,self.descriptor,self.context,self.artifact(),b"[]")["errors"],["SOURCE_ATTESTATION_UNKNOWN_AUTHORITY"])

    def test_exact_byte_digest_and_context_mismatches(self):
        self.assertEqual(self.verify(evidence=self.evidence+b" ")["errors"],["SOURCE_ATTESTATION_DIGEST_MISMATCH"])
        self.assertEqual(self.verify(context=self.context+b" ")["errors"],["SOURCE_ATTESTATION_DIGEST_MISMATCH"])
        other=canon({"source_type":"DIRECT_EXPORT","source_id":"reviewed-export-2","generation":"gen-7"})
        self.assertEqual(self.verify(descriptor=other)["errors"],["SOURCE_ATTESTATION_DIGEST_MISMATCH"])
        reordered=b'{"source_id":"reviewed-export-1","source_type":"DIRECT_EXPORT","generation":"gen-7"}'
        spaced=self.descriptor+b"\n"
        unicode_descriptor=canon({"source_type":"DIRECT_EXPORT","source_id":unicodedata.normalize("NFD","reviewed-export-\N{LATIN SMALL LETTER E WITH ACUTE}"),"generation":"gen-7"})
        for raw in (reordered,spaced,unicode_descriptor): self.assertEqual(self.verify(descriptor=raw)["errors"],["SOURCE_ATTESTATION_DIGEST_MISMATCH"])

    def test_signature_is_bound_before_digest_context_and_generation(self):
        signed=json.loads(self.artifact())
        for field,value in (("context_sha256","0"*64),("evidence_sha256","1"*64),("generation","gen-8")):
            changed=dict(signed); changed[field]=value
            self.assertEqual(self.verify(canon(changed))["errors"],["SOURCE_ATTESTATION_SIGNATURE_INVALID"])

    def test_generation_source_policy_expiry_and_duplicate(self):
        changed=canon({"source_type":"DIRECT_EXPORT","source_id":"reviewed-export-1","generation":"gen-8"})
        a=self.artifact(source_binding_sha256=hashlib.sha256(changed).hexdigest())
        self.assertEqual(self.verify(a,descriptor=changed)["errors"],["SOURCE_ATTESTATION_GENERATION_MISMATCH"])
        self.assertEqual(self.verify(now=201)["errors"],["SOURCE_ATTESTATION_EXPIRED"])
        valid=self.verify(); replay=canon([valid["attestation_replay_id"]]); duplicate=self.verify(replay=replay); self.assertEqual(duplicate["errors"],["SOURCE_ATTESTATION_DUPLICATE"]); self.assertEqual(duplicate["replay"],"DUPLICATE_REJECTED")
        changed_evidence=b"different artifact bytes"
        changed=self.artifact(evidence_sha256=hashlib.sha256(changed_evidence).hexdigest())
        self.assertEqual(self.verify(changed,replay=replay,evidence=changed_evidence)["errors"],["SOURCE_ATTESTATION_DUPLICATE"])
        artifact=self.artifact(source_type="MCP_PAGE"); self.assertEqual(self.verify(artifact)["errors"],["SOURCE_ATTESTATION_POLICY_MISMATCH"])

    def test_closed_canonical_grammar_bool_float_unknown_and_manifest(self):
        for field,value in (("attestation_nonce",True),("attestation_nonce",False),("attestation_nonce",1.0),("acquired_at",True),("expires_at",200.0)):
            self.assertEqual(self.verify(self.artifact(**{field:value}))["errors"],["SOURCE_ATTESTATION_CANONICAL_INVALID"])
        value=json.loads(self.artifact()); value["extra"]={"raw":"secret-marker"}; raw=canon(value); result=self.verify(raw); self.assertEqual(result["errors"],["SOURCE_ATTESTATION_SCHEMA_INVALID"]); self.assertNotIn("secret-marker",json.dumps(result))
        self.assertEqual(self.verify(manifest=canon({"schema":"bad","policy_revision":att.POLICY,"authorities":[]}))["errors"],["SOURCE_AUTHORITY_MANIFEST_INVALID"])
        self.assertEqual(self.verify(replay=canon([True]))["errors"],["SOURCE_ATTESTATION_REPLAY_INVALID"])
        self.assertEqual(self.verify(self.artifact(attestation_nonce="x"*129))["errors"],["SOURCE_ATTESTATION_CANONICAL_INVALID"])
        for changes in ({"acquired_at":120,"issued_at":110},{"issued_at":201,"expires_at":200},{"issued_at":"110"}): self.assertEqual(self.verify(self.artifact(**changes))["errors"],["SOURCE_ATTESTATION_CANONICAL_INVALID"])

    def test_manifest_duplicates_and_pinned_empty_production_manifest(self):
        item=json.loads(self.manifest)["authorities"][0]
        duplicate_authority={**item,"authority_version":"2","key_id":"fixture-key-2"}
        duplicate_key={**item,"authority_id":"fixture-authority-2","authority_version":"2"}
        for second in (duplicate_authority,duplicate_key):
            malformed=canon({"schema":"tclk-source-authorities-v1","policy_revision":att.POLICY,"authorities":[item,second]})
            self.assertEqual(self.verify(manifest=malformed)["errors"],["SOURCE_AUTHORITY_MANIFEST_INVALID"])
        manifest_bytes=Path("data/tclk_source_authorities.json").read_bytes(); self.assertEqual(hashlib.sha256(manifest_bytes).hexdigest(),att.MANIFEST_SHA256); self.assertEqual(json.loads(manifest_bytes)["authorities"],[])
        self.assertEqual(att.verify_source_attestation(self.evidence,self.descriptor,self.context,self.artifact(),b"[]")["source_attestation"],"SOURCE_ATTESTATION_INVALID")

    def test_same_nonce_is_authority_scoped(self):
        first=self.verify(); other=Ed25519PrivateKey.generate()
        second_item={"authority_id":"fixture-authority-2","authority_version":"1","policy_id":att.POLICY,"key_id":"fixture-key-2","public_key_b64url":b64(other.public_key().public_bytes_raw()),"allowed_source_types":["DIRECT_EXPORT"],"allowed_source_ids":["reviewed-export-1"]}
        manifest=canon({"schema":"tclk-source-authorities-v1","policy_revision":att.POLICY,"authorities":[json.loads(self.manifest)["authorities"][0],second_item]})
        value=json.loads(self.artifact()); value.update(authority_id="fixture-authority-2",key_id="fixture-key-2"); value.pop("signature"); value["signature"]=b64(other.sign(att.DOMAIN+canon(value)))
        result=self.verify(canon(value),replay=canon([first["attestation_replay_id"]]),manifest=manifest); self.assertEqual(result["source_attestation"],"SOURCE_ATTESTATION_VERIFIED"); self.assertNotEqual(result["attestation_replay_id"],first["attestation_replay_id"])

    def test_verified_provenance_never_escalates_offer_wide_boundaries(self):
        result=self.verify(); self.assertEqual(result["source_completeness"],"COMPLETENESS_NOT_ESTABLISHED"); self.assertEqual(result["winner"],"GLOBAL_WINNER_UNRESOLVED"); self.assertEqual(result["race_loss"],"NOT_ISSUED"); self.assertEqual(result["lock"],"NOT_VERIFIED"); self.assertEqual(result["settlement"],"NOT_VERIFIED"); self.assertFalse(result["ready_to_act"]); self.assertFalse(result["authorized_to_act"]); self.assertFalse(result["live_action_enabled"])
        for mutation in (lambda x:x.update(source_attestation="SOURCE_ATTESTATION_VERIFIED"),lambda x:x.update(source_authenticity="AUTHENTICATED_SOURCE"),lambda x:x.update(source_completeness="OFFER_WIDE_COMPLETENESS_VERIFIED"),lambda x:x.update(winner="OFFER_GLOBAL_WINNER_VERIFIED")):
            invalid=copy.deepcopy(self.verify(self.artifact(authority_id="unknown"))); mutation(invalid); invalid["artifact_id"]=att._hash(att._canon({k:v for k,v in invalid.items() if k!="artifact_id"}))
            with self.assertRaises(Exception): att._validate_result(invalid)

    def test_privacy_reachability_and_sealed_production_api(self):
        result=self.verify(); rendered=json.dumps(result)
        for secret in (self.evidence.decode().strip(),"reviewed-export-1",json.loads(self.artifact())["signature"],json.loads(self.manifest)["authorities"][0]["public_key_b64url"]): self.assertNotIn(secret,rendered)
        self.assertEqual(att.__all__,["verify_source_attestation"]); self.assertEqual(list(inspect.signature(att.verify_source_attestation).parameters),["evidence_bytes","source_descriptor_bytes","acquisition_context_bytes","attestation_bytes","replay_ledger_bytes"])
        source=inspect.getsource(att)
        for word in ("requests.","urlopen","socket.","subprocess.","PrivateKey","settlement_client","post_signed"): self.assertNotIn(word,source)
        with self.assertRaises(AttributeError): att.POLICY="forged"

    def test_schema_index_compatibility_and_api_inventory(self):
        index=json.loads(Path("schemas/index.json").read_text()); self.assertIn("schemas/tclk-source-attestation.v1.json",{x["path"] for x in index["schemas"]})
        compatibility=json.loads(Path("data/technocore_compatibility.json").read_text()); item=compatibility["tclk_source_attestation"]; self.assertEqual(item["classification"],"SAFE_PURE_VALIDATOR"); self.assertEqual(item["completeness"],"COMPLETENESS_NOT_ESTABLISHED"); self.assertEqual(item["winner"],"GLOBAL_WINNER_UNRESOLVED")
        inventory=Path("docs/TECHNOCORE_SAFETY_FOUNDATION.md").read_text(); self.assertIn("sealed source-attestation verifier",inventory); self.assertIn("`UNSAFE`: **0**",inventory)

if __name__ == "__main__": unittest.main()
