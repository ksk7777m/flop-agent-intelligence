import base64, copy, hashlib, inspect, json, unittest
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
        self.context = canon({"source_type":"DIRECT_EXPORT","source_id":"reviewed-export-1","generation":"gen-7","acquisition_mode":"OFFLINE_IMPORT","acquired_at":100})
        self.manifest = canon({"schema":"tclk-source-authorities-v1","policy_revision":att.POLICY,"authorities":[{"authority_id":"fixture-authority","authority_version":"1","policy_id":att.POLICY,"key_id":"fixture-key","public_key_b64url":b64(self.key.public_key().public_bytes_raw()),"allowed_source_types":["DIRECT_EXPORT"]}]})

    def artifact(self, **changes):
        value={"version":att.ARTIFACT_VERSION,"authority_id":"fixture-authority","authority_version":"1","policy_id":att.POLICY,"key_id":"fixture-key","source_type":"DIRECT_EXPORT","source_binding_sha256":hashlib.sha256(self.descriptor).hexdigest(),"generation":"gen-7","acquired_at":100,"issued_at":90,"expires_at":200,"evidence_sha256":hashlib.sha256(self.evidence).hexdigest(),"context_sha256":hashlib.sha256(self.context).hexdigest(),"attestation_nonce":"17"}
        value.update(changes); value["signature"]=b64(self.key.sign(att.DOMAIN+canon(value))); return canon(value)

    def verify(self, artifact=None, replay=b"[]", manifest=None, now=150, evidence=None, descriptor=None, context=None):
        return att._verify(self.evidence if evidence is None else evidence, self.descriptor if descriptor is None else descriptor, self.context if context is None else context, self.artifact() if artifact is None else artifact, replay, self.manifest if manifest is None else manifest, now)

    def test_valid_signature_exact_digests_generation_policy_and_nonce(self):
        result=self.verify(); self.assertEqual(result["source_attestation"],"SOURCE_ATTESTATION_VERIFIED"); self.assertEqual(result["source_authenticity"],"AUTHENTICATED_SOURCE"); self.assertEqual(result["replay"],"UNSEEN_IN_PROVIDED_LEDGER"); self.assertEqual([x["state"] for x in result["stages"]],["VERIFIED"]*9)
        Draft202012Validator(json.loads(Path("schemas/tclk-source-attestation.v1.json").read_text())).validate(result)

    def test_unknown_wrong_key_bad_signature_and_forged_labels(self):
        unknown=self.artifact(authority_id="trusted-by-caller"); self.assertEqual(self.verify(unknown)["errors"],["SOURCE_ATTESTATION_UNKNOWN_AUTHORITY"])
        other=Ed25519PrivateKey.generate(); wrong=canon({"schema":"tclk-source-authorities-v1","policy_revision":att.POLICY,"authorities":[{"authority_id":"fixture-authority","authority_version":"1","policy_id":att.POLICY,"key_id":"fixture-key","public_key_b64url":b64(other.public_key().public_bytes_raw()),"allowed_source_types":["DIRECT_EXPORT"]}]})
        self.assertEqual(self.verify(manifest=wrong)["errors"],["SOURCE_ATTESTATION_SIGNATURE_INVALID"])
        value=json.loads(self.artifact()); value["signature"]="A"*86; self.assertEqual(self.verify(canon(value))["errors"],["SOURCE_ATTESTATION_SIGNATURE_INVALID"])
        self.assertEqual(att.verify_source_attestation(self.evidence,self.descriptor,self.context,self.artifact(),b"[]")["errors"],["SOURCE_ATTESTATION_UNKNOWN_AUTHORITY"])

    def test_exact_byte_digest_and_context_mismatches(self):
        self.assertEqual(self.verify(evidence=self.evidence+b" ")["errors"],["SOURCE_ATTESTATION_DIGEST_MISMATCH"])
        self.assertEqual(self.verify(context=self.context+b" ")["errors"],["SOURCE_ATTESTATION_DIGEST_MISMATCH"])
        other=canon({"source_type":"DIRECT_EXPORT","source_id":"reviewed-export-2","generation":"gen-7"})
        self.assertEqual(self.verify(descriptor=other)["errors"],["SOURCE_ATTESTATION_DIGEST_MISMATCH"])

    def test_generation_source_policy_expiry_and_duplicate(self):
        changed=canon({"source_type":"DIRECT_EXPORT","source_id":"reviewed-export-1","generation":"gen-8"})
        a=self.artifact(source_binding_sha256=hashlib.sha256(changed).hexdigest())
        self.assertEqual(self.verify(a,descriptor=changed)["errors"],["SOURCE_ATTESTATION_GENERATION_MISMATCH"])
        self.assertEqual(self.verify(now=201)["errors"],["SOURCE_ATTESTATION_EXPIRED"])
        valid=self.verify(); replay=canon([valid["attestation_replay_id"]]); duplicate=self.verify(replay=replay); self.assertEqual(duplicate["errors"],["SOURCE_ATTESTATION_DUPLICATE"]); self.assertEqual(duplicate["replay"],"DUPLICATE_REJECTED")
        artifact=self.artifact(source_type="MCP_PAGE"); self.assertEqual(self.verify(artifact)["errors"],["SOURCE_ATTESTATION_POLICY_MISMATCH"])

    def test_closed_canonical_grammar_bool_float_unknown_and_manifest(self):
        for field,value in (("attestation_nonce",True),("attestation_nonce",1.0),("acquired_at",True),("expires_at",200.0)):
            self.assertEqual(self.verify(self.artifact(**{field:value}))["errors"],["SOURCE_ATTESTATION_CANONICAL_INVALID"])
        value=json.loads(self.artifact()); value["extra"]={"raw":"secret-marker"}; raw=canon(value); result=self.verify(raw); self.assertEqual(result["errors"],["SOURCE_ATTESTATION_SCHEMA_INVALID"]); self.assertNotIn("secret-marker",json.dumps(result))
        self.assertEqual(self.verify(manifest=canon({"schema":"bad","policy_revision":att.POLICY,"authorities":[]}))["errors"],["SOURCE_AUTHORITY_MANIFEST_INVALID"])
        self.assertEqual(self.verify(replay=canon([True]))["errors"],["SOURCE_ATTESTATION_REPLAY_INVALID"])

    def test_verified_provenance_never_escalates_offer_wide_boundaries(self):
        result=self.verify(); self.assertEqual(result["source_completeness"],"COMPLETENESS_NOT_ESTABLISHED"); self.assertEqual(result["winner"],"GLOBAL_WINNER_UNRESOLVED"); self.assertEqual(result["race_loss"],"NOT_ISSUED"); self.assertEqual(result["lock"],"NOT_VERIFIED"); self.assertEqual(result["settlement"],"NOT_VERIFIED"); self.assertFalse(result["ready_to_act"]); self.assertFalse(result["authorized_to_act"]); self.assertFalse(result["live_action_enabled"])

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
