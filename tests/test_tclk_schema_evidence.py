import copy
import hashlib
import inspect
import json
import tempfile
import unittest
from pathlib import Path

import jsonschema

from flop_agent import tclk_schema_evidence as evidence


class TclkSchemaEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.value = json.loads(Path("data/tclk_official_schema_evidence.json").read_text())
        self.schema = json.loads(Path("schemas/tclk-official-schema-evidence.v1.json").read_text())

    def test_checked_in_artifact_matches_offline_loader_and_schema(self):
        jsonschema.Draft202012Validator.check_schema(self.schema)
        jsonschema.Draft202012Validator(self.schema).validate(self.value)
        self.assertEqual(dict(evidence.load_pinned_evidence()), self.value)
        evidence.validate_evidence(self.value)

    def test_repository_commit_path_blob_hash_and_size_are_exact(self):
        source = self.value["source_identity"]; snapshot = self.value["snapshot_identity"]
        self.assertEqual((source["owner"], source["name"]), ("flop-labs", "tclk"))
        self.assertRegex(source["commit_sha"], r"^[0-9a-f]{40}$")
        self.assertEqual(snapshot["source_path"], "schema/tclk1-frames.schema.json")
        self.assertRegex(snapshot["blob_sha1"], r"^[0-9a-f]{40}$")
        raw = evidence.SNAPSHOT.read_bytes()
        self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()),
                         (snapshot["byte_length"], snapshot["content_sha256"]))
        self.assertEqual(evidence._git_blob_id(raw), snapshot["blob_sha1"])
        for path, blob, digest, size in (
            (evidence.LICENSE, evidence.LICENSE_BLOB, evidence.LICENSE_SHA256, evidence.LICENSE_SIZE),
            (evidence.SPEC, evidence.SPEC_BLOB, evidence.SPEC_SHA256, evidence.SPEC_SIZE),
            (evidence.FRAMES, evidence.FRAMES_BLOB, evidence.FRAMES_SHA256, evidence.FRAMES_SIZE),
            (evidence.VECTORS, evidence.VECTORS_BLOB, evidence.VECTORS_SHA256, evidence.VECTORS_SIZE)):
            raw=path.read_bytes()
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest(), evidence._git_blob_id(raw)),
                             (size, digest, blob))

    def test_acquisition_is_fixed_bounded_get_only_and_commit_pinned(self):
        item = self.value["acquisition_evidence"]
        self.assertEqual(item["method"], "GET"); self.assertEqual(item["accept_encoding"], "identity")
        self.assertEqual(item["mutable_main_resolution_gets"], 1)
        self.assertTrue(item["all_content_gets_commit_pinned"])
        self.assertEqual(item["automatic_retry_count"], 0)
        self.assertTrue(item["manual_reexecution_occurred"])
        self.assertEqual(item["acquisition_policy_conformance"], "ACQUISITION_POLICY_DEVIATION_RECORDED")
        self.assertEqual(item["acquisition_audit"], "ACQUISITION_AUDIT_INCOMPLETE")
        self.assertTrue(item["no_further_fetch_allowed"])
        for field in ("redirects_allowed", "fallback_enabled", "credentials_used", "raw_error_material_retained"):
            self.assertFalse(item[field])
        for field in ("bounded_response", "content_type_validated", "content_length_validated", "duplicate_headers_rejected"):
            self.assertTrue(item[field])
        self.assertEqual(item["api_gets"] + item["raw_gets"], item["acquisition_attempt_count"])
        self.assertEqual(sum(x["attempts"] for x in item["resource_attempts"]), 26)
        attempts={x["source_id"]:x["attempts"] for x in item["resource_attempts"]}
        self.assertEqual((attempts["SCHEMA_METADATA"], attempts["SCHEMA_RAW"]), (2, 2))

    def test_accept_semantics_are_extracted_from_snapshot(self):
        semantics = self.value["schema_semantics"]
        self.assertEqual(semantics["required_fields_source_order"], ["type", "from", "ref", "statement", "contract", "nonce"])
        self.assertEqual(semantics["required_field_set"], ["contract", "from", "nonce", "ref", "statement", "type"])
        self.assertTrue(semantics["contract_required"])
        self.assertEqual(semantics["contract_type"], "STRING_HEX32")
        self.assertEqual(semantics["additional_properties"], "REJECTED")
        self.assertEqual(semantics["reference_completeness"], "COMPLETE_LOCAL_SAME_DOCUMENT")
        self.assertTrue(all(ref.startswith("#/$defs/") for ref in semantics["references"]))

    def test_duplicate_json_unknown_keyword_remote_and_missing_ref_fail(self):
        raw = evidence.SNAPSHOT.read_bytes()
        with self.assertRaisesRegex(evidence.SchemaEvidenceError, "DUPLICATE_JSON_KEY"):
            evidence._extract(b'{"$schema":1,"$schema":2}')
        for mutate in (lambda x: x.update({"unknown": True}),
                       lambda x: x["$defs"]["accept"]["properties"]["contract"].update({"$ref": "https://example.invalid/schema"}),
                       lambda x: x["$defs"]["accept"]["properties"]["contract"].update({"$ref": "#/$defs/missing"})):
            value = json.loads(raw); mutate(value)
            with self.assertRaises(evidence.SchemaEvidenceError):
                evidence._extract(json.dumps(value).encode())

    def test_required_order_contract_and_expectation_drift_fail(self):
        raw = json.loads(evidence.SNAPSHOT.read_text())
        variants=[]
        value=copy.deepcopy(raw); value["$defs"]["accept"]["required"].remove("contract"); variants.append(value)
        value=copy.deepcopy(raw); value["$defs"]["accept"]["additionalProperties"]=True; variants.append(value)
        value=copy.deepcopy(raw); value["$defs"]["accept"]["properties"]["contract"]={"type":"string"}; variants.append(value)
        value=copy.deepcopy(raw); value["$defs"]["hex32"]["unknownKeyword"]=True; variants.append(value)
        for value in variants:
            with self.assertRaisesRegex(evidence.SchemaEvidenceError, "SCHEMA_EXPECTATION_MISMATCH"):
                evidence._extract(json.dumps(value).encode())
        reordered=copy.deepcopy(raw); reordered["$defs"]["accept"]["required"].reverse()
        extracted=evidence._extract(json.dumps(reordered).encode())
        self.assertEqual(extracted["required_field_set"], ["contract", "from", "nonce", "ref", "statement", "type"])
        self.assertEqual(extracted["required_fields_source_order"], list(reversed(["type", "from", "ref", "statement", "contract", "nonce"])))

    def test_private_fixed_reader_rejects_missing_modified_symlink_and_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); missing=root/"missing"
            with self.assertRaisesRegex(evidence.SchemaEvidenceError, "SNAPSHOT_READ_FAILED"):
                evidence._read_fixed(missing, "0"*40, "0"*64, 1, "fixture")
            modified=root/"modified"; modified.write_bytes(b"x")
            with self.assertRaisesRegex(evidence.SchemaEvidenceError, "SNAPSHOT_HASH_MISMATCH"):
                evidence._read_fixed(modified, evidence._git_blob_id(b"x"), "0"*64, 1, "fixture")
            link=root/"link"; link.symlink_to(modified)
            with self.assertRaisesRegex(evidence.SchemaEvidenceError, "SNAPSHOT_FILE_INVALID"):
                evidence._read_fixed(link, "0"*40, "0"*64, 1, "fixture")
            large=root/"large"; large.write_bytes(b"x"*(evidence.MAX_SCHEMA_BYTES+1))
            with self.assertRaisesRegex(evidence.SchemaEvidenceError, "SNAPSHOT_SIZE_MISMATCH"):
                evidence._read_fixed(large, "0"*40, "0"*64, evidence.MAX_SCHEMA_BYTES+1, "fixture")

    def test_hash_length_and_identity_mutations_fail_closed(self):
        mutations = [
            ("source_identity", "commit_sha"), ("snapshot_identity", "source_path"),
            ("snapshot_identity", "blob_sha1"), ("snapshot_identity", "content_sha256"),
            ("snapshot_identity", "byte_length"), ("snapshot_identity", "retention"),
            ("snapshot_identity", "license"), ("schema_semantics", "required_field_set"),
            ("schema_semantics", "contract_required"), ("schema_semantics", "reference_completeness"),
            ("derivation_evidence", "status")]
        for outer, inner in mutations:
            value=copy.deepcopy(self.value)
            value[outer][inner] = list(reversed(value[outer][inner])) if isinstance(value[outer][inner], list) else "CHANGED"
            with self.assertRaises(evidence.SchemaEvidenceError): evidence.validate_evidence(value)
            with self.assertRaises(jsonschema.ValidationError): jsonschema.Draft202012Validator(self.schema).validate(value)
        value=copy.deepcopy(self.value); value["acquisition_evidence"]["api_gets"]=True
        body={key:value[key] for key in evidence.FIELDS if key != "artifact_id"}
        value["artifact_id"]=evidence._digest({"domain":evidence.DOMAIN,"schema":evidence.SCHEMA,
            "canonical_encoding":evidence.CANONICAL_ENCODING,**body})
        with self.assertRaisesRegex(evidence.SchemaEvidenceError, "EVIDENCE_CONTRADICTION"):
            evidence.validate_evidence(value)

    def test_license_derivation_issue_and_local_profile_boundaries(self):
        self.assertEqual(self.value["snapshot_identity"]["license"], "APACHE_2_0_LICENSE_FILE_OBSERVED")
        self.assertEqual(self.value["snapshot_identity"]["redistribution_basis"], "REDISTRIBUTION_BASIS_RECORDED")
        self.assertEqual(self.value["derivation_evidence"]["status"], "CONTRACT_DERIVATION_SPEC_PINNED")
        self.assertFalse(self.value["derivation_evidence"]["implementation_in_scope"])
        self.assertEqual(self.value["issue_142_evidence"]["canonical_object_type"], "ISSUE")
        self.assertEqual(self.value["issue_142_evidence"]["maintainer_ratification"], "NOT_CONFIRMED")
        self.assertEqual(self.value["issue_142_evidence"]["observed_at"], "OBSERVATION_TIMESTAMP_NOT_RETAINED")
        self.assertFalse(self.value["issue_142_evidence"]["current_state"])
        self.assertEqual(self.value["local_profile_comparison"]["comparison"], "SPEC_DRIFT")
        self.assertEqual(self.value["local_profile_comparison"]["missing_locally_enforced_fields"], ["from", "nonce", "ref", "statement"])
        self.assertEqual(self.value["local_profile_comparison"]["additional_properties_comparison"], "BOTH_REJECT")
        self.assertFalse(self.value["local_profile_comparison"]["automatic_migration"])

    def test_derivation_golden_vector_recomputes_offline(self):
        offer={"amount":"1000000","asset":"FLOP","claimByMs":1756703600000,
            "expiresMs":1756700600000,"from":"did:key:z6Mk"+"f"*44,
            "id":"0xd001fbbf4fa36d9ab8ea88df02a8b3303539e9d59f7ff9d9bfeb679318e9ce75",
            "job":{"context":"ctx-1","id":"task-3f","proto":"a2a"},"lock":"hash",
            "nonce":"9f2c81d04c9e1f7a","rails":["flop-htlc","x402"],
            "refundAfterMs":1756707200000,"role":"payer","type":"offer"}
        accept={"from":"did:key:z6Mk"+"g"*44,"ref":offer["id"],
            "statement":"0x"+"ab"*32,"nonce":"0011223344556677"}
        payload=json.dumps({"offer":offer,"accept":accept},sort_keys=True,separators=(",",":"),ensure_ascii=True)
        actual="0x"+hashlib.sha256(("FLOP::tclk::v1|contract|"+payload).encode()).hexdigest()
        self.assertEqual(actual,"0x2768bf32b455317879796093ff2e5882371cbec238611ca71f555a7fcbe58e1c")
        self.assertEqual(self.value["derivation_evidence"]["algorithm"]["golden_vector_consistency"], "OFFLINE_RECOMPUTED_MATCH")

    def test_derivation_sources_agree_on_domain_canonicalization_and_vector(self):
        spec=evidence.SPEC.read_text(); frames=evidence.FRAMES.read_text(); vectors=evidence.VECTORS.read_text()
        self.assertIn("FLOP::tclk::v1|contract|<canonical {offer, accept-core}>", spec)
        self.assertIn('TCLK_DOMAIN = "FLOP::tclk::v1"', frames)
        self.assertIn('domainHash("contract", canonicalJson({ offer, accept }))', frames)
        self.assertIn("Object.keys(record)", frames); self.assertIn(".sort()", frames)
        self.assertIn('padStart(4, "0")', frames)
        self.assertIn("0x2768bf32b455317879796093ff2e5882371cbec238611ca71f555a7fcbe58e1c", vectors)
        self.assertNotIn("SPDX-License-Identifier", evidence.SNAPSHOT.read_text())

    def test_module_dependencies_are_sealed_and_no_public_fetch_api_exists(self):
        for name in ("SNAPSHOT", "SCHEMA_SHA256", "SPEC", "FRAMES", "VECTORS", "_read_fixed", "load_pinned_evidence"):
            with self.assertRaisesRegex(AttributeError, "dependencies are sealed"):
                setattr(evidence, name, object())
        for name in ("fetch", "download", "update", "migrate", "post", "sign", "execute", "poll"):
            self.assertFalse(hasattr(evidence, name))
        self.assertEqual(set(evidence.__all__), {"SchemaEvidenceError", "load_pinned_evidence", "validate_evidence"})

    def test_public_privacy_and_action_isolation(self):
        encoded=json.dumps(self.value).lower()
        for forbidden in ('"raw_schema"','"body"','"comment"','"username"','"token"',
                          '"authorization"','"cookie"','"header"','"error_body"',
                          '"absolute_path"','"url"','"metadata"'):
            self.assertNotIn(forbidden, encoded)
        self.assertEqual(self.value["action_state"], {"mode":"NO_LIVE_ACTION",
            "ready_to_act":False,"authorized_to_act":False,"live_action_enabled":False,
            "compatibility":"COMPATIBILITY_REVIEW_REQUIRED"})
        source=inspect.getsource(evidence).lower()
        for forbidden in ("urllib", "requests", "httpx", "socket", "subprocess", "mcp", "wallet", "--confirm"):
            self.assertNotIn(forbidden, source)

    def test_errors_do_not_echo_remote_or_local_values(self):
        marker="sensitive-remote-marker"
        value=copy.deepcopy(self.value); value["source_identity"]=marker
        with self.assertRaises(evidence.SchemaEvidenceError) as raised: evidence.validate_evidence(value)
        self.assertNotIn(marker, repr(raised.exception)); self.assertIsNone(raised.exception.__cause__)


if __name__ == "__main__": unittest.main()
