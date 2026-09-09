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

    def test_acquisition_is_fixed_bounded_get_only_and_commit_pinned(self):
        item = self.value["acquisition_evidence"]
        self.assertEqual(item["method"], "GET"); self.assertEqual(item["accept_encoding"], "identity")
        self.assertEqual(item["mutable_main_resolution_gets"], 1)
        self.assertTrue(item["all_content_gets_commit_pinned"])
        for field in ("redirects_allowed", "retry_mechanism", "fallback_enabled", "credentials_used", "raw_error_material_retained"):
            self.assertFalse(item[field])
        for field in ("bounded_response", "content_type_validated", "content_length_validated", "duplicate_headers_rejected"):
            self.assertTrue(item[field])
        self.assertEqual(item["api_gets"] + item["raw_gets"], item["total_gets"])

    def test_accept_semantics_are_extracted_from_snapshot(self):
        semantics = self.value["schema_semantics"]
        self.assertEqual(semantics["required_fields"], ["type", "from", "ref", "statement", "contract", "nonce"])
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
        value=copy.deepcopy(raw); value["$defs"]["accept"]["required"].reverse(); variants.append(value)
        value=copy.deepcopy(raw); value["$defs"]["accept"]["required"].remove("contract"); variants.append(value)
        value=copy.deepcopy(raw); value["$defs"]["accept"]["additionalProperties"]=True; variants.append(value)
        value=copy.deepcopy(raw); value["$defs"]["accept"]["properties"]["contract"]={"type":"string"}; variants.append(value)
        value=copy.deepcopy(raw); value["$defs"]["hex32"]["unknownKeyword"]=True; variants.append(value)
        for value in variants:
            with self.assertRaisesRegex(evidence.SchemaEvidenceError, "SCHEMA_EXPECTATION_MISMATCH"):
                evidence._extract(json.dumps(value).encode())

    def test_private_fixed_reader_rejects_missing_modified_symlink_and_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); missing=root/"missing"
            with self.assertRaisesRegex(evidence.SchemaEvidenceError, "SNAPSHOT_READ_FAILED"):
                evidence._read_fixed(missing, "0"*64, 1, "fixture")
            modified=root/"modified"; modified.write_bytes(b"x")
            with self.assertRaisesRegex(evidence.SchemaEvidenceError, "SNAPSHOT_HASH_MISMATCH"):
                evidence._read_fixed(modified, "0"*64, 1, "fixture")
            link=root/"link"; link.symlink_to(modified)
            with self.assertRaisesRegex(evidence.SchemaEvidenceError, "SNAPSHOT_FILE_INVALID"):
                evidence._read_fixed(link, "0"*64, 1, "fixture")
            large=root/"large"; large.write_bytes(b"x"*(evidence.MAX_SCHEMA_BYTES+1))
            with self.assertRaisesRegex(evidence.SchemaEvidenceError, "SNAPSHOT_SIZE_MISMATCH"):
                evidence._read_fixed(large, "0"*64, evidence.MAX_SCHEMA_BYTES+1, "fixture")

    def test_hash_length_and_identity_mutations_fail_closed(self):
        mutations = [
            ("source_identity", "commit_sha"), ("snapshot_identity", "source_path"),
            ("snapshot_identity", "blob_sha1"), ("snapshot_identity", "content_sha256"),
            ("snapshot_identity", "byte_length"), ("snapshot_identity", "retention"),
            ("snapshot_identity", "license"), ("schema_semantics", "required_fields"),
            ("schema_semantics", "contract_required"), ("schema_semantics", "reference_completeness"),
            ("derivation_evidence", "status")]
        for outer, inner in mutations:
            value=copy.deepcopy(self.value)
            value[outer][inner] = list(reversed(value[outer][inner])) if isinstance(value[outer][inner], list) else "CHANGED"
            with self.assertRaises(evidence.SchemaEvidenceError): evidence.validate_evidence(value)
            with self.assertRaises(jsonschema.ValidationError): jsonschema.Draft202012Validator(self.schema).validate(value)

    def test_license_derivation_issue_and_local_profile_boundaries(self):
        self.assertEqual(self.value["snapshot_identity"]["license"], "APACHE_2_0_OBSERVED")
        self.assertEqual(self.value["derivation_evidence"]["status"], "CONTRACT_DERIVATION_SPEC_PINNED")
        self.assertFalse(self.value["derivation_evidence"]["implementation_in_scope"])
        self.assertEqual(self.value["issue_142_evidence"]["canonical_object_type"], "ISSUE")
        self.assertEqual(self.value["issue_142_evidence"]["maintainer_ratification"], "NOT_CONFIRMED")
        self.assertEqual(self.value["local_profile_comparison"]["comparison"], "SPEC_DRIFT")
        self.assertFalse(self.value["local_profile_comparison"]["automatic_migration"])

    def test_module_dependencies_are_sealed_and_no_public_fetch_api_exists(self):
        for name in ("SNAPSHOT", "SCHEMA_SHA256", "_read_fixed", "load_pinned_evidence"):
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
