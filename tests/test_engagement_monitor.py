import io, json, math, tempfile, threading, unittest
from unittest import mock
from email.message import Message
from pathlib import Path
from urllib.error import HTTPError

from flop_agent.engagement import SOURCE_URL, build_sample, diff, room_status, series
from flop_agent.engagement_history import HistoryCorruption, append, latest, load, validate
from scripts.collect_engagement import CollectionError, MAX_RESPONSE_BYTES, backoff, fetch, interval_minutes, validate_endpoint
import jsonschema


class Response:
    status = 200
    headers = Message()
    def __init__(self, body=b'{}', url=SOURCE_URL): self.body, self.url = body, url
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, size=-1): return self.body if size < 0 else self.body[:size]
    def geturl(self): return self.url


class EngagementMonitorTests(unittest.TestCase):
    def sample(self, when="2026-08-29T00:00:00Z"):
        return build_sample({"rooms":[{"room":"a","window":0}],"engagement":{}}, fetched_at=when,
                            source_sha256="0"*64, collector_version="test")

    def test_fixed_get_endpoint_redirect_and_cross_origin(self):
        self.assertEqual(validate_endpoint(SOURCE_URL), SOURCE_URL)
        for url in (
            "https://example.test/", "https://technocore.chat/r/a", "https://technocore.chat/kv/a",
            "https://technocore.chat/rooms?limit=200&format=json",
            "https://technocore.chat/rooms?format=json&limit=200&limit=200",
            "https://technocore.chat/rooms?format=%6ason&limit=200",
            SOURCE_URL + "#fragment", "https://technocore.chat:443/rooms?format=json&limit=200",
            "https://TECHNOCORE.chat/rooms?format=json&limit=200",
            "https://technocore.chat/rooms/?format=json&limit=200",
            "http://technocore.chat/rooms?format=json&limit=200",
        ):
            with self.assertRaises(ValueError): validate_endpoint(url)
        seen = {}
        def ok(req, timeout): seen.update(method=req.method, timeout=timeout); return Response()
        fetch(opener=ok); self.assertEqual(seen["method"], "GET")
        with self.assertRaises(CollectionError): fetch(opener=lambda req, timeout: Response(url="https://example.test/"))
        with self.assertRaises(CollectionError): fetch(opener=lambda req, timeout: Response(url="https://technocore.chat/rooms?format=json"))

    def test_success_body_size_is_bounded_by_header_and_actual_read(self):
        headers=Message(); headers["Content-Length"]=str(MAX_RESPONSE_BYTES + 1)
        response=Response(b"{}"); response.headers=headers
        with self.assertRaises(CollectionError) as caught:
            fetch(opener=lambda req, timeout: response)
        self.assertEqual(caught.exception.code,"RESPONSE_TOO_LARGE")
        oversized=Response(b"x" * (MAX_RESPONSE_BYTES + 1))
        with self.assertRaises(CollectionError) as caught:
            fetch(opener=lambda req, timeout: oversized)
        self.assertEqual(caught.exception.code,"RESPONSE_TOO_LARGE")

    def test_http_failures_no_body_read_and_no_retry(self):
        headers=Message(); headers["Retry-After"]="37"
        def limited(req, timeout): raise HTTPError(SOURCE_URL,429,"",headers,io.BytesIO(b"secret-error-body"))
        with self.assertRaises(CollectionError) as caught: fetch(opener=limited)
        self.assertEqual(caught.exception.retry_after,37)
        self.assertIsNone(backoff(429,retry_header="tomorrow")); self.assertEqual(backoff(503,99),21600)
        with self.assertRaises(TimeoutError): fetch(opener=lambda req, timeout: (_ for _ in ()).throw(TimeoutError()))

    def test_interval_and_normalization(self):
        self.assertEqual(interval_minutes("15"),15)
        with self.assertRaises(ValueError): interval_minutes("4")
        row=self.sample(); self.assertEqual(row["per_room"][0]["status"],"INSUFFICIENT_WINDOW")
        self.assertIsNone(row["per_room"][0]["generation"]); self.assertEqual(room_status(20),"OBSERVED")
        self.assertNotIn("topic",json.dumps(row)); self.assertNotIn("raw",json.dumps(row))
        self.assertEqual(row["source_evidence_level"],"OFFICIAL_PUBLIC_ENDPOINT")
        self.assertEqual(row["derived_evidence_level"],"LOCAL_DERIVED")

    def test_optional_nulls_and_invalid_source_numerics(self):
        row=build_sample({"rooms":[{"room":"a"}],"engagement":{"zero_response_share":None}},
                         fetched_at="2026-08-29T00:00:00Z",source_sha256="0"*64,collector_version="test")
        for field in ("rooms_total","notes_total","notes_capacity"):
            self.assertIsNone(row[field])
        for field in ("first_seq","generation"):
            self.assertIsNone(row["per_room"][0][field])
        invalid = [
            {"total":-1}, {"engagement":{"zero_response_share":1.1}},
            {"engagement":{"nick_diversity":-0.1}}, {"engagement":{"windowed_messages":1.5}},
            {"rooms":[{"room":"a","last_seq":"1"}]}, {"rooms":[{"room":"a","window":math.nan}]},
            {"rooms":[{"room":"a","idle_seconds":math.inf}]},
        ]
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                build_sample(raw,fetched_at="2026-08-29T00:00:00Z",source_sha256="0"*64,collector_version="test")

    def test_history_dedupe_restart_order_invalid_partial(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"history.jsonl"; self.assertEqual(load(path),[])
            old=self.sample(); new=self.sample("2026-08-29T01:00:00Z")
            self.assertTrue(append(path,new)); self.assertTrue(append(path,old)); self.assertFalse(append(path,old))
            self.assertEqual(latest(load(path))["fetched_at"],new["fetched_at"])
            with path.open("a") as handle: handle.write('{"partial":')
            self.assertEqual(len(load(path)),2)
            self.assertTrue(append(path,self.sample("2026-08-29T02:00:00Z")))
            self.assertTrue(path.with_suffix(".jsonl.recovery-tail").exists())
            self.assertEqual(len(load(path)),3)

    def test_middle_history_corruption_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"history.jsonl"
            append(path,self.sample())
            with path.open("a") as handle: handle.write('{"bad":true}\n')
            append_payload=json.dumps(self.sample("2026-08-29T01:00:00Z"))+"\n"
            with path.open("a") as handle: handle.write(append_payload)
            with self.assertRaises(HistoryCorruption): load(path)

    def test_concurrent_duplicate_is_appended_once(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"history.jsonl"; results=[]
            barrier=threading.Barrier(2)
            def worker():
                barrier.wait(); results.append(append(path,self.sample()))
            threads=[threading.Thread(target=worker) for _ in range(2)]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            self.assertEqual(sorted(results),[False,True]); self.assertEqual(len(load(path)),1)

    def test_short_writes_are_completed_and_invalid_sample_is_not_appended(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"history.jsonl"; original_write=__import__("os").write
            def short_write(descriptor, data):
                return original_write(descriptor, data[:max(1, min(7, len(data)))])
            with mock.patch("flop_agent.engagement_history.os.write",side_effect=short_write):
                self.assertTrue(append(path,self.sample()))
            self.assertEqual(len(load(path)),1)
            bad=dict(self.sample("2026-08-29T01:00:00Z")); bad["unexpected"]=True
            with self.assertRaises(ValueError): append(path,bad)
            self.assertEqual(len(load(path)),1)

    def test_diff_and_conservative_interpretation(self):
        old=self.sample(); new=self.sample("2026-08-29T01:00:00Z")
        old["per_room"][0]["room"]="old"; new["per_room"][0]["room"]="new"
        result=diff(old,new); self.assertEqual(result["new_rooms"],["new"])
        self.assertEqual(result["not_observed_in_latest_snapshot"],["old"])
        encoded=json.dumps(series([old,new])); self.assertIn("NO_PERSISTENT_CHANGE_ESTABLISHED",encoded)
        for prohibited in ("SPAM","BOT","DEAD","SYBIL","AIR_DROP_SCORE","REWARD_SCORE"):
            self.assertNotIn(prohibited,encoded)
        same_old=self.sample(); same_new=self.sample("2026-08-29T01:00:00Z")
        same_new["per_room"][0]["window"]=20
        changed=diff(same_old,same_new)["changed_rooms"][0]
        self.assertEqual(changed["changed_fields"],[])
        self.assertEqual(changed["observation_context"],"OBSERVATION_CONTEXT_CHANGED")

    def test_strict_schema_and_negative_cases(self):
        root=Path(__file__).resolve().parents[1]
        schema=json.loads((root/"schemas/engagement-sample.v1.json").read_text())
        sample=self.sample(); jsonschema.Draft202012Validator(schema).validate(sample)
        bad=dict(sample); bad["raw_body"]="forbidden"
        with self.assertRaises(jsonschema.ValidationError): jsonschema.Draft202012Validator(schema).validate(bad)
        with self.assertRaises(ValueError): validate(bad)
        bad=dict(sample); bad["source_sha256"]="no"
        with self.assertRaises(jsonschema.ValidationError): jsonschema.Draft202012Validator(schema).validate(bad)

    def test_public_api_schemas_and_capabilities_are_strict(self):
        root=Path(__file__).resolve().parents[1]
        family=json.loads((root/"schemas/engagement-api.v1.json").read_text())
        for name, definition in (("engagement-status","status"),("engagement-diff","diff"),("engagement-series","series")):
            payload=json.loads((root/f"api/{name}.json").read_text())
            jsonschema.Draft202012Validator(family).validate(payload)
            bad=dict(payload); bad["unexpected"]=True
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.Draft202012Validator(family).validate(bad)
        capabilities=json.loads((root/"api/capabilities.json").read_text())
        cap_schema=json.loads((root/"schemas/capabilities.v1.json").read_text())
        jsonschema.Draft202012Validator(cap_schema).validate(capabilities)
        self.assertEqual(capabilities["scheduler"],"DISABLED")
        self.assertEqual(capabilities["drift_implementation"],"NOT_IMPLEMENTED")
        self.assertFalse(capabilities["live_write_enabled"])

    def test_no_engagement_scheduler_or_auto_start(self):
        root=Path(__file__).resolve().parents[1]
        workflows="\n".join(path.read_text() for path in (root/".github/workflows").glob("*.y*ml"))
        self.assertNotIn("collect_engagement",workflows)
        readme=(root/"README.md").read_text().lower()
        self.assertIn("scheduling disabled",readme)
        self.assertIn("no scheduler is installed or activated",readme)
    def test_dashboard_is_independently_loaded_and_inert(self):
        root=Path(__file__).resolve().parents[1]
        js=(root/"dashboard.js").read_text(); html=(root/"index.html").read_text()
        self.assertIn("ENGAGEMENT DATA UNAVAILABLE",js)
        self.assertIn("loadPresenceData().then",js); self.assertIn("loadKvData().then",js)
        self.assertIn("textContent",js); self.assertNotIn("innerHTML",js)
        self.assertIn("NO REVIEWED ENGAGEMENT HISTORY YET",html)
        self.assertIn("malformed Engagement API",js)
        self.assertNotIn("<canvas",html.lower())


if __name__ == "__main__": unittest.main()
