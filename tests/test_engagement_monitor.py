import io, json, tempfile, unittest
from email.message import Message
from pathlib import Path
from urllib.error import HTTPError

from flop_agent.engagement import SOURCE_URL, build_sample, diff, room_status, series
from flop_agent.engagement_history import append, latest, load
from scripts.collect_engagement import CollectionError, backoff, fetch, interval_minutes, validate_endpoint
import jsonschema


class Response:
    status = 200
    headers = Message()
    def __init__(self, body=b'{}', url=SOURCE_URL): self.body, self.url = body, url
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self): return self.body
    def geturl(self): return self.url


class EngagementMonitorTests(unittest.TestCase):
    def sample(self, when="2026-08-29T00:00:00Z"):
        return build_sample({"rooms":[{"room":"a","window":0}],"engagement":{}}, fetched_at=when,
                            source_sha256="0"*64, collector_version="test")

    def test_fixed_get_endpoint_redirect_and_cross_origin(self):
        self.assertEqual(validate_endpoint(SOURCE_URL), SOURCE_URL)
        for url in ("https://example.test/", "https://technocore.chat/r/a", "https://technocore.chat/kv/a"):
            with self.assertRaises(ValueError): validate_endpoint(url)
        seen = {}
        def ok(req, timeout): seen.update(method=req.method, timeout=timeout); return Response()
        fetch(opener=ok); self.assertEqual(seen["method"], "GET")
        with self.assertRaises(CollectionError): fetch(opener=lambda req, timeout: Response(url="https://example.test/"))

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

    def test_history_dedupe_restart_order_invalid_partial(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"history.jsonl"; self.assertEqual(load(path),[])
            old=self.sample(); new=self.sample("2026-08-29T01:00:00Z")
            self.assertTrue(append(path,new)); self.assertTrue(append(path,old)); self.assertFalse(append(path,old))
            self.assertEqual(latest(load(path))["fetched_at"],new["fetched_at"])
            with path.open("a") as handle: handle.write('{"partial":')
            with self.assertRaises(ValueError): load(path)
            self.assertEqual(len(load(path,strict=False)),2)

    def test_diff_and_conservative_interpretation(self):
        old=self.sample(); new=self.sample("2026-08-29T01:00:00Z")
        old["per_room"][0]["room"]="old"; new["per_room"][0]["room"]="new"
        result=diff(old,new); self.assertEqual(result["new_rooms"],["new"])
        self.assertEqual(result["not_observed_in_latest_snapshot"],["old"])
        encoded=json.dumps(series([old,new])); self.assertIn("NO_PERSISTENT_CHANGE_ESTABLISHED",encoded)
        for prohibited in ("SPAM","BOT","DEAD","SYBIL","AIR_DROP_SCORE","REWARD_SCORE"):
            self.assertNotIn(prohibited,encoded)

    def test_strict_schema_and_negative_cases(self):
        root=Path(__file__).resolve().parents[1]
        schema=json.loads((root/"schemas/engagement-sample.v1.json").read_text())
        sample=self.sample(); jsonschema.Draft202012Validator(schema).validate(sample)
        bad=dict(sample); bad["raw_body"]="forbidden"
        with self.assertRaises(jsonschema.ValidationError): jsonschema.Draft202012Validator(schema).validate(bad)
        bad=dict(sample); bad["source_sha256"]="no"
        with self.assertRaises(jsonschema.ValidationError): jsonschema.Draft202012Validator(schema).validate(bad)

    def test_dashboard_is_independently_loaded_and_inert(self):
        root=Path(__file__).resolve().parents[1]
        js=(root/"dashboard.js").read_text(); html=(root/"index.html").read_text()
        self.assertIn("ENGAGEMENT DATA UNAVAILABLE",js)
        self.assertIn("loadPresenceData().then",js); self.assertIn("loadKvData().then",js)
        self.assertIn("textContent",js); self.assertNotIn("innerHTML",js)
        self.assertIn("NO REVIEWED ENGAGEMENT HISTORY YET",html)


if __name__ == "__main__": unittest.main()
