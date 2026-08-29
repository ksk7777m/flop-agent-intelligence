#!/usr/bin/env python3
"""Run one fixed-endpoint engagement observation. This is not a scheduler."""

from __future__ import annotations

import argparse, hashlib, json, os, subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from flop_agent.engagement import SOURCE_URL, build_sample, diff, series
from flop_agent.engagement_history import append, load, range_rows

VERSION = "0.1.0"
BACKOFF_SECONDS = (900, 1800, 3600, 7200, 14400, 21600)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None


class CollectionError(RuntimeError):
    def __init__(self, status: int | None, retry_after: int | None = None):
        super().__init__(f"engagement collection failed: HTTP {status or 'NETWORK'}")
        self.status, self.retry_after = status, retry_after


def validate_endpoint(url: str) -> str:
    if url != SOURCE_URL: raise ValueError("engagement source is an exact fixed allowlist entry")
    return url


def interval_minutes(value: str | None = None) -> int:
    try: minutes = int(value if value is not None else os.getenv("ENGAGEMENT_INTERVAL_MIN", "15"))
    except ValueError: raise ValueError("ENGAGEMENT_INTERVAL_MIN must be an integer") from None
    if minutes < 5: raise ValueError("ENGAGEMENT_INTERVAL_MIN must be at least 5")
    return minutes


def retry_after(value: str | None) -> int | None:
    value = value.strip() if isinstance(value, str) else ""
    return int(value) if value.isdigit() and 1 <= int(value) <= 21600 else None


def backoff(status: int, failure_count: int = 1, retry_header: str | None = None) -> int | None:
    if status == 429: return retry_after(retry_header)
    if 500 <= status <= 599: return BACKOFF_SECONDS[min(max(failure_count, 1) - 1, 5)]
    return None


def fetch(*, timeout: float = 20.0, opener=None) -> tuple[bytes, int, object]:
    request = Request(validate_endpoint(SOURCE_URL), method="GET", headers={
        "Accept": "application/json",
        "User-Agent": f"flop-agent-intelligence/{VERSION} (+https://github.com/ksk7777m/flop-agent-intelligence)",
    })
    open_fn = opener or build_opener(NoRedirect()).open
    try:
        with open_fn(request, timeout=timeout) as response:
            if response.geturl() != SOURCE_URL: raise CollectionError(response.status)
            return response.read(), response.status, response.headers
    except HTTPError as error:
        # Deliberately discard every error body and perform no retry.
        raise CollectionError(error.code, backoff(error.code, retry_header=error.headers.get("Retry-After"))) from None


def collect(root: Path, *, timeout: float = 20.0, opener=None,
            fetched_at: str | None = None) -> dict:
    interval_minutes()
    body, status, _headers = fetch(timeout=timeout, opener=opener)
    try: raw = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError): raise ValueError("official endpoint returned invalid JSON") from None
    if not isinstance(raw, dict): raise ValueError("official endpoint returned a non-object")
    fetched_at = fetched_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    try:
        revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                                  capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError): revision = None
    sample = build_sample(raw, fetched_at=fetched_at, source_sha256=hashlib.sha256(body).hexdigest(),
                          collector_version=VERSION, git_revision=revision, content_length=len(body))
    history_path = root / "runtime/engagement/history.jsonl"
    before = load(history_path)
    append(history_path, sample)
    rows = load(history_path)
    output = root / "runtime/engagement/public-preview"; output.mkdir(parents=True, exist_ok=True)
    (output / "engagement-status.json").write_text(json.dumps(sample, indent=2) + "\n", encoding="utf-8")
    (output / "engagement-diff.json").write_text(json.dumps(diff(before[-1] if before else None, sample), indent=2) + "\n", encoding="utf-8")
    stamp = datetime.fromisoformat(fetched_at.replace("Z", "+00:00"))
    (output / "engagement-series.json").write_text(json.dumps(series(range_rows(rows, now=stamp)), indent=2) + "\n", encoding="utf-8")
    return sample


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args(); print(json.dumps(collect(args.root, timeout=args.timeout), indent=2))


if __name__ == "__main__": main()
