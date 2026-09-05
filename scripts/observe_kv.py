#!/usr/bin/env python3
"""Poll the explicit KV allowlist once and emit privacy-safe static JSON."""

import json

from flop_agent.kv_observatory import (
    observe_production_kv,
)


def main() -> None:
    result = observe_production_kv()
    print(json.dumps(result, indent=2))
    if result["failed"] or result["rate_limited"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
