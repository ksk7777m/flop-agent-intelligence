#!/usr/bin/env python3
"""Poll the explicit KV allowlist once and emit privacy-safe static JSON."""

import argparse
import json
from pathlib import Path

from flop_agent.kv_observatory import (
    Store,
    build_production_observer,
    production_configs,
    production_read_interval,
    write_snapshots,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    expected_config = (Path(__file__).resolve().parents[1] / "examples" / "kv-observer.example.json").resolve()
    if args.config.resolve() != expected_config:
        raise SystemExit("production KV observer requires the repository-reviewed config")
    configs = production_configs()
    store = Store(args.state)
    result = build_production_observer(
        store, read_interval=production_read_interval()).poll()
    write_snapshots(store, configs, args.output_dir)
    print(json.dumps(result, indent=2))
    if result["failed"] or result["rate_limited"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
