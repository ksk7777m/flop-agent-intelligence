#!/usr/bin/env python3
"""Poll the explicit KV allowlist once and emit privacy-safe static JSON."""

import argparse
import json
from pathlib import Path

from flop_agent.kv_observatory import Observer, Store, current_read_interval, load_config, write_snapshots


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    configs = load_config(args.config)
    store = Store(args.state)
    result = Observer(configs, store, read_interval=current_read_interval()).poll()
    write_snapshots(store, configs, args.output_dir)
    print(json.dumps(result, indent=2))
    if result["failed"] or result["rate_limited"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
