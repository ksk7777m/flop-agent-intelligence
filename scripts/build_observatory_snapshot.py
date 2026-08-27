#!/usr/bin/env python3
"""Build reviewed static Observatory JSON from already-fetched official JSON."""

import argparse
import json
from pathlib import Path

from flop_agent.observatory import build_snapshot


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rooms-input", type=Path, required=True)
    parser.add_argument("--lobby-input", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--fetched-at", required=True)
    parser.add_argument("--spec-version")
    args = parser.parse_args()
    raw = json.loads(args.rooms_input.read_text(encoding="utf-8"))
    lobby = json.loads(args.lobby_input.read_text(encoding="utf-8")) if args.lobby_input else None
    snapshots = build_snapshot(raw, fetched_at=args.fetched_at, lobby_metadata=lobby, spec_version=args.spec_version)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, payload in snapshots.items():
        (args.output_dir / f"{name}.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
