#!/usr/bin/env python3
from pathlib import Path
from flop_agent.identity import create_identity

root = Path(__file__).resolve().parents[1]
print(create_identity(root / "secrets/agent_identity.json"))
