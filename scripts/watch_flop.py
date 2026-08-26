#!/usr/bin/env python3
import json
from flop_agent.watcher import dry_run

print(json.dumps({"dry_run": True, "results": dry_run()}, indent=2))

