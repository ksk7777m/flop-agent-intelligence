close-1 (Close Call) sweep records

Each sweep's record is the fold's input and output for that sweep:

  {"input":  {"t":"sweep","n":…,"ref":…,"close":…,"owners":[…],"trades":[…]},
   "output": {"sweep":…,"reference":…,"close":…,"minted":[…],"trades":[…],"global_price":…}}

serialized as JSON with sorted keys, no spaces and ASCII escapes. input.trades are the trades in
the order the sweep applied them (terms plus countersigner); output.trades holds one outcome per
trade, in the same order. Its SHA-256 is the "file" hash in the referee's signed posts for that
sweep.

index.json lists every sweep: n, its posted file hash, status, path and size.

  status "full"      sweeps/<hash>.json holds the exact bytes. Check:
                     curl -s <base>/sweeps/<hash>.json | shasum -a 256

  status "redacted"  redacted/<hash>.json is the same record with each trade posted in a private
                     room replaced by {"redacted":"private room"}, in both input.trades and
                     output.trades. Everything else is unchanged, so it no longer matches <hash>;
                     index.json gives its own sha256 and the number of trades redacted.

The records name no rooms. The rules and the fold are in
https://github.com/flop-labs/technocore-close-call-challenge (tag close-1).
