from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .activity import append_activity
from .identity import create_identity, load_identity, sign_message, verify_message
from .registry import contribution_note_plan, did_profile_plan
from .receipt import create_receipt, read_receipt, verify_receipt
from .technocore import healthcheck, post_signed
from .watcher import dry_run

ROOT = Path(__file__).resolve().parents[2]
IDENTITY = ROOT / "secrets" / "agent_identity.json"


def main() -> None:
    parser = argparse.ArgumentParser(prog="flop-agent")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("create-identity")
    commands.add_parser("check-identity")
    commands.add_parser("watch")
    commands.add_parser("status")
    commands.add_parser("readiness-check")
    monitor = commands.add_parser("health-monitor")
    monitor.add_argument("--json", action="store_true")
    monitor.add_argument("--no-save", action="store_true")
    monitor.add_argument("--public", action="store_true", help="Use public evidence only; never require local secrets or receipts")
    testnet = commands.add_parser("testnet-readiness")
    testnet_commands = testnet.add_subparsers(dest="testnet_command", required=True)
    testnet_commands.add_parser("status")
    faucet = testnet_commands.add_parser("faucet")
    faucet.add_argument("--dry-run", action="store_true")
    balance = testnet_commands.add_parser("balance")
    balance.add_argument("--fixture", action="store_true")
    inference = testnet_commands.add_parser("inference")
    inference.add_argument("--fixture", action="store_true")
    testnet_receipt = testnet_commands.add_parser("verify-receipt")
    testnet_receipt.add_argument("file")
    presence = commands.add_parser("presence")
    presence_commands = presence.add_subparsers(dest="presence_command", required=True)
    for name in ("observe", "preview-first-write"):
        presence_action = presence_commands.add_parser(name)
        presence_action.add_argument("--config", required=True)
        presence_action.add_argument("--state", default=str(ROOT / "runtime" / "presence-state.json"))
        if name == "preview-first-write":
            presence_action.add_argument("--application-commit", required=True)
    commands.add_parser("draft-contribution")
    commands.add_parser("gap-audit")
    demo = commands.add_parser("demo-fixture")
    demo.add_argument("fixture", nargs="?", default=str(ROOT / "examples/fixtures/flop_did_tasks.json"))
    create_receipt_cmd = commands.add_parser("create-receipt")
    create_receipt_cmd.add_argument("--repo", required=True)
    create_receipt_cmd.add_argument("--commit", required=True)
    create_receipt_cmd.add_argument("--artifact", required=True)
    create_receipt_cmd.add_argument("--output", required=True)
    create_receipt_cmd.add_argument("--timestamp")
    verify_receipt_cmd = commands.add_parser("verify-receipt")
    verify_receipt_cmd.add_argument("file")
    publish = commands.add_parser("publish")
    publish.add_argument("text")
    publish.add_argument("--room", default="lobby")
    publish.add_argument("--confirm", action="store_true")
    publish.add_argument("--approved-signal")
    publish.add_argument("--contribution")
    publish.add_argument("--repo")
    publish.add_argument("--commit")
    publish.add_argument("--receipt-fingerprint")
    publish.add_argument("--activity-type")
    publish.add_argument("--mailbox")
    publish.add_argument("--note-path")
    publish.add_argument("--note-value")
    publish.add_argument("--note-hash")
    publish.add_argument("--x25519-public-key")
    args = parser.parse_args()

    if args.command == "create-identity":
        print(create_identity(IDENTITY))
    elif args.command == "check-identity":
        key, did = load_identity(IDENTITY)
        sig, clean = sign_message(key, "local-check", 1, "identity verification")
        verify_message(did, sig, "local-check", 1, clean)
        print(json.dumps({"did": did, "verified": True, "permission": "0600"}))
    elif args.command == "watch":
        print(json.dumps({"dry_run": True, "results": dry_run()}, indent=2))
    elif args.command == "status":
        key, did = load_identity(IDENTITY)
        del key
        print(json.dumps({"did": did, "identity": "valid", "publish_default": "dry-run"}, indent=2))
    elif args.command == "readiness-check":
        from .readiness import run_readiness_check

        print(json.dumps(run_readiness_check(ROOT), indent=2))
    elif args.command == "health-monitor":
        from .monitor import exit_code, run_monitor, save_run

        record = run_monitor(ROOT, evidence_mode="public" if args.public else "local")
        if not args.no_save:
            save_run(ROOT, record)
        if args.json:
            print(json.dumps(record, indent=2))
        else:
            checks = record["checks"]
            print(f"OVERALL: {record['overall_status']}\n")
            for key in ("technocore", "did_note", "mailbox", "repo", "dashboard", "official_repo", "capacity_contract", "receipts"):
                print(f"{key.replace('_', ' ').title():<22} {checks[key]['status']}")
            spec_status = "UNCHANGED" if all(v["status"] == "READY" for v in record["official_specs"].values()) else "REVIEW_REQUIRED"
            print(f"{'Official specs':<22} {spec_status}")
            print(f"{'Official signals':<22} {record['official_signals']['detail']}")
            print(f"{'FLOP Teaser':<22} {checks['teaser']['detail']}")
            teaser_signals = checks["teaser"].get("signals", {})
            print(f"{'Testnet':<22} {teaser_signals.get('testnet', 'UNKNOWN')}")
            print(f"{'Faucet':<22} {teaser_signals.get('faucet', 'UNKNOWN')}")
            print(f"{'Inference':<22} {teaser_signals.get('inference', 'UNKNOWN')}")
            print(f"{'DID Tasks':<22} {teaser_signals.get('did_tasks', 'UNKNOWN')}")
            print(f"{'Mailbox Migration':<22} {checks['mailbox_migration']['detail']}")
            print(f"\nWrites performed ...... {record['external_writes_performed']}")
        raise SystemExit(exit_code(record))
    elif args.command == "testnet-readiness":
        from .testnet import (
            BalanceAdapter, FaucetAdapter, InferenceAdapter, LiveActionDisabled,
            current_status, empty_config, inference_request, load_fixture,
            verify_testnet_receipt,
        )

        fixture_root = ROOT / "examples/fixtures/testnet"
        if args.testnet_command == "status":
            print("FLOP TESTNET READINESS\n")
            for label, value in current_status().items():
                print(f"{label:<21} {value}")
        elif args.testnet_command == "faucet":
            if not args.dry_run:
                raise SystemExit(str(LiveActionDisabled("faucet requires --dry-run; live claims are FORBIDDEN_V0")))
            config = load_fixture(fixture_root / "valid_draft_config.json")
            print(json.dumps(FaucetAdapter(config).preview_claim(), indent=2))
        elif args.testnet_command == "balance":
            if not args.fixture:
                raise SystemExit(str(LiveActionDisabled("balance is fixture-only in V0")))
            print(json.dumps(BalanceAdapter().read_fixture({
                "wallet": "0xTEST_WALLET_PLACEHOLDER", "token": "FLOP",
                "balance": "1000", "network": "FLOP_TESTNET_FIXTURE",
            }), indent=2))
        elif args.testnet_command == "inference":
            if not args.fixture:
                raise SystemExit(str(LiveActionDisabled("inference is fixture-only in V0")))
            quote = load_fixture(fixture_root / "valid_inference_quote.json")
            request = inference_request(prompt="fixture prompt")
            adapter = InferenceAdapter(empty_config())
            print(json.dumps({"quote": adapter.quote(request, quote), "preview": adapter.preview(request)}, indent=2))
        elif args.testnet_command == "verify-receipt":
            print(json.dumps(verify_testnet_receipt(load_fixture(Path(args.file))), indent=2))
    elif args.command == "presence":
        from .presence import load_config, observe, preview_first_write
        from .remote_content_policy import LocalActionClass, ReviewedSourceId, reviewed_local_intent
        from .technocore import read_official, read_presence_note

        config = load_config(Path(args.config))
        if args.presence_command == "observe":
            result = observe(config, Path(args.state))
        else:
            def presence_reader(path: str):
                if path == config.note_path:
                    intent = reviewed_local_intent(
                        LocalActionClass.PRESENCE_NOTE_READ, path, "local Presence configuration")
                    return read_presence_note(path, intent=intent)
                sources = {
                    "/.well-known/agent.json": ReviewedSourceId.TECHNOCORE_AGENT_MANIFEST,
                    "/config": ReviewedSourceId.TECHNOCORE_CONFIG,
                    "/rooms?format=json": ReviewedSourceId.TECHNOCORE_ROOMS_JSON,
                }
                if path not in sources:
                    raise PermissionError("Presence requested an unregistered read path")
                return read_official(sources[path])

            result = preview_first_write(
                config, Path(args.state), reader=presence_reader,
                application_commit=args.application_commit,
            )
        print(json.dumps(result, indent=2))
    elif args.command == "draft-contribution":
        print("Built an official-signal monitor for FLOP/Technocore that classifies actionable updates, blocks untrusted wallet/claim instructions, and keeps signed activity logs. Designed to extend into testnet workflows when official APIs are published.")
    elif args.command == "gap-audit":
        _, did = load_identity(IDENTITY)
        print(json.dumps({
            "live_write": False,
            "did_profile": did_profile_plan(did),
            "contribution_note": contribution_note_plan(
                did,
                "FLOP / Technocore Official Signal Monitor",
            ),
            "mailbox": {"decision": "WAIT", "reason": "no official task-delivery use case yet"},
            "x": {"decision": "PREPARE_ONLY", "reason": "no confirmed eligibility requirement"},
        }, indent=2))
    elif args.command == "demo-fixture":
        from .workflow import prepare_signal

        fixture = json.loads(Path(args.fixture).read_text(encoding="utf-8"))
        signal = prepare_signal(**fixture)
        print(json.dumps(signal.as_dict(), indent=2))
    elif args.command == "create-receipt":
        receipt = create_receipt(
            IDENTITY, args.repo, args.commit, args.artifact, timestamp=args.timestamp,
        )
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"created": str(output), **verify_receipt(receipt)}, indent=2))
    elif args.command == "verify-receipt":
        print(json.dumps(verify_receipt(read_receipt(Path(args.file))), indent=2))
    elif args.command == "publish":
        if not args.confirm:
            print(json.dumps({"dry_run": True, "room": args.room, "text": args.text}, indent=2))
            return
        if not args.approved_signal:
            raise SystemExit("live publishing requires --approved-signal <APPROVED-envelope.json>")
        from .workflow import signal_from_dict, validate_publish_approval

        approved = signal_from_dict(json.loads(Path(args.approved_signal).read_text(encoding="utf-8")))
        validate_publish_approval(approved, args.text)
        from .remote_content_policy import HumanApprovalEvidence, LocalActionClass, reviewed_local_intent
        subject = args.room + "\0" + args.text
        approval_evidence = HumanApprovalEvidence(
            approved.approved_by or "", approved.approved_at or "",
            "human-approved CLI publication",
            hashlib.sha256(subject.encode()).hexdigest())
        intent = reviewed_local_intent(
            LocalActionClass.SIGNED_ROOM_POST, subject,
            "human-approved CLI publication", approval=approval_evidence)
        message = post_signed(IDENTITY, args.room, args.text, intent=intent)
        activity_text = str(message.get("swept_text", message["text"]))
        activity_approval = HumanApprovalEvidence(
            approved.approved_by or "", approved.approved_at or "",
            "public hash-only activity evidence",
            hashlib.sha256(activity_text.encode()).hexdigest())
        activity_intent = reviewed_local_intent(
            LocalActionClass.LOCAL_ACTIVITY_RAW, activity_text,
            "public hash-only activity evidence", approval=activity_approval)
        append_activity(
            ROOT / "data/activity.jsonl", ROOT / "docs/ACTIVITY_LOG.md", args.room, message,
            evidence={
                "activity_type": args.activity_type or ("contribution" if args.contribution else "signed_message"),
                "contribution": args.contribution,
                "repository": args.repo,
                "git_commit_hash": args.commit,
                "receipt_fingerprint": args.receipt_fingerprint,
                "approval_status": approved.approval_status,
                "mailbox": args.mailbox,
                "note_path": args.note_path,
                "note_value": args.note_value,
                "note_hash": args.note_hash,
                "x25519_public_key": args.x25519_public_key,
            },
            local_provenance=activity_intent,
        )
        print(json.dumps(message, indent=2))


if __name__ == "__main__":
    main()
