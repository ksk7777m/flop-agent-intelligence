"""Fail when public publication surfaces expose unsafe capabilities or data."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
import jsonschema

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_TOP = {
    "README.md", "README.ja.md", "README.zh-CN.md", "AI_ONBOARDING.md",
    "ai-onboarding.json", "llms.txt", "openapi.json", "index.html",
    "dashboard.js", "sitemap.xml",
}
PUBLIC_DIRS = ("docs", "schemas", "api", "examples", "prompts")

FORBIDDEN_PATTERNS = {
    "local filesystem path": re.compile(
        r"(?:file://|/Users/[^/\s]+/|/private/tmp/|/var/folders/|/home/[^/\s]+/|[A-Za-z]:\\Users\\[^\\\s]+\\)",
        re.IGNORECASE,
    ),
    "private Technocore locator": re.compile(
        r"(?<![A-Za-z0-9_])(?:[a-z0-9]+-)*(?:mb-)?p-[a-z0-9][a-z0-9_-]*",
        re.IGNORECASE,
    ),
    "PEM private key": re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"),
    "credential-bearing URL": re.compile(r"https?://[^\s/@:]+:[^\s/@]+@"),
    "Technocore write route": re.compile(
        r"technocore\.chat/(?:say|say-signed|set|set-signed|post|note|claim)(?:/|\b)",
        re.IGNORECASE,
    ),
    "wallet secret material": re.compile(
        r"(?:seed phrase|wallet private key|wallet_secret|private_key|mnemonic)\s*[:=]\s*[\"']?[^\s\"']+",
        re.IGNORECASE,
    ),
}
RAW_FIELDS = {
    "raw_value", "value_raw", "note_value", "response_body",
    "message_body", "raw_body", "content", "body",
}
ALWAYS_RAW_FIELDS = RAW_FIELDS - {"content", "body"}
ENGAGEMENT_RAW_FIELDS = {
    "raw_response", "response_body", "raw_body", "room_message",
    "message_body", "topic", "topic_raw",
}
ENGAGEMENT_SOURCE_URL = "https://technocore.chat/rooms?format=json&limit=200"


def public_files(root: Path = ROOT) -> list[Path]:
    files = [root / name for name in PUBLIC_TOP if (root / name).is_file()]
    for dirname in PUBLIC_DIRS:
        directory = root / dirname
        if directory.is_dir():
            files.extend(path for path in directory.rglob("*") if path.is_file())
    return sorted(set(files))


def scan_text(text: str) -> list[str]:
    return [label for label, pattern in FORBIDDEN_PATTERNS.items() if pattern.search(text)]


def is_database_artifact(name: str) -> bool:
    return re.search(r"\.(?:sqlite3?|db)(?:-(?:wal|shm))?$|-(?:wal|shm)$", name, re.IGNORECASE) is not None


def is_private_runtime_artifact(name: str) -> bool:
    path=Path(name)
    lowered=tuple(part.lower() for part in path.parts); filename=path.name.lower()
    parts={"site-packages","python-wheelhouse","wheelhouse","pip-cache","pip_cache",
           "generations",".venv","venv","production-runtime"}
    names={"production-runtime.json","scheduler-state.json","scheduler-state.lock",
           "history.jsonl","history.jsonl.lock","pyvenv.cfg"}
    runtime_lock=filename.endswith(".lock") and bool({"runtime","engagement","generations"}.intersection(lowered))
    pip_cache=any(lowered[index:index+2]==(".cache","pip") for index in range(len(lowered)-1))
    prelog=filename.startswith("launcher-preflight") and ".jsonl" in filename
    inventory=("wheel" in filename and "inventory" in filename)
    return (path.suffix.lower()==".whl" or bool(parts.intersection(lowered)) or filename in names
            or runtime_lock or pip_cache or prelog or inventory)


def is_generated_private_plist(name: str, text: str) -> bool:
    path=Path(name)
    return (path.suffix.lower()==".plist" and not path.name.endswith(".plist.template")
            and bool(scan_text(text)))


def scan() -> list[str]:
    findings: list[str] = []
    files = public_files()
    tracked = subprocess.run(["git","ls-files","-z"],cwd=ROOT,capture_output=True,
                             check=True).stdout.decode("utf-8").split("\0")
    for name in filter(None,tracked):
        if is_private_runtime_artifact(name):
            findings.append(f"{name}: private runtime artifact is tracked")
        path=ROOT/name
        if path.suffix==".plist" and not path.name.endswith(".plist.template"):
            try: plist_text=path.read_text(encoding="utf-8")
            except (OSError,UnicodeDecodeError):
                findings.append(f"{name}: unreadable generated plist is tracked")
            else:
                if is_generated_private_plist(name,plist_text):
                    findings.append(f"{name}: local generated plist is tracked")
    for path in files:
        text = path.read_text(encoding="utf-8")
        for label in scan_text(text):
            findings.append(f"{path.relative_to(ROOT)}: {label}")
        name = str(path.relative_to(ROOT))
        if is_database_artifact(name):
            findings.append(f"{name}: database artifact in public publication surface")

    openapi = json.loads((ROOT / "openapi.json").read_text(encoding="utf-8"))
    for route, operations in openapi.get("paths", {}).items():
        unsafe = set(operations) - {"get", "parameters", "summary", "description"}
        if unsafe:
            findings.append(f"openapi.json: non-GET operation at {route}: {sorted(unsafe)}")

    for path in sorted((ROOT / "api").rglob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))

        def visit(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key.lower() in RAW_FIELDS:
                        findings.append(
                            f"{path.relative_to(ROOT)}: raw-value-shaped public field {key}"
                        )
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)
            elif (
                path.parent.name == "kv"
                and isinstance(value, str)
                and re.search(r"https?://", value)
                and value != "https://technocore.chat"
            ):
                findings.append(
                    f"{path.relative_to(ROOT)}: note-derived or unexpected URL in public API"
                )

        visit(payload)

        if path.name.startswith("engagement-"):
            def visit_engagement(value):
                if isinstance(value, dict):
                    for key, child in value.items():
                        if key.lower() in ENGAGEMENT_RAW_FIELDS:
                            findings.append(f"{path.relative_to(ROOT)}: forbidden Engagement field {key}")
                        if key == "source_url" and child != ENGAGEMENT_SOURCE_URL:
                            findings.append(f"{path.relative_to(ROOT)}: unapproved Engagement source URL")
                        visit_engagement(child)
                elif isinstance(value, list):
                    for child in value: visit_engagement(child)
            visit_engagement(payload)

    schema_jobs = (
        ("api/engagement-status.json", "schemas/engagement-api.v1.json", "status"),
        ("api/engagement-diff.json", "schemas/engagement-api.v1.json", "diff"),
        ("api/engagement-series.json", "schemas/engagement-api.v1.json", "series"),
        ("api/capabilities.json", "schemas/capabilities.v1.json", None),
    )
    for api_name, schema_name, definition in schema_jobs:
        payload = json.loads((ROOT / api_name).read_text(encoding="utf-8"))
        full_schema = json.loads((ROOT / schema_name).read_text(encoding="utf-8"))
        schema = full_schema
        try:
            jsonschema.Draft202012Validator(schema).validate(payload)
        except jsonschema.ValidationError:
            findings.append(f"{api_name}: public schema mismatch")

    workflows = ROOT / ".github/workflows"
    for path in workflows.glob("*.y*ml") if workflows.is_dir() else ():
        text = path.read_text(encoding="utf-8")
        if "collect_engagement" in text and re.search(r"(?m)^\s*(?:schedule|push|pull_request):", text):
            findings.append(f"{path.relative_to(ROOT)}: active Engagement collection trigger")

    for path in public_files(ROOT):
        if "runtime/engagement" in str(path.relative_to(ROOT)):
            findings.append(f"{path.relative_to(ROOT)}: runtime Engagement history is public")

    for path in (p for p in files if p.suffix == ".json" and "schemas" not in p.parts and "api" not in p.parts):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            findings.append(f"{path.relative_to(ROOT)}: malformed public JSON")
            continue

        def visit_public_json(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key.lower() in ALWAYS_RAW_FIELDS:
                        findings.append(f"{path.relative_to(ROOT)}: raw-content public field {key}")
                    visit_public_json(child)
            elif isinstance(value, list):
                for child in value:
                    visit_public_json(child)

        visit_public_json(payload)

    manifest = json.loads((ROOT / "ai-onboarding.json").read_text(encoding="utf-8"))
    if manifest.get("mode") != "read-only":
        findings.append("ai-onboarding.json: mode is not read-only")
    return findings


if __name__ == "__main__":
    failures = scan()
    if failures:
        raise SystemExit("Public-safety scan failed:\n- " + "\n- ".join(failures))
    print(f"Public-safety scan passed ({len(public_files())} files, GET-only OpenAPI).")
