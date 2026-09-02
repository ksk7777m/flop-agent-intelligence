"""Fail when public publication surfaces expose unsafe capabilities or data."""

from __future__ import annotations

import json
import plistlib
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
MAX_TRACKED_TEXT_BYTES = 1024 * 1024
MAX_JSONL_RECORDS = 256
OVERSIZED_SAMPLE_BYTES = 256 * 1024


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
    parts={"site-packages","python-wheelhouse","wheelhouse","wheel-house","wheels","pip-cache","pip_cache",
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
    if path.name.endswith(".plist.template"): return False
    try: value=plistlib.loads(text.encode())
    except (ValueError,plistlib.InvalidFileException): return False
    if not isinstance(value,dict): return False
    arguments=value.get("ProgramArguments",[])
    return (value.get("Label")=="com.flop-agent-intelligence.engagement-scheduler"
            and isinstance(arguments,list) and bool(scan_text("\n".join(
                item for item in arguments if isinstance(item,str)))))


def is_structured_private_artifact(name: str,text: str) -> bool:
    """Recognize strong runtime structures without banning generic documentation."""
    path=Path(name); values=[]
    try: values=[json.loads(text)]
    except json.JSONDecodeError:
        for line in text.splitlines()[:MAX_JSONL_RECORDS]:
            if not line.strip(): continue
            try: values.append(json.loads(line))
            except json.JSONDecodeError: continue
    for value in values:
        if not isinstance(value,dict): continue
        keys=set(value)
        if (value.get("schema")=="engagement-production-runtime-v1"
                or {"interpreter_realpath","project_revision","dependency_lock_sha256",
                    "wheels","readiness"} <= keys
                or keys=={"timestamp","stage","error_class","approved_revision","runtime_version"}):
            return True
        if ({"schema","scheduler_enabled","circuit_state","attempts_24h",
             "run_in_progress","normal_interval_minutes"} <= keys):
            return True
        public_prefix=path.parts[0] if path.parts else ""
        if (public_prefix not in {*PUBLIC_DIRS,"api","schemas","examples"}
                and {"collector_version","git_revision","source_sha256","per_room","fetched_at"} <= keys):
            return True
    return is_generated_private_plist(name,text)


def bounded_text(path: Path) -> str | None:
    """Read only bounded UTF-8 text; never decode or parse binary/oversized data."""
    try:
        metadata=path.stat()
        if metadata.st_size>MAX_TRACKED_TEXT_BYTES: return None
        data=path.read_bytes()
    except OSError: return None
    if b"\0" in data: return None
    try: text=data.decode("utf-8")
    except UnicodeDecodeError: return None
    controls=sum(byte<32 and byte not in {9,10,13} for byte in data)
    return None if data and controls/max(1,len(data))>.01 else text


def oversized_text_sample(path: Path) -> str | None:
    """Return a bounded prefix/suffix sample only for oversized text-like files."""
    try:
        size=path.stat().st_size
        if size<=MAX_TRACKED_TEXT_BYTES: return None
        with path.open("rb") as stream:
            prefix=stream.read(OVERSIZED_SAMPLE_BYTES)
            stream.seek(max(0,size-OVERSIZED_SAMPLE_BYTES)); suffix=stream.read(OVERSIZED_SAMPLE_BYTES)
    except OSError: return None
    data=prefix+b"\n"+suffix
    if b"\0" in data: return None
    try: text=data.decode("utf-8")
    except UnicodeDecodeError: return None
    controls=sum(byte<32 and byte not in {9,10,13} for byte in data)
    return None if controls/max(1,len(data))>.01 else text


def required_bounded_text(path: Path) -> str:
    text=bounded_text(path)
    if text is None: raise ValueError(f"unreadable or oversized required public text: {path}")
    return text


def tracked_artifact_reason(name: str,path: Path) -> str | None:
    if is_private_runtime_artifact(name): return "private runtime artifact is tracked"
    text=bounded_text(path)
    if text is not None and is_structured_private_artifact(name,text):
        return "structured private runtime artifact is tracked"
    oversized=oversized_text_sample(path)
    if oversized is not None:
        return ("oversized structured private runtime artifact is tracked"
                if is_structured_private_artifact(name,oversized)
                else "oversized unapproved tracked text requires explicit review")
    return None


def scan() -> list[str]:
    findings: list[str] = []
    files = public_files()
    tracked = subprocess.run(["git","ls-files","-z"],cwd=ROOT,capture_output=True,
                             check=True).stdout.decode("utf-8").split("\0")
    for name in filter(None,tracked):
        path=ROOT/name
        reason=tracked_artifact_reason(name,path)
        if reason is not None: findings.append(f"{name}: {reason}")
    for path in files:
        text = required_bounded_text(path)
        for label in scan_text(text):
            findings.append(f"{path.relative_to(ROOT)}: {label}")
        name = str(path.relative_to(ROOT))
        if is_database_artifact(name):
            findings.append(f"{name}: database artifact in public publication surface")

    openapi = json.loads(required_bounded_text(ROOT / "openapi.json"))
    for route, operations in openapi.get("paths", {}).items():
        unsafe = set(operations) - {"get", "parameters", "summary", "description"}
        if unsafe:
            findings.append(f"openapi.json: non-GET operation at {route}: {sorted(unsafe)}")

    for path in sorted((ROOT / "api").rglob("*.json")):
        payload = json.loads(required_bounded_text(path))

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
        payload = json.loads(required_bounded_text(ROOT / api_name))
        full_schema = json.loads(required_bounded_text(ROOT / schema_name))
        schema = full_schema
        try:
            jsonschema.Draft202012Validator(schema).validate(payload)
        except jsonschema.ValidationError:
            findings.append(f"{api_name}: public schema mismatch")

    workflows = ROOT / ".github/workflows"
    for path in workflows.glob("*.y*ml") if workflows.is_dir() else ():
        text = required_bounded_text(path)
        if "collect_engagement" in text and re.search(r"(?m)^\s*(?:schedule|push|pull_request):", text):
            findings.append(f"{path.relative_to(ROOT)}: active Engagement collection trigger")

    for path in public_files(ROOT):
        if "runtime/engagement" in str(path.relative_to(ROOT)):
            findings.append(f"{path.relative_to(ROOT)}: runtime Engagement history is public")

    for path in (p for p in files if p.suffix == ".json" and "schemas" not in p.parts and "api" not in p.parts):
        try:
            payload = json.loads(required_bounded_text(path))
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

    manifest = json.loads(required_bounded_text(ROOT / "ai-onboarding.json"))
    if manifest.get("mode") != "read-only":
        findings.append("ai-onboarding.json: mode is not read-only")
    return findings


if __name__ == "__main__":
    failures = scan()
    if failures:
        raise SystemExit("Public-safety scan failed:\n- " + "\n- ".join(failures))
    print(f"Public-safety scan passed ({len(public_files())} files, GET-only OpenAPI).")
