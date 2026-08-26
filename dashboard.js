const DATA = ["monitor", "readiness", "signals", "health", "evidence", "maintenance"];
const safeStatus = value => String(value || "UNKNOWN").toUpperCase();
const statusClass = value => "status-" + safeStatus(value).toLowerCase().replaceAll(" ", "-").replaceAll("_", "-");
const text = (tag, value, className) => {
  const node = document.createElement(tag);
  node.textContent = value;
  if (className) node.className = className;
  return node;
};

async function loadData() {
  const pairs = await Promise.all(DATA.map(async name => {
    const response = await fetch(`./data/${name}.json`, {cache: "no-store"});
    if (!response.ok) throw new Error(`${name}: HTTP ${response.status}`);
    return [name, await response.json()];
  }));
  return Object.fromEntries(pairs);
}

function renderReadiness(data) {
  document.querySelector("#headline").textContent = data.headline;
  document.querySelector("#generated-at").textContent = `DATASET ${data.generated_at}`;
  const root = document.querySelector("#readiness");
  for (const item of data.items) {
    const card = text("article", "", "card");
    const top = text("div", "", "card-top");
    top.append(text("span", safeStatus(item.status), `badge ${statusClass(item.status)}`), text("span", item.trust, "trust"));
    card.append(top, text("h3", item.label), text("p", item.detail));
    root.append(card);
  }
}

function renderMonitor(data) {
  const root = document.querySelector("#monitor");
  const values = [
    ["Overall", data.overall_status],
    ["Freshness", data.freshness],
    ["Official specs", data.official_spec_drift],
    ["Actionable signals", String(data.new_actionable_signals)],
    ["DID Note", data.did_note_integrity],
    ["Mailbox", data.mailbox_health],
    ["Capacity contract", data.capacity_contract],
    ["Public evidence", data.public_evidence_health],
    ["External writes", String(data.writes_performed)]
  ];
  for (const [label, value] of values) {
    const item = text("div", "", "monitor-item");
    item.append(text("small", label), text("strong", value, statusClass(value)));
    root.append(item);
  }
  document.querySelector("#monitor-detail").textContent =
    `Last verified: ${data.last_checked} · Last fully successful: ${data.last_successful_check || "not established"} · ${data.public_evidence_detail}`;
}

function renderSignals(data) {
  const root = document.querySelector("#signals");
  for (const item of data.signals) {
    const row = text("article", "", "signal");
    const meta = text("div", "", "signal-meta");
    meta.append(text("div", item.timestamp), text("div", `TIER ${item.source_tier} · ${item.verification_status}`), text("div", item.source));
    const body = text("div");
    const link = text("a", item.title);
    link.href = item.url; link.rel = "noopener noreferrer";
    const heading = text("h3"); heading.append(link);
    body.append(heading, text("p", item.summary));
    row.append(meta, body, text("span", item.classification, "classification"));
    root.append(row);
  }
  const reviews = document.querySelector("#review-notes");
  for (const note of data.review_notes || []) reviews.append(text("p", `${note.status} · ${note.source}: ${note.reason}`));
}

function renderHealth(data) {
  const root = document.querySelector("#health");
  for (const item of data.checks) {
    const row = text("div", "", "health-row");
    row.append(text("span", item.label), text("span", safeStatus(item.status), statusClass(item.status)));
    root.append(row);
  }
  document.querySelector("#last-checked").textContent =
    `Last checked: ${data.last_checked} · Last successful: ${data.last_successful} · Next: ${data.next_scheduled_check || "manual"}`;
}

function renderEvidence(data) {
  const labels = {
    artifact: "Artifact", repository: "Repository", original_public_commit: "Original commit",
    receipt_sha256: "Receipt SHA-256", canonical_payload_sha256: "Payload SHA-256",
    technocore_seq: "Technocore seq", technocore_permalink: "Signed record", did: "DID",
    did_note_path: "DID Note", did_note_sha256: "Note SHA-256",
    mailbox_status: "Mailbox", legacy_mailbox_status: "Legacy mailbox",
    legacy_mailbox_historical_seq: "Legacy evidence seq", live_record_status: "Live record",
    historical_evidence_status: "Historical evidence", x25519_public_key: "X25519 public",
    x_explanation: "X explanation"
  };
  const root = document.querySelector("#evidence");
  for (const [key, label] of Object.entries(labels)) {
    const row = text("div");
    const dd = text("dd");
    const value = data[key];
    if (typeof value === "string" && value.startsWith("https://")) {
      const a = text("a", value); a.href = value; a.rel = "noopener noreferrer"; dd.append(a);
    } else dd.textContent = value;
    row.append(text("dt", label), dd); root.append(row);
  }
}

function renderMaintenance(data) {
  const root = document.querySelector("#maintenance");
  for (const item of data.entries) {
    const row = text("article", "", "maintenance-row");
    const copy = text("p", `${item.change} — ${item.reason}`);
    row.append(text("time", item.date), text("strong", item.type.toUpperCase()), copy);
    root.append(row);
  }
}

loadData().then(data => {
  renderMonitor(data.monitor);
  renderReadiness(data.readiness);
  renderSignals(data.signals);
  renderHealth(data.health);
  renderEvidence(data.evidence);
  renderMaintenance(data.maintenance);
}).catch(error => {
  document.querySelector("main").prepend(text("div", `Dashboard data unavailable: ${error.message}`, "error-box"));
  document.querySelector("#headline").textContent = "ERROR · DATA REVIEW REQUIRED";
});
