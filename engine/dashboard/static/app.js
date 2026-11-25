// Analyst Lab dashboard: plain JavaScript over the JSON API (engine/dashboard/app.py).
// A React front end can replace this file later; the API stays the same.
"use strict";

const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const api = async (path, opts) => {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(`${path}: ${r.status} ${(await r.text()).slice(0, 200)}`);
  return r.json();
};

// tabs ------------------------------------------------------------------------------------------
function show(tab) {
  document.querySelectorAll("nav button").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.id === `tab-${tab}`));
  if (tab === "scenarios") loadScenarios();
  if (tab === "investigation" && cy) cy.resize();
}
document.querySelectorAll("nav button").forEach((b) => b.addEventListener("click", () => show(b.dataset.tab)));

// alerts ----------------------------------------------------------------------------------------
async function loadAlerts() {
  const level = $("#min-level").value;   // empty until /api/config arrived: then the server's frozen floor applies
  const rows = await api(level ? `/api/alerts?min_level=${encodeURIComponent(level)}` : "/api/alerts");
  $("#alert-count").textContent = rows.length ? `(${rows.length})` : "";
  $("#alerts-empty").hidden = rows.length > 0;
  $("#alerts tbody").innerHTML = rows.map((a) =>
    `<tr class="click" data-id="${esc(a.id)}"><td>${esc(a.time)}</td><td class="level ${esc(a.level)}">${esc(a.level)}</td>` +
    `<td><strong>${esc(a.title)}</strong><br><span class="muted">${esc(a.reason)}</span></td><td>${esc(a.host)}</td><td>${esc(a.source)}</td></tr>`).join("");
  document.querySelectorAll("#alerts tr.click").forEach((tr) => tr.addEventListener("click", () => investigate(tr.dataset.id)));
}
$("#min-level").addEventListener("change", loadAlerts);

// investigation ---------------------------------------------------------------------------------
let cy = null;
const COLORS = { fact: "#1f6f43", hypothesis: "#b54708", gap: "#7a2e8f" };
// keys = the graph's node kinds (engine/graph.py: process, file, endpoint, dns, port)
const SHAPES = { process: "round-rectangle", file: "rectangle", endpoint: "diamond", dns: "hexagon", port: "triangle", autostart: "star" };

async function investigate(id) {
  show("investigation");
  $("#inv-head").textContent = "Loading...";
  const inv = await api(`/api/alerts/${encodeURIComponent(id)}`);
  const a = inv.alert;
  $("#inv-head").innerHTML = `<strong>${esc(a.title)}</strong> · <span class="level ${esc(a.level)}">${esc(a.level)}</span> · ${esc(a.time)} · ${esc(a.host)}` +
    ` · <a href="/api/alerts/${encodeURIComponent(id)}/report" target="_blank">Open report</a><br><span class="muted">${esc(inv.report.summary)}</span>` +
    (inv.warnings || []).map((w) => `<br><strong class="warning">Warning: ${esc(w)}</strong>`).join("");
  const elements = [
    ...inv.nodes.map((n) => ({ data: { id: n.id, label: n.label, kind: n.kind, gaps: n.gaps.join(", "), seed: n.seed ? 1 : 0, hub: n.hub ? 1 : 0, hop: n.hop ? 1 : 0 } })),
    ...inv.edges.map((e) => ({ data: { id: e.id, source: e.source, target: e.target, grade: e.grade, band: e.band || "",
                                       sentence: e.sentence, time: e.time, evidence: e.evidence } })),
  ];
  if (cy) cy.destroy();
  cy = cytoscape({
    container: $("#graph"), elements, wheelSensitivity: 0.3,
    layout: { name: "cose", animate: false, nodeRepulsion: () => 9000, idealEdgeLength: () => 70, randomize: false, fit: true, padding: 20 },
    style: [
      { selector: "node", style: { label: "data(label)", "font-size": 9, "text-wrap": "wrap", "text-max-width": 90,
                                    "background-color": "#dfe6f5", shape: (el) => SHAPES[el.data("kind")] || "ellipse", width: 26, height: 26 } },
      { selector: "node[gaps != '']", style: { "border-width": 2, "border-style": "dotted", "border-color": COLORS.gap } },
      { selector: "node[hop = 1]", style: { "border-width": 2, "border-style": "dashed", "border-color": COLORS.hypothesis } },
      { selector: "node[hub = 1]", style: { "border-width": 3, "border-style": "double", "border-color": "#667085", opacity: 0.75 } },
      { selector: "node[seed = 1]", style: { "background-color": "#ffd8a8", "border-width": 2, "border-color": "#b54708" } },
      { selector: "edge", style: { width: 2, "curve-style": "bezier", "target-arrow-shape": "triangle", "line-color": COLORS.fact, "target-arrow-color": COLORS.fact } },
      { selector: "edge[grade = 'hypothesis']", style: { "line-style": "dashed", "line-color": COLORS.hypothesis, "target-arrow-color": COLORS.hypothesis, label: "data(band)", "font-size": 8 } },
      { selector: ":selected", style: { "line-color": "#2f5bd3", "target-arrow-color": "#2f5bd3", "background-color": "#9db4ef" } },
    ],
  });
  cy.on("tap", "edge", (ev) => showEvidence(ev.target.data()));
  cy.on("tap", "node", (ev) => showNode(ev.target.data(), inv));
  $("#timeline tbody").innerHTML = inv.report.timeline.map((t) =>
    `<tr><td>${esc(t.time)}</td><td>${esc(t.text)}</td><td class="muted">${esc(t.grade)}</td></tr>`).join("");
}

async function showEvidence(d) {
  const box = $("#evidence");
  box.innerHTML = `<p><strong>${esc(d.sentence)}</strong><br><span class="muted">${esc(d.grade)}${d.band ? " · " + esc(d.band) : ""} · ${esc(d.time)}</span></p>`;
  for (const key of d.evidence || []) {
    try {
      const row = await api(`/api/events/${encodeURIComponent(key)}`);
      box.insertAdjacentHTML("beforeend", `<pre>${esc(JSON.stringify(row, null, 1))}</pre>`);
    } catch (e) { box.insertAdjacentHTML("beforeend", `<pre>${esc(e.message)}</pre>`); }
  }
}

function showNode(d, inv) {
  const lines = inv.edges.filter((e) => e.source === d.id || e.target === d.id).map((e) => `<li>${esc(e.sentence)}</li>`).join("");
  $("#evidence").innerHTML = `<p><strong>${esc(d.label)}</strong> <span class="muted">(${esc(d.kind)})</span></p>` +
    (d.gaps ? `<p class="muted">gaps: ${esc(d.gaps)}</p>` : "") +
    (d.hub ? `<p class="muted">hub: a common program that starts many different programs; shown but not followed further</p>` : "") +
    `<ul>${lines}</ul>`;
}

// scenarios -------------------------------------------------------------------------------------
async function loadScenarios() {
  const rows = await api("/api/scenarios");
  $("#scenarios tbody").innerHTML = rows.map((s) =>
    `<tr><td>${esc(s.id.toUpperCase())}</td><td>${esc(s.title)}</td><td>${esc(s.last_result || "-")} <span class="muted">${esc(s.last_run || "")}</span></td>` +
    `<td><button class="run" data-id="${esc(s.id)}">Run in VM</button></td></tr>`).join("");
  document.querySelectorAll("button.run").forEach((b) => b.addEventListener("click", async () => {
    try { renderRun(await api(`/api/scenarios/${encodeURIComponent(b.dataset.id)}/run`, { method: "POST" })); }
    catch (e) { $("#run").textContent = e.message; }
  }));
  renderRun(await api("/api/run"));
}
function renderRun(s) {
  if (!s.scenario) return;
  const state = s.running ? "running" : `finished (exit ${s.exit_code})`;
  $("#run").textContent = `${s.scenario.toUpperCase()}: ${state}\n\n${s.log_tail.join("\n")}`;
}
setInterval(async () => { if ($("#tab-scenarios").classList.contains("active")) renderRun(await api("/api/run")); }, 5000);

// live updates ----------------------------------------------------------------------------------
async function init() {
  try {                                          // the level list and the frozen default come from the server
    const cfg = await api("/api/config");
    $("#min-level").innerHTML = cfg.levels.map((l) =>
      `<option${l === cfg.min_level ? " selected" : ""}>${esc(l)}</option>`).join("");
  } catch (e) { console.error(e); }              // without it the server's own default still applies
  await loadAlerts();
  const events = new EventSource("/api/stream");
  events.onmessage = () => loadAlerts();
}
init();
