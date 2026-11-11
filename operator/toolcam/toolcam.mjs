// Tool cam: follows the lab's real /activity log during a live hunt and shows each bot's
// tool call as it happens: Arkime calls in Arkime's own UI with the bot's exact
// expression; Elastic/intel/detection calls as the exact query plus the real rows the lab
// returns for it. Captures timestamped 1920x1080 JPEG frames twice a second.
// Usage: bun operator/toolcam/toolcam.mjs <outDir> <labUrl> <arkimeUrl> <caseId> <startEpoch> <stopEpoch> <activityAfter>
// The headless browser is TOOLCAM_BROWSER (default: Microsoft Edge on Windows, else chromium). Hunt progress comes
// from the Hunt Board on 127.0.0.1:TOOLCAM_BOARD_PORT (default 8790, the board's own default).
import { mkdirSync, writeFileSync, appendFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { pipeline as progress, endSummary } from "./progress.mjs";

const args = process.argv.slice(2);
if (args.length !== 7 || args.includes("--help")) {
  console.error("usage: bun toolcam.mjs <outDir> <labUrl> <arkimeUrl> <caseId> <startEpoch> <stopEpoch> <activityAfter>");
  process.exit(2);
}
const [dir, LAB, ARK, CASE, START, STOP, AFTER] = args;
const outDir = resolve(dir); // the browser does not resolve a relative --user-data-dir against our working directory
const FR = join(outDir, "frames"); mkdirSync(FR, { recursive: true });
const LOG = join(outDir, "events.jsonl");
const log = obj => appendFileSync(LOG, JSON.stringify({ t: Date.now(), ...obj }) + "\n");
const BROWSER = process.env.TOOLCAM_BROWSER || (process.platform === "win32"
  ? "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" : "chromium");
const BOARD_PORT = Number(process.env.TOOLCAM_BOARD_PORT || 8790);
const PORT = 9400 + Math.floor(Math.random() * 400);
const edge = spawn(BROWSER, ["--headless=new", `--remote-debugging-port=${PORT}`, "--remote-debugging-address=127.0.0.1",
  `--user-data-dir=${join(outDir, "edge-profile")}`, "--window-size=1920,1080", "--hide-scrollbars", "--no-first-run",
  "--disable-extensions", "--force-device-scale-factor=1", "about:blank"], { stdio: "ignore" });
edge.on("error", err => { console.error(`cannot start ${BROWSER} (set TOOLCAM_BROWSER): ${err.message}`); process.exit(1); });
const sleep = ms => new Promise(r => setTimeout(r, ms));

let wsUrl;
for (let i = 0; i < 60 && !wsUrl; i++) {
  try { wsUrl = (await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json()).find(t => t.type === "page").webSocketDebuggerUrl; }
  catch { await sleep(500); }
}
if (!wsUrl) { console.error(`${BROWSER} exposed no DevTools page on port ${PORT}`); edge.kill(); process.exit(1); }
const ws = new WebSocket(wsUrl); await new Promise(r => ws.onopen = r);
let id = 0; const pending = new Map();
ws.onmessage = m => { const d = JSON.parse(m.data); if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); } };
const cdp = (method, params = {}) => new Promise(r => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
await cdp("Page.enable"); await cdp("Runtime.enable");
await cdp("Emulation.setDeviceMetricsOverride", { width: 1920, height: 1080, deviceScaleFactor: 1, mobile: false });

const ROLE = {
  "framework-researcher": ["Threat Hunter", "#22c55e"], "framework-network-analyst": ["Network Analyst", "#38bdf8"],
  "framework-librarian": ["Threat Intelligence Analyst", "#f59e0b"], "framework-builder": ["Detection Engineer", "#a78bfa"],
  "framework-reviewer": ["Purple Team Analyst", "#f472b6"], "framework-coordinator": ["Incident Response Lead", "#e5e7eb"],
};
const TOOLNAME = { elastic_search: "Elasticsearch · search", elastic_aggregate: "Elasticsearch · aggregation", detection_test: "Elasticsearch · detection test",
  intel_lookup: "Threat intel feed · lookup", arkime_sessions: "Arkime · sessions", arkime_unique: "Arkime · unique values", hunt_lab_query: "Lab summary query",
  packet_fields: "tshark · saved-capture fields" };
let status = "Starting…";
const esc = s => String(s ?? "").replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
const chrome = (e, body) => {
  const [role, color] = ROLE[e.profile] || [e.profile, "#fff"];
  const q = e.params.expression ?? e.params.q ?? e.params.filter ?? e.params.values ?? "";
  const extra = ["field", "interval", "name", "size", "length", "sort"].filter(k => e.params[k]).map(k => `${k} = ${esc(e.params[k])}`).join(" · ");
  const count = e.error ? `<span style="color:#f87171">lab refused: ${esc(e.error)}</span>` : `${(e.total ?? e.result_count ?? "?").toLocaleString?.() ?? e.total} results`;
  return `<div id="tc-top" style="position:fixed;left:0;right:0;top:0;z-index:2147483647;background:#0b1020ee;color:#fff;font:600 22px system-ui;padding:14px 22px;border-bottom:4px solid ${color}">
    <div style="display:flex;gap:18px;align-items:baseline"><span style="color:${color};font-size:30px">${esc(role)}</span><span style="opacity:.85">drives ${esc(TOOLNAME[e.tool] || e.tool)}</span>
    <span style="margin-left:auto;font-size:26px">${count}</span></div>
    <div style="font:500 24px ui-monospace,Consolas,monospace;margin-top:8px;color:#e2e8f0;white-space:pre-wrap;word-break:break-all">${esc(q || "(all case data)")}</div>
    ${extra ? `<div style="font:400 18px system-ui;opacity:.7;margin-top:4px">${extra}</div>` : ""}</div>
  <div id="tc-bot" style="position:fixed;left:0;right:0;bottom:0;z-index:2147483647;background:#0b1020ee;color:#cbd5e1;font:500 20px system-ui;padding:10px 22px">
    <span id="tc-status">${esc(status)}</span><span style="float:right;opacity:.7">call at ${esc(String(e.time).slice(11, 19))} UTC · case ${esc(CASE)} · synthetic lab data · live tool call</span></div>${body ?? ""}`;
};
const bars = (rows, color) => {
  const max = Math.max(1, ...rows.map(r => r[1]));
  return rows.slice(0, 18).map(([k, v]) => `<div style="display:flex;align-items:center;gap:14px;margin:6px 0"><div style="width:520px;text-align:right;font:500 20px ui-monospace,Consolas;color:#e2e8f0;overflow:hidden;white-space:nowrap;text-overflow:ellipsis">${esc(k)}</div>
    <div style="height:26px;width:${Math.max(4, 1100 * v / max)}px;background:${color};border-radius:4px"></div><div style="font:600 20px system-ui">${Number(v).toLocaleString()}</div></div>`).join("");
};
const table = (rows, cols) => `<table style="border-collapse:collapse;font:400 17px ui-monospace,Consolas;color:#e2e8f0;width:100%">
  <tr>${cols.map(c => `<th style="text-align:left;padding:6px 10px;border-bottom:2px solid #334155;color:#94a3b8">${esc(c)}</th>`).join("")}</tr>
  ${rows.slice(0, 16).map(r => `<tr>${cols.map(c => `<td style="padding:5px 10px;border-bottom:1px solid #1e293b;max-width:520px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis">${esc(typeof r[c] === "object" ? JSON.stringify(r[c]) : r[c])}</td>`).join("")}</tr>`).join("")}</table>`;

async function labGet(e) {
  const r = await fetch(`${LAB}${e.endpoint}?${new URLSearchParams(e.params)}`, { headers: { "X-Hermes-Profile": "hunt-board" } });
  return r.ok ? await r.json() : { error: `HTTP ${r.status}` };
}
async function consoleView(e) {
  const [, color] = ROLE[e.profile] || [, "#fff"];
  let body = "";
  if (e.error) body = `<div style="font:500 30px system-ui;color:#f87171">The lab refused this query (${esc(e.error)}); the bot has to rephrase it.</div>`;
  else {
    const d = await labGet(e);
    if (e.tool === "elastic_aggregate") body = bars((d.buckets || []).map(b => [b.key, b.count]), color);
    else if (e.tool === "detection_test") body = `<div style="font:600 34px system-ui;margin-bottom:14px">${Number(d.total ?? 0).toLocaleString()} matching events${d.total ? ` · ${esc(String(d.first ?? "").slice(11, 19))} → ${esc(String(d.last ?? "").slice(11, 19))}` : ""}</div>` + bars((d.hosts || []).map(h => [h.key, h.count]), color);
    else if (e.tool === "intel_lookup") body = table((d.matches || []), ["indicator.value", "indicator.type", "confidence", "threat.feed.name", "description"]) + `<div style="margin-top:14px;font:500 20px system-ui;opacity:.8">no match: ${esc((d.unmatched || []).join(", "))}</div>`;
    else {
      const rows = d.hits || d.records || d.events || d.sessions || d.rows || [];
      const cols = [...new Set(rows.flatMap(r => Object.keys(r)))].filter(c => !/^_/.test(c)).slice(0, 7);
      body = table(rows, cols.length ? cols : ["(no rows)"]);
    }
  }
  const html = `<html><body style="margin:0;background:#0f172a;color:#fff;font-family:system-ui">${chrome(e)}<div style="position:absolute;top:190px;left:40px;right:40px;bottom:70px;overflow:hidden">${body}</div></body></html>`;
  await cdp("Page.navigate", { url: "about:blank" }); await sleep(150);
  await cdp("Runtime.evaluate", { expression: `document.open();document.write(${JSON.stringify(html)});document.close()` });
}
async function arkimeView(e) {
  const expr = e.params.expression || "";
  const full = `tags == "case:${CASE}"` + (expr ? ` && (${expr})` : "");
  const page = e.tool === "arkime_unique" ? "spiview" : "sessions";
  await cdp("Page.navigate", { url: `${ARK}/${page}?startTime=${START}&stopTime=${STOP}&expression=${encodeURIComponent(full)}` });
  await sleep(3500);
  await cdp("Runtime.evaluate", { expression: `(()=>{document.body.style.paddingTop='170px';const d=document.createElement('div');d.innerHTML=${JSON.stringify(chrome(e))};document.body.append(...d.children)})()` });
}
async function card(title, sub) {
  const html = `<html><body style="margin:0;background:#0b1020;color:#fff;font-family:system-ui;display:flex;flex-direction:column;justify-content:center;align-items:center;height:100vh">
    <div style="font:700 76px system-ui">${esc(title)}</div><div style="font:400 34px system-ui;opacity:.8;margin-top:22px;text-align:center;max-width:1500px">${sub}</div>
    <div id="tc-status" style="position:fixed;bottom:26px;font:500 22px system-ui;opacity:.75">${esc(status)}</div></body></html>`;
  await cdp("Page.navigate", { url: "about:blank" }); await sleep(150);
  await cdp("Runtime.evaluate", { expression: `document.open();document.write(${JSON.stringify(html)});document.close()` });
}

// Frame capture loop (2 fps), timestamped. A capture requested mid-navigation can wait
// forever for a frame, so each one is raced against a 3 s timeout and simply retried.
let frame = 0, running = true, captureErrors = 0;
(async () => { while (running) { const t = Date.now();
  const r = await Promise.race([cdp("Page.captureScreenshot", { format: "jpeg", quality: 82 }), sleep(3000).then(() => ({ timeout: true }))]);
  if (r.result?.data) { writeFileSync(join(FR, `f${String(++frame).padStart(6, "0")}.jpg`), Buffer.from(r.result.data, "base64")); appendFileSync(join(outDir, "frames.txt"), `${frame} ${t}\n`); }
  else if (++captureErrors <= 50) log({ kind: "capture_error", error: r.timeout ? "timeout" : JSON.stringify(r.error ?? r).slice(0, 200) });
  await sleep(Math.max(0, 500 - (Date.now() - t))); } })();

const h = await (await fetch(`${LAB}/health`, { headers: { "X-Hermes-Profile": "hunt-board" } })).json();
await card("Six AI bots hunt an intrusion", `${Number(h.event_count).toLocaleString()} events · ${Number(h.network_session_count).toLocaleString()} network sessions · ${Number(h.intel_count).toLocaleString()} intel indicators<br>Each bot drives its own tool: Elastic, Arkime, threat intel, detection tests`);
log({ kind: "card", title: "opening" });
let after = Number(AFTER), lastShown = 0, finishedAt = null, endedIso = null;
let queue = [], steps = [];
while (true) {
  try {
    const a = await (await fetch(`${LAB}/activity?after=${after}&limit=100`, { headers: { "X-Hermes-Profile": "hunt-board" } })).json();
    // The activity log is shared by every hunt: once this workflow has ended, later calls belong to the next one.
    for (const e of a.entries || []) { after = Math.max(after, e.seq); if (!endedIso || e.time <= endedIso) queue.push(e); }
    const s = await (await fetch(`http://127.0.0.1:${BOARD_PORT}/state.json`)).json();
    steps = s.steps || steps;
    const p = (s.run && s.run.parent) || {};
    const round = p.rounds ? `Round ${p.round_index}/${p.rounds} · ` : "";
    const pipeline = round + progress(steps);
    // While behind, the frame shows an older queued call, so say so instead of implying it is the current step.
    status = queue.length > 2 ? `Replaying queued calls (${queue.length} waiting) · pipeline now: ${pipeline}` : pipeline;
    await cdp("Runtime.evaluate", { expression: `(()=>{const x=document.getElementById('tc-status'); if(x) x.textContent=${JSON.stringify(status)}})()` });
    if (p.temporal_status && p.temporal_status !== "RUNNING") {
      endedIso ??= new Date().toISOString();
      queue = queue.filter(e => e.time <= endedIso);
      if (!queue.length) finishedAt ??= Date.now();
    }
  } catch (err) { log({ kind: "poll_error", error: String(err).slice(0, 200) }); }
  if (queue.length && Date.now() - lastShown >= 2500) {
    const e = queue.shift();
    try { if (/^arkime_/.test(e.tool) && !e.error) await arkimeView(e); else await consoleView(e); log({ kind: "call", seq: e.seq, tool: e.tool, profile: e.profile, backlog: queue.length }); }
    catch (err) { log({ kind: "view_error", seq: e.seq, error: String(err).slice(0, 200) }); }
    lastShown = Date.now();
  }
  if (finishedAt && Date.now() - finishedAt > 3000) break;
  await sleep(400);
}
await card("Hunt complete", esc(endSummary(steps)));
log({ kind: "card", title: "complete" }); await sleep(6000);
running = false; await sleep(800); edge.kill(); log({ kind: "end", frames: frame }); process.exit(0);
