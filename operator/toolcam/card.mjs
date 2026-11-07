// Render a 1920x1080 HTML card to PNG with a headless browser (the end card for assemble.py --end-card).
// Usage: bun operator/toolcam/card.mjs <in.html> <out.png>
// The browser is TOOLCAM_BROWSER (default: Microsoft Edge on Windows, else chromium).
import { spawn } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { resolve } from "node:path";
const args = process.argv.slice(2);
if (args.length !== 2 || args.includes("--help")) { console.error("usage: bun card.mjs <in.html> <out.png>"); process.exit(2); }
const [src, out] = args;
const BROWSER = process.env.TOOLCAM_BROWSER || (process.platform === "win32"
  ? "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" : "chromium");
const prof = resolve(out + ".edge-profile"); mkdirSync(prof, { recursive: true }); // the browser needs an absolute --user-data-dir
const PORT = 9850 + Math.floor(Math.random() * 100);
const edge = spawn(BROWSER, ["--headless=new", `--remote-debugging-port=${PORT}`,
  "--remote-debugging-address=127.0.0.1", `--user-data-dir=${prof}`, "--window-size=1920,1080", "--hide-scrollbars", "--no-first-run", "about:blank"], { stdio: "ignore" });
edge.on("error", err => { console.error(`cannot start ${BROWSER} (set TOOLCAM_BROWSER): ${err.message}`); rmSync(prof, { recursive: true, force: true }); process.exit(1); });
const sleep = ms => new Promise(r => setTimeout(r, ms));
let wsUrl;
for (let i = 0; i < 40 && !wsUrl; i++) { try { wsUrl = (await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json()).find(t => t.type === "page")?.webSocketDebuggerUrl; } catch { } if (!wsUrl) await sleep(500); }
if (!wsUrl) { console.error(`${BROWSER} exposed no DevTools page on port ${PORT}`); edge.kill(); process.exit(1); }
const ws = new WebSocket(wsUrl); await new Promise(r => ws.onopen = r);
let id = 0; const pend = new Map(); ws.onmessage = m => { const d = JSON.parse(m.data); if (d.id && pend.has(d.id)) { pend.get(d.id)(d); pend.delete(d.id); } };
const cdp = (method, params = {}) => new Promise(r => { const i = ++id; pend.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
await cdp("Emulation.setDeviceMetricsOverride", { width: 1920, height: 1080, deviceScaleFactor: 1, mobile: false });
await cdp("Runtime.evaluate", { expression: `document.open();document.write(${JSON.stringify(readFileSync(src, "utf8"))});document.close()` });
await sleep(400);
const r = await cdp("Page.captureScreenshot", { format: "png" });
writeFileSync(out, Buffer.from(r.result.data, "base64"));
edge.kill(); await sleep(300); rmSync(prof, { recursive: true, force: true }); process.exit(0);
