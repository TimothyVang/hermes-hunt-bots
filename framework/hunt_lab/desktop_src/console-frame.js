/* Authored data: document factory; build_console.py includes this in plugin.js. */
function createConsoleFrameUrl(bundle, wsURL) {
  // Accept only QEMU's exact IPv4 loopback transport, never HTTP pages, remote
  // hosts, credentials, alternate spellings, URL paths, queries, or fragments.
  if (typeof wsURL !== 'string' || wsURL !== wsURL.trim()) return null;
  const match = /^ws:\/\/127\.0\.0\.1:([1-9]\d{0,4})\/?$/.exec(wsURL);
  if (!match || Number(match[1]) > 65535) return null;
  const endpoint = `ws://127.0.0.1:${match[1]}/`;
  // Source remains readable in the generated module, including upstream license
  // notices. Escape HTML script terminators without changing JavaScript values.
  const script = bundle.replace(/<\/script/gi, '<\\/script');
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src ${endpoint}; img-src data: blob:; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer"><title>Profile-owned QEMU console</title>
<style>
html,body{margin:0;width:100%;height:100%;overflow:hidden;background:#15171a;color:#edf0f4;font:13px system-ui,sans-serif}
body{display:flex;flex-direction:column}header{display:flex;align-items:center;gap:12px;padding:10px;border-bottom:1px solid #454a51}
#console-status{flex:1;margin:0}button{background:#292e36;color:inherit;border:1px solid #737b87;border-radius:4px;padding:6px 10px;white-space:nowrap}
button:disabled{opacity:.5}button:focus-visible{outline:2px solid #95caff;outline-offset:2px}
#console-screen{flex:1;min-height:0;overflow:hidden}footer{padding:5px 10px;color:#c3c9d1;font-size:11px}
</style></head><body data-console-websocket="${endpoint}">
<header><p id="console-status" role="status" aria-live="polite">Connecting directly to QEMU; guest HTTP services are not required…</p><button id="console-focus" type="button" disabled>Focus console</button></header>
<div id="console-screen" role="region" aria-label="Live QEMU guest display"></div>
<footer>Native profile-owned VM display · noVNC 1.6.0 (MPL-2.0) · No host clipboard integration, external page, or automatic VM lifecycle.</footer>
<script type="module">${script}</script></body></html>`;
  return `data:text/html;charset=utf-8,${encodeURIComponent(html)}`;
}
