import { atom, host, useValue, SandboxedFrame, ROUTES_AREA, SIDEBAR_NAV_AREA, PALETTE_AREA } from '@hermes/plugin-sdk';
// Read optional SDK members off the namespace: a named import of one an older desktop lacks would fail the whole plugin.
import * as hermesSdk from '@hermes/plugin-sdk';
import { useEffect, useRef, useState } from 'react';
import { jsx, jsxs } from 'react/jsx-runtime';

const PROFILES = new Set([
  'framework-network-analyst'
]);
const PAGE = '/hunt-lab';
const INITIAL_MESSAGE = 'Click Find profiles, then choose the exact VM owner. No VM is started on page load.';
const LAB_NOTE = 'Starting the VM is a human action. Nothing starts on page load.';
const state = atom({ routes: [], selected: '', busy: false, result: null, code: null, operation: null, observedAt: null, message: INITIAL_MESSAGE });
const key = route => JSON.stringify([route.connectionId, route.mode, route.profile, route.targetProfile]);

// Hunt Command design system (the approved design canvas). Surfaces use the host's --ui-bg-*
// variables and ink and hairlines are the host's --ui-base at the canvas alphas, so the pages sit inside
// whichever Desktop theme is active. Colour means state only: four state hues plus one accent for focus. Hairlines, one container per section,
// 16px Lucide icons at stroke 1.5, and status as a 12px glyph beside a word.
const CSS = `
.hc-root{--hc-blocked:#f0565b;--hc-working:#e5a83b;--hc-done:#3fc1a5;--hc-accent:#5d9bff;--hc-idle:color-mix(in srgb,var(--ui-base) 40%,transparent);--hc-mono:var(--dt-font-mono,ui-monospace,"Cascadia Mono","SF Mono",Consolas,monospace);--hc-ink1:var(--ui-base);--hc-ink2:color-mix(in srgb,var(--ui-base) 68%,transparent);--hc-ink3:color-mix(in srgb,var(--ui-base) 56%,transparent);--hc-line1:color-mix(in srgb,var(--ui-base) 24%,transparent);--hc-line2:color-mix(in srgb,var(--ui-base) 12%,transparent);--hc-line3:color-mix(in srgb,var(--ui-base) 8%,transparent);--hc-fill2:color-mix(in srgb,var(--ui-base) 4%,transparent);--hc-raised:var(--ui-bg-elevated);color:var(--hc-ink1);font-size:13px;line-height:18px;font-variant-numeric:tabular-nums;-webkit-font-smoothing:antialiased}
:root:not(.dark) .hc-root{--hc-blocked:#d93036;--hc-working:#b27100;--hc-done:#0f8a72;--hc-accent:#2f6fe4}
.hc-root *{box-sizing:border-box}
.hc-page{height:100%;display:flex;flex-direction:column;min-height:0;background:var(--ui-bg-editor)}
.hc-bar{flex:none;height:44px;display:flex;align-items:center;gap:12px;padding:0 24px;min-width:0;background:var(--ui-bg-chrome);border-bottom:.5px solid var(--hc-line2)}
.hc-title{margin:0;font-size:15px;line-height:22px;font-weight:600;white-space:nowrap}
.hc-sub{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;line-height:16px;color:var(--hc-ink3)}
.hc-bar-r{margin-left:auto;display:flex;align-items:center;gap:8px;flex:none}
.hc-body{flex:1 1 auto;min-height:0;overflow:auto;container-type:inline-size}
.hc-mono{font-family:var(--hc-mono);font-size:12px;letter-spacing:0}
.hc-ink3{color:var(--hc-ink3)}
.hc-i{flex:none;display:block}
.hc-g{flex:none;display:block}
.hc-g-blocked{color:var(--hc-blocked)}.hc-g-working{color:var(--hc-working)}.hc-g-done{color:var(--hc-done)}.hc-g-idle{color:var(--hc-idle)}
.hc-st{display:inline-flex;align-items:center;gap:6px;white-space:nowrap;color:var(--hc-ink2)}
.hc-h{display:flex;align-items:center;gap:8px;min-height:18px;margin:0 0 8px;font-size:13px;line-height:18px;font-weight:600;color:var(--hc-ink1)}
.hc-aside{margin-left:auto;display:flex;align-items:center;gap:8px;font-size:12px;font-weight:400;color:var(--hc-ink3);white-space:nowrap}
.hc-aside .hc-btn{margin:-3px 0}
.hc-box{background:var(--hc-raised);border-radius:10px;box-shadow:inset 0 0 0 .5px var(--hc-line2)}
.hc-facts{display:grid;grid-template-columns:140px minmax(0,1fr);row-gap:10px;column-gap:12px;margin:0;font-size:13px;line-height:18px}
.hc-facts dt{color:var(--hc-ink3)}
.hc-facts dd{margin:0;min-width:0;color:var(--hc-ink1);overflow-wrap:anywhere}
.hc-facts dd.hc-ell{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.hc-btn{display:inline-flex;align-items:center;gap:6px;flex:none;height:28px;padding:0 12px;border:0;border-radius:999px;background:transparent;box-shadow:inset 0 0 0 .5px var(--hc-line1);color:var(--hc-ink1);font-family:inherit;font-size:13px;font-weight:500;line-height:1;white-space:nowrap;text-decoration:none;cursor:pointer}
.hc-btn:hover:not(:disabled){background:var(--hc-fill2)}
.hc-btn.primary{background:var(--hc-ink1);color:var(--ui-bg-editor);box-shadow:none}
.hc-btn.primary:hover:not(:disabled){background:var(--hc-ink2)}
.hc-btn.sm{height:24px;padding:0 10px;font-size:12px}
.hc-btn:disabled{opacity:.45;cursor:default}
.hc-btn:focus-visible,.hc-more summary:focus-visible{outline:1px solid var(--hc-accent);outline-offset:1px}
.hc-route:focus-within{box-shadow:inset 0 0 0 1px var(--hc-accent)}
.hc-lab{display:grid;grid-template-columns:minmax(0,1fr) 520px;gap:32px;padding:24px 32px;align-items:start}
@container (max-width:1000px){.hc-lab{grid-template-columns:minmax(0,1fr)}}
.hc-col{display:flex;flex-direction:column;gap:24px;min-width:0}
.hc-route{position:relative;display:flex;align-items:center;gap:8px;height:36px;padding:0 12px;min-width:0}
.hc-route>.hc-i:first-child{color:var(--hc-ink2)}
.hc-route-t{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1 1 auto}
.hc-route select{position:absolute;inset:0;width:100%;height:100%;margin:0;opacity:0;cursor:pointer;font-size:13px;color-scheme:inherit}
.hc-route select:disabled{cursor:default}
.hc-route select:disabled~.hc-i{opacity:.45}
.hc-pad{padding:16px 20px}
.hc-pad>p{margin:12px 0 0;color:var(--hc-ink3)}
.hc-actions{display:flex;align-items:center;flex-wrap:wrap;gap:8px}
.hc-note{flex:1 1 240px;min-width:0;margin:0 0 0 8px;font-size:12px;line-height:16px;color:var(--hc-ink3);overflow-wrap:anywhere}
.hc-run{display:flex;flex-direction:column;gap:16px;padding:4px 0 0 24px;border-left:.5px solid var(--hc-line2)}
.hc-run>p{margin:0;color:var(--hc-ink3)}
.hc-console{height:340px;border-radius:8px;overflow:hidden;background:#0b0b0b}
.hc-more summary{list-style:none;display:flex;align-items:center;gap:8px;min-height:32px;padding:6px 12px;border-radius:10px;color:var(--hc-ink2);font-weight:500;cursor:pointer}
.hc-more summary::-webkit-details-marker{display:none}
.hc-more summary:hover{color:var(--hc-ink1)}
.hc-more summary .hc-i{color:var(--hc-ink3)}
.hc-more[open] summary .hc-i{transform:rotate(90deg)}
.hc-more ul{margin:0;padding:0 16px 12px 36px;display:grid;gap:4px;font-size:12px;line-height:16px;color:var(--hc-ink2)}
.hc-frame{flex:1 1 auto;min-height:0;display:flex}
.hc-empty{margin:auto;width:min(640px,100%);padding:24px 32px;display:flex;flex-direction:column;gap:12px}
.hc-empty h2{margin:0;font-size:15px;line-height:22px;font-weight:600}
.hc-empty p{margin:0;color:var(--hc-ink2)}
.hc-cmd{display:flex;align-items:center;gap:8px;min-width:0}
.hc-cmd code{flex:1 1 auto;min-width:0;overflow-x:auto;white-space:nowrap;padding:6px 10px;border-radius:8px;background:var(--hc-raised);box-shadow:inset 0 0 0 .5px var(--hc-line2);font-family:var(--hc-mono);font-size:12px;line-height:16px;color:var(--hc-ink1);scrollbar-width:thin}
.hc-card{max-width:640px;margin:4px 0 0;min-width:0}
.hc-card-h{display:flex;align-items:center;gap:8px;height:40px;padding:0 14px;min-width:0;border-bottom:.5px solid var(--hc-line3)}
.hc-card-t{font-weight:500;white-space:nowrap}
.hc-card-a{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--hc-mono);font-size:12px;line-height:16px;color:var(--hc-ink3)}
.hc-card-m{margin-left:auto;flex:none;font-size:12px;line-height:16px;color:var(--hc-ink3);white-space:nowrap}
.hc-card-b{display:flex;gap:16px;padding:12px 14px;min-width:0}
.hc-card-b .hc-facts{flex:1 1 auto;grid-template-columns:112px minmax(0,1fr);row-gap:6px;font-size:12px;line-height:16px}
.hc-card-b .hc-facts.wide{grid-template-columns:120px minmax(0,1fr)}
.hc-thumb{flex:none;width:168px;height:100px;border-radius:8px;overflow:hidden;background:#0a0a0a;box-shadow:inset 0 0 0 .5px var(--hc-line2)}
.hc-thumb img{display:block;width:100%;height:100%;object-fit:cover;object-position:top left}
`;
// React 19 hoists and de-duplicates this sheet by href, whichever surface renders first.
const sheet = () => jsx('style', { href: 'hunt-command-lab-ui', precedence: 'default', children: CSS });

// Lucide 0.577.0 icon nodes, copied path for path (the host's own set is Tabler and lacks several).
// Lucide is under the ISC License. Copyright (c) for portions of Lucide are held by Cole Bemis
// 2013-2026 as part of Feather (MIT). All other copyright (c) for Lucide are held by Lucide
// Contributors 2026. Permission to use, copy, modify, and/or distribute this software for any purpose
// with or without fee is hereby granted, provided that the above copyright notice and this permission
// notice appear in all copies. THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO
// EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
// DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
// NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
// THIS SOFTWARE.
//
// The MIT License (MIT) (for portions derived from Feather). Copyright (c) 2013-2026 Cole Bemis.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to the following conditions: The above copyright
// notice and this permission notice shall be included in all copies or substantial portions of the Software. THE
// SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
const ICONS = {
  play: [['path', { d: 'M5 5a2 2 0 0 1 3.008-1.728l11.997 6.998a2 2 0 0 1 .003 3.458l-12 7A2 2 0 0 1 5 19z' }]],
  // circle-stop, with its square filled so Stop never reads as an empty checkbox.
  circleStop: [['circle', { cx: 12, cy: 12, r: 10 }], ['rect', { x: 9, y: 9, width: 6, height: 6, rx: 1, fill: 'currentColor' }]],
  externalLink: [['path', { d: 'M15 3h6v6' }], ['path', { d: 'M10 14 21 3' }], ['path', { d: 'M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6' }]],
  server: [['rect', { width: 20, height: 8, x: 2, y: 2, rx: 2, ry: 2 }], ['rect', { width: 20, height: 8, x: 2, y: 14, rx: 2, ry: 2 }],
    ['line', { x1: 6, x2: 6.01, y1: 6, y2: 6 }], ['line', { x1: 6, x2: 6.01, y1: 18, y2: 18 }]],
  chevronDown: [['path', { d: 'm6 9 6 6 6-6' }]],
  chevronRight: [['path', { d: 'm9 18 6-6-6-6' }]],
  globe: [['circle', { cx: 12, cy: 12, r: 10 }], ['path', { d: 'M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20' }], ['path', { d: 'M2 12h20' }]]
};
const icon = name => jsx('svg', {
  className: 'hc-i', width: 16, height: 16, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 1.5,
  strokeLinecap: 'round', strokeLinejoin: 'round', 'aria-hidden': true, focusable: 'false',
  children: ICONS[name].map(([tag, attributes], index) => jsx(tag, attributes, index))
});
// Status glyphs: 12px shapes, always beside a word, never used as icons.
const GLYPHS = {
  blocked: ['circle', { cx: 6, cy: 6, r: 4, fill: 'currentColor' }],
  working: ['path', { d: 'M6 1.75a4.25 4.25 0 1 1-4.25 4.25', fill: 'none', stroke: 'currentColor', strokeWidth: 1.5, strokeLinecap: 'round' }],
  done: ['path', { d: 'M2.25 6.25 4.75 8.75 9.75 3.5', fill: 'none', stroke: 'currentColor', strokeWidth: 1.5, strokeLinecap: 'round', strokeLinejoin: 'round' }],
  idle: ['circle', { cx: 6, cy: 6, r: 3.25, fill: 'none', stroke: 'currentColor', strokeWidth: 1.5 }]
};
const glyph = tone => jsx('svg', { className: `hc-g hc-g-${tone}`, width: 12, height: 12, viewBox: '0 0 12 12', 'aria-hidden': true, focusable: 'false',
  children: jsx(GLYPHS[tone][0], GLYPHS[tone][1]) });
const status = (tone, text) => jsxs('span', { className: `hc-st ${tone}`, children: [glyph(tone), jsx('span', { children: text })] });
const mono = text => jsx('span', { className: 'hc-mono', children: text });
const heading = (title, aside) => jsxs('div', { className: 'hc-h', children: [title, aside ? jsxs('div', { className: 'hc-aside', children: [].concat(aside) }) : null] });
const facts = (rows, className = 'hc-facts') => jsx('dl', { className, children: rows.flatMap(([label, value, ell]) => [
  jsx('dt', { children: label }, `${label}-t`),
  jsx('dd', { className: ell ? 'hc-ell' : undefined, title: ell && typeof value === 'string' ? value : undefined,
    children: Array.isArray(value) ? jsxs('span', { children: value }) : value }, `${label}-d`)
]) });
const button = (label, onClick, { disabled = false, primary = false, small = false, glyph: name = null, title } = {}) => jsxs('button', {
  type: 'button', className: `hc-btn${primary ? ' primary' : ''}${small ? ' sm' : ''}`, onClick, disabled, title,
  children: [name ? icon(name) : null, label]
});
// Opens in the user's browser; only validated loopback http URLs ever reach this.
const link = (label, href, small = false) => jsxs('a', { className: `hc-btn${small ? ' sm' : ''}`, href, target: '_blank', rel: 'noopener noreferrer',
  children: [icon('externalLink'), label] });
const limits = (summary, items) => jsxs('details', { className: 'hc-box hc-more', children: [
  jsxs('summary', { children: [icon('chevronRight'), summary] }, 'summary'),
  jsx('ul', { children: items.map(item => jsx('li', { children: item }, item)) }, 'items')
] });
const pageBar = (title, sub, right) => jsxs('header', { className: 'hc-bar', children: [
  jsx('h1', { className: 'hc-title', children: title }), sub, right ? jsxs('div', { className: 'hc-bar-r', children: right }) : null
] });
const clockTime = date => [date.getHours(), date.getMinutes(), date.getSeconds()].map(part => String(part).padStart(2, '0')).join(':');

function localRoutes(inventory) {
  if (!Array.isArray(inventory)) throw new Error('route_inventory_invalid');
  const candidates = inventory.filter(route => route && route.mode === 'local'
    && typeof route.connectionId === 'string' && route.connectionId.trim()
    && typeof route.profile === 'string' && route.profile.trim()
    && PROFILES.has(route.targetProfile));
  // Multiple local registry sources claiming the same owner are not interchangeable.
  // Remote routes are never selected or used, even if they expose the same name.
  return candidates.filter(route => candidates.filter(other => other.targetProfile === route.targetProfile).length === 1);
}

async function discover() {
  if (state.get().busy) return;
  state.set({ ...state.get(), busy: true, result: null, code: null, operation: null, observedAt: null, selected: '', routes: [], message: 'Reading registered local routes…' });
  try {
    if (typeof host.profileRoutes !== 'function' || typeof host.requestProfile !== 'function') {
      state.set({ ...state.get(), message: 'unsupported_version: this Desktop build lacks connection-scoped profile CLI requests.' });
      return;
    }
    const routes = localRoutes(await host.profileRoutes());
    state.set({ ...state.get(), routes, message: routes.length
      ? 'Choose one local framework profile. Duplicate local owners and all remote routes are excluded.'
      : 'No unambiguous local framework profiles are registered. No remote or active-profile fallback was attempted.' });
  } catch {
    state.set({ ...state.get(), message: 'route_discovery_failed: registered local profile routes could not be read. No VM operation was attempted.' });
  } finally {
    state.set({ ...state.get(), busy: false });
  }
}

function decode(output, owner) {
  if (typeof output !== 'string') return null;
  // Hermes can add startup diagnostics around the CLI's single-line JSON. Never
  // display those logs, and never accept a result belonging to a different owner.
  for (const line of output.split(/\r?\n/).reverse()) {
    try {
      const value = JSON.parse(line);
      if (value && typeof value === 'object' && !Array.isArray(value)
        && value.profile === owner && typeof value.state === 'string'
        && (typeof value.reason === 'string' || value.reason === null)) return value;
    } catch { /* Only the plugin's structured result is displayable. */ }
  }
  return null;
}
let observation = 0;
const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
const OBSERVING = 'Observing setup: read-only status every 5 s for up to ten minutes. No lifecycle retry is issued.';

async function observeSetup(route, token) {
  // Only a successful human Prepare/Start opens this finite read-only observer.
  // Ten minutes is a UI observation bound, not a setup deadline or a start retry.
  const deadline = Date.now() + 600000;
  for (let attempt = 0; attempt < 120; attempt += 1) {
    await delay(5000);
    if (Date.now() >= deadline) break;
    if (observation !== token || state.get().selected !== key(route)) return;
    try {
      const registered = localRoutes(await host.profileRoutes());
      if (!registered.some(candidate => key(candidate) === key(route))) return;
      const remaining = Math.floor((deadline - Date.now()) / 1000);
      if (remaining < 1) break;
      const reply = await host.requestProfile(route, 'cli.exec', {
        argv: ['-p', route.targetProfile, 'hunt-lab', 'status'], timeout: Math.min(30, remaining)
      }, Math.min(35000, remaining * 1000), { spawnPriority: 'foreground' });
      if (observation !== token || state.get().selected !== key(route)) return;
      const result = !reply?.blocked && Number.isInteger(reply?.code)
        ? decode(reply.output, route.targetProfile) : null;
      if (!result) {
        state.set({ ...state.get(), message: 'Setup observation stopped: status unavailable. No lifecycle retry was attempted; refresh status explicitly.' });
        return;
      }
      const watching = reply.code === 0 && ['preparing', 'starting'].includes(result.state);
      state.set({ ...state.get(), result, code: reply.code, operation: 'status', observedAt: new Date(),
        message: watching ? OBSERVING : reply.code !== 0 ? `status failed (CLI exit ${reply.code}). No retry was attempted.` : '' });
      if (!watching) return;
    } catch {
      if (observation === token) state.set({ ...state.get(), message: 'Setup observation stopped: local status request failed. Refresh status explicitly; no lifecycle retry or fallback was attempted.' });
      return;
    }
  }
  if (observation === token) state.set({ ...state.get(), message: 'Automatic status observation ended after its bounded lifetime. Setup may still be working; refresh status explicitly. No Start retry was issued.' });
}

async function operate(operation) {
  const current = state.get();
  if (current.busy || !['status', 'prepare', 'start', 'stop'].includes(operation)) return;
  const route = current.routes.find(candidate => key(candidate) === current.selected);
  if (!route) {
    state.set({ ...current, result: null, code: null, operation: null, observedAt: null, message: 'Select an unambiguous local framework route first.' });
    return;
  }
  const token = ++observation;
  state.set({ ...current, busy: true, result: null, code: null, operation: null, observedAt: null, message: `Requesting ${operation} for ${route.targetProfile}…` });
  try {
    // Revalidate the exact registry descriptor on every human action; stale
    // selections never fall back to the currently active chat or a remote host.
    const registered = localRoutes(await host.profileRoutes());
    if (!registered.some(candidate => key(candidate) === key(route))) {
      state.set({ ...state.get(), routes: registered, selected: '', message: 'route_not_registered_or_ambiguous: select a current unique local route. No VM operation was attempted.' });
      return;
    }
    const reply = await host.requestProfile(route, 'cli.exec', {
      argv: ['-p', route.targetProfile, 'hunt-lab', operation], timeout: 60
    }, 65000, { spawnPriority: 'foreground' });
    if (reply?.blocked) {
      state.set({ ...state.get(), message: 'cli_blocked: Hermes refused this noninteractive command. VM state is unknown; no fallback was attempted.' });
      return;
    }
    if (!reply || !Number.isInteger(reply.code)) {
      state.set({ ...state.get(), message: 'invalid_cli_response: no exit status was returned. VM state is unknown; refresh before another lifecycle action.' });
      return;
    }
    const result = decode(reply.output, route.targetProfile);
    if (!result) {
      state.set({ ...state.get(), code: reply.code, message: `invalid_or_mismatched_cli_output (exit ${reply.code}): no structured result for the selected owner. The backend plugin may be absent or disabled. VM state is unknown; no fallback was attempted.` });
      return;
    }
    const watching = reply.code === 0 && ['prepare', 'start'].includes(operation) && ['preparing', 'starting'].includes(result.state);
    // A successful reply speaks through the status facts; the note line carries only failures and observation.
    state.set({ ...state.get(), result, code: reply.code, operation, observedAt: new Date(), message: reply.code !== 0
      ? `${operation}: ${result.state}${result.reason ? ` — ${result.reason}` : ''} (CLI exit ${reply.code}). Operation failed; no retry or alternate host was attempted.`
      : watching ? OBSERVING : '' });
    if (watching) void observeSetup(route, token);
  } catch (error) {
    const code = typeof error?.code === 'number' ? ` (${error.code})` : '';
    state.set({ ...state.get(), message: `profile_rpc_failed${code}: the selected route did not return a result. The request may have reached the backend; VM state is unknown. Refresh status before retrying. No fallback was attempted.` });
  } finally {
    state.set({ ...state.get(), busy: false });
  }
}

function loopbackUrl(value, protocols = ['http:']) {
  if (typeof value !== 'string' || value !== value.trim()) return null;
  try {
    const url = new URL(value);
    if (!protocols.includes(url.protocol) || !['127.0.0.1', '[::1]'].includes(url.hostname)
      || url.username || url.password || !url.port || Number(url.port) < 1) return null;
    return url.href;
  } catch { return null; }
}

// An error needs attention, so it takes the blocked hue; a stopped VM is idle.
const STATE_TONES = { running: 'done', starting: 'working', preparing: 'working', stopping: 'working', stopped: 'idle', error: 'blocked' };
const NOT_REPORTED = 'not reported';

function vmStatus(current, result) {
  if (current.busy) return status('working', 'requesting…');
  if (!current.selected) return status('idle', 'no VM selected');
  if (!result) return status('idle', 'unknown');
  return status(STATE_TONES[result.state] ?? 'idle', result.state);
}

function statusFacts(current, result) {
  const prepared = result.prepared === true ? 'Yes' : result.prepared === false ? 'No' : NOT_REPORTED;
  const stage = result.setup && typeof result.setup.stage === 'string'
    ? [' · setup stage ', mono(result.setup.stage), result.setup.reason ? ` · ${result.setup.reason}` : ''] : [];
  const rows = [
    ['State', vmStatus(current, result)],
    ['VM', result.vm_name == null ? NOT_REPORTED : mono(String(result.vm_name))],
    ['Reason', result.reason ?? 'none'],
    ['Prepared', [prepared, ...stage]],
    ['Memory', result.memory_mib == null ? NOT_REPORTED : [mono(String(result.memory_mib)), ' MiB']],
    ['Acceleration', result.accel == null ? NOT_REPORTED : mono(String(result.accel))],
    ['Last command', [mono(`hunt-lab ${current.operation ?? 'status'}`), ` · exit ${current.code}`]]
  ];
  // While running, the process id belongs with the running facts.
  if (result.pid != null && result.state !== 'running') rows.splice(2, 0, ['PID', mono(String(result.pid))]);
  return facts(rows);
}

function endpoint(value, protocols) {
  return loopbackUrl(value, protocols) ? mono(value) : 'no validated loopback endpoint reported';
}

function runningState(current, owner, result, ready) {
  const running = result && current.code === 0 && result.state === 'running';
  if (!running) {
    return jsx('div', { className: 'hc-run', children: jsx('p', {
      children: 'Guest service links and console are hidden until a successful running status for this owner is returned.' }) });
  }
  const consoleUrl = consoleFrameUrl(result.console_websocket_url);
  const arkime = loopbackUrl(result.arkime_url);
  const lab = loopbackUrl(result.lab_console_url);
  return jsxs('div', { className: 'hc-run', children: [
    facts([
      ['State', vmStatus(current, result)],
      ['PID', result.pid == null ? NOT_REPORTED : mono(String(result.pid))],
      ['Lab', endpoint(result.lab_url, ['http:'])],
      ['Arkime', endpoint(result.arkime_url, ['http:'])],
      ['Console', consoleUrl ? mono(result.console_websocket_url) : 'no validated ws://127.0.0.1:<port> transport reported']
    ]),
    consoleUrl
      ? jsx('div', { className: 'hc-console', children: jsx(SandboxedFrame, {
        src: consoleUrl, sandbox: 'allow-scripts', title: `QEMU console — ${owner}`,
        style: { width: '100%', height: '100%', border: '0', display: 'block' }
      }) })
      : jsx('p', { children: 'Console not available: no external page, alternate viewer, or Bot Screen was opened.' }),
    jsxs('div', { className: 'hc-actions', children: [
      button('Stop lab', () => operate('stop'), { disabled: !ready, glyph: 'circleStop' }),
      arkime ? link('Open Arkime', arkime) : null,
      lab ? link('Open lab', lab) : null
    ] })
  ] });
}

function routePicker(current) {
  const route = current.routes.find(candidate => key(candidate) === current.selected);
  const shown = route
    ? [mono(route.profile), jsx('span', { className: 'hc-ink3', style: { fontSize: '12px' }, children: ` · ${route.connectionId} · target ${route.targetProfile}` })]
    : jsx('span', { className: 'hc-ink3', children: current.routes.length ? 'Select a local route' : 'No route yet: click Find profiles' });
  return jsxs('div', { className: 'hc-box hc-route', children: [
    icon('server'),
    jsx('span', { className: 'hc-route-t', children: shown }),
    jsx('select', {
      'aria-label': 'VM owner', value: current.selected, disabled: current.busy || !current.routes.length,
      onChange: event => state.set({ ...state.get(), selected: event.target.value, result: null, code: null, operation: null, observedAt: null, message: 'Owner selected. Refresh status before deciding whether to start or shut down.' }),
      children: [jsx('option', { value: '', children: 'Select a local route' }, ''), ...current.routes.map(candidate => jsx('option', {
        value: key(candidate), children: `${candidate.profile} · ${candidate.connectionId} · target ${candidate.targetProfile}`
      }, key(candidate)))]
    }),
    icon('chevronDown')
  ] });
}

function HuntingLab() {
  const current = useValue(state);
  const ready = !current.busy && !!current.selected;
  const owner = current.routes.find(route => key(route) === current.selected)?.targetProfile;
  const result = current.result && current.result.profile === owner ? current.result : null;
  const vmState = result?.state;
  return jsxs('div', { className: 'hc-root hc-page', children: [sheet(),
    pageBar('Hunting Lab', jsx('span', { className: 'hc-sub', children: 'Local VM for read-only evidence queries' })),
    jsx('div', { className: 'hc-body', children: jsxs('div', { className: 'hc-lab', children: [
      jsxs('div', { className: 'hc-col', children: [
        jsxs('section', { 'aria-label': 'VM owner', children: [
          heading('Route', button('Find profiles', discover, { disabled: current.busy, small: true })),
          routePicker(current)
        ] }),
        jsxs('section', { 'aria-label': 'VM status', children: [
          heading('Status', [result && current.observedAt ? `observed ${clockTime(current.observedAt)}` : null,
            button('Refresh status', () => operate('status'), { disabled: !ready, small: true })]),
          jsxs('div', { className: 'hc-box hc-pad', children: result ? [statusFacts(current, result)] : [
            facts([['State', vmStatus(current, null)]]),
            jsx('p', { children: 'No validated status for the selected profile. Refresh status explicitly.' })
          ] })
        ] }),
        jsxs('div', { className: 'hc-actions', role: 'toolbar', 'aria-label': 'Lab VM lifecycle', children: [
          // While the last validated status is running, Stop lab beside the running facts is the only lifecycle action.
          button('Start lab', () => operate('start'), vmState === 'running'
            ? { disabled: true, glyph: 'play', title: 'VM is running' } : { disabled: !ready, primary: true, glyph: 'play' }),
          button(result?.prepared === true ? 'Prepare again' : 'Prepare lab', () => operate('prepare'),
            { disabled: !ready || vmState === 'running', title: vmState === 'running' ? 'VM is running' : undefined }),
          // Running with a clean status: Stop sits with the running facts. Stopped: there is nothing to stop.
          // A running state from a failed call (a Stop that exited non-zero) keeps Stop here, since the running column is hidden.
          (vmState === 'running' && current.code === 0) || vmState === 'stopped' ? null : button('Stop lab', () => operate('stop'), { disabled: !ready, glyph: 'circleStop' }),
          jsx('p', { className: 'hc-note', role: 'status', 'aria-live': 'polite', children: current.message || LAB_NOTE })
        ] }),
        limits('Requirements and limits', [
          'Only local framework routes are offered; duplicate local owners and every remote route are excluded.',
          'The first explicit Start prepares verified public runtime assets, then boots. Prepare downloads and provisions without booting.',
          'Automatic first setup needs Windows x64 with Windows Hypervisor Platform already enabled, 5 GiB available RAM and 37 GiB free disk, and makes large public downloads.',
          'The guest uses 4 GiB RAM, two vCPUs and a 32 GiB virtual disk. No elevation, Windows-feature change or software-emulation fallback is attempted.',
          'A running QEMU process is not proof that guest services finished booting.',
          'After a human Start or Prepare, only read-only status is observed, for up to ten minutes. Refresh explicitly after that.',
          'No lifecycle retry, model call, host Docker fallback or VMware dependency is used. This page reads no conversations, credentials or memory.',
          'The console is the real QEMU boot console for this profile-owned VM; input goes to the guest. Bot Screen is separate: it is not a VM launcher or console.'
        ])
      ] }),
      jsxs('section', { 'aria-label': 'Running state', children: [heading('Running state'), runningState(current, owner, result, ready)] })
    ] }) })
  ] });
}

// Live hunt board: a read-only page served by `python -m hermes_temporal.board` on a
// fixed loopback port. It is embedded only after an explicit click, in an opaque-origin
// sandbox, and shows only real workflow status and the bots' recorded outputs.
const BOARD = '/hunt-board';
const BOARD_URL = 'http://127.0.0.1:8790/';
const BOARD_COMMAND = 'python -m hermes_temporal.board --workflow-id <practice id> --input <lab input JSON> --port 8790';
const board = atom({ shown: false, nonce: 0 });

function HuntBoard() {
  const current = useValue(board);
  const CopyButton = hermesSdk.CopyButton;
  return jsxs('div', { className: 'hc-root hc-page', children: [sheet(),
    pageBar('Hunt Board', [
      jsx('span', { className: 'hc-mono hc-ink3', children: BOARD_URL.slice(0, -1) }, 'url'),
      jsx('span', { className: 'hc-sub', children: '· loaded on click, read-only' }, 'note')
    ], [
      current.shown ? button('Hide', () => board.set({ ...board.get(), shown: false }), { small: true }) : null,
      button(current.shown ? 'Reload' : 'Show board', () => board.set({ shown: true, nonce: current.nonce + 1 }), { small: true, primary: !current.shown }),
      link('Open in browser', BOARD_URL, true)
    ]),
    jsx('div', { className: 'hc-frame', children: current.shown
      ? jsx(SandboxedFrame, {
        src: BOARD_URL, sandbox: 'allow-scripts', title: 'Live hunt board',
        style: { flex: '1 1 auto', width: '100%', height: '100%', minHeight: 0, border: '0', display: 'block' }
      }, String(current.nonce))
      : jsxs('div', { className: 'hc-empty', children: [
        jsx('h2', { children: 'Board hidden' }),
        jsx('p', { children: 'Start the board server, then click Show board. Nothing is fetched until you do. The board shows only what the bots wrote; approvals are recorded separately.' }),
        jsxs('div', { className: 'hc-cmd', children: [
          jsx('code', { children: BOARD_COMMAND }),
          CopyButton ? jsx(CopyButton, { text: BOARD_COMMAND, appearance: 'icon', label: 'Copy start command' }) : null
        ] })
      ] }) })
  ] });
}

// lab_browser chat card: the call's action, its arguments or result fields, and a small window onto
// that bot's real lab browser. While the call runs it shows the hunt board's live MJPEG stream of the
// bot's browser; once it finishes, the final frame lab_browser saved (result.image_path), else the
// board's latest frame. A thumbnail that cannot load is left out rather than drawn empty.
const LIVE_URL = 'http://127.0.0.1:8790/live/';
const LIVE_RETRY_MS = 5000;
// The board's own /live/<profile> path pattern.
const LIVE_PROFILE = /^[a-z0-9-]+$/;
// lab_browser argument fields, in the order a reader needs them.
const ARG_FIELDS = ['page', 'url', 'q', 'expression', 'text', 'key', 'direction', 'ref'];
const str = value => (typeof value === 'string' ? value : '');

// The call's own profile: lab_browser stamps it on every result; while running, the profile that owns this chat.
function callProfile(result, chatProfile) {
  const profile = typeof result?.profile === 'string' ? result.profile : chatProfile;
  return typeof profile === 'string' && LIVE_PROFILE.test(profile) ? profile : null;
}

function LiveThumb({ profile }) {
  const [attempt, setAttempt] = useState(0);
  const [down, setDown] = useState(false);
  useEffect(() => {
    if (!down) return undefined;
    const timer = setTimeout(() => { setDown(false); setAttempt(n => n + 1); }, LIVE_RETRY_MS);
    return () => clearTimeout(timer);
  }, [down]);
  if (!profile || down) return null;
  return jsx('div', { className: 'hc-thumb', children: jsx('img', { src: `${LIVE_URL}${profile}.mjpg?attempt=${attempt}`,
    alt: `Live lab browser of ${profile}`, onError: () => setDown(true) }, attempt) });
}

function FinalThumb({ imagePath, profile, resolveImageUrl }) {
  // undefined: resolving; null: no local frame, use the board's.
  const [local, setLocal] = useState(undefined);
  const [boardDown, setBoardDown] = useState(false);
  useEffect(() => {
    let current = true;
    setLocal(undefined);
    if (!imagePath || typeof resolveImageUrl !== 'function') { setLocal(null); return undefined; }
    resolveImageUrl(imagePath).then(url => { if (current) setLocal(url || null); }, () => { if (current) setLocal(null); });
    return () => { current = false; };
  }, [imagePath, resolveImageUrl]);
  const image = local
    ? jsx('img', { src: local, alt: 'Final lab browser frame', onError: () => setLocal(null) })
    : local === null && profile && !boardDown
      ? jsx('img', { src: `${LIVE_URL}${profile}.jpg`, alt: `Latest lab browser frame of ${profile}`, onError: () => setBoardDown(true) })
      : null;
  return image ? jsx('div', { className: 'hc-thumb', children: image }) : null;
}

const clock = milliseconds => {
  const seconds = Math.max(0, Math.floor(milliseconds / 1000));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
};

// Elapsed time as this card saw it: from mount while running, frozen when the call settles.
// A card first drawn already settled (an older call) has no observed duration and shows none.
function useElapsed(running) {
  const started = useRef(Date.now());
  const settled = useRef(running ? null : false);
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!running) return undefined;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [running]);
  if (running) return clock(now - started.current);
  if (settled.current === null) settled.current = Date.now();
  return settled.current ? clock(settled.current - started.current) : '';
}

function argRows(call) {
  return ARG_FIELDS.filter(field => str(call[field])).map(field => [field, mono(str(call[field])), true]);
}

function LabVmCard({ args, profile: chatProfile, resolveImageUrl, result, status: callStatus }) {
  const call = args && typeof args === 'object' ? args : {};
  const outcome = result && typeof result === 'object' ? result : null;
  const profile = callProfile(outcome, chatProfile);
  const running = callStatus === 'running';
  const failed = !running && (callStatus === 'error' || outcome?.ok === false);
  const elapsed = useElapsed(running);
  const [tone, word] = running ? ['working', 'running'] : failed ? ['blocked', 'failed'] : ['done', 'done'];
  const profileRow = profile ? [['profile', mono(profile)]] : [];
  let rows;
  let thumb = null;
  if (running) {
    rows = [...argRows(call), ...profileRow];
    thumb = jsx(LiveThumb, { profile });
  } else if (failed) {
    const error = `${str(outcome?.error) || 'no result'}${str(outcome?.detail) ? ` (${outcome.detail})` : ''}`;
    rows = [...argRows(call), ['error', error], ...profileRow];
  } else {
    const page = outcome?.result && typeof outcome.result === 'object' ? outcome.result : {};
    rows = [
      str(page.title) ? ['title', str(page.title), true] : null,
      str(page.url) ? ['url', mono(str(page.url)), true] : null,
      Array.isArray(page.elements) ? ['elements', String(page.elements.length)] : typeof page.elements === 'number' ? ['elements', String(page.elements)] : null,
      typeof page.blocked_requests === 'number' ? ['blocked requests', String(page.blocked_requests)] : null,
      str(outcome?.image_path) ? ['image', mono(str(outcome.image_path)), true] : null
    ].filter(Boolean);
    if (!rows.length) rows = [...argRows(call), ...profileRow];
    thumb = jsx(FinalThumb, { imagePath: str(outcome?.image_path), profile, resolveImageUrl });
  }
  return jsxs('div', { className: 'hc-root hc-box hc-card', 'data-hunt-lab-vm': callStatus, children: [sheet(),
    jsxs('div', { className: 'hc-card-h', children: [
      icon('globe'),
      glyph(tone),
      jsx('span', { className: 'hc-card-t', children: 'lab_browser' }),
      jsx('span', { className: 'hc-card-a', children: str(call.action) || 'browse' }),
      jsx('span', { className: 'hc-card-m', children: elapsed ? `${word} · ${elapsed}` : word })
    ] }),
    jsxs('div', { className: 'hc-card-b', children: [
      rows.length ? facts(rows, `hc-facts${thumb && !running ? ' wide' : ''}`) : null,
      thumb
    ] })
  ] });
}

// Hunt Command Desktop theme: the canvas's dark surfaces (rail #0e0e0e, chrome #121212, pane #161616,
// raised #1c1c1c) with white ink and neutral lines; the blue accent marks focus only. The host mixes
// these seeds (chrome = 74% background, pane = 38% card, raised = 46% popover over its neutrals), so
// the values below are the seeds that land on the canvas hexes. A data contribution is a DesktopTheme;
// it only joins the theme picker and changes nothing until picked.
const HUNT_COMMAND_THEME = {
  name: 'hunt-command',
  label: 'Hunt Command',
  description: 'Neutral dark, white ink, colour only for state',
  colors: {
    background: '#141414', foreground: '#FFFFFF',
    card: '#161616', cardForeground: '#FFFFFF',
    muted: '#1C1C1C', mutedForeground: '#999999',
    popover: '#232323', popoverForeground: '#FFFFFF',
    primary: '#FFFFFF', primaryForeground: '#161616',
    secondary: '#1C1C1C', secondaryForeground: '#B4B4B4',
    accent: '#222222', accentForeground: '#FFFFFF',
    border: '#2B2B2B', input: '#3A3A3A',
    ring: '#5D9BFF', midground: '#FFFFFF', midgroundForeground: '#0A0A0A', composerRing: '#FFFFFF',
    destructive: '#F0565B', destructiveForeground: '#FFFFFF',
    sidebarBackground: '#0E0E0E', sidebarBorder: '#262626',
    userBubble: '#343434', userBubbleBorder: '#242424'
  },
  typography: {
    fontSans: 'Inter, "Segoe UI Variable Text", "Segoe UI", system-ui, -apple-system, sans-serif',
    fontMono: 'ui-monospace, "Cascadia Mono", "SF Mono", Consolas, monospace'
  }
};

// Native Desktop's manifest is this default-exported HermesPlugin object.
// package.json supplies versioned ESM metadata; it is not a dashboard manifest.
export default {
  id: 'hunt-lab', name: 'Hunting Lab', defaultEnabled: true,
  register(ctx) {
    ctx.register({ id: 'page', area: ROUTES_AREA, data: { path: PAGE }, render: () => jsx(HuntingLab, {}) });
    ctx.register({ id: 'sidebar', area: SIDEBAR_NAV_AREA, data: { path: PAGE, label: 'Hunting Lab', codicon: 'beaker' } });
    ctx.register({ id: 'open', area: PALETTE_AREA, data: { id: 'hunt-lab.open', label: 'Open Hunting Lab', run: () => host.navigate(PAGE) } });
    ctx.register({ id: 'board', area: ROUTES_AREA, data: { path: BOARD }, render: () => jsx(HuntBoard, {}) });
    ctx.register({ id: 'board-sidebar', area: SIDEBAR_NAV_AREA, data: { path: BOARD, label: 'Hunt Board', codicon: 'list-unordered' } });
    ctx.register({ id: 'board-open', area: PALETTE_AREA, data: { id: 'hunt-lab.board', label: 'Open Hunt Board', run: () => host.navigate(BOARD) } });
    // Older desktops have no tool-card area; the generic tool row (with its thumbnail) stays.
    if (hermesSdk.TOOL_CARD_AREA) {
      ctx.register({ id: 'lab-browser-card', area: hermesSdk.TOOL_CARD_AREA, data: { tool: 'lab_browser', render: props => jsx(LabVmCard, props) } });
    }
    // Older desktops have no theme area; the plugin's pages still load and follow the active theme.
    if (hermesSdk.THEMES_AREA) {
      ctx.register({ id: 'theme', area: hermesSdk.THEMES_AREA, data: HUNT_COMMAND_THEME });
    }
  }
};
