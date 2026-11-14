// Original local-development UI. The only third-party code is the Lucide icon path data, under the ISC
// License (notice beside ICONS below); no mascot assets are bundled.
import { atom, host, ROUTES_AREA, SIDEBAR_NAV_AREA, PALETTE_AREA, Button, useValue } from '@hermes/plugin-sdk';
import { jsx } from 'react/jsx-runtime';

// [role, profile id, remit, monogram]
const ROLES = Object.freeze([
  ['Incident Response Lead', 'framework-coordinator', 'Native Astra orchestration; Luna/Terra per-task delegation.', 'IR'],
  ['Threat Hunter', 'framework-researcher', 'Supplied evidence and testable alternatives only.', 'TH'],
  ['Detection Engineer', 'framework-builder', 'Draft and offline review; no deployment.', 'DE'],
  ['Purple Team Analyst', 'framework-reviewer', 'Independent supplied-evidence review; no adversary emulation.', 'PT'],
  ['Threat Intelligence Analyst', 'framework-librarian', 'Attributed intelligence drafts, not trusted memory.', 'TI'],
  ['Network Analyst', 'framework-network-analyst', 'Use only approved sanitized Arkime/Wireshark summaries; never raw captures or sensitive tool views.', 'NA']
]);
const GATES = Object.freeze([
  ['Scope', 'A human establishes sources, time, authority, exclusions and destination.'],
  ['Evidence + hypotheses', 'Parallel only after human scope approval; facts and hypotheses remain distinct.'],
  ['Analysis', 'Requires both branch handoffs and separate human decisions.'],
  ['Independent review', 'Check evidence and alternatives; disclose independence limitations.'],
  ['Handoff', 'A decision request, not remediation, release or promotion.']
]);
// Hunt Command design system (the approved design canvas). Surfaces use the host's --ui-bg-*
// variables and ink and hairlines are the host's --ui-base at the canvas alphas, so the page sits inside
// whichever Desktop theme is active; the blue accent marks focus only. One container per section, 16px Lucide icons at stroke 1.5.
const CSS = `
.hw{--hw-accent:#5d9bff;--hw-mono:var(--dt-font-mono,ui-monospace,"Cascadia Mono","SF Mono",Consolas,monospace);--hw-ink1:var(--ui-base);--hw-ink2:color-mix(in srgb,var(--ui-base) 68%,transparent);--hw-ink3:color-mix(in srgb,var(--ui-base) 56%,transparent);--hw-line1:color-mix(in srgb,var(--ui-base) 24%,transparent);--hw-line2:color-mix(in srgb,var(--ui-base) 12%,transparent);--hw-line3:color-mix(in srgb,var(--ui-base) 8%,transparent);--hw-fill1:color-mix(in srgb,var(--ui-base) 6%,transparent);--hw-fill2:color-mix(in srgb,var(--ui-base) 4%,transparent);--hw-raised:var(--ui-bg-elevated);height:100%;display:flex;flex-direction:column;min-height:0;background:var(--ui-bg-editor);color:var(--hw-ink1);font-size:13px;line-height:18px;font-variant-numeric:tabular-nums;-webkit-font-smoothing:antialiased}
:root:not(.dark) .hw{--hw-accent:#2f6fe4}
.hw *{box-sizing:border-box}
.hw-bar{flex:none;height:44px;display:flex;align-items:center;gap:12px;padding:0 24px;min-width:0;background:var(--ui-bg-chrome);border-bottom:.5px solid var(--hw-line2)}
.hw-title{margin:0;font-size:15px;line-height:22px;font-weight:600;white-space:nowrap}
.hw-sub{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;line-height:16px;color:var(--hw-ink3)}
.hw-body{flex:1 1 auto;min-height:0;overflow:auto;container-type:inline-size}
.hw-page{padding:24px 32px;display:flex;flex-direction:column;gap:24px}
.hw-h{display:flex;align-items:center;gap:8px;min-height:18px;margin:0 0 8px;font-size:13px;line-height:18px;font-weight:600}
.hw-aside{margin-left:auto;font-size:12px;font-weight:400;color:var(--hw-ink3);white-space:nowrap}
.hw-h .hw-btn{margin:-3px 0 -3px auto}
.hw-box{background:var(--hw-raised);border-radius:10px;box-shadow:inset 0 0 0 .5px var(--hw-line2)}
.hw-i{flex:none;display:block}
.hw-mono{font-family:var(--hw-mono);letter-spacing:0}
.hw-steps{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(5,minmax(0,1fr))}
.hw-step{padding:16px;min-width:0;border-left:.5px solid var(--hw-line2)}
.hw-step:first-child{border-left:0}
.hw-step b{display:flex;align-items:center;gap:8px;font-weight:600}
.hw-step b span{color:var(--hw-ink3);font-weight:500}
.hw-step p{margin:4px 0 0;font-size:12px;line-height:16px;color:var(--hw-ink2)}
.hw-grid{display:grid;grid-template-columns:minmax(0,1fr) 400px;gap:24px;align-items:start}
.hw-col{display:flex;flex-direction:column;gap:24px;min-width:0}
@container (max-width:1000px){.hw-grid{grid-template-columns:minmax(0,1fr)}.hw-steps{grid-template-columns:repeat(auto-fit,minmax(168px,1fr))}}
.hw-list{list-style:none;margin:0;padding:0}
.hw-li{display:flex;align-items:center;gap:12px;min-height:32px;padding:10px 16px;border-top:.5px solid var(--hw-line3);min-width:0}
.hw-li:first-child{border-top:0}
.hw-mg{display:inline-flex;align-items:center;justify-content:center;flex:none;width:20px;height:20px;border-radius:4px;background:var(--hw-fill1);box-shadow:inset 0 0 0 .5px var(--hw-line2);font-size:10px;line-height:1;font-weight:600;letter-spacing:.02em;color:var(--hw-ink2)}
.hw-who{width:240px;flex:none;min-width:0}
.hw-who b{display:block;font-weight:500}
.hw-who code{display:block;font-family:var(--hw-mono);font-size:11px;line-height:16px;color:var(--hw-ink3)}
.hw-remit{flex:1 1 auto;min-width:0;font-size:12px;line-height:16px;color:var(--hw-ink2)}
@container (max-width:760px){.hw-who{width:180px}}
.hw-screen{padding:16px;display:flex;flex-direction:column;gap:12px}
.hw-label{font-size:12px;line-height:16px;color:var(--hw-ink3)}
.hw-select{position:relative;display:flex;align-items:center;gap:8px;height:32px;padding:0 10px;border-radius:8px;box-shadow:inset 0 0 0 .5px var(--hw-line1);min-width:0}
.hw-select:focus-within{box-shadow:inset 0 0 0 1px var(--hw-accent)}
.hw-select-t{flex:1 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px}
.hw-select select{position:absolute;inset:0;width:100%;height:100%;margin:0;opacity:0;cursor:pointer;font-size:13px}
.hw-row{display:flex;align-items:center;flex-wrap:wrap;gap:8px}
.hw-status{flex:1 1 160px;min-width:0;margin:0;font-size:12px;line-height:16px;color:var(--hw-ink3)}
.hw-btn{display:inline-flex;align-items:center;gap:6px;flex:none;height:28px;padding:0 12px;border:0;border-radius:999px;background:transparent;box-shadow:inset 0 0 0 .5px var(--hw-line1);color:var(--hw-ink1);font-family:inherit;font-size:13px;font-weight:500;line-height:1;white-space:nowrap;cursor:pointer}
.hw-btn.primary{background:var(--hw-ink1);color:var(--ui-bg-editor);box-shadow:none}
.hw-btn.danger{color:#f0565b;box-shadow:inset 0 0 0 .5px color-mix(in srgb,#f0565b 48%,transparent)}
.hw-btn.sm{height:24px;padding:0 10px;font-size:12px}
.hw-btn:disabled{opacity:.45;cursor:default}
.hw-btn:hover:not(:disabled){background:var(--hw-fill2)}
.hw-btn.primary:hover:not(:disabled){opacity:.88}
.hw-gate{padding:16px;display:flex;flex-direction:column;gap:12px;margin-top:12px}
.hw-gate-fields{display:flex;flex-wrap:wrap;align-items:center;gap:8px}
.hw-input{height:30px;padding:0 10px;border:0;border-radius:8px;background:var(--ui-bg-editor);box-shadow:inset 0 0 0 .5px var(--hw-line1);color:var(--hw-ink1);font-family:var(--hw-mono);font-size:12px;min-width:0}
.hw-textarea{width:100%;min-height:64px;padding:8px 10px;border:0;border-radius:8px;background:var(--ui-bg-editor);box-shadow:inset 0 0 0 .5px var(--hw-line1);color:var(--hw-ink1);font-family:inherit;font-size:12px;line-height:16px;resize:vertical}
.hw-input:focus-visible,.hw-textarea:focus-visible{outline:1px solid var(--hw-accent);outline-offset:1px}
.hw-facts{display:grid;grid-template-columns:136px minmax(0,1fr);row-gap:6px;column-gap:12px;margin:0;font-size:12px;line-height:16px}
.hw-facts dt{color:var(--hw-ink3)}
.hw-facts dd{margin:0;min-width:0;color:var(--hw-ink1);overflow-wrap:anywhere}
.hw-unverified{padding:10px 12px;border-radius:8px;background:var(--hw-fill2);box-shadow:inset 0 0 0 .5px var(--hw-line1);display:flex;flex-direction:column;gap:6px}
.hw-unverified b{font-size:12px;color:#e5a83b}
.hw-unverified pre{margin:0;white-space:pre-wrap;overflow-wrap:anywhere;font-family:var(--hw-mono);font-size:11px;line-height:15px;color:var(--hw-ink2)}
.hw-gate-open{padding:12px;border-radius:8px;background:var(--hw-fill1);box-shadow:inset 0 0 0 .5px var(--hw-line1);display:flex;flex-direction:column;gap:10px}
.hw-decisions{list-style:none;margin:0;padding:0;display:grid;gap:4px;font-size:12px;line-height:16px;color:var(--hw-ink2)}
.hw-link{display:flex;align-items:center;gap:12px;width:100%;min-height:32px;padding:8px 16px;border:0;border-top:.5px solid var(--hw-line3);background:transparent;color:var(--hw-ink1);font:inherit;text-align:left;cursor:pointer}
.hw-list>li:first-child .hw-link{border-top:0;border-radius:10px 10px 0 0}
.hw-list>li:last-child .hw-link{border-radius:0 0 10px 10px}
.hw-link:hover{background:var(--hw-fill2)}
.hw-link span{flex:1 1 auto;min-width:0}
.hw-link .hw-i{color:var(--hw-ink2)}
.hw-btn:focus-visible,.hw-link:focus-visible,.hw-more summary:focus-visible{outline:1px solid var(--hw-accent);outline-offset:-1px}
.hw-more summary{list-style:none;display:flex;align-items:center;gap:8px;min-height:32px;padding:6px 12px;border-radius:10px;color:var(--hw-ink2);font-weight:500;cursor:pointer}
.hw-more summary::-webkit-details-marker{display:none}
.hw-more summary:hover{color:var(--hw-ink1)}
.hw-more summary .hw-i{color:var(--hw-ink3)}
.hw-more[open] summary .hw-i{transform:rotate(90deg)}
.hw-notes{padding:4px 16px 16px 36px;display:grid;gap:16px}
.hw-notes h3{margin:0 0 4px;font-size:12px;line-height:16px;font-weight:600;color:var(--hw-ink1)}
.hw-notes ul,.hw-notes p{margin:0;font-size:12px;line-height:16px;color:var(--hw-ink2)}
.hw-notes ul{padding-left:16px;display:grid;gap:4px}
`;
// React 19 hoists and de-duplicates this sheet by href.
const sheet = () => jsx('style', {href:'hunt-command-workspace-ui', precedence:'default', children:CSS});
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
  monitor: [['rect',{width:20,height:14,x:2,y:3,rx:2}],['line',{x1:8,x2:16,y1:21,y2:21}],['line',{x1:12,x2:12,y1:17,y2:21}]],
  chevronDown: [['path',{d:'m6 9 6 6 6-6'}]],
  chevronRight: [['path',{d:'m9 18 6-6-6-6'}]],
  flaskConical: [['path',{d:'M14 2v6a2 2 0 0 0 .245.96l5.51 10.08A2 2 0 0 1 18 22H6a2 2 0 0 1-1.755-2.96l5.51-10.08A2 2 0 0 0 10 8V2'}],['path',{d:'M6.453 15h11.094'}],['path',{d:'M8.5 2h7'}]],
  list: [['path',{d:'M3 5h.01'}],['path',{d:'M3 12h.01'}],['path',{d:'M3 19h.01'}],['path',{d:'M8 5h13'}],['path',{d:'M8 12h13'}],['path',{d:'M8 19h13'}]],
  layoutGrid: [['rect',{width:7,height:7,x:3,y:3,rx:1}],['rect',{width:7,height:7,x:14,y:3,rx:1}],['rect',{width:7,height:7,x:14,y:14,rx:1}],['rect',{width:7,height:7,x:3,y:14,rx:1}]],
  users: [['path',{d:'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2'}],['path',{d:'M16 3.128a4 4 0 0 1 0 7.744'}],['path',{d:'M22 21v-2a4 4 0 0 0-3-3.87'}],['circle',{cx:9,cy:7,r:4}]],
  globe: [['circle',{cx:12,cy:12,r:10}],['path',{d:'M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20'}],['path',{d:'M2 12h20'}]],
  messageSquare: [['path',{d:'M22 17a2 2 0 0 1-2 2H6.828a2 2 0 0 0-1.414.586l-2.202 2.202A.71.71 0 0 1 2 21.286V5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2z'}]]
};
const icon = name => jsx('svg', {className:'hw-i', width:16, height:16, viewBox:'0 0 24 24', fill:'none', stroke:'currentColor', strokeWidth:1.5,
  strokeLinecap:'round', strokeLinejoin:'round', 'aria-hidden':true, focusable:'false',
  children:ICONS[name].map(([tag, attributes], index) => jsx(tag, attributes, index))});
const heading = (title, aside) => jsx('div', {className:'hw-h', children:[title, aside ? jsx('span', {className:'hw-aside', children:aside}, 'aside') : null]});
const SCREEN_PROFILE_IDS = new Set(ROLES.map(([, id]) => id));
const screenState = atom({ routes: [], selected: '', message: '' });
const routeKey = route => JSON.stringify([route.connectionId, route.mode, route.profile, route.targetProfile]);
function ScreenSelector() {
  const state = useValue(screenState);
  const discover = async () => {
    if (typeof host.profileRoutes !== 'function') {
      screenState.set({...screenState.get(),routes:[],selected:'',message:'Connection-scoped profile discovery is unavailable in this Desktop build.'});
      return;
    }
    let autoRoute = null;
    try {
      const routes = (await host.profileRoutes()).filter(route =>
        SCREEN_PROFILE_IDS.has(route.targetProfile)
      );
      const localMatches = routes.filter(route => route && route.mode === 'local'
        && typeof route.connectionId === 'string' && route.connectionId.trim()
        && typeof route.profile === 'string' && route.profile.trim());
      const uniqueLocal = route => localMatches.filter(other => other.targetProfile === route.targetProfile).length === 1;
      autoRoute = localMatches.length === 1
        ? localMatches[0]
        : (localMatches.find(route => route.targetProfile === 'framework-coordinator' && uniqueLocal(route)) || null);
      const autoSelected = autoRoute ? routeKey(autoRoute) : '';
      screenState.set({
        routes,
        selected:autoSelected,
        message:autoRoute
          ? `Selected ${autoRoute.targetProfile}; reading screen status…`
          : routes.length ? 'Choose one exact registered connection/profile route.' : 'No registered framework profile routes were found.'
      });
    } catch {
      screenState.set({...screenState.get(),routes:[],selected:'',message:'Registered connection/profile routes could not be read. No fallback was attempted.'});
      return;
    }
    if (autoRoute && typeof host.requestProfile === 'function') {
      try {
        const snapshot = await host.requestProfile(autoRoute, 'display.status', {}, 15000, { spawnPriority: 'foreground' });
        const statusWord = typeof snapshot?.state === 'string' && snapshot.state ? snapshot.state : 'ready';
        if (screenState.get().selected === routeKey(autoRoute)) {
          screenState.set({...screenState.get(),message:`Selected ${autoRoute.targetProfile} · screen ${statusWord}.`});
        }
      } catch {
        if (screenState.get().selected === routeKey(autoRoute)) {
          screenState.set({...screenState.get(),message:`Selected ${autoRoute.targetProfile} · status unavailable; click Open screen to inspect.`});
        }
      }
    }
  };
  const open = async () => {
    const current = screenState.get();
    const route = current.routes.find(candidate => routeKey(candidate) === current.selected);
    if (!route) {
      screenState.set({...current,message:'Select a registered connection and profile first.'});
      return;
    }
    if (typeof host.openScreen !== 'function') {
      screenState.set({...current,message:'Native Screen opening is unavailable. Update Hermes Desktop; no alternate viewer was used.'});
      return;
    }
    let result;
    try {
      result = await host.openScreen(route);
    } catch {
      screenState.set({...screenState.get(),message:'Native Screen opening failed. No fallback was attempted.'});
      return;
    }
    const messages = {
      opened:'Native Bot Screen opened for the selected connection/profile.',
      action_failed:'Native Screen could not open. No alternate host or viewer was used.',
      connection_missing:'The selected connection was removed. Choose a currently registered route.',
      plugin_disabled:'The bundled Bot Screen provider is disabled.',
      provider_unavailable:'The bundled Bot Screen provider is unavailable in this Desktop build.',
      route_ambiguous:'The selected route is ambiguous. Refresh the registered route list.',
      route_not_registered:'The selected route is no longer registered. Refresh before opening.',
      unsupported_version:'This Hermes Desktop version does not support native Screen opening.'
    };
    screenState.set({...screenState.get(),message:messages[result?.status] || 'Native Screen opening failed.'});
  };
  const selected = state.routes.find(route => routeKey(route) === state.selected);
  return jsx('section', {'aria-label':'Bot screen', children:[
    heading('Bot screen', jsx('button', {type:'button', className:'hw-btn sm', onClick:discover, children:'Find profiles'})),
    jsx('div', {className:'hw-box hw-screen', children:[
      jsx('div', {className:'hw-label', children:'Connection / profile'}, 'label'),
      jsx('div', {className:'hw-select', children:[
        jsx('span', {className:'hw-select-t', children:selected
          ? jsx('span', {className:'hw-mono', children:`${selected.profile} · ${selected.connectionId} → ${selected.targetProfile}`})
          : jsx('span', {style:{color:'var(--hw-ink3)', fontSize:'13px'}, children:state.routes.length ? 'Select a route' : 'No route yet: click Find profiles'})}, 'shown'),
        jsx('select', {'aria-label':'Connection / profile', value:state.selected, onChange:event=>screenState.set({...screenState.get(),selected:event.target.value}), children:[
          jsx('option', {value:'', children:'Select a route'}, 'empty'),
          ...state.routes.map(route=>jsx('option', {value:routeKey(route), children:`${route.connectionId} · ${route.profile} → ${route.targetProfile}`}, routeKey(route)))
        ]}, 'select'),
        jsx('span', {children:icon('chevronDown')}, 'chevron')
      ]}, 'select'),
      jsx('div', {className:'hw-row', children:[
        jsx('button', {type:'button', className:'hw-btn', onClick:open, 'data-cyber-action':'open-screen', children:[icon('monitor'), 'Open screen']}, 'open'),
        jsx('p', {className:'hw-status', role:'status', 'aria-live':'polite', children:state.message || 'From host.profileRoutes'}, 'status')
      ]}, 'actions')
    ]})
  ]});
}
const SAFE_LOOPBACK = /^127\.0\.0\.1:([1-9]\d{0,4})$/;
const SAFE_WORKFLOW = /^[A-Za-z0-9._:-]{1,128}$/;
function validLoopback(raw) {
  const value = String(raw || '127.0.0.1:7233').trim();
  const match = SAFE_LOOPBACK.exec(value);
  if (!match) return null;
  const port = Number(match[1]);
  return Number.isInteger(port) && port >= 1 && port <= 65535 ? `127.0.0.1:${port}` : null;
}
function validOperator(raw) {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 200) return null;
  for (let index = 0; index < trimmed.length; index += 1) {
    const code = trimmed.charCodeAt(index);
    if (code < 0x20 || code === 0x7f) return null;
  }
  return trimmed.replace(/ +/g, ' ');
}
function validNote(raw) {
  if (typeof raw !== 'string') return null;
  const normalized = raw.trim().replace(/\r\n/g, '\n');
  if (!normalized || normalized.length > 1000) return null;
  for (let index = 0; index < normalized.length; index += 1) {
    const code = normalized.charCodeAt(index);
    if ((code < 0x20 && code !== 0x09 && code !== 0x0a) || code === 0x7f) return null;
  }
  return normalized;
}
const INITIAL_GATE_MESSAGE = 'Enter a Temporal workflow ID and click Load gate status to review or decide open human gates.';
const INITIAL_GATE_STATE = Object.freeze({
  address: '127.0.0.1:7233',
  workflowId: '',
  operatorName: '',
  checkNote: '',
  busy: false,
  status: null,
  message: INITIAL_GATE_MESSAGE
});
const gateState = atom({ ...INITIAL_GATE_STATE });
// Track monotonic handoff sequence numbers via nanostores rather than importing react hooks,
// because framework/desktop/test-plugin.mjs links only @hermes/plugin-sdk and react/jsx-runtime.
let consumedHandoffSeq = 0;
let consumedLegacyKey = '';
let gateRequestSeq = 0;
function exactLoopback(raw) {
  return typeof raw === 'string' && raw.trim() ? validLoopback(raw) : null;
}
function applyHandoffTarget(nextWorkflowId, nextAddress) {
  const latest = gateState.get();
  const workflowId = nextWorkflowId || latest.workflowId;
  const address = nextAddress || latest.address || '127.0.0.1:7233';
  if (workflowId === latest.workflowId && address === latest.address) return;
  gateRequestSeq += 1;
  gateState.set({
    ...latest,
    workflowId,
    address,
    busy: false,
    status: null,
    message: workflowId
      ? `Ready to inspect ${workflowId} on ${address}. Click Load gate status.`
      : INITIAL_GATE_MESSAGE
  });
}
function syncWorkflowHandoff() {
  if (typeof globalThis === 'undefined') return;
  const raw = globalThis.__HUNT_COMMAND_HANDOFF__;
  if (!raw) consumedHandoffSeq = 0;
  if (raw && typeof raw === 'object' && Number.isInteger(raw.seq) && raw.seq > 0) {
    if (raw.seq !== consumedHandoffSeq) {
      consumedHandoffSeq = raw.seq;
      const wf = typeof raw.workflowId === 'string' && SAFE_WORKFLOW.test(raw.workflowId.trim()) ? raw.workflowId.trim() : '';
      const addr = validLoopback(raw.address) || '127.0.0.1:7233';
      applyHandoffTarget(wf, addr);
    }
    return;
  }
  const legacyWf = typeof globalThis.__HUNT_COMMAND_WORKFLOW_ID__ === 'string'
    && SAFE_WORKFLOW.test(globalThis.__HUNT_COMMAND_WORKFLOW_ID__.trim())
    ? globalThis.__HUNT_COMMAND_WORKFLOW_ID__.trim()
    : '';
  const legacyAddr = typeof globalThis.__HUNT_COMMAND_TEMPORAL_ADDRESS__ === 'string'
    ? (validLoopback(globalThis.__HUNT_COMMAND_TEMPORAL_ADDRESS__) || '')
    : '';
  if (!legacyWf && !legacyAddr) {
    consumedLegacyKey = '';
    return;
  }
  const legacyKey = `${legacyWf}@${legacyAddr}`;
  if (legacyKey !== consumedLegacyKey) {
    consumedLegacyKey = legacyKey;
    applyHandoffTarget(legacyWf, legacyAddr || '127.0.0.1:7233');
  }
}
if (typeof globalThis !== 'undefined') {
  globalThis.__HUNT_COMMAND_ON_HANDOFF__ = () => syncWorkflowHandoff();
}
function factRows(items) {
  return jsx('dl', {className:'hw-facts', children:items.flatMap(([term, value]) => [
    jsx('dt', {children:term}, `${term}-dt`),
    jsx('dd', {children:value}, `${term}-dd`)
  ])}, 'facts');
}
function HumanGatesPanel() {
  syncWorkflowHandoff();
  const current = useValue(gateState);
  const updateTargetFields = patch => {
    const latest = gateState.get();
    const nextAddress = Object.prototype.hasOwnProperty.call(patch, 'address') ? patch.address : latest.address;
    const nextWorkflowId = Object.prototype.hasOwnProperty.call(patch, 'workflowId') ? patch.workflowId : latest.workflowId;
    const matchesLoaded = Boolean(
      latest.status
      && exactLoopback(nextAddress) === latest.status.address
      && String(nextWorkflowId || '').trim() === latest.status.workflowId
    );
    gateRequestSeq += 1;
    gateState.set({
      ...latest,
      address: nextAddress,
      workflowId: nextWorkflowId,
      busy: false,
      status: matchesLoaded ? latest.status : null,
      message: matchesLoaded ? latest.message : INITIAL_GATE_MESSAGE
    });
  };
  const loadStatus = async () => {
    syncWorkflowHandoff();
    const latest = gateState.get();
    if (latest.busy) return;
    if (!host.huntWorkbench || typeof host.huntWorkbench.gateStatus !== 'function') {
      gateState.set({...latest,message:'Local Temporal gate workbench is unavailable in this Desktop build.'});
      return;
    }
    const workflowId = latest.workflowId.trim();
    const address = validLoopback(latest.address);
    if (!address) {
      gateState.set({...latest,message:'Temporal address must stay on 127.0.0.1:<port>.'});
      return;
    }
    if (!SAFE_WORKFLOW.test(workflowId)) {
      gateState.set({...latest,address,workflowId,message:'Enter a valid workflow ID (for example practice-dns-001) first.'});
      return;
    }
    const reqSeq = ++gateRequestSeq;
    gateState.set({...latest,address,workflowId,busy:true,message:`Querying Temporal workflow ${workflowId} on ${address}…`});
    try {
      const reply = await host.huntWorkbench.gateStatus({ address, workflowId });
      if (reqSeq !== gateRequestSeq) return;
      if (!reply?.ok || !reply.status) {
        gateState.set({...gateState.get(),busy:false,status:null,message:reply?.error || 'Could not query Temporal workflow status.'});
        return;
      }
      const openLabel = reply.status.openGate ? reply.status.openGate.label : `No open human gate (${reply.status.stage || 'idle'})`;
      gateState.set({...gateState.get(),busy:false,status:reply.status,message:`Loaded ${workflowId}: ${openLabel}.`});
    } catch {
      if (reqSeq !== gateRequestSeq) return;
      gateState.set({...gateState.get(),busy:false,status:null,message:'Temporal gate status query failed.'});
    }
  };
  const submitDecision = async choice => {
    const latest = gateState.get();
    const status = latest.status;
    const openGate = status?.openGate;
    if (latest.busy || !status || !openGate) return;
    if (!host.huntWorkbench || typeof host.huntWorkbench.decideGate !== 'function') {
      gateState.set({...latest,message:'Local Temporal gate decision runner is unavailable in this Desktop build.'});
      return;
    }
    const editedAddress = exactLoopback(latest.address);
    if (!editedAddress || editedAddress !== status.address || latest.workflowId.trim() !== status.workflowId) {
      gateState.set({...latest,status:null,message:'Target workflow or loopback address changed. Click Load gate status before deciding.'});
      return;
    }
    const operatorName = validOperator(latest.operatorName);
    if (!operatorName) {
      gateState.set({...latest,message:'Enter your operator name (1-200 printable characters) before approving or rejecting.'});
      return;
    }
    const checkNote = validNote(latest.checkNote);
    if (!checkNote) {
      gateState.set({...latest,message:'Complete "What did you check?" (1-1000 characters) before recording a human gate decision.'});
      return;
    }
    if (!status.childWorkflowId) {
      gateState.set({...latest,message:'No active round workflow ID is attached to receive this decision.'});
      return;
    }
    const reqSeq = ++gateRequestSeq;
    gateState.set({...latest,busy:true,message:`Recording ${choice} decision on ${openGate.stepId} (${openGate.phase})…`});
    let reply;
    try {
      reply = await host.huntWorkbench.decideGate({
        address: status.address,
        childWorkflowId: status.childWorkflowId,
        stepId: openGate.stepId,
        phase: openGate.phase,
        choice,
        operatorName,
        checkNote
      });
    } catch {
      if (reqSeq === gateRequestSeq) {
        gateState.set({...gateState.get(),busy:false,message:'Human gate decision failed.'});
      }
      return;
    }
    if (reqSeq !== gateRequestSeq) return;
    if (!reply?.ok) {
      gateState.set({...gateState.get(),busy:false,message:reply?.error || 'Human gate decision failed.'});
      return;
    }
    const safeGateStatus = async workflowId => {
      try {
        return await host.huntWorkbench.gateStatus({ address: status.address, workflowId });
      } catch {
        return null;
      }
    };
    // A PracticeWorkflow parent re-resolves its *current* round, which may already be N+1;
    // only the child that received the signal can confirm the decision was recorded.
    const confirmed = await safeGateStatus(status.childWorkflowId);
    if (reqSeq !== gateRequestSeq) return;
    const recorded = Boolean(
      reply.decisionId
      && confirmed?.ok
      && Array.isArray(confirmed.status?.decisions)
      && confirmed.status.decisions.some(item => item && item.decisionId === reply.decisionId)
    );
    const refreshed = status.childWorkflowId === status.workflowId ? confirmed : await safeGateStatus(status.workflowId);
    if (reqSeq !== gateRequestSeq) return;
    const recordedMessage = `Recorded ${choice} by ${reply.decidedBy || operatorName} via cli (${reply.decisionId})`;
    if (!refreshed?.ok || !refreshed.status) {
      gateState.set({
        ...gateState.get(),
        busy: false,
        checkNote: '',
        status: null,
        message: recorded
          ? `${recordedMessage}, but workflow refresh failed. Click Load gate status before deciding again.`
          : 'Decision signal sent, but workflow refresh failed. Click Load gate status before deciding again.'
      });
      return;
    }
    gateState.set({
      ...gateState.get(),
      busy: false,
      checkNote: recorded ? '' : gateState.get().checkNote,
      status: refreshed.status,
      message: recorded
        ? `${recordedMessage}.`
        : `Decision signal sent (${reply.decisionId || 'unconfirmed'}), but ${reply.decisionId || 'decision'} was not recorded in workflow state.`
    });
  };
  const status = current.status;
  const openGate = status?.openGate || null;
  const syntheticAllowed = Boolean(status && status.syntheticOnly === true && status.dataOrigin === 'synthetic');
  const targetMatchesStatus = Boolean(
    status
    && exactLoopback(current.address) === status.address
    && current.workflowId.trim() === status.workflowId
  );
  const readyToDecide = !current.busy && targetMatchesStatus && Boolean(openGate && validOperator(current.operatorName) && validNote(current.checkNote));
  const choices = Array.isArray(openGate?.choices) ? openGate.choices : [];
  const approveChoice = choices.includes('accept') ? 'accept' : 'approve';
  const rejectChoice = choices.includes('abort') ? 'abort' : 'deny';
  const approveLabel = approveChoice === 'accept' ? 'Accept reconciliation' : 'Approve gate';
  const rejectLabel = rejectChoice === 'abort' ? 'Abort round' : 'Reject gate';
  return jsx('div', {className:'hw-box hw-gate', 'aria-label':'Live human gate controls', children:[
    jsx('div', {className:'hw-gate-fields', children:[
      jsx('input', {
        type:'text', className:'hw-input', 'aria-label':'Temporal loopback address', placeholder:'127.0.0.1:7233',
        style:{width:'148px'}, value:current.address, disabled:current.busy,
        onChange:event=>updateTargetFields({address:event.target.value})
      }, 'addr'),
      jsx('input', {
        type:'text', className:'hw-input', 'aria-label':'Workflow ID', placeholder:'Workflow ID (e.g. practice-dns-001)',
        style:{flex:'1 1 220px'}, value:current.workflowId, disabled:current.busy,
        onChange:event=>updateTargetFields({workflowId:event.target.value})
      }, 'wid'),
      jsx('button', {
        type:'button', className:'hw-btn sm primary', onClick:loadStatus, disabled:current.busy,
        'data-cyber-action':'load-gate-status', children:status ? 'Refresh gate status' : 'Load gate status'
      }, 'load')
    ]}, 'query'),
    jsx('p', {className:'hw-status', role:'status', 'aria-live':'polite', children:current.message}, 'msg'),
    status ? factRows([
      ['Workflow', jsx('span', {className:'hw-mono', children:`${status.workflowId}${status.childWorkflowId && status.childWorkflowId !== status.workflowId ? ` → ${status.childWorkflowId}` : ''}`})],
      ['Case / origin', jsx('span', {className:'hw-mono', children:`${status.caseId || 'not reported'} · origin=${status.dataOrigin}`})],
      ['Stage', jsx('span', {className:'hw-mono', children:`${status.stage || 'unknown'}${status.temporalStatus ? ` (${status.temporalStatus})` : ''}`})],
      ['Visibility rule', syntheticAllowed
        ? 'Synthetic case verified: unverified bot handoff summary may be previewed below.'
        : 'ID-and-status view only: bot-written summaries are withheld for non-synthetic data origins (public-dataset, work-export, work-connected).']
    ]) : null,
    syntheticAllowed && status?.unverifiedBotSummary ? jsx('div', {className:'hw-unverified', children:[
      jsx('b', {children:'Bot-written, unverified:'}, 'label'),
      jsx('pre', {children:status.unverifiedBotSummary}, 'body')
    ]}, 'summary') : null,
    openGate ? jsx('div', {className:'hw-gate-open', children:[
      jsx('b', {children:`${openGate.label} · step=${openGate.stepId} (${openGate.phase})`}, 'gtitle'),
      jsx('div', {className:'hw-label', children:'Human gates (scope and incident) are never auto-approved. Enter your operator identity and what you verified against primary lab evidence.'}, 'gnote'),
      jsx('input', {
        type:'text', className:'hw-input', 'aria-label':'Operator name', placeholder:'Operator name (required, 1-200 chars)',
        value:current.operatorName, disabled:current.busy,
        onChange:event=>gateState.set({...gateState.get(),operatorName:event.target.value})
      }, 'op'),
      jsx('textarea', {
        className:'hw-textarea', 'aria-label':'What did you check?',
        placeholder:'What did you check? Cite concrete event IDs, scope boundaries, or evidence verified (required, 1-1000 chars)',
        value:current.checkNote, disabled:current.busy,
        onChange:event=>gateState.set({...gateState.get(),checkNote:event.target.value})
      }, 'note'),
      jsx('div', {className:'hw-row', children:[
        jsx('button', {
          type:'button', className:'hw-btn primary', disabled:!readyToDecide,
          'data-cyber-action':'approve-gate', onClick:()=>submitDecision(approveChoice),
          children:approveLabel
        }, 'approve'),
        jsx('button', {
          type:'button', className:'hw-btn danger', disabled:!readyToDecide,
          'data-cyber-action':'reject-gate', onClick:()=>submitDecision(rejectChoice),
          children:rejectLabel
        }, 'reject')
      ]}, 'btns')
    ]}, 'open') : null,
    status && Array.isArray(status.decisions) && status.decisions.length ? jsx('div', {children:[
      jsx('div', {className:'hw-label', children:'Recorded gate decisions'}, 'dlabel'),
      jsx('ul', {className:'hw-decisions', children:status.decisions.map((item, idx) => jsx('li', {
        className:'hw-mono',
        children:`${item.stepId} (${item.phase}): ${item.decision} · decided_by=${item.decidedBy || 'unknown'} · via=${item.via || 'cli'}`
      }, item.decisionId || `${item.stepId}-${idx}`))}, 'dlist')
    ]}, 'decisions') : null
  ]});
}
const quickLink = (glyph, label, onClick, extra = {}) => jsx('li', {children:jsx('button', {type:'button', className:'hw-link', onClick, ...extra,
  children:[icon(glyph), jsx('span', {children:label}, 'label'), icon('chevronRight')]})}, label);
const notes = (title, items) => jsx('div', {children:[
  jsx('h3', {children:title}, 'title'),
  jsx('ul', {children:items.map(item=>jsx('li', {children:item}, item))}, 'items')
]}, title);
function workspace(ctx) {
  const run = id => {
    if (typeof ctx.runAction !== 'function') {
      host.notify({kind:'error',message:'This Hermes release does not expose the required SDK action.'}); return;
    }
    const result = ctx.runAction(id);
    if (!result?.ok) host.notify({kind:'error',message:`Native action unavailable: ${result?.reason || 'unsupported'}. No fallback was attempted.`});
  };
  return jsx('div', {className:'hw', 'data-cyber-workspace':'v1', children:[sheet(),
    jsx('header', {className:'hw-bar', children:[
      jsx('h1', {className:'hw-title', children:'Cybersecurity workspace'}, 'title'),
      jsx('span', {className:'hw-sub', children:'Supplied-evidence workbench. Human gates record explicit loopback Temporal CLI decisions.'}, 'sub')
    ]}),
    jsx('div', {className:'hw-body', children:jsx('div', {className:'hw-page', children:[
      jsx('section', {'aria-label':'Human-controlled gates', children:[
        heading('Human-controlled gates', 'governed scope & incident review — never auto-approved'),
        jsx('ol', {className:'hw-box hw-steps', 'aria-label':'Gate order', children:GATES.map(([name,detail],index)=>jsx('li', {className:'hw-step', children:[
          jsx('b', {children:[jsx('span', {children:String(index+1)}, 'n'), name]}, 'name'),
          jsx('p', {children:detail}, 'detail')
        ]}, name))}, 'order'),
        jsx(HumanGatesPanel, {}, 'live-gates')
      ]}, 'gates'),
      jsx('div', {className:'hw-grid', children:[
        jsx('section', {'aria-label':'Team', children:[
          heading('Team', `${ROLES.length} roles → profiles`),
          jsx('ul', {className:'hw-box hw-list', children:ROLES.map(([title,id,scope,monogram])=>jsx('li', {className:'hw-li', children:[
            jsx('span', {className:'hw-mg', 'aria-hidden':true, children:monogram}, 'mg'),
            jsx('div', {className:'hw-who', children:[jsx('b', {children:title}, 'b'), jsx('code', {children:id}, 'c')]}, 'who'),
            jsx('div', {className:'hw-remit', title:scope, children:scope}, 'remit')
          ]}, id))})
        ]}, 'team'),
        jsx('div', {className:'hw-col', children:[
          jsx(ScreenSelector, {}, 'screen'),
          jsx('section', {'aria-label':'Quick links', children:[
            heading('Quick links'),
            jsx('ul', {className:'hw-box hw-list', children:[
              quickLink('flaskConical', 'Open hunting lab', ()=>host.navigate('/hunt-lab')),
              quickLink('list', 'Open hunt board', ()=>host.navigate('/hunt-board')),
              quickLink('layoutGrid', 'Open native Kanban', ()=>host.navigate('/kanban')),
              quickLink('users', 'Open native profile manager', ()=>run('nav.profiles')),
              quickLink('globe', 'Open in-app browser', ()=>run('view.showBrowser')),
              quickLink('messageSquare', 'Show gate reminder on the pet', ()=>{
                if (!ctx.pet?.visible) {host.notify({kind:'info',message:'No visible native pet. No asset was installed or changed.'});return;}
                ctx.pet.say('Execution is not approval. Human gates remain in control.',{id:'human-gates',tone:'wait',ttlMs:6000});
              },{'data-cyber-action':'pet'})
            ]})
          ]}, 'links')
        ]}, 'side')
      ]}, 'grid'),
      jsx('details', {className:'hw-box hw-more', children:[
        jsx('summary', {children:[icon('chevronRight'), 'Notes and limits']}, 'summary'),
        jsx('div', {className:'hw-notes', children:[
          jsx('p', {children:'Board transitions and successful execution never count as human approval. Knowledge and memory promotion need a separate human decision; nothing is written to trusted memory automatically.'}, 'gates'),
          notes('Bot screen', [
            'Opens the native Bot Screen for one exact registered route. It does not show or start the Hunting Lab; lab state is unknown here.',
            'Opening an already-running screen attaches live frames; revealing an existing tab may retain its current control lease.',
            'Starting, taking over, handing back and pasting remain separate native user actions.'
          ]),
          notes('How to use these surfaces', [
            'Hunting Lab: a separate human-operated page owns the local analyst-profile lab, run as host Docker containers. Navigating there does not start anything.',
            'Explicit Start loads one case into a fresh container project; Stop removes it. Status does not install, repair or start anything.',
            'The lab page shows the real container lab state and links to the lab console, Kibana and Arkime, never Bot Screen.',
            'Lab start and stop are deliberate human actions, not advisory ledger gates or model permissions. No provider or model call is needed to operate the lab.',
            'The Network Analyst keeps its existing SOUL restrictions: only bounded approved synthetic summaries through the read-only lab tool, never Arkime controls or raw captures.',
            'Kanban: inspect only. Do not add runnable research cards or enable dispatcher workers here. Native Kanban can run agents; it is not the human-operated ledger. This plugin has no task-write capability in its code.',
            'Browser: use an approved public page or synthetic local document only. Never inspect account pages, headers, cookies, credentials, authentication payloads or session data. No browser observation is automatic.',
            'HUD: use the native titlebar control or your bound Toggle HUD action only above an approved synthetic document. The SDK intentionally does not allow toggleHud; no synthetic shortcuts or underlying-window reads are used here.',
            'Memory graph: use the native command palette Memory graph entry (or /memory-graph) for a human-reviewed profile. This page\'s gate guide is NOT native memory and reads none. Do not infer trust or approval from graph edges.',
            'Pets are optional status mascots, never evidence or approval. Choose reviewed assets in native Appearance settings; no catalog asset or image-generation backend is installed by this plugin.'
          ]),
          notes('Model routes and known failures', [
            'Required native routes, provider anthropic: Incident Response Lead and Purple Team Analyst on claude-opus-5-5; Threat Hunter, Detection Engineer, Threat Intelligence Analyst and Network Analyst on claude-sonnet-5-5.',
            'These are requirements, NOT live verification. No fallback or model substitution is authorized.',
            'Known completion-role-label inconsistency: a delegating coordinator completion may display leaf despite nested delegation.',
            'Child-reported identity limits: leaf route reports are not independent attestation of upstream model internals. Require actual route/status evidence for each new run.',
            'runtime_draining and profile_mismatch must remain visible failures. Do not retry inference blindly, disable profile guards, reset profiles or delete databases.',
            'Source diagnostics are not proof of a repaired live exchange.'
          ]),
          notes('Boundaries', [
            'OMP is development-only, never a product runtime dependency.',
            'This companion performs no collection, telemetry, scanning, capture, Arkime connection, adversary emulation, remediation, trading, external messaging or schedules.',
            'Navigating to Hunting Lab does not start the lab; human lifecycle controls there are distinct from these advisory gates.',
            'This plugin makes no model calls, reads no conversations or memory, changes no specialist safeguards, and records human gate decisions only on explicit operator approval or rejection over loopback Temporal.',
            'It cannot enforce other tools or plugins; profiles and role instructions are not sandboxes.'
          ])
        ]}, 'notes')
      ]}, 'more')
    ]})})
  ]});
}
export default {
  id:'cybersecurity-workspace', name:'Cybersecurity workspace', defaultEnabled:true,
  register(ctx) {
    consumedHandoffSeq = 0;
    consumedLegacyKey = '';
    gateRequestSeq += 1;
    screenState.set({ routes: [], selected: '', message: '' });
    gateState.set({ ...INITIAL_GATE_STATE });
    if (typeof globalThis !== 'undefined') {
      globalThis.__HUNT_COMMAND_ON_HANDOFF__ = () => syncWorkflowHandoff();
    }
    syncWorkflowHandoff();
    ctx.register({id:'workspace',area:ROUTES_AREA,data:{path:'/cybersecurity-workspace'},render:()=>workspace(ctx)});
    ctx.register({id:'nav',area:SIDEBAR_NAV_AREA,data:{path:'/cybersecurity-workspace',label:'Cybersecurity workspace',codicon:'shield'}});
    ctx.register({id:'open',area:PALETTE_AREA,data:{id:'cybersecurity-workspace.open',label:'Open cybersecurity workspace',run:()=>host.navigate('/cybersecurity-workspace')}});
    ctx.register({id:'gates',area:'statusBar.right',render:()=>jsx(Button,{variant:'ghost',size:'sm',onClick:()=>host.navigate('/cybersecurity-workspace'),children:'Human gates'})});
  }
};
