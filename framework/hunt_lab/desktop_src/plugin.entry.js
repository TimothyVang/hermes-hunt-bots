import { atom, host, useValue, Button, SandboxedFrame, ROUTES_AREA, SIDEBAR_NAV_AREA, PALETTE_AREA } from '@hermes/plugin-sdk';
import { jsx } from 'react/jsx-runtime';

const PROFILES = new Set([
  'framework-network-analyst'
]);
const PAGE = '/hunt-lab';
const state = atom({ routes: [], selected: '', busy: false, result: null, code: null, message: 'Find local framework profiles, then choose the exact VM owner. No VM is started on page load.' });
const key = route => JSON.stringify([route.connectionId, route.mode, route.profile, route.targetProfile]);
const style = { padding: '16px', height: '100%', overflow: 'auto', color: 'var(--ui-text-primary)' };
const card = { border: '1px solid var(--ui-stroke-secondary)', borderRadius: '8px', padding: '12px', marginBottom: '12px' };
const muted = { color: 'var(--ui-text-secondary)' };
const p = text => jsx('p', { style: muted, children: text });
const button = (label, onClick, disabled) => jsx(Button, { onClick, disabled, children: label });

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
  state.set({ ...state.get(), busy: true, result: null, code: null, selected: '', routes: [], message: 'Reading registered local routes…' });
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
      state.set({ ...state.get(), result, code: reply.code,
        message: `status: ${result.state}${result.reason ? ` — ${result.reason}` : ''} (CLI exit ${reply.code}).` });
      if (reply.code !== 0 || !['preparing', 'starting'].includes(result.state)) return;
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
    state.set({ ...current, result: null, code: null, message: 'Select an unambiguous local framework route first.' });
    return;
  }
  const token = ++observation;
  state.set({ ...current, busy: true, result: null, code: null, message: `Requesting ${operation} for ${route.targetProfile}…` });
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
    state.set({ ...state.get(), result, code: reply.code, message: `${operation}: ${result.state}${result.reason ? ` — ${result.reason}` : ''} (CLI exit ${reply.code}).${reply.code !== 0 ? ' Operation failed; no retry or alternate host was attempted.' : ''}` });
    if (reply.code === 0 && ['prepare', 'start'].includes(operation)
      && ['preparing', 'starting'].includes(result.state)) void observeSetup(route, token);
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

function services(current) {
  const owner = current.routes.find(route => key(route) === current.selected)?.targetProfile;
  const result = current.result;
  if (!result || result.profile !== owner) return [p('No validated status for the selected profile. Refresh status explicitly.')];
  const details = [p(`Owner: ${result.profile} · VM: ${result.vm_name ?? 'not reported'} · State: ${result.state} · Reason: ${result.reason ?? 'none'} · CLI exit: ${current.code}`),
    p(`PID: ${result.pid ?? 'not reported'} · Memory MiB: ${result.memory_mib ?? 'not reported'} · Acceleration: ${result.accel ?? 'not reported'}`)];
  if (result.setup && typeof result.setup.stage === 'string') {
    details.push(p(`Setup stage: ${result.setup.stage} · Prepared: ${result.prepared === true ? 'yes' : 'no'}${result.setup.reason ? ` · ${result.setup.reason}` : ''}`));
  }
  if (current.code !== 0 || result.state !== 'running') {
    return [...details, p('Guest service links and console are hidden until a successful running status for this owner is returned.')];
  }
  for (const [label, value] of [['Read-only hunting lab', result.lab_url], ['Arkime', result.arkime_url]]) {
    const url = loopbackUrl(value);
    details.push(url ? jsx('p', { children: jsx('a', { href: url, target: '_blank', rel: 'noopener noreferrer', children: `Open ${label}` }) })
      : p(`${label}: no validated loopback HTTP endpoint reported.`));
  }
  const consoleUrl = consoleFrameUrl(result.console_websocket_url);
  if (consoleUrl) {
    details.push(p('Real QEMU boot console for this profile-owned VM, available independently of guest HTTP readiness. Click the display to send keyboard and pointer input to the guest, not native Bot Screen.'));
    details.push(jsx(SandboxedFrame, {
      src: consoleUrl, sandbox: 'allow-scripts',
      title: `QEMU console — ${owner}`,
      style: { width: '100%', height: '580px', border: '1px solid var(--ui-stroke-secondary)' }
    }));
  } else {
    details.push(p('Console not available: no validated ws://127.0.0.1:<port> QEMU transport was returned. No external page, alternate viewer, or Bot Screen was opened.'));
  }
  return details;
}

function HuntingLab() {
  const current = useValue(state);
  const ready = !current.busy && !!current.selected;
  return jsx('div', { style, children: [
    jsx('h2', { children: 'Hunting Lab' }),
    p('Native Hermes-managed QEMU VM. First explicit Start automatically prepares verified public runtime assets before booting; Prepare downloads/provisions without starting the VM. No setup, download or boot occurs on page load. This page makes no provider calls and reads no conversations, credentials, or memory.'),
    p('Automatic first setup requires Windows x64, Windows Hypervisor Platform already enabled, 5 GiB available RAM and 37 GiB free disk. It makes large public downloads; the guest uses 4 GiB RAM, two vCPUs and a 32 GiB virtual disk. No elevation, Windows-feature change or software-emulation fallback is attempted.'),
    jsx('section', { style: card, children: [
      jsx('h3', { children: 'Explicit local VM owner' }),
      button('Find local framework profiles', discover, current.busy),
      jsx('label', { children: [' Local connection / profile ', jsx('select', {
        value: current.selected, disabled: current.busy,
        onChange: event => state.set({ ...state.get(), selected: event.target.value, result: null, code: null, message: 'Owner selected. Refresh status before deciding whether to start or shut down.' }),
        children: [jsx('option', { value: '', children: 'Select a local route' }), ...current.routes.map(route => jsx('option', {
          value: key(route), children: `${route.connectionId} · ${route.profile} → ${route.targetProfile}`
        }, key(route)))]
      })] }),
      jsx('div', { style: { display: 'flex', gap: '8px', marginTop: '12px', flexWrap: 'wrap' }, children: [
        button('Refresh status', () => operate('status'), !ready),
        button('Prepare lab assets', () => operate('prepare'), !ready),
        button('Start lab VM', () => operate('start'), !ready),
        button('Shut down lab VM', () => operate('stop'), !ready)
      ] }),
      jsx('p', { role: 'status', 'aria-live': 'polite', children: current.message })
    ] }),
    jsx('section', { style: card, children: [jsx('h3', { children: 'Owned guest services and QEMU console' }), ...services(current)] }),
    p('A running QEMU process is not proof that guest services finished booting. Human Start/Prepare may observe status for up to ten minutes; only read-only status requests are repeated. No lifecycle retry, model call, host Docker fallback, or VMware dependency is used. Refresh explicitly after observation ends. Bot Screen is separate, not a VM launcher or console.'),
  ] });
}

// Live hunt board: a read-only page served by `python -m hermes_temporal.board` on a
// fixed loopback port. It is embedded only after an explicit click, in an opaque-origin
// sandbox, and shows only real workflow status and the bots' recorded outputs.
const BOARD = '/hunt-board';
const BOARD_URL = 'http://127.0.0.1:8790/';
const board = atom({ shown: false, nonce: 0 });

function HuntBoard() {
  const current = useValue(board);
  return jsx('div', { style: { ...style, display: 'flex', flexDirection: 'column' }, children: [
    jsx('h2', { children: 'Hunt Board' }),
    p('Live, read-only view of a running supplied-evidence hunt: which bot is working, the case events each bot cites, the hosts, programs and domains they link, and their claims and review verdicts. It shows only what the bots wrote; approvals are recorded separately.'),
    p('Start the board server first: python -m hermes_temporal.board --workflow-id <practice id> --input <lab input JSON> --port 8790. Nothing is fetched until you click Show board.'),
    jsx('div', { style: { display: 'flex', gap: '8px' }, children: [
      button(current.shown ? 'Reload board' : 'Show board', () => board.set({ shown: true, nonce: current.nonce + 1 }), false),
      current.shown ? button('Hide board', () => board.set({ ...board.get(), shown: false }), false) : null
    ] }),
    current.shown
      ? jsx(SandboxedFrame, {
        src: BOARD_URL, sandbox: 'allow-scripts', title: 'Live hunt board',
        style: { width: '100%', flex: '1', minHeight: '760px', marginTop: '12px', border: '1px solid var(--ui-stroke-secondary)' }
      }, String(current.nonce))
      : null
  ] });
}

// Native Desktop's manifest is this default-exported HermesPlugin object.
// package.json supplies versioned ESM metadata; it is not a dashboard manifest.
export default {
  id: 'hunt-lab', name: 'Hunting Lab', defaultEnabled: true,
  register(ctx) {
    ctx.register({ id: 'page', area: ROUTES_AREA, data: { path: PAGE }, render: () => jsx(HuntingLab, {}) });
    ctx.register({ id: 'sidebar', area: SIDEBAR_NAV_AREA, data: { path: PAGE, label: 'Hunting Lab', codicon: 'server-environment' } });
    ctx.register({ id: 'open', area: PALETTE_AREA, data: { id: 'hunt-lab.open', label: 'Open Hunting Lab', run: () => host.navigate(PAGE) } });
    ctx.register({ id: 'board', area: ROUTES_AREA, data: { path: BOARD }, render: () => jsx(HuntBoard, {}) });
    ctx.register({ id: 'board-sidebar', area: SIDEBAR_NAV_AREA, data: { path: BOARD, label: 'Hunt Board', codicon: 'pulse' } });
    ctx.register({ id: 'board-open', area: PALETTE_AREA, data: { id: 'hunt-lab.board', label: 'Open Hunt Board', run: () => host.navigate(BOARD) } });
  }
};
