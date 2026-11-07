// Original local-development UI; no third-party code or mascot assets bundled.
import { atom, host, ROUTES_AREA, SIDEBAR_NAV_AREA, PALETTE_AREA, Button, useValue } from '@hermes/plugin-sdk';
import { jsx } from 'react/jsx-runtime';

const ROLES = Object.freeze([
  ['Incident Response Lead', 'framework-coordinator', 'Native Astra orchestration; Luna/Terra per-task delegation.'],
  ['Threat Hunter', 'framework-researcher', 'Supplied evidence and testable alternatives only.'],
  ['Detection Engineer', 'framework-builder', 'Draft and offline review; no deployment.'],
  ['Purple Team Analyst', 'framework-reviewer', 'Independent supplied-evidence review; no adversary emulation.'],
  ['Threat Intelligence Analyst', 'framework-librarian', 'Attributed intelligence drafts, not trusted memory.'],
  ['Network Analyst', 'framework-network-analyst', 'Use only approved sanitized Arkime/Wireshark summaries; never raw captures or sensitive tool views.']
]);
const GATES = Object.freeze([
  ['scope', 'A human establishes sources, time, authority, exclusions and destination.'],
  ['evidence + hypotheses', 'Parallel only after human scope approval; facts and hypotheses remain distinct.'],
  ['analysis', 'Requires both branch handoffs and separate human decisions.'],
  ['independent review', 'Check evidence and alternatives; disclose independence limitations.'],
  ['handoff', 'A decision request, not remediation, release or promotion.']
]);
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
    try {
      const routes = (await host.profileRoutes()).filter(route =>
        SCREEN_PROFILE_IDS.has(route.targetProfile)
      );
      screenState.set({routes,selected:'',message:routes.length ? 'Choose one exact registered connection/profile route.' : 'No registered framework profile routes were found.'});
    } catch {
      screenState.set({...screenState.get(),routes:[],selected:'',message:'Registered connection/profile routes could not be read. No fallback was attempted.'});
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
  return jsx('div',{children:[
    action('Find framework profiles',discover),
    jsx('label',{children:['Explicit connection / profile ',jsx('select',{value:state.selected,onChange:event=>screenState.set({...screenState.get(),selected:event.target.value}),children:[
      jsx('option',{value:'',children:'Select a route'},'empty'),
      ...state.routes.map(route=>jsx('option',{value:routeKey(route),children:`${route.connectionId} · ${route.profile} → ${route.targetProfile}`},routeKey(route)))
    ]})]}),
    action('Open native Bot Screen',open),
    paragraph(state.message)
  ]});
}
const style = { padding:'16px', color:'var(--ui-text-primary)', overflow:'auto', height:'100%' };
const card = { border:'1px solid var(--ui-stroke-secondary)', borderRadius:'8px', padding:'12px', marginBottom:'10px' };
const muted = { color:'var(--ui-text-secondary)' };
function paragraph(text) { return jsx('p', {style:muted, children:text}); }
function section(title, children) { return jsx('section', {style:card, children:[jsx('h3',{children:title}), ...children]}); }
function action(label, onClick, extra={}) { return jsx(Button, {...extra, onClick, children:label}); }
function workspace(ctx) {
  const run = id => {
    if (typeof ctx.runAction !== 'function') {
      host.notify({kind:'error',message:'This Hermes release does not expose the required SDK action.'}); return;
    }
    const result = ctx.runAction(id);
    if (!result?.ok) host.notify({kind:'error',message:`Native action unavailable: ${result?.reason || 'unsupported'}. No fallback was attempted.`});
  };
  return jsx('div', {style, 'data-cyber-workspace':'v1', children:[
    jsx('h2',{children:'Cybersecurity workspace'}),
    paragraph('Supplied-evidence workbench. Displayed gates are instructions, not an approval record or a live ledger mirror.'),
    section('Human-controlled gates',[
      jsx('ol',{children:GATES.map(([name,detail])=>jsx('li',{children:[jsx('strong',{children:name}), ' — '+detail]},name))}),
      paragraph('Board transitions and successful execution never count as human approval. Knowledge and memory promotion require a separate human decision. No automatic trusted-memory writes.'),
      jsx('svg',{viewBox:'0 0 760 92',role:'img','aria-label':'Advisory gate graph: scope to evidence and hypotheses to analysis to independent review to handoff; no live memory data',children:[
        jsx('path',{d:'M105 45 L190 22 L330 45 M105 45 L190 68 L330 45 M330 45 L470 45 L625 45',fill:'none',stroke:'var(--ui-stroke-secondary)',strokeWidth:2}),
        ...[['scope',15,45],['evidence',190,22],['hypotheses',190,78],['analysis',335,45],['review',475,45],['handoff',630,45]].map(([label,x,y])=>jsx('text',{x,y,fill:'var(--ui-text-secondary)',fontSize:14,children:label},label))
      ]})
    ]),
    section('Six native profiles',ROLES.map(([title,id,scope])=>jsx('p',{children:[jsx('strong',{children:title}), ' · '+id+' — '+scope]},id))),
    section('Explicit native Bot Screen',[
      paragraph('Select one registered connection/profile route and deliberately open its native Bot Screen. Opening an already-running screen attaches live frames; revealing an existing tab may retain its current control lease. Starting, taking over, handing back and pasting remain separate native user actions. This is not a VM boot/console view, and VM power state is unknown here.'),
      jsx(ScreenSelector,{})
    ]),
    section('Built-in hunting lab',[
      action('Open hunting lab',()=>host.navigate('/hunt-lab')),
      paragraph('A separate human-operated page owns the local analyst-profile QEMU lab. Explicit Start prepares verified public runtime assets on first use, then boots the VM; Prepare downloads/provisions without booting. Status does not install, repair or start anything. The page shows real VM setup progress and QEMU console, never Bot Screen.'),
      paragraph('VM launch, shutdown and guest-console input are deliberate human actions, not advisory ledger gates or model permissions. The Network Analyst keeps its existing SOUL restrictions: only bounded approved synthetic summaries through the read-only lab tool, never Arkime controls or raw captures. No provider/model call is needed to operate the lab.')
    ]),
    section('Native surfaces',[
      action('Open native Kanban',()=>host.navigate('/kanban')),
      paragraph('Inspect only: do not add runnable research cards or enable dispatcher workers here. Native Kanban can run agents; it is not the human-operated ledger. This plugin has no task-write capability in its code.'),
      action('Open native profile manager',()=>run('nav.profiles')),
      action('Open in-app browser',()=>run('view.showBrowser')),
      paragraph('Browser: use an approved public page or synthetic local document only. Never inspect account pages, headers, cookies, credentials, authentication payloads or session data. No browser observation is automatic.'),
      paragraph('HUD: use the native titlebar control or your bound Toggle HUD action only above an approved synthetic document. The SDK intentionally does not allow toggleHud; no synthetic shortcuts or underlying-window reads are used here.'),
      paragraph('Memory graph: use the native command palette Memory graph entry (or /memory-graph) for a human-reviewed profile. This advisory gate graph is NOT native memory and reads none. Do not infer trust or approval from graph edges.'),
      action('Pet: show gate reminder',()=>{
        if (!ctx.pet?.visible) {host.notify({kind:'info',message:'No visible native pet. No asset was installed or changed.'});return;}
        ctx.pet.say('Execution is not approval. Human gates remain in control.',{id:'human-gates',tone:'wait',ttlMs:6000});
      },{'data-cyber-action':'pet'}),
      paragraph('Pets are optional status mascots, never evidence or approval. Choose reviewed assets in native Appearance settings; no catalog asset or image-generation backend is installed by this plugin.')
    ]),
    section('Route and failure disclosure',[
      paragraph('Required native routes, provider anthropic: Incident Response Lead and Purple Team Analyst on claude-opus-5-5; Threat Hunter, Detection Engineer, Threat Intelligence Analyst and Network Analyst on claude-sonnet-5. These are requirements, NOT live verification. No fallback or model substitution is authorized.'),
      paragraph('Known completion-role-label inconsistency: a delegating coordinator completion may display leaf despite nested delegation. Child-reported identity limits: leaf route reports are not independent attestation of upstream model internals. Require actual route/status evidence for each new run.'),
      paragraph('runtime_draining and profile_mismatch must remain visible failures. Do not retry inference blindly, disable profile guards, reset profiles or delete databases. Source diagnostics are not proof of a repaired live exchange.')
    ]),
    section('Boundaries',[
      paragraph('OMP is development-only, never a product runtime dependency. This companion performs no collection, telemetry, scanning, capture, Arkime connection, adversary emulation, remediation, trading, external messaging or schedules. Navigating to Hunting Lab does not launch its VM; human lifecycle controls there are distinct from these advisory gates.'),
      paragraph('This plugin makes no model calls, reads no conversations or memory, saves no decisions and changes no specialist safeguards. It cannot enforce other tools or plugins; profiles and role instructions are not sandboxes.')
    ])
  ]});
}
export default {
  id:'cybersecurity-workspace', name:'Cybersecurity workspace', defaultEnabled:true,
  register(ctx) {
    ctx.register({id:'workspace',area:ROUTES_AREA,data:{path:'/cybersecurity-workspace'},render:()=>workspace(ctx)});
    ctx.register({id:'nav',area:SIDEBAR_NAV_AREA,data:{path:'/cybersecurity-workspace',label:'Cybersecurity workspace',codicon:'shield'}});
    ctx.register({id:'open',area:PALETTE_AREA,data:{id:'cybersecurity-workspace.open',label:'Open cybersecurity workspace',run:()=>host.navigate('/cybersecurity-workspace')}});
    ctx.register({id:'gates',area:'statusBar.right',render:()=>action('Human gates',()=>host.navigate('/cybersecurity-workspace'))});
  }
};
