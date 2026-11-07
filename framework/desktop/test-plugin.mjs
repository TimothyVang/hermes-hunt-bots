import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(process.argv[2], 'utf8');
const registrations = [], calls = [], bubbles = [], screenCalls = [];
const screenRoute = {connectionId:'guest-a',mode:'remote',profile:'coord-alias',targetProfile:'framework-coordinator'};
const host = {
  navigate: path => calls.push(['navigate', path]),
  notify: value => calls.push(['notify', value]),
  profileRoutes: async () => [
    screenRoute,
    {connectionId:'guest-b',mode:'remote',profile:'unapproved-profile',targetProfile:'unapproved-profile'},
    {connectionId:'guest-c',mode:'remote',profile:'framework-coordinator',targetProfile:'personal-profile'}
  ],
  openScreen: async route => { screenCalls.push(route); return {status:'opened'}; },
  request: () => { throw Error('Unexpected gateway read/write'); },
  state: new Proxy({}, { get() { throw Error('Unexpected private app-state read'); } })
};
const atom = initial => ({value:initial,get(){return this.value;},set(value){this.value=value;}});
const useValue = value => value.get();
const jsx = (type, props) => ({ type, props });
const context = vm.createContext({ console });
const sdk = new vm.SyntheticModule(['host', 'ROUTES_AREA', 'SIDEBAR_NAV_AREA', 'PALETTE_AREA', 'Button', 'atom', 'useValue'], function () {
  for (const [k,v] of Object.entries({ host, ROUTES_AREA:'routes', SIDEBAR_NAV_AREA:'sidebar.nav', PALETTE_AREA:'palette', Button:'button', atom, useValue })) this.setExport(k,v);
}, { context });
const react = new vm.SyntheticModule(['jsx'], function () { this.setExport('jsx', jsx); }, { context });
const module = new vm.SourceTextModule(source, { context });
await module.link(name => {
  if (name === '@hermes/plugin-sdk') return sdk;
  if (name === 'react/jsx-runtime') return react;
  throw Error('Unsupported import ' + name);
});
await module.evaluate();
const plugin = module.namespace.default;
const ctx = {
  register: value => registrations.push(value),
  runAction: id => { calls.push(['action',id]); return {ok:false,reason:'unavailable'}; },
  pet: { visible:false, say: text => { bubbles.push(text); return () => {}; } },
  storage: new Proxy({}, { get() { throw Error('Unexpected persistent write/read'); } })
};
plugin.register(ctx);
assert.equal(calls.length, 0, 'Loading must not navigate, call models or mutate work');
assert.equal(bubbles.length, 0, 'No automatic pet alerts');
const page = registrations.find(r => r.area === 'routes');
const tree = page.render();
const nodes=[];
function walk(n) {
  if (!n || typeof n !== 'object') return;
  if (Array.isArray(n)) return n.forEach(walk);
  if (typeof n.type === 'function') return walk(n.type(n.props));
  nodes.push(n); walk(n.props?.children);
}
walk(tree);
for (const n of nodes.filter(n=>typeof n.props?.onClick==='function')) await n.props.onClick();
assert.equal(screenCalls.length,0,'Opening requires an explicit route selection and a separate click');
nodes.length=0;
walk(page.render());
const selector=nodes.find(n=>n.type==='select');
assert.ok(selector,'Profile routes expose an explicit selector');
const optionTargets=nodes.filter(n=>n.type==='option' && n.props.value).map(n=>JSON.parse(n.props.value)[3]);
assert.deepEqual(optionTargets,['framework-coordinator'],'A framework-named alias must not expose an unapproved target profile');
const selectedRouteKey=JSON.stringify([screenRoute.connectionId,screenRoute.mode,screenRoute.profile,screenRoute.targetProfile]);
await selector.props.onChange({target:{value:selectedRouteKey}});
const openScreen=nodes.find(n=>n.props?.children==='Open native Bot Screen');
assert.ok(openScreen);
await openScreen.props.onClick();
assert.equal(screenCalls.length,1,'An explicit open dispatches once, without retries or a fallback route');
const callsBeforeFailure=calls.length;
host.openScreen=async route=>{screenCalls.push(route);throw Error('Synthetic transport failure');};
await openScreen.props.onClick();
assert.equal(screenCalls.length,2,'A rejected open must not retry');
assert.equal(calls.length,callsBeforeFailure,'A rejected open must not navigate or invoke another viewer');
nodes.length=0;
walk(page.render());
assert.equal(nodes.find(n=>n.type==='select').props.value,selectedRouteKey,'Failure preserves the selected route for inspection');
assert.ok(calls.some(c=>c[0]==='notify'), 'Unavailable SDK actions must be disclosed');
assert.ok(!calls.some(c=>c[0]==='action' && /Hud|memory|cron|messaging/.test(c[1])));
assert.equal(bubbles.length,0,'Hidden pets must not produce a false visible-alert claim');
ctx.pet.visible=true;
const pet=nodes.find(n=>n.props?.['data-cyber-action']==='pet');
assert.ok(pet); await pet.props.onClick();
assert.equal(bubbles.length,1);
console.log('workspace contract passed');
