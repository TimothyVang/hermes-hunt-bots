// Hunt progress text for toolcam.mjs from the Hunt Board's /state.json steps, serial or parallel.
// A parallel round lists each step's wave and runs a wave's steps at once; a serial round has one step per wave.
const ENDED = new Set(["done", "dropped", "stopped"]);
const WAITING = new Set(["pending", "not_reached"]);
const waveOf = (s, i) => (Number.isInteger(s.wave) ? s.wave : i + 1);

function counts(steps) {
  const done = steps.filter(s => s.state === "done").length;
  const dropped = steps.filter(s => s.state === "dropped" || s.state === "stopped")
    .map(s => `${s.step_id} ${s.state}: ${(s.reason || "no reason given").replace(/_/g, " ")}`);
  return `${done}/${steps.length} steps done` + (dropped.length ? ` · ${dropped.join(", ")}` : "");
}

// One status line: every open step of the current wave, then the ended count; never a fixed step total.
export function pipeline(steps) {
  const waves = new Set(steps.map(waveOf)).size;
  const open = steps.map((s, i) => ({ s, i, w: waveOf(s, i) })).filter(x => !ENDED.has(x.s.state) && !WAITING.has(x.s.state));
  if (!open.length) return counts(steps);
  const wave = Math.min(...open.map(x => x.w));
  const now = open.filter(x => x.w === wave);
  if (waves === steps.length) return `Step ${now[0].i + 1}/${steps.length} · ${now[0].s.role || now[0].s.profile} ${now[0].s.state}`;
  // A wave's steps often share one bot, so they are named by step.
  return `Wave ${wave}/${waves} · ${now.map(x => `${x.s.step_id} ${x.s.state}`).join(", ")} · ${counts(steps)}`;
}

// The closing card's subtitle, from the round's last steps.
export function endSummary(steps) {
  const last = steps[steps.length - 1];
  return counts(steps) + (last && last.state === "done" ? ". Final report written by the Incident Response Lead." : ".");
}
