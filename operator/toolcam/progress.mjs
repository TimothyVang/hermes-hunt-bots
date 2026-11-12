// Hunt progress text for toolcam.mjs from the Hunt Board's /state.json steps, serial or parallel.
// A parallel round lists each step's wave and runs a wave's steps at once; a serial round has one step per wave.
const ENDED = new Set(["done", "dropped", "stopped"]);
const WAITING = new Set(["pending", "not_reached"]);
// Past this many steps a list is replaced by its count, so a wide wave keeps the line short.
const NAMED = 4;
const waveOf = (s, i) => (Number.isInteger(s.wave) ? s.wave : i + 1);
const names = list => (list.length > NAMED ? `${list.length} steps` : list.join(", "));

// Dropped and stopped steps grouped by state and reason: "follow-2, follow-5 dropped: retry exhausted".
function flagged(steps) {
  const groups = new Map();
  for (const s of steps.filter(x => x.state === "dropped" || x.state === "stopped")) {
    const key = `${s.state}: ${(s.reason || "no reason given").replace(/_/g, " ")}`;
    groups.set(key, [...(groups.get(key) || []), s.step_id]);
  }
  return [...groups].map(([key, ids]) => `${names(ids)} ${key}`);
}

function counts(steps) {
  const done = steps.filter(s => s.state === "done").length;
  return [`${done}/${steps.length} steps done`, ...flagged(steps)].join(" · ");
}

// One status line: the open steps of the current wave, then the ended count; never a fixed step total.
export function pipeline(steps) {
  const waves = new Set(steps.map(waveOf)).size;
  const open = steps.map((s, i) => ({ s, i, w: waveOf(s, i) })).filter(x => !ENDED.has(x.s.state) && !WAITING.has(x.s.state));
  if (!open.length) return counts(steps);
  const wave = Math.min(...open.map(x => x.w));
  const now = open.filter(x => x.w === wave);
  if (waves === steps.length) return `Step ${now[0].i + 1}/${steps.length} · ${now[0].s.role || now[0].s.profile} ${now[0].s.state}`;
  // A wave's steps often share one bot, so they are named by step, or counted by state when there are many.
  const shown = now.length > NAMED
    ? `${now.length} steps: ` + [...new Set(now.map(x => x.s.state))].map(st => `${now.filter(x => x.s.state === st).length} ${st}`).join(", ")
    : now.map(x => `${x.s.step_id} ${x.s.state}`).join(", ");
  return `Wave ${wave}/${waves} · ${shown} · ${counts(steps)}`;
}

// The closing card: complete only when every step ended and none stopped; otherwise the round ended early,
// and the card names the waves it never reached.
export function endCard(steps) {
  const early = steps.some(s => s.state === "stopped" || !ENDED.has(s.state));
  if (!early) {
    const last = steps[steps.length - 1];
    return { title: "Hunt complete",
             sub: counts(steps) + (last && last.state === "done" ? ". Final report written by the Incident Response Lead." : ".") };
  }
  const unreached = steps.map((s, i) => ({ s, w: waveOf(s, i) })).filter(x => !ENDED.has(x.s.state));
  const waves = [...new Set(unreached.map(x => x.w))];
  const span = waves.length === 1 ? `wave ${waves[0]}` : `waves ${Math.min(...waves)}–${Math.max(...waves)}`;
  return { title: "Hunt ended early",
           sub: counts(steps) + (unreached.length ? ` · not reached: ${span} (${unreached.length} steps)` : "") + "." };
}
