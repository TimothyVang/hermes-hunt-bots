# Adapted from oh-my-pi packages/coding-agent/src/tools/browser/interactions.ts
# (checkClickActionable and composedContains, commit 89833d37f43289f0c33a5658d8784b0086254cf8).
# Modified: ported to one CDP Runtime.callFunctionOn page function, adds a disabled check, returns
# fixed reason codes and the visible box, and hit-tests a caller-chosen point inside that box.
#
# MIT License
#
# Copyright (c) 2025 Mario Zechner
# Copyright (c) 2025-2026 Can Bölük
# Copyright (c) 2026 Stencil Labs, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""Page function deciding whether an element can take a real pointer click, and where."""

CLICK_ACTIONABLE = r"""
function (px, py) {
  const element = this;
  const contains = (ancestor, descendant) => {
    for (let current = descendant; current;) {
      if (current === ancestor) return true;
      const root = current.getRootNode();
      current = current.assignedSlot || current.parentElement || root.host || null;
    }
    return false;
  };
  if (!element.isConnected) return { ok: false, reason: "detached" };
  if (element.disabled === true || element.getAttribute("aria-disabled") === "true") return { ok: false, reason: "disabled" };
  const style = getComputedStyle(element);
  if (style.display === "none") return { ok: false, reason: "display_none" };
  if (style.visibility === "hidden" || style.visibility === "collapse") return { ok: false, reason: "hidden" };
  if (style.pointerEvents === "none") return { ok: false, reason: "pointer_events_none" };
  // A custom checkbox or radio keeps its real control at opacity:0 under the box it draws; the hit test decides.
  if (Number(style.opacity) === 0 &&
      !element.matches('input[type="checkbox"], input[type="radio"], [role="checkbox" i], [role="radio" i], [role="switch" i]')) {
    return { ok: false, reason: "transparent" };
  }
  const rect = element.getBoundingClientRect();
  if (rect.width < 1 || rect.height < 1) return { ok: false, reason: "zero_size" };
  // A wrapped link's box centre can fall between its lines, on the parent; aim at its first visible line.
  const fragments = Array.from(element.getClientRects());
  const box = fragments.length === 0 ? rect : fragments.find(r =>
    Math.min(innerWidth, r.right) - Math.max(0, r.left) >= 1 && Math.min(innerHeight, r.bottom) - Math.max(0, r.top) >= 1);
  if (!box) return { ok: false, reason: "off_viewport" };
  const left = Math.max(0, Math.min(innerWidth, box.left));
  const right = Math.max(0, Math.min(innerWidth, box.right));
  const top = Math.max(0, Math.min(innerHeight, box.top));
  const bottom = Math.max(0, Math.min(innerHeight, box.bottom));
  if (right - left < 1 || bottom - top < 1) return { ok: false, reason: "off_viewport" };
  const chosen = typeof px === "number" && typeof py === "number" && px >= left && px < right && py >= top && py < bottom;
  const x = chosen ? px : Math.floor((left + right) / 2);
  const y = chosen ? py : Math.floor((top + bottom) / 2);
  let hit = document.elementFromPoint(x, y);
  for (let depth = 0; hit && hit.shadowRoot && depth < 16; depth++) {
    const nested = hit.shadowRoot.elementFromPoint(x, y);
    if (!nested || nested === hit) break;
    hit = nested;
  }
  if (!hit) return { ok: false, reason: "no_hit" };
  // A label forwards a click to its control unless the hit is other interactive content inside it.
  const interactive = 'a[href], area[href], button, details, embed, iframe, input:not([type="hidden"]), label, select, textarea, summary, audio[controls], video[controls], [contenteditable=""], [contenteditable="true"]';
  const forwardedBy = owner => {
    let current = hit;
    while (current && current !== owner) {
      if (current.matches(interactive)) return false;
      current = current.assignedSlot || current.parentElement || current.getRootNode().host || null;
    }
    return current === owner;
  };
  if (!(contains(element, hit) || contains(hit, element) || Array.from(element.labels || []).some(forwardedBy))) {
    return { ok: false, reason: "covered" };
  }
  return { ok: true, x, y, left, top, right, bottom };
}
"""
