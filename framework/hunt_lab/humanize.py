"""Human-like pointer paths and typing cadence: pure functions of their inputs and a random.Random."""
from __future__ import annotations

import math

JITTER_PX = 1.2
CURVE = 0.16
OVERSHOOT_PX = (3.0, 9.0)
OVERSHOOT_CHANCE = 0.3
KEY_MS = (35.0, 650.0)
PAUSE_AFTER = frozenset(' .,;:!?-_/()[]{}"\'=&|<>')


def _ease(t):
    return 4 * t ** 3 if t < 0.5 else 1 - (-2 * t + 2) ** 3 / 2


def _bezier(p0, p1, p2, p3, t):
    u = 1 - t
    return tuple(u ** 3 * a + 3 * u * u * t * b + 3 * u * t * t * c + t ** 3 * d for a, b, c, d in zip(p0, p1, p2, p3))


def _curve(start, end, rng, duration, t0, steps):
    (sx, sy), (ex, ey) = start, end
    distance = math.hypot(ex - sx, ey - sy)
    ux, uy = (ex - sx) / distance, (ey - sy) / distance
    nx, ny = -uy, ux

    def control(along):
        bend = rng.uniform(-CURVE, CURVE) * distance
        return sx + ux * along * distance + nx * bend, sy + uy * along * distance + ny * bend

    p1, p2 = control(rng.uniform(0.2, 0.4)), control(rng.uniform(0.6, 0.85))
    points = []
    for i in range(1, steps + 1):
        x, y = _bezier(start, p1, p2, end, _ease(i / steps))
        if i < steps:
            x += rng.uniform(-JITTER_PX, JITTER_PX)
            y += rng.uniform(-JITTER_PX, JITTER_PX)
        points.append((x, y, t0 + duration * i / steps))
    return points


def mouse_path(start, end, rng, *, width=40.0):
    """Timed points [(x, y, ms)] from start to exactly end along an eased, slightly bent Bezier curve.

    Duration follows Fitts's law for the target width; long moves sometimes overshoot a few pixels
    past the target and correct back, as a hand does.
    """
    start, end = (float(start[0]), float(start[1])), (float(end[0]), float(end[1]))
    distance = math.hypot(end[0] - start[0], end[1] - start[1])
    if distance < 1:
        return [(*start, 0.0), (*end, rng.uniform(15, 35))]
    duration = (90 + 110 * math.log2(1 + distance / max(width, 8.0))) * rng.uniform(0.85, 1.2)
    steps = max(12, min(48, round(distance / 14)))
    path = [(*start, 0.0)]
    if distance > 120 and rng.random() < OVERSHOOT_CHANCE:
        reach = rng.uniform(*OVERSHOOT_PX) / distance
        aim = (end[0] + (end[0] - start[0]) * reach, end[1] + (end[1] - start[1]) * reach)
        path += _curve(start, aim, rng, duration, 0.0, steps)
        settle = rng.uniform(60, 140)
        tail = rng.randint(3, 5)
        path += [(aim[0] + (end[0] - aim[0]) * i / tail, aim[1] + (end[1] - aim[1]) * i / tail,
                  duration + settle * i / tail) for i in range(1, tail + 1)]
    else:
        path += _curve(start, end, rng, duration, 0.0, steps)
    path[-1] = (*end, path[-1][2])
    return [(round(x, 2), round(y, 2), round(t, 2)) for x, y, t in path]


def aim_point(left, top, right, bottom, rng):
    """A point inside the visible box, biased to its middle the way people aim, never on its edge."""
    def axis(low, high):
        middle, half = (low + high) / 2, (high - low) / 2
        return middle + max(-0.6 * half, min(0.6 * half, rng.gauss(0, half / 3)))
    return round(axis(left, right), 2), round(axis(top, bottom), 2)


def press_hold_ms(rng):
    return rng.uniform(55, 125)


def typing_delays(text, rng):
    """Milliseconds to wait before each character: a skewed per-key rhythm, slower after spaces and
    punctuation, with occasional short thinking pauses; every delay stays within KEY_MS."""
    delays = []
    previous = None
    for char in text:
        delay = rng.lognormvariate(math.log(95), 0.35)
        if previous is not None and previous in PAUSE_AFTER:
            delay += rng.uniform(40, 160)
        if rng.random() < 0.04:
            delay += rng.uniform(150, 350)
        delays.append(round(max(KEY_MS[0], min(KEY_MS[1], delay)), 2))
        previous = char
    return delays


def wheel_steps(direction, rng):
    """[(delta_y, ms_before)] for one flick of the wheel: a few ticks of varying size and spacing."""
    sign = 1 if direction == 'down' else -1
    return [(sign * round(rng.uniform(80, 130)), round(rng.uniform(25, 90), 2)) for _ in range(rng.randint(3, 6))]
