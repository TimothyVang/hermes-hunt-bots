"""Human-like input: pointer paths and typing cadence are bounded, plausible, and reproducible by seed."""
import math
import random
import unittest

from hunt_lab import humanize


def _frame(start, end, point):
    """(distance along start->end, distance from that line) for one path point."""
    (sx, sy), (ex, ey) = start, end
    length = math.hypot(ex - sx, ey - sy)
    ux, uy = (ex - sx) / length, (ey - sy) / length
    dx, dy = point[0] - sx, point[1] - sy
    return dx * ux + dy * uy, abs(-dx * uy + dy * ux)


class MousePathTests(unittest.TestCase):
    def moves(self):
        rng = random.Random(1)
        for seed in range(300):
            start = (rng.uniform(0, 1300), rng.uniform(0, 800))
            end = (rng.uniform(0, 1300), rng.uniform(0, 800))
            if math.dist(start, end) > 20:
                yield seed, start, end

    def test_paths_run_exactly_from_start_to_target_with_rising_time(self):
        for seed, start, end in self.moves():
            path = humanize.mouse_path(start, end, random.Random(seed), width=60)
            self.assertEqual(path[0][:2], (round(start[0], 2), round(start[1], 2)))
            self.assertEqual(path[-1][:2], (round(end[0], 2), round(end[1], 2)))
            self.assertEqual(path[0][2], 0)
            times = [point[2] for point in path]
            self.assertTrue(all(a < b for a, b in zip(times, times[1:])), seed)
            self.assertGreaterEqual(len(path), 13)
            self.assertTrue(80 <= times[-1] <= 1500, (seed, times[-1]))

    def test_paths_stay_near_the_straight_line_and_overshoot_only_slightly(self):
        overshoots = 0
        for seed, start, end in self.moves():
            distance = math.dist(start, end)
            path = humanize.mouse_path(start, end, random.Random(seed), width=60)
            farthest = 0.0
            for point in path:
                along, off = _frame(start, end, point)
                self.assertLessEqual(off, 0.2 * distance + 3, seed)
                self.assertGreaterEqual(along, -3, seed)
                self.assertLessEqual(along, distance + 12, seed)
                farthest = max(farthest, along)
            overshoots += farthest > distance + 2
        self.assertGreater(overshoots, 0, 'long moves sometimes overshoot and correct')

    def test_the_same_seed_gives_the_same_path_and_another_seed_does_not(self):
        start, end = (40.0, 700.0), (980.0, 115.0)
        first = humanize.mouse_path(start, end, random.Random(42))
        self.assertEqual(first, humanize.mouse_path(start, end, random.Random(42)))
        self.assertNotEqual(first, humanize.mouse_path(start, end, random.Random(43)))

    def test_a_target_under_the_pointer_still_gets_a_timed_arrival(self):
        path = humanize.mouse_path((10, 10), (10.4, 10), random.Random(0))
        self.assertEqual((path[0][:2], path[-1][:2]), ((10.0, 10.0), (10.4, 10.0)))
        self.assertGreater(path[-1][2], 0)

    def test_aim_points_land_inside_the_visible_box(self):
        for seed in range(500):
            x, y = humanize.aim_point(100, 40, 160, 64, random.Random(seed))
            self.assertTrue(100 < x < 160 and 40 < y < 64, (seed, x, y))


class TypingTests(unittest.TestCase):
    TEXT = 'ip.dst == 203.0.113.7 && port.dst == 443, then protocols == tls; host.http == "cdn.example"'

    def test_every_key_waits_a_bounded_time(self):
        for seed in range(100):
            delays = humanize.typing_delays(self.TEXT, random.Random(seed))
            self.assertEqual(len(delays), len(self.TEXT))
            self.assertTrue(all(35 <= delay <= 650 for delay in delays), seed)

    def test_the_same_seed_types_with_the_same_rhythm(self):
        self.assertEqual(humanize.typing_delays(self.TEXT, random.Random(5)),
                         humanize.typing_delays(self.TEXT, random.Random(5)))
        self.assertNotEqual(humanize.typing_delays(self.TEXT, random.Random(5)),
                            humanize.typing_delays(self.TEXT, random.Random(6)))

    def test_keys_after_spaces_and_punctuation_come_slower(self):
        after, other = [], []
        for seed in range(50):
            for previous, delay in zip(' ' + self.TEXT, humanize.typing_delays(self.TEXT, random.Random(seed))):
                (after if previous in ' .,;=&"' else other).append(delay)
        self.assertGreater(sum(after) / len(after), sum(other) / len(other) + 40)

    def test_wheel_flicks_scroll_the_requested_way(self):
        for direction, sign in (('down', 1), ('up', -1)):
            steps = humanize.wheel_steps(direction, random.Random(3))
            self.assertTrue(3 <= len(steps) <= 6)
            self.assertTrue(all(delta * sign >= 80 and pause > 0 for delta, pause in steps))


if __name__ == '__main__':
    unittest.main()
