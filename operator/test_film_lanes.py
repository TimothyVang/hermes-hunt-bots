"""Lanes in the filmed loop: config, isolation checks, scoring over lanes and one review for every lane.

No lab, browser, Temporal or ffmpeg. Run from the repository root:
python -m unittest discover -s operator -p "test_*.py"
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import film_loop
import tool_loops as tl
from film import lanes
from film import review
from lab_paths import DEFAULT_LANE, RUNTIME, Lane

TWO = [{'name': 'l1', 'hermes_home': 'lab-home', 'task_queue': 'hermes-claude-practice'},
       {'name': 'l2', 'hermes_home': 'lab-home-2', 'task_queue': 'hermes-claude-practice-2',
        'hermes_exe': r'C:\lab2\hermes.exe'}]


class LaneConfigTest(unittest.TestCase):
    def test_no_lanes_file_means_the_one_lab_the_environment_names(self):
        self.assertEqual(lanes.load(None), [DEFAULT_LANE])
        self.assertEqual(DEFAULT_LANE.name, '')
        self.assertEqual(lanes.problems([DEFAULT_LANE]), [])

    def test_a_lanes_file_gives_each_lane_its_own_home_queue_and_browser_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'lanes.json'
            path.write_text(json.dumps(TWO), encoding='utf-8')
            l1, l2 = lanes.load(path)
        self.assertEqual((l1.name, l1.home, l1.task_queue), ('l1', (RUNTIME / 'lab-home').resolve(), 'hermes-claude-practice'))
        self.assertEqual(l2.browser_root, (RUNTIME / 'lab-home-2').resolve() / 'profiles' / 'framework-network-analyst'
                         / 'hunt-lab-browser')
        env = l2.env()
        self.assertEqual((env['HERMES_HOME'], env['HUNT_BOTS_TASK_QUEUE'], env['LAB_HERMES_EXE']),
                         (str(l2.home), 'hermes-claude-practice-2', r'C:\lab2\hermes.exe'))
        self.assertEqual(l2.temporal_cli()[-2:], ['--task-queue', 'hermes-claude-practice-2'])
        self.assertEqual(lanes.problems([l1, l2]), [])

    def test_malformed_lanes_are_refused(self):
        bad = [[], [{'name': 'l1'}], [{**TWO[0], 'name': 'Lane One'}], [{**TWO[0], 'colour': 'red'}],
               [{**TWO[0], 'region': [0, 0, 1920, 1080]}], [{**TWO[0], 'task_queue': ''}]]
        for items in bad:
            with self.subTest(items=items), self.assertRaises(ValueError):
                lanes.parse(items)

    def test_lanes_that_could_interfere_are_refused_at_start(self):
        l1, l2 = lanes.parse(TWO)
        cases = {'name': Lane('l1', l2.home, l2.task_queue),
                 'task_queue': Lane('l2', l2.home, l1.task_queue),
                 'hermes_home': Lane('l2', l1.home, l2.task_queue),
                 'own task_queue': Lane('l2', l2.home, None)}
        for needle, other in cases.items():
            with self.subTest(needle=needle):
                self.assertTrue(any(needle in p for p in lanes.problems([l1, other])), lanes.problems([l1, other]))
        self.assertTrue(any('browser dir' in p for p in lanes.problems([l1, cases['hermes_home']])))

    def test_workflow_ids_and_folders_name_the_lane_and_a_single_run_keeps_its_own(self):
        l1, _ = lanes.parse(TWO)
        with patch.object(tl, 'RUN_TAG', '-a'):
            self.assertEqual(tl.workflow_id('film-03', 'lab-med-001'), 'film-03-a-lab-med-001')
            self.assertEqual(tl.workflow_id('film-03', 'lab-med-001', l1), 'film-03-a-l1-lab-med-001')
        loop = Path('film-03')
        self.assertEqual((film_loop.lane_dir(loop, DEFAULT_LANE), film_loop.lane_dir(loop, l1)), (loop, loop / 'l1'))


def lane_out(name, found, coverage, halts=0, misattributed=0, video=True):
    return {'lane': name, 'found': found, 'coverage': coverage, 'halts': halts, 'misattributed': misattributed,
            'video': f'{name}.mp4' if video else None}


class GatewayPreflightTest(unittest.TestCase):
    def lane_with(self, temp, state):
        home = Path(temp) / 'home'
        home.mkdir()
        if state is not None:
            (home / 'gateway_state.json').write_text(json.dumps(state), encoding='utf-8')
        return Lane('l2', home, 'q2')

    def test_only_a_live_persistent_gateway_passes(self):
        running = {'pid': 4242, 'gateway_state': 'running', 'argv': ['main.py', 'gateway', 'run', '--quiet']}
        cases = [
            (running, True, []),
            (None, True, ['no Hermes gateway']),
            (running, False, ['is not running']),
            ({**running, 'gateway_state': 'stopped'}, True, ['is not running']),
            ({**running, 'argv': running['argv'] + ['--idle-exit']}, True, ['auto-started']),
        ]
        for state, alive, expected in cases:
            with self.subTest(state=state, alive=alive), tempfile.TemporaryDirectory() as temp:
                lane = self.lane_with(temp, state)
                found = lanes.gateway_problems([lane], alive=lambda pid, alive=alive: alive and pid == 4242)
                self.assertEqual(len(found), len(expected))
                for problem, phrase in zip(found, expected):
                    self.assertIn(phrase, problem)
                    self.assertIn('hermes gateway run', problem)


class LaneScoringTest(unittest.TestCase):
    def test_the_loop_scores_the_mean_and_any_lane_halting_fails_the_keep_rule(self):
        outs = {'l1': lane_out('l1', 14, 0.6), 'l2': lane_out('l2', 0, 0.2, halts=1)}
        loop = film_loop.aggregate(outs)
        self.assertEqual(loop, {'found': 7.0, 'coverage': 0.4, 'halts': 1, 'misattributed': 0})
        self.assertFalse(film_loop.keep(loop, {'found': 5, 'coverage': 0.1}))
        clean = film_loop.aggregate({'l1': lane_out('l1', 14, 0.6), 'l2': lane_out('l2', 10, 0.4)})
        self.assertEqual(clean, {'found': 12.0, 'coverage': 0.5, 'halts': 0, 'misattributed': 0})
        self.assertTrue(film_loop.keep(clean, {'found': 11, 'coverage': 0.4}))

    def test_a_blamed_decoy_in_one_lane_fails_the_keep_rule(self):
        loop = film_loop.aggregate({'l1': lane_out('l1', 18, 1.0), 'l2': lane_out('l2', 18, 1.0, misattributed=1)})
        self.assertEqual(loop['misattributed'], 1)
        self.assertFalse(film_loop.keep(loop, {'found': 0, 'coverage': 0}))

    def test_the_best_lane_cut_stands_for_the_loop(self):
        self.assertEqual(film_loop.best_lane({'l1': lane_out('l1', 16, 0.9, halts=1), 'l2': lane_out('l2', 9, 0.3)}), 'l2')
        self.assertEqual(film_loop.best_lane({'l1': lane_out('l1', 9, 0.3), 'l2': lane_out('l2', 9, 0.5)}), 'l2')
        self.assertEqual(film_loop.best_lane({'l1': lane_out('l1', 18, 1, video=False), 'l2': lane_out('l2', 2, 0)}), 'l2')
        self.assertIsNone(film_loop.best_lane({'l1': lane_out('l1', 18, 1, video=False)}))

    def test_a_saved_state_resumes_as_one_lane_without_the_knobs_the_cut_dropped(self):
        old = {'found': 9, 'coverage': 0.3, 'misattributed': 0, 'halts': 0, 'result': {'rounds': []}, 'driving': {},
               'video': 'v.mp4', 'loop': 4}
        state = film_loop.upgrade({'best': dict(old), 'last': dict(old), 'last_calls': {'researcher': {'calls': 3}},
                                   'knobs': {'speed': 12.0, 'pad_before': 3.0, 'pad_after': 6.0, 'captions': True}})
        self.assertEqual(state['last']['lanes']['default']['found'], 9)
        self.assertEqual((state['best']['best_lane'], state['last_calls']), ('default', {'default': {'researcher': {'calls': 3}}}))
        self.assertEqual(state['knobs'], {'speed': 12.0, 'captions': True})
        self.assertIs(film_loop.upgrade(state), state)


GOOD = {'tools': {'elastic': {'driven': True, 'evidence': 'typed'}, 'arkime': {'driven': True, 'evidence': 'typed'}},
        'typing_visible': True, 'cursor_visible': True, 'readability': 4, 'readability_notes': 'fine',
        'dead_time': 'little', 'brief_suggestions': [], 'knobs': {}, 'ready': False, 'summary': 'both lanes drive'}


def cut(name, screen_seconds, found):
    seg = {'kind': 'board', 'start': 0, 'end': screen_seconds * 5, 'speed': 5.0, 'captions': [{'text': f'{name} cap'}],
           'out_start': 5, 'out_end': 5 + screen_seconds}
    edit = {'segments': [{'kind': 'intro', 'out_start': 0, 'out_end': 5}, seg], 'out_seconds': screen_seconds + 12,
            'round_seconds': screen_seconds * 5, 'speed': 5.0, 'stages': [], 'longest_board_hold_seconds': 4.0,
            'browser_active_seconds': {}, 'browser_any_active_seconds': 0, 'board_frames': 9, 'screencast_frames': {},
            'knobs': {}, 'video': 'video.mp4'}
    return {'lane': name, 'd': Path(name), 'edit': edit, 'actions': [], 'cov': {'coverage': 0.5},
            'result': {'rounds': [{'found': found, 'total': 18}], 'misattributed': 0, 'halts': 0}}


class LaneReviewTest(unittest.TestCase):
    def run_review(self, cuts):
        calls, stacked = [], []

        def ask(prompt, d, stem, image=None):
            calls.append((prompt, image))
            return json.dumps(GOOD)

        def stack(d, sheets):
            stacked.append(dict(sheets))
            return Path(d) / 'review.png'
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(review, 'sheet', lambda d, edit, actions: Path(d) / 'review.png'), \
                patch.object(review, 'stack', stack):
            out = review.review(Path(tmp), [{**c, 'd': Path(tmp) / c['d']} for c in cuts], ask)
            written = json.loads((Path(tmp) / 'review.json').read_text(encoding='utf-8'))
            return out, calls, stacked, written, Path(tmp)

    def test_two_lanes_get_one_review_call_with_one_stacked_image_and_per_lane_and_mean_metrics(self):
        out, calls, stacked, written, tmp = self.run_review([cut('l1', 30, 12), cut('l2', 10, 6)])
        self.assertEqual(len(calls), 1)
        prompt, image = calls[0]
        self.assertEqual(image, tmp / 'review.png')
        self.assertEqual(stacked, [{'l1': tmp / 'l1' / 'review.png', 'l2': tmp / 'l2' / 'review.png'}])
        context = json.loads(prompt[len(review.REVIEW_RULES):])
        self.assertEqual(sorted(context['lanes']), ['l1', 'l2'])
        self.assertEqual((context['lanes']['l1']['round']['found'], context['lanes']['l2']['round']['found']), (12, 6))
        self.assertEqual(context['mean_over_lanes']['board_seconds'], 20)
        self.assertEqual(written['metrics']['lanes']['l2']['board_seconds'], 10)
        self.assertEqual(written['metrics']['lanes']['l2']['longest_frozen_board_seconds'], 0.8)
        self.assertTrue(out['review']['tools']['arkime']['driven'])

    def test_one_lane_sends_its_own_sheet_unstacked(self):
        _, calls, stacked, written, tmp = self.run_review([cut('default', 30, 12)])
        self.assertEqual((len(calls), stacked, calls[0][1]), (1, [], tmp / 'default' / 'review.png'))
        self.assertEqual(written['metrics']['mean']['board_seconds'], 30)


if __name__ == '__main__':
    unittest.main()
