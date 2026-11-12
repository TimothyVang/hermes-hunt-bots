"""Tests for the filmed loop's pure parts and the screencast client, with no lab, browser or ffmpeg.

Run from the repository root: python -m unittest discover -s operator -p "test_*.py"
"""
import base64
import json
import queue
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import film_loop
import tool_loops as tl
from film import actions as acts
from film import edit as cutter
from film import record, review, screencast
from hunt_lab import screencast as core  # importable once film.screencast has put the framework on sys.path
from lab_paths import Lane

T0 = 1_800_000_000.0


def audit(t, profile, action='open', page='kibana_discover', query=None, text=None, entered=None, ok=True, submit=False):
    return json.dumps({'t': int(t * 1000), 'profile': profile, 'action': action, 'page': page, 'query': query,
                       'text': text, 'entered': entered, 'ok': ok, 'submit': submit})


def activity(t, profile, tool, ok=True, **params):
    iso = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(t)) + f'.{int(t % 1 * 1000):03d}Z'
    return {'seq': 1, 'time': iso, 'profile': profile, 'tool': tool, 'params': params, 'result_count': 3, 'total': 9,
            'error': None if ok else 'invalid_query'}


TH, NA = 'framework-researcher', 'framework-network-analyst'


class CoverageTest(unittest.TestCase):
    def test_share_of_api_searches_typed_on_screen_per_owner(self):
        actions = acts.from_audit([
            audit(T0 + 5, TH, query='Process.Name:x.exe  ', entered='typed'),
            audit(T0 + 6, TH, query='host.name:y', entered='url'),
            audit(T0 + 7, TH, action='click'),
        ], T0, T0 + 100) + acts.from_activity([
            activity(T0 + 1, TH, 'elastic_search', q='process.name:x.exe'),
            activity(T0 + 2, TH, 'elastic_search', q='process.name:x.exe'),
            activity(T0 + 3, TH, 'elastic_search', q='host.name:y'),
            activity(T0 + 4, TH, 'elastic_search', ok=False, q='bad:('),
            activity(T0 + 4, TH, 'elastic_aggregate', q='', field='host.name'),
            activity(T0 + 8, NA, 'arkime_sessions', expression='port == 53'),
        ])
        cov = acts.coverage(actions)
        th, na = cov['owners'][TH], cov['owners'][NA]
        self.assertEqual((th['api_searches'], th['typed_searches'], th['shown_in_browser'], th['both_tools']), (2, 1, 1, True))
        self.assertEqual(th['coverage'], 0.5)
        self.assertEqual((na['api_searches'], na['typed_searches'], na['coverage']), (1, 0, 0.0))
        self.assertEqual(cov['coverage'], 0.25)

    def test_typed_search_on_the_wrong_tool_or_outside_the_round_does_not_count(self):
        actions = acts.from_audit([
            audit(T0 + 5, TH, page='arkime_sessions', query='q1', entered='typed'),
            audit(T0 + 6, TH, page='lab_console', query='q1', entered='typed'),
            audit(T0 + 500, TH, query='q1', entered='typed'),
        ], T0, T0 + 100) + acts.from_activity([activity(T0 + 1, TH, 'elastic_search', q='q1')])
        self.assertEqual(acts.coverage(actions)['owners'][TH]['coverage'], 0.0)

    def test_typing_into_the_search_box_with_enter_counts_as_a_typed_search(self):
        actions = acts.from_audit([audit(T0 + 5, NA, action='type', page='arkime_spiview', text='port == 53', submit=True)],
                                  T0, T0 + 100) + acts.from_activity([activity(T0 + 1, NA, 'arkime_unique', expression='port == 53')])
        self.assertEqual(acts.coverage(actions)['owners'][NA]['coverage'], 1.0)


class KeepRuleTest(unittest.TestCase):
    BEST = {'found': 12, 'coverage': 0.5}

    def outcome(self, found, coverage, misattributed=0, halts=0):
        return {'found': found, 'coverage': coverage, 'misattributed': misattributed, 'halts': halts}

    def test_keep_rule(self):
        cases = [
            (self.outcome(12, 0.6), True),
            (self.outcome(12, 0.5), False),
            (self.outcome(14, 0.4), True),
            (self.outcome(14, 0.39), False),
            # A coverage gain of at least 0.2 survives a score drop within the one-round noise band (2).
            (self.outcome(11, 0.9), True),
            (self.outcome(10, 0.71), True),
            (self.outcome(9, 0.9), False),
            (self.outcome(11, 0.69), False),
            (self.outcome(18, 1.0, misattributed=1), False),
            (self.outcome(18, 1.0, halts=1), False),
        ]
        for new, kept in cases:
            with self.subTest(new=new):
                self.assertEqual(film_loop.keep(new, self.BEST), kept)

    def test_rejudge_last_keeps_a_loop_the_old_rule_reverted_and_only_that_loop(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(film_loop, 'FILM_LOOPS', Path(temp)), \
                patch.object(film_loop.tl, 'log'):
            (Path(temp) / 'film-01').mkdir()
            (Path(temp) / 'film-01' / 'decision.json').write_text(json.dumps({'kept': False}), encoding='utf-8')
            best = {'loop': 0, 'found': 7, 'coverage': 0.05, 'video': None}
            last = {'loop': 1, 'found': 5, 'coverage': 0.64, 'misattributed': 0, 'halts': 0, 'video': None}
            state = {'best': best, 'last': last, 'no_gain': 1,
                     'history': [{'loop': 1, 'found': 5, 'coverage': 0.64, 'kept': False}]}
            self.assertTrue(film_loop.rejudge_last(state, 'keep rule gained a noise band'))
            self.assertIs(state['best'], last)
            self.assertEqual((state['history'][-1]['kept'], state['no_gain']), (True, 0))
            record = json.loads((Path(temp) / 'film-01' / 'decision.json').read_text(encoding='utf-8'))
            self.assertEqual(record, {'kept': True, 'rejudged': 'keep rule gained a noise band'})
            # Already kept, or a decoy blamed: nothing changes.
            self.assertFalse(film_loop.rejudge_last(state, 'again'))
            blamed = {'best': best, 'last': {**last, 'misattributed': 1}, 'no_gain': 1,
                      'history': [{'loop': 1, 'found': 5, 'coverage': 0.64, 'kept': False}]}
            self.assertFalse(film_loop.rejudge_last(blamed, 'decoy'))
            self.assertIs(blamed['best'], best)

    def test_seed_config_reads_film_and_tool_loop_best_files(self):
        base = {'scope': 'Synthetic lab-med-001 only; case brief'}
        film = {'brief': 'b', 'guidance': {'evidence': 'g'}, 'drive_note': 'use lab_browser'}
        self.assertEqual(film_loop.seed_config(film, base), {'brief': 'b', 'guidance': {'evidence': 'g'},
                                                             'drive_note': 'use lab_browser'})
        tool = {'brief': 't', 'stage_guidance': {'network': 'n'}}
        self.assertEqual(film_loop.seed_config(tool, base), {'brief': 't', 'guidance': {'network': 'n'},
                                                             'drive_note': film_loop.DRIVE_NOTE})
        self.assertEqual(film_loop.seed_config({}, base)['brief'], 'case brief')

    def test_finished_needs_all_facts_coverage_and_a_ready_review(self):
        best = {'found': 18, 'coverage': 0.8, 'review': {'ready': True}}
        self.assertTrue(film_loop.finished(best))
        self.assertFalse(film_loop.finished({**best, 'coverage': 0.79}))
        self.assertFalse(film_loop.finished({**best, 'review': None}))


def good_review(**over):
    obj = {'tools': {'elastic': {'driven': True, 'evidence': 'search typed in the lab console'},
                     'arkime': {'driven': False, 'evidence': 'no Arkime page shown'}},
           'typing_visible': True, 'cursor_visible': True, 'readability': 4, 'readability_notes': 'consoles small',
           'dead_time': 'long sped-up stretches', 'brief_suggestions': ['run Arkime searches in the browser'],
           'knobs': {'speed': 16, 'captions': False}, 'ready': False, 'summary': 'Elastic driven, Arkime not.'}
    obj.update(over)
    return obj


class ReviewValidationTest(unittest.TestCase):
    def test_valid_review_passes_with_knobs_normalized(self):
        rv, problems = review.validate(good_review())
        self.assertEqual(problems, [])
        self.assertEqual(rv['knobs'], {'speed': 16.0, 'captions': False})

    def test_schema_violations_are_reported(self):
        bad = [
            good_review(tools={'elastic': {'driven': True, 'evidence': 'x'}}),
            good_review(readability=7),
            good_review(ready='yes'),
            good_review(knobs={'fps': 60}),
            good_review(knobs={'speed': 100}),
            good_review(knobs={'intro_title': '18 of 18 facts found'}),
            good_review(brief_suggestions=['x'] * 6),
            good_review(verdict='great'),
        ]
        for obj in bad:
            with self.subTest(obj=obj):
                rv, problems = review.validate(obj)
                self.assertIsNone(rv)
                self.assertTrue(problems)

    def test_a_browser_moment_shows_the_actor_screencast_frame_at_its_place_in_the_cut(self):
        segs = cutter.timeline(stage_plan(speed=5))
        edit = {'round_start': T0, 'round_end': T0 + 120, 'segments': segs}
        typed = acts.from_audit([audit(T0 + 30, TH, query='a', entered='typed'),
                                 audit(T0 + 60, NA, page='arkime_sessions', query='b', entered='typed')], T0, T0 + 120)
        browsers = {TH: [(T0 + 29, 'th-1.jpg'), (T0 + 31, 'th-2.jpg'), (T0 + 50, 'th-3.jpg')]}
        self.assertEqual(review.browser_moments(edit, typed, browsers),
                         [(cutter.to_output(segs, 30), typed[0].caption, 'th-2.jpg')])

    def test_bad_json_is_retried_once_and_never_more(self):
        replies = iter(['I think it is fine.', json.dumps(good_review())])
        calls = []

        def ask(prompt, d, stem, image=None):
            calls.append((stem, image, prompt))
            return next(replies)
        out = review.consult('PROMPT', Path('.'), 'sheet.png', ask)
        self.assertEqual((out['calls'], len(calls), out['review']['ready']), (2, 2, False))
        self.assertIn('REJECTED', calls[1][2])
        self.assertEqual({c[1] for c in calls}, {'sheet.png'})

        calls.clear()
        out = review.consult('PROMPT', Path('.'), 'sheet.png', lambda *a, **k: calls.append(a) or '{"ready": true}')
        self.assertEqual((len(calls), out['review']), (2, None))
        self.assertTrue(out['problems'])


def steps(*states):
    states = states + ('pending',) * (len(tl.STEPS) - len(states))
    return [{'index': i, 'step_id': tl.STEPS[i], 'role': f'Role {i}', 'profile': 'p', 'state': s} for i, s in enumerate(states)]


# The board as the recorder sampled it: scope's gate opens 2 s into the round, evidence starts at 40 s,
# hypotheses at 90 s and is still running when the round's footage ends at 120 s.
SAMPLES = [(T0 - 5, steps()), (T0 + 2, steps('awaiting_approval')), (T0 + 10, steps('working')),
           (T0 + 40, steps('done', 'working')), (T0 + 90, steps('done', 'done', 'working'))]


def stage_plan(speed, actions=(), captions=False):
    stages = cutter.stage_timings(SAMPLES, T0, T0 + 120)
    return cutter.plan(120, T0, stages, list(actions), cutter.Knobs(speed=speed, captions=captions), speed,
                       cutter.wave_count(SAMPLES))


# The steps of a real parallel round's final status (team-k6-131024-real-win-002:round:001, through the board's
# build_state): (step_id, role, wave, final state, reason). follow-2 was dropped after its retry.
PARALLEL = [('scope', 'Incident Response Lead', 1, 'done', ''), ('evidence', 'Threat Hunter', 2, 'done', ''),
            ('hypotheses', 'Threat Hunter', 2, 'done', ''), ('network', 'Network Analyst', 2, 'done', ''),
            ('intel', 'Threat Intelligence Analyst', 2, 'done', ''), ('analysis', 'Incident Response Lead', 3, 'done', ''),
            ('follow-1', 'Threat Hunter', 4, 'done', ''), ('follow-2', 'Threat Hunter', 4, 'dropped', 'retry_exhausted'),
            ('follow-3', 'Threat Hunter', 4, 'done', ''), ('follow-4', 'Threat Hunter', 4, 'done', ''),
            ('follow-5', 'Threat Hunter', 4, 'done', ''), ('follow-6', 'Threat Hunter', 4, 'done', ''),
            ('merge', 'Incident Response Lead', 5, 'done', ''), ('detection', 'Detection Engineer', 6, 'done', ''),
            ('purple', 'Purple Team Analyst', 7, 'done', ''), ('incident', 'Incident Response Lead', 8, 'done', '')]


def wave_steps(open_wave, closed, working=None):
    """The parallel round's board steps: closed waves in their final state, open_wave's steps working (or
    working[step_id] when given), the rest pending."""
    out = []
    for i, (step_id, role, wave, final, reason) in enumerate(PARALLEL):
        state = final if wave in closed else (working or {}).get(step_id, 'working') if wave == open_wave else 'pending'
        out.append({'index': i, 'step_id': step_id, 'role': role, 'profile': 'p', 'state': state, 'wave': wave,
                    'reason': reason if state == final else ''})
    return out


# Each wave opens 2 s after the previous one closes and lasts 60 s; the round's footage ends at 500 s.
PAR_SAMPLES = [(T0 - 5, wave_steps(None, set()))]
for _k in range(8):
    PAR_SAMPLES += [(T0 + 62 * _k + 2, wave_steps(_k + 1, set(range(1, _k + 1)))),
                    (T0 + 62 * _k + 62, wave_steps(None, set(range(1, _k + 2))))]

# The same round halted in its follow-up wave: the board marks the wave's open steps stopped and later waves
# not reached.
HALTED = [s | ({'state': 'stopped', 'reason': 'workflow_halted'} if s['wave'] == 4 else
               {'state': 'not_reached'} if s['wave'] > 4 else {}) for s in wave_steps(None, {1, 2, 3})]


class ParallelFilmTest(unittest.TestCase):
    def test_a_dropped_step_ends_with_its_reason(self):
        stages = {s.step_id: s for s in cutter.stage_timings(PAR_SAMPLES, T0, T0 + 500)}
        self.assertEqual(len(stages), 16)
        drop = stages['follow-2']
        self.assertEqual((drop.wave, drop.finished, drop.end - T0, drop.state, drop.reason),
                         (4, True, 248, 'dropped', 'retry_exhausted'))

    def test_one_chapter_card_per_wave_counted_from_the_steps(self):
        items = cutter.plan(500, T0, cutter.stage_timings(PAR_SAMPLES, T0, T0 + 500), [], cutter.Knobs(captions=False),
                            5, cutter.wave_count(PAR_SAMPLES))
        chapters = [s for s in cutter.timeline(items) if s['kind'] == 'chapter']
        self.assertEqual([(c['wave'], c['at']) for c in chapters], [(w, 62 * (w - 1) + 2) for w in range(1, 9)])
        follow = chapters[3]
        self.assertEqual(follow['step_ids'], [f'follow-{n}' for n in range(1, 7)])
        self.assertEqual(follow['lines'][:3], ['Wave 4 of 8 · 6 steps',
                                               'Follow-1, Follow-2, Follow-3, Follow-4, Follow-5, Follow-6', 'Threat Hunter'])
        self.assertEqual(follow['lines'][4:], ['1 min 00 s', 'Dropped (retry exhausted): Follow-2'])
        self.assertEqual(chapters[1]['lines'][:2], ['Wave 2 of 8 · Evidence, Hypotheses, Network, Intel',
                                                    'Threat Hunter · Network Analyst · Threat Intelligence Analyst'])
        self.assertFalse(any('not finished' in line for c in chapters for line in c['lines']))

    def test_card_lines_stay_inside_the_frame_for_the_widest_wave(self):
        def card(reasons):
            wide = [cutter.Stage(n, f'follow-{n}', 'Threat Hunter', 4, T0, T0 + 60, True, 'stopped' if n % 2 else 'dropped',
                                 reasons(n)) for n in range(1, 13)]
            return cutter.chapter_lines(cutter.Chapter(0, 4, tuple(wide), 8))

        for lines in (card(lambda n: 'no_surviving_dependency'), card(lambda n: f'reason_{n}')):
            self.assertLessEqual(len(lines[0]), cutter.TITLE_CHARS)
            self.assertTrue(all(len(line) <= cutter.CARD_CHARS for line in lines[1:]))
            # Renderer.card spaces lines 68 px around the middle: the first and last must stay inside 1080 px.
            self.assertLessEqual(len(lines), cutter.CARD_LINES)
            self.assertGreaterEqual(540 - (len(lines) - 1) * 34, 52)
        shared = card(lambda n: 'no_surviving_dependency')
        flagged = shared[[k for k, line in enumerate(shared) if line.startswith('Stopped (')][0]:]
        self.assertEqual([line.split(':')[0] for line in flagged if ': Follow-' in line],
                         ['Stopped (no surviving dependency)', 'Dropped (no surviving dependency)'])
        self.assertEqual(sum(line.count('Follow-') for line in flagged), 12)
        self.assertTrue(card(lambda n: f'reason_{n}')[-1].endswith('more lines in edit.json'))
        outro = cutter.steps_lines([{'index': n, 'step_id': f'follow-{n}', 'state': 'dropped', 'wave': 4,
                                     'reason': 'no_surviving_dependency'} for n in range(12)])
        self.assertTrue(all(len(line) <= cutter.CARD_CHARS for line in outro))
        self.assertEqual(sum(line.count('follow-') for line in outro), 12)

    def test_the_outro_counts_the_real_steps(self):
        self.assertEqual(cutter.steps_lines(PAR_SAMPLES[-1][1]),
                         ['15 of 16 steps done in 8 waves · 1 dropped', 'Dropped (retry exhausted): follow-2'])
        self.assertEqual(cutter.steps_lines(steps(*['done'] * 9)), ['9 of 9 steps done'])
        self.assertEqual(cutter.steps_lines(HALTED),
                         ['6 of 16 steps done in 8 waves · 6 stopped · 4 not reached',
                          'Stopped (workflow halted): follow-1, follow-2, follow-3, follow-4, follow-5, follow-6'])

    def test_the_recorder_keeps_wave_and_reason(self):
        kept = record.steps_of({'steps': PAR_SAMPLES[-1][1]})[7]
        self.assertEqual((kept['wave'], kept['state'], kept['reason']), (4, 'dropped', 'retry_exhausted'))


JS = shutil.which('bun') or shutil.which('node')


@unittest.skipUnless(JS, 'needs bun or node')
class ToolcamProgressTest(unittest.TestCase):
    def progress(self, steps):
        url = (Path(__file__).parent / 'toolcam' / 'progress.mjs').resolve().as_uri()
        code = (f'import {{ pipeline, endCard }} from {json.dumps(url)};'
                f'const s = {json.dumps(steps)}; console.log(JSON.stringify([pipeline(s), endCard(s)]));')
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / 'p.mjs'
            script.write_text(code, encoding='utf-8')
            out = subprocess.run([JS, str(script)], capture_output=True, text=True, encoding='utf-8', check=True)
        return json.loads(out.stdout)

    def test_every_open_step_of_the_wave_and_dropped_counts_as_ended(self):
        mid = wave_steps(4, {1, 2, 3}, {'follow-1': 'done', 'follow-2': 'dropped', 'follow-3': 'awaiting_review'})
        mid[7]['reason'] = 'retry_exhausted'
        line, _ = self.progress(mid)
        self.assertEqual(line, 'Wave 4/8 · follow-3 awaiting_review, follow-4 working, follow-5 working, follow-6 working'
                               ' · 7/16 steps done · follow-2 dropped: retry exhausted')

    def test_a_wide_wave_is_counted_by_state(self):
        line, _ = self.progress(wave_steps(4, {1, 2, 3}, {'follow-1': 'awaiting_review'}))
        self.assertEqual(line, 'Wave 4/8 · 6 steps: 1 awaiting_review, 5 working · 6/16 steps done')

    def test_the_end_card_counts_the_real_steps(self):
        self.assertEqual(self.progress(PAR_SAMPLES[-1][1])[1],
                         {'title': 'Hunt complete', 'sub': '15/16 steps done · follow-2 dropped: retry exhausted. Final '
                                                           'report written by the Incident Response Lead.'})

    def test_a_halted_round_ends_early_and_names_what_it_never_reached(self):
        self.assertEqual(self.progress(HALTED)[1],
                         {'title': 'Hunt ended early', 'sub': '6/16 steps done · 6 steps stopped: workflow halted · '
                                                              'not reached: waves 5–8 (4 steps).'})

    def test_a_serial_round_shows_its_one_open_step(self):
        self.assertEqual(self.progress(steps('done', 'working'))[0], 'Step 2/9 · Role 1 working')


class StageTimingTest(unittest.TestCase):
    def test_each_stage_starts_when_the_board_first_shows_it_past_pending(self):
        stages = cutter.stage_timings(SAMPLES, T0, T0 + 120)
        self.assertEqual([(s.number, s.step_id, s.start - T0, s.end - T0, s.finished) for s in stages],
                         [(1, 'scope', 2, 40, True), (2, 'evidence', 40, 90, True), (3, 'hypotheses', 90, 120, False)])
        self.assertEqual(cutter.stage_count(SAMPLES), 9)

    def test_a_stage_already_under_way_when_filming_began_gets_no_chapter(self):
        stages = cutter.stage_timings(SAMPLES[2:], T0, T0 + 120)
        self.assertEqual([s.step_id for s in stages], ['evidence', 'hypotheses'])

    def test_the_recorder_samples_only_changes_of_the_board_steps(self):
        states = iter([{'steps': steps()}, {'steps': steps()}, None, {'steps': steps('working')}])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'board-state.jsonl'
            poller = record.StatePoller('http://127.0.0.1:1/', path, fetch=lambda url: next(states))
            for _ in range(4):
                poller.sample()
            samples = cutter.read_states(path)
        self.assertEqual(poller.samples, 2)
        self.assertEqual([s[1][0]['state'] for s in samples], ['pending', 'working'])
        self.assertEqual(set(samples[0][1][0]), {'index', 'step_id', 'role', 'profile', 'state', 'wave', 'reason'})

    def test_the_board_is_started_for_the_round_lane_and_its_live_browsers(self):
        lane = Lane('l2', Path('home2'), 'q2')
        cmd = record.board_command(8123, 'film-01-l2-c', Path('d/input.json'), lane, 41)
        self.assertEqual(cmd[1:4], ['-B', '-m', 'hermes_temporal.board'])
        args = dict(zip(cmd[4::2], cmd[5::2]))
        self.assertEqual({k: args[k] for k in ('--workflow-id', '--input', '--port', '--lab-state-dir', '--hermes-home',
                                               '--activity-after')},
                         {'--workflow-id': 'film-01-l2-c', '--input': str(Path('d/input.json')), '--port': '8123',
                          '--lab-state-dir': str(lane.state_dir), '--hermes-home': 'home2', '--activity-after': '41'})


class EditPlanTest(unittest.TestCase):
    def test_the_reviewed_cut_plays_the_whole_round_at_one_constant_speed(self):
        items = stage_plan(speed=5)
        board = [i for i in items if isinstance(i, cutter.Segment)]
        self.assertEqual({s.speed for s in board}, {5})
        self.assertEqual([(s.start, s.end) for s in board], [(0, 2), (2, 40), (40, 90), (90, 120)])
        segs = cutter.timeline(items)
        self.assertAlmostEqual(sum(s['out_end'] - s['out_start'] for s in segs if s['kind'] == 'board'), 120 / 5)
        # Round second 50 is 2+38+10 s of footage at 5x after the intro and two chapter cards.
        self.assertAlmostEqual(cutter.to_output(segs, 50), cutter.INTRO_SECONDS + 50 / 5 + 2 * cutter.CHAPTER_SECONDS)
        self.assertAlmostEqual(cutter.to_output(segs, 100) - cutter.to_output(segs, 95), 1.0)

    def test_a_chapter_card_opens_each_real_stage_start(self):
        items = stage_plan(speed=5)
        chapters = [(k, i) for k, i in enumerate(items) if isinstance(i, cutter.Chapter)]
        self.assertEqual([i.at for _, i in chapters], [2, 40, 90])
        for k, chapter in chapters:
            self.assertEqual(items[k + 1].start, chapter.at)
        first = cutter.chapter_lines(chapters[0][1])
        self.assertEqual((first[0], first[1], first[3]), ('Wave 1 of 9 · Scope', 'Role 0', '38 s'))
        self.assertIn('not finished', cutter.chapter_lines(chapters[2][1])[2])

    def test_option_a_footage_lasts_exactly_as_long_as_the_round(self):
        segs = cutter.timeline(stage_plan(speed=1))
        self.assertEqual(sum(s['out_end'] - s['out_start'] for s in segs if s['kind'] == 'board'), 120)
        self.assertEqual(segs[-1]['out_end'], cutter.INTRO_SECONDS + 120 + 3 * cutter.CHAPTER_SECONDS + cutter.OUTRO_SECONDS)

    def test_every_option_b_frame_carries_the_speed_label(self):
        items = stage_plan(speed=5, actions=acts.from_activity([activity(T0 + 30, TH, 'elastic_search', q='a')]),
                           captions=True)
        segs = cutter.timeline(items)
        cards = {'intro': 'intro.jpg', 'outro': 'outro.jpg'} | {i: f'ch-{i.wave}.jpg' for i in items
                                                              if isinstance(i, cutter.Chapter)}
        entries = cutter.listing(items, [(-1, 'f0.jpg'), (10, 'f1.jpg'), (70, 'f2.jpg')], cards, 5)
        self.assertEqual((entries[0][0], entries[-1][0]), ('intro.jpg', 'outro.jpg'))
        self.assertAlmostEqual(sum(s for _, s in entries), segs[-1]['out_end'])
        with tempfile.TemporaryDirectory() as tmp, patch.object(cutter.subprocess, 'run') as run:
            r = cutter.Renderer(Path(tmp))
            r.video(entries, 5, cutter.overlay(segs, 5), Path(tmp) / 'video.mp4')
            graph = (Path(tmp) / 'video.filter.txt').read_text(encoding='utf-8')
            texts = {f.read_text(encoding='utf-8'): f for f in Path(tmp).glob('text-*.txt')}
        self.assertEqual(run.call_count, 1)
        self.assertIn(f'trim=duration={segs[-1]["out_end"]:.6f}', graph)
        draws = graph.split(',drawtext=')
        label = next(d for d in draws if texts['5x speed · every frame is real'].name in d)
        self.assertNotIn('enable=', label)
        caption = next(d for d in draws if any(texts[t].name in d for t in texts if 'elastic_search' in t))
        self.assertIn('enable=', caption)

    def test_captions_follow_the_bots_and_can_be_turned_off(self):
        actions = acts.from_activity([activity(T0 + 30, TH, 'elastic_search', q='a')])
        on = [i for i in stage_plan(speed=5, actions=actions, captions=True) if isinstance(i, cutter.Segment)]
        self.assertEqual([(c.start, c.end) for c in on[1].captions], [(5.6, 7.6)])
        self.assertIn('elastic_search', on[1].captions[0].text)
        off = stage_plan(speed=5, actions=actions)
        self.assertFalse(any(i.captions for i in off if isinstance(i, cutter.Segment)))

    def test_frame_schedule_holds_each_frame_until_the_next(self):
        frames = [(10, 'a'), (20, 'b'), (25, 'c'), (40, 'd')]
        self.assertEqual(cutter.frame_schedule(frames, 15, 30), [('a', 5), ('b', 5), ('c', 5)])

    def test_blank_screencast_frames_are_never_counted_as_shown(self):
        with tempfile.TemporaryDirectory() as tmp:
            blank, page = Path(tmp) / 'blank.jpg', Path(tmp) / 'page.jpg'
            blank.write_bytes(b'\0' * 7_000)
            page.write_bytes(b'\0' * 90_000)
            shown = cutter.shown_frames({TH: [(T0 + 20, blank), (T0 + 31, page), (T0 + 33, blank)], NA: [(T0 + 40, blank)]})
            self.assertEqual(shown, {TH: [(T0 + 31, page)]})

    def test_browser_live_time_and_the_longest_frozen_board(self):
        self.assertEqual(cutter.active_seconds([T0 + 1, T0 + 3, T0 + 50], T0, T0 + 55, hold=8), 10 + 5)
        self.assertEqual(cutter.longest_hold([T0 - 2, T0 + 10, T0 + 12], T0, T0 + 40), 28)

    def test_removed_knobs_are_refused(self):
        self.assertEqual(cutter.check_knobs({'pad_before': 3})[1], ['unknown knob pad_before'])
        self.assertEqual(cutter.Knobs().speed, 5.0)


class FakeBrowser:
    """A DevTools browser endpoint: answers attach and screencast commands and emits frames."""

    def __init__(self, frames, targets=('T1',)):
        self.inbox, self.sent, self.frames, self.targets = queue.Queue(), [], frames, targets

    def send(self, text):
        m = json.loads(text)
        self.sent.append(m)
        method, sid = m['method'], m.get('sessionId')
        if method == 'Target.getTargets':
            self.push({'id': m['id'], 'result': {'targetInfos': [{'targetId': 'W1', 'type': 'service_worker'}]
                                                + [{'targetId': t, 'type': 'page'} for t in self.targets]}})
        elif method == 'Target.attachToTarget':
            self.session = 'S-' + m['params']['targetId']
            self.push({'method': 'Target.attachedToTarget', 'params': {'sessionId': self.session}})
            self.push({'id': m['id'], 'result': {'sessionId': self.session}})
        elif method == 'Page.startScreencast':
            self.push({'id': m['id'], 'result': {}, 'sessionId': sid})
            self.push({'method': 'Page.screencastVisibilityChanged', 'params': {'visible': True}, 'sessionId': sid})
            for n, (t, data) in enumerate(self.frames):
                self.push({'method': 'Page.screencastFrame', 'sessionId': sid, 'params': {
                    'data': base64.b64encode(data).decode(), 'metadata': {'timestamp': t}, 'sessionId': 100 + n}})
            self.push({'method': 'Page.screencastFrame', 'sessionId': 'OTHER', 'params': {
                'data': base64.b64encode(b'not ours').decode(), 'metadata': {'timestamp': 1.0}, 'sessionId': 999}})
        elif 'id' in m and method != 'Page.screencastFrameAck':
            self.push({'id': m['id'], 'result': {}})

    def push(self, message):
        self.inbox.put(json.dumps(message))

    def recv(self):
        return self.inbox.get()

    def close(self):
        self.inbox.put(None)


class ScreencastTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        log, tl.LOG = tl.LOG, self.root / 'loop.log'
        self.addCleanup(setattr, tl, 'LOG', log)
        (self.root / 'browsers' / TH).mkdir(parents=True)

    def point_at(self, ws_url, target):
        (self.root / 'browsers' / TH / 'session.json').write_text(json.dumps({'ws_url': ws_url, 'main_target': target}))

    def wait_for(self, check):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if check():
                return
            time.sleep(0.02)
        self.fail('timed out')

    def test_frames_are_indexed_acked_and_reattached_when_the_target_changes(self):
        browsers = {'ws://b1': FakeBrowser([(T0 + 1.25, b'jpeg-1'), (T0 + 2.5, b'jpeg-2')]),
                    'ws://b2': FakeBrowser([(T0 + 9.0, b'jpeg-3')])}
        connected = []

        def connect(url):
            connected.append(url)
            return browsers[url]
        out = self.root / 'screencast'
        self.point_at('ws://b1', 'T1')
        watcher = screencast.Watcher(out, root=self.root / 'browsers', profiles=(TH,), connect=connect, poll=0.05).start()
        try:
            self.wait_for(lambda: len(screencast.read_index(out).get(TH, [])) == 2)
            self.point_at('ws://b2', 'T2')
            self.wait_for(lambda: len(screencast.read_index(out).get(TH, [])) == 3)
        finally:
            watcher.stop()
        frames = screencast.read_index(out)[TH]
        self.assertEqual([(t, p.name, p.read_bytes()) for t, p in frames], [
            (T0 + 1.25, '000001.jpg', b'jpeg-1'), (T0 + 2.5, '000002.jpg', b'jpeg-2'), (T0 + 9.0, '000003.jpg', b'jpeg-3')])
        lines = [json.loads(x) for x in (out / 'index.jsonl').read_text().splitlines()]
        self.assertEqual(lines[0], {'t': T0 + 1.25, 'profile': TH, 'file': f'{TH}/000001.jpg'})
        self.assertEqual(connected, ['ws://b1', 'ws://b2'])
        b1 = browsers['ws://b1'].sent
        self.assertEqual([m['params']['targetId'] for m in b1 if m['method'] == 'Target.attachToTarget'], ['T1'])
        self.assertEqual([m['params']['sessionId'] for m in b1 if m['method'] == 'Page.screencastFrameAck'], [100, 101])
        self.assertIn('Page.stopScreencast', [m['method'] for m in browsers['ws://b2'].sent])
        sent = {m['method'] for b in browsers.values() for m in b.sent}
        self.assertLessEqual(sent, core.READ_ONLY)

    def test_a_freshly_launched_browser_is_filmed_before_lab_browser_writes_session_json(self):
        live = 'ws://127.0.0.1:9222/devtools/browser/new'
        browser = FakeBrowser([(T0 + 0.5, b'typing the first search')], targets=('T1', 'T9'))
        connected = []

        def connect(url):
            connected.append(url)
            if url != live:
                raise ConnectionRefusedError(url)
            return browser
        self.point_at('ws://127.0.0.1:9100/devtools/browser/old', 'T0')
        port = self.root / 'browsers' / TH / 'user-data'
        port.mkdir()
        (port / 'DevToolsActivePort').write_text('9222\n/devtools/browser/new\n')
        out = self.root / 'screencast'
        watcher = screencast.Watcher(out, root=self.root / 'browsers', profiles=(TH,), connect=connect, poll=0.05).start()
        try:
            self.wait_for(lambda: len(screencast.read_index(out).get(TH, [])) == 1)
            self.point_at(live, 'T1')
            time.sleep(0.3)
        finally:
            watcher.stop()
        self.assertEqual(connected, [live])
        self.assertEqual([m['params']['targetId'] for m in browser.sent if m['method'] == 'Target.attachToTarget'], ['T1'])
        self.assertEqual(screencast.read_index(out)[TH][0][1].read_bytes(), b'typing the first search')

    def test_the_client_refuses_any_command_that_could_drive_the_page(self):
        client = core.ReadOnlyCdp(FakeBrowser([]), lambda m: None)
        try:
            for method in ('Input.dispatchMouseEvent', 'Runtime.evaluate', 'Fetch.enable', 'Page.navigate'):
                with self.assertRaises(PermissionError):
                    client.post(method, {})
        finally:
            client.close()

    def test_a_missing_or_partial_session_file_attaches_nothing(self):
        connected = []
        (self.root / 'browsers' / TH / 'session.json').write_text('{"ws_url": "ws://b1"}')
        watcher = screencast.Watcher(self.root / 'sc', root=self.root / 'browsers', profiles=(TH, NA),
                                     connect=connected.append, poll=0.02).start()
        time.sleep(0.2)
        watcher.stop()
        self.assertEqual(connected, [])
        self.assertEqual(screencast.read_index(self.root / 'sc'), {})


if __name__ == '__main__':
    unittest.main()
