"""Tests for the filmed loop's pure parts and the screencast client, with no lab, browser or ffmpeg.

Run from the repository root: python -m unittest discover -s operator -p "test_*.py"
"""
import base64
import json
import queue
import tempfile
import time
import unittest
from pathlib import Path

import film_loop
import tool_loops as tl
from film import actions as acts
from film import edit as cutter
from film import record, review, screencast

T0 = 1_800_000_000.0


def audit(t, profile, action='open', page='lab_console', query=None, text=None, entered=None, ok=True, submit=False):
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
            (self.outcome(11, 0.9), False),
            (self.outcome(18, 1.0, misattributed=1), False),
            (self.outcome(18, 1.0, halts=1), False),
        ]
        for new, kept in cases:
            with self.subTest(new=new):
                self.assertEqual(film_loop.keep(new, self.BEST), kept)

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

    def test_a_browser_moment_shows_the_actor_page_once_it_is_on_screen(self):
        segs = [cutter.Segment(0, 27, 10), cutter.Segment(27, 31, 1), cutter.Segment(31, 36, 1, TH), cutter.Segment(36, 120, 10)]
        edit = {'t0': T0, 'capture_seconds': 120, 'segments': [{**vars(s), 'captions': []} for s in segs]}
        typed = acts.from_audit([audit(T0 + 30, TH, query='a', entered='typed')], T0, T0 + 120)
        self.assertEqual([t for t, _ in review.browser_moments(edit, typed)], [cutter.to_output(segs, 31.5)])

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


class EditPlanTest(unittest.TestCase):
    KNOBS = cutter.Knobs(speed=10, pad_before=3, pad_after=6)

    def plan(self, audit_lines, activity_entries=(), frames=None, duration=120):
        actions = acts.from_audit(audit_lines, T0, T0 + duration) + acts.from_activity(list(activity_entries))
        return cutter.plan(duration, T0, actions, frames or {}, self.KNOBS)

    def test_browser_stretches_play_real_time_on_the_actor_screencast(self):
        segs = self.plan([audit(T0 + 30, TH, query='a', entered='typed'), audit(T0 + 33, TH, action='click'),
                          audit(T0 + 80, NA, page='arkime_sessions', query='b', entered='typed')],
                         [activity(T0 + 10, TH, 'elastic_search', q='a')],
                         frames={TH: [T0 + 20, T0 + 31], NA: [T0 + 82]})
        self.assertEqual([(s.start, s.end, s.speed, s.screencast) for s in segs], [
            (0, 27, 10, None), (27, 39, 1, TH), (39, 77, 10, None), (77, 82, 1, None), (82, 86, 1, NA), (86, 120, 10, None)])
        self.assertEqual(segs[1].captions[0].start, 3.0)
        self.assertIn('Threat Hunter · lab console (Elastic) · searches "a"', segs[1].captions[0].text)
        self.assertTrue(segs[0].captions and 'elastic_search' in segs[0].captions[0].text)
        self.assertEqual(cutter.to_output(segs, 30), cutter.INTRO_SECONDS + 2.7 + 3)

    def test_overlapping_bots_split_without_overlap_and_tiny_gaps_stay_real_time(self):
        segs = self.plan([audit(T0 + 50, TH, query='a', entered='typed'), audit(T0 + 52, NA, page='arkime_sessions')])
        real = [(s.start, s.end) for s in segs if s.speed == 1]
        self.assertEqual(real, [(47, 50), (50, 58)])
        self.assertEqual(segs[0].start, 0)
        self.assertEqual(segs[-1].end, 120)
        for a, b in zip(segs, segs[1:]):
            self.assertEqual(a.end, b.start)

    def test_captions_off_and_no_browser_action_means_one_sped_up_backdrop(self):
        segs = cutter.plan(60, T0, acts.from_activity([activity(T0 + 5, TH, 'elastic_search', q='a')]), {},
                           cutter.Knobs(captions=False))
        self.assertEqual([(s.start, s.end, s.speed, s.screencast, s.captions) for s in segs], [(0, 60, 12.0, None, ())])

    def test_frame_schedule_holds_each_frame_until_the_next(self):
        frames = [(10, 'a'), (20, 'b'), (25, 'c'), (40, 'd')]
        self.assertEqual(cutter.frame_schedule(frames, 15, 30), [('a', 5), ('b', 5), ('c', 5)])

    def test_blank_screencast_frames_are_never_shown(self):
        with tempfile.TemporaryDirectory() as tmp:
            blank, page = Path(tmp) / 'blank.jpg', Path(tmp) / 'page.jpg'
            blank.write_bytes(b'\0' * 7_000)
            page.write_bytes(b'\0' * 90_000)
            shown = cutter.shown_frames({TH: [(T0 + 20, blank), (T0 + 31, page), (T0 + 33, blank)], NA: [(T0 + 40, blank)]})
            self.assertEqual(shown, {TH: [(T0 + 31, page)]})
            segs = self.plan([audit(T0 + 30, TH, query='a', entered='typed')],
                             frames={p: [t for t, _ in v] for p, v in shown.items()})
            self.assertEqual([(s.start, s.end, s.screencast) for s in segs if s.speed == 1], [(27, 31, None), (31, 36, TH)])
            self.assertEqual(cutter.frame_schedule([(t - T0, f) for t, f in shown[TH]], 31, 36), [(page, 5)])


class PrivacyCoverageTest(unittest.TestCase):
    TITLES = {k: f'{c.title} [wf]' for k, c in record.CONSOLES.items()}

    def ours(self, **over):
        return [record.Win(self.TITLES[k], over.get(k, c.rect), True, True) for k, c in record.CONSOLES.items()]

    def test_consoles_tile_the_capture_region_exactly(self):
        self.assertTrue(record.tiles(record.REGION, [c.rect for c in record.CONSOLES.values()]))
        self.assertFalse(record.tiles(record.REGION, [c.rect for c in record.CONSOLES.values()][:2]))

    def test_any_foreign_window_above_a_console_or_a_misplaced_console_is_reported(self):
        browser = record.Win('My personal browser', record.Rect(100, 100, 800, 600), True, False)
        far = record.Win('Elsewhere', record.Rect(2000, 1200, 800, 600), True, True)
        self.assertEqual(record.uncovered([far, *self.ours(), browser], self.TITLES), [])
        self.assertTrue(any('My personal browser' in p for p in record.uncovered([browser, *self.ours()], self.TITLES)))
        self.assertTrue(record.uncovered(self.ours(audit=record.Rect(1280, 0, 640, 500)), self.TITLES))
        self.assertTrue(record.uncovered(self.ours()[:2], self.TITLES))


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
        self.assertLessEqual(sent, screencast.READ_ONLY)

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
        client = screencast.ReadOnlyCdp(FakeBrowser([]), lambda m: None)
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
