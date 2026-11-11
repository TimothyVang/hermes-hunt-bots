"""Operator tool_loops behavior that a live loop depends on."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import tool_loops as tl


class ChildOutputTest(unittest.TestCase):
    def test_a_cli_child_printing_non_ascii_text_succeeds_and_round_trips(self):
        # Stage outputs carry text such as arrows and dashes. On Windows a piped child encodes its
        # stdout with the locale code page unless told otherwise; one such character halted a
        # whole filmed round (driver error: UnicodeEncodeError).
        text = 'stage handoff \u2192 claim \u2014 \u201cquoted\u201d \u2026'
        child = [sys.executable, '-c', f'import json; print(json.dumps({{"note": {text!r}}}, ensure_ascii=False))']
        rc, out, err = tl.tcli(lane=Mock(temporal_cli=lambda: child))
        self.assertEqual(rc, 0, err)
        self.assertIn(text, out)


def step(step_id, state, wave, execution_id=None, reason=''):
    return {'step_id': step_id, 'state': state, 'wave': wave, 'execution_id': execution_id, 'reason': reason}


def result(execution_id, output, status='completed', reason_code='completed', usage=None):
    return {'status': status, 'execution_id': execution_id, 'output': output, 'reason_code': reason_code,
            'session_id': None, 'usage': usage}


def usage(total, duration_ms):
    return {'input_tokens': total - 10, 'output_tokens': 10, 'cache_read_tokens': 3, 'cache_write_tokens': 1,
            'total_tokens': total, 'duration_ms': duration_ms}


def run_rounds(statuses):
    """run_config over these final round statuses, with the lab, Temporal, the gate driver and the scorer
    faked. A completed round has its saved final report. Returns (run result, summary log line)."""
    def fake_tcli(*args, lane=None, timeout=180):
        if args[0] == 'practice':
            return 0, '', ''
        return 0, json.dumps(statuses[int(args[1].rsplit(':', 1)[-1]) - 1]), ''

    scored = {'found': 18, 'total': 18, 'misattributed_decoys': [], 'facts': []}
    with tempfile.TemporaryDirectory() as tmp, patch.object(tl, 'GATE_RUNS', Path(tmp)), \
            patch.object(tl, 'ROUNDS', len(statuses)), patch.object(tl, 'tcli', fake_tcli), \
            patch.object(tl, 'lab_url', return_value='http://lab'), patch.object(tl, 'last_seq', return_value=0), \
            patch.object(tl, 'activity_since', return_value=[]), patch.object(tl, 'score', return_value=scored), \
            patch.object(tl.subprocess, 'run', return_value=Mock(stdout='')), patch.object(tl, 'log') as log:
        outputs = Path(tmp) / 'outputs' / tl.workflow_id('loop-t', 'case-1')
        outputs.mkdir(parents=True)
        for n, status in enumerate(statuses, 1):
            if status['stage'] == 'completed':
                (outputs / f'{n:03d}-incident.txt').write_text('report', encoding='utf-8')
        run, _calls = tl.run_config('loop-t', {}, 'brief', {}, 'case-1', 'truth.json', d=Path(tmp) / 'loop-t')
    return run, log.call_args.args[0]


class RoundRecordTest(unittest.TestCase):
    def test_a_parallel_round_is_read_by_execution_id_with_its_dropped_steps_and_summed_usage(self):
        finished = {
            'stage': 'completed', 'step_id': None, 'execution_id': None, 'handoff_rejections': [],
            'steps': [step('scope', 'done', 1, 'x:scope'), step('evidence', 'done', 2, 'x:evidence:retry'),
                      step('intel', 'dropped', 2, 'x:intel', 'timeout'), step('incident', 'done', 3, 'x:incident')],
            # Not in step order: position says nothing about whose result each one is.
            'results': [result('x:incident', 'final report', usage=usage(700, 4000)),
                        result('x:intel', '', 'failed', 'timeout'),
                        result('x:scope', 'sc', usage=usage(100, 1000)),
                        result('x:evidence:retry', 'ev-out', usage=usage(200, 2000))]}
        halted = {
            'stage': 'rejected', 'step_id': 'wave-2', 'execution_id': None, 'handoff_rejections': [],
            'steps': [step('scope', 'done', 1, 'y:scope'), step('evidence', 'stopped', 2, 'y:evidence', 'native_failed'),
                      step('incident', 'not_reached', 3)],
            'results': [result('y:evidence', '', 'failed', 'native_failed'), result('y:scope', 'sc')]}
        run, summary = run_rounds([finished, halted])
        first, second = run['rounds']
        self.assertEqual(first['sizes'], [('scope', 'completed', 'completed', 2), ('evidence', 'completed', 'completed', 6),
                                          ('intel', 'failed', 'timeout', 0), ('incident', 'completed', 'completed', 12)])
        self.assertEqual(first['dropped'], [{'step_id': 'intel', 'reason': 'timeout'}])
        self.assertEqual(first['usage'], {'input_tokens': 970, 'output_tokens': 30, 'cache_read_tokens': 9,
                                          'cache_write_tokens': 3, 'total_tokens': 1000, 'duration_ms': 7000,
                                          'steps_without_usage': 1, 'retried_attempts': 0})
        # A dropped optional step does not make a completed round a halt.
        self.assertTrue(first['completed'])
        self.assertEqual(first['found'], 18)
        self.assertEqual(second['sizes'], [('scope', 'completed', 'completed', 2), ('evidence', 'failed', 'native_failed', 0),
                                           ('incident', 'not_reached', '', 0)])
        self.assertEqual(second['dropped'], [])
        self.assertNotIn('usage', second)
        self.assertEqual(run['halts'], 1)
        self.assertIn(' calls 0 dropped 1 tokens 1000 in ', summary)

    def test_a_serial_round_is_still_read_in_stage_order(self):
        results = [result('w:0', 'sc'), result('w:1', 'ev-out'), result('w:2', '', 'failed', 'timeout')]
        before_usage = [{key: value for key, value in item.items() if key != 'usage'} for item in results]
        cases = {'a status from before steps and usage existed': {'results': before_usage},
                 'a serial status with an empty steps list': {'results': results, 'steps': []}}
        for name, shape in cases.items():
            with self.subTest(name):
                halted = {'stage': 'rejected', 'step_id': 'hypotheses', 'execution_id': 'w:2',
                          'handoff_rejections': [], **shape}
                run, summary = run_rounds([halted])
                entry = run['rounds'][0]
                self.assertEqual(entry['sizes'], [('scope', 'completed', 'completed', 2),
                                                  ('evidence', 'completed', 'completed', 6),
                                                  ('hypotheses', 'failed', 'timeout', 0)])
                self.assertNotIn('dropped', entry)
                self.assertNotIn('usage', entry)
                self.assertRegex(summary, r' misattributed 0 calls 0 in [0-9.]+ min$')


def rejection(step_id, outcome, rejected):
    return {'step_id': step_id, 'reason': 'ValueError: invalid handoff', 'outcome': outcome, 'result': rejected}


class UsageTotalTest(unittest.TestCase):
    def test_a_retried_step_bills_both_of_its_attempts(self):
        # The workflow drops a retried attempt from results; only its handoff rejection keeps it.
        st = {'results': [result('w:0', 'sc', usage=usage(100, 1000)), result('w:1:retry', 'ev', usage=usage(300, 3000))],
              'handoff_rejections': [rejection('evidence', 'retried', result('w:1', 'bad', usage=usage(200, 2000)))]}
        self.assertEqual(tl.usage_total(st), {'input_tokens': 570, 'output_tokens': 30, 'cache_read_tokens': 9,
                                              'cache_write_tokens': 3, 'total_tokens': 600, 'duration_ms': 6000,
                                              'steps_without_usage': 0, 'retried_attempts': 1})

    def test_a_retried_attempt_without_usage_is_a_step_without_usage(self):
        st = {'results': [result('w:0', 'sc', usage=usage(100, 1000))],
              'handoff_rejections': [rejection('scope', 'retried', result('w:0-first', 'bad'))]}
        total = tl.usage_total(st)
        self.assertEqual((total['total_tokens'], total['steps_without_usage'], total['retried_attempts']), (100, 1, 1))

    def test_a_rejection_that_ended_the_round_is_counted_once(self):
        final = result('w:1:retry', 'bad again', usage=usage(300, 3000))
        st = {'results': [result('w:0', 'sc', usage=usage(100, 1000)), final],
              'handoff_rejections': [rejection('evidence', 'retried', result('w:1', 'bad', usage=usage(200, 2000))),
                                     rejection('evidence', 'retry_exhausted', final)]}
        total = tl.usage_total(st)
        self.assertEqual((total['total_tokens'], total['retried_attempts']), (600, 1))

    def test_a_round_record_includes_retried_attempts(self):
        retried = {'stage': 'completed', 'step_id': None, 'execution_id': None,
                   'results': [result('w:0', 'sc', usage=usage(100, 1000))],
                   'handoff_rejections': [rejection('scope', 'retried', result('w:0-first', 'bad', usage=usage(50, 500)))]}
        run, summary = run_rounds([retried])
        self.assertEqual(run['rounds'][0]['usage']['total_tokens'], 150)
        self.assertIn(' tokens 150 in ', summary)
PUBLIC_SCOPE = 'Public research dataset dedale-001 (real lab telemetry, no customer data) only; case brief'


class BaseInputTest(unittest.TestCase):
    def export(self, base, **options):
        """base_input with lab-input faked: it writes base to the requested --output path."""
        calls = []

        def fake_run(argv, **_kwargs):
            calls.append(argv)
            Path(argv[argv.index('--output') + 1]).write_text(json.dumps(base), encoding='utf-8')
            return Mock(returncode=0, stderr='')

        lane = Mock(temporal_cli=lambda: ['cli'], state_dir='state')
        lane.name = ''
        with tempfile.TemporaryDirectory() as tmp, patch.object(tl, 'TOOL_LOOPS', Path(tmp)), \
                patch.object(tl.subprocess, 'run', fake_run):
            return tl.base_input('dedale-001', lane, **options), calls

    def test_public_dataset_approval_is_passed_only_when_asked(self):
        synthetic = {'scope': 'Synthetic dedale-001 only; case brief', 'synthetic_only': True}
        _, [argv] = self.export(synthetic)
        self.assertNotIn('--allow-public-dataset', argv)
        public = {'scope': PUBLIC_SCOPE, 'synthetic_only': False, 'data_origin': 'public-dataset'}
        base, [argv] = self.export(public, allow_public_dataset=True)
        self.assertEqual(argv[:4], ['cli', 'lab-input', '--tool-driven', '--allow-public-dataset'])
        self.assertEqual(base, public)
        # A public input on disk (here written by the fake) is never used without the approval.
        with self.assertRaises(SystemExit):
            self.export(public)

    def test_a_new_brief_keeps_the_base_origin(self):
        public = {'scope': PUBLIC_SCOPE, 'synthetic_only': False, 'data_origin': 'public-dataset'}
        self.assertEqual(tl.build_input(public, 'new brief', {}, 'dedale-001')['scope'],
                         'Public research dataset dedale-001 (real lab telemetry, no customer data) only; new brief')
        synthetic = {'scope': 'Synthetic dedale-001 only; case brief', 'synthetic_only': True}
        self.assertEqual(tl.build_input(synthetic, 'new brief', {}, 'dedale-001')['scope'],
                         'Synthetic dedale-001 only; new brief')


if __name__ == '__main__':
    unittest.main()
