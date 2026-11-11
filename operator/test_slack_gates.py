"""slack_gates: the operator's Slack bridge, with a fake Slack client and a fake CLI runner (no slack_sdk needed)."""
import io
import json
import os
import re
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import drive_gates as dg
import slack_gates as sg

CHILD = 'loop-wf:round:001'
OPERATOR, STRANGER = 'U0ADA', 'U0EVE'
BOT_TOKEN = 'xoxb-test-bot-token-never-shown'
APP_TOKEN = 'xapp-test-app-token-never-shown'
SUMMARY = 'Bot-written, unverified: Scope covers ws-01 & <ws-02>.'
NOTE = 'I read the scope and the excluded hosts.'
ALREADY = 'Already being decided: this gate was claimed by another answer.'


class FakeSlack:
    def __init__(self):
        self.calls, self.count = [], 0

    def _call(self, method, kwargs, reply):
        self.calls.append((method, kwargs))
        return reply

    def chat_postMessage(self, **kwargs):
        self.count += 1
        return self._call('chat_postMessage', kwargs, {'ok': True, 'channel': 'D0CARDS', 'ts': f'1.{self.count}'})

    def chat_update(self, **kwargs):
        return self._call('chat_update', kwargs, {'ok': True})

    def chat_postEphemeral(self, **kwargs):
        return self._call('chat_postEphemeral', kwargs, {'ok': True})

    def views_open(self, **kwargs):
        return self._call('views_open', kwargs, {'ok': True})

    def conversations_open(self, **kwargs):
        return self._call('conversations_open', kwargs, {'ok': True, 'channel': {'id': 'D0CARDS'}})

    def named(self, method):
        return [kwargs for name, kwargs in self.calls if name == method]


class FakeCli:
    """Answers status with the gate open and decision with signal_sent, unless told otherwise."""

    def __init__(self, gate='wave-1', decision=(0, '{"workflow_id": "x", "signal_sent": true}')):
        self.calls, self.gate, self.decision, self.during = [], gate, decision, None

    def __call__(self, argv):
        self.calls.append(list(argv))
        if argv[-2] == 'status':
            during, self.during = self.during, None
            if during:
                during()
            return 0, json.dumps({'stage': 'awaiting_review', 'step_id': self.gate})
        return self.decision

    def decisions(self):
        return [argv for argv in self.calls if 'decision' in argv]


class BridgeTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name)
        self.slack, self.lines, self.cli = FakeSlack(), [], FakeCli()

    def bridge(self, content='minimal', channel='D0CARDS'):
        args = sg.parse_args(['--operator-name', 'Ada  Lovelace', '--operator-user', OPERATOR, '--decision-dir',
                              str(self.folder), '--content', content] + (['--channel', channel] if channel else []))
        bridge = sg.Bridge(args, self.slack, run=self.cli, log=self.lines.append)
        bridge.start()
        return bridge

    def open_gate(self, gate='wave-1', kind='scope'):
        record = dg.pending_record('loop-wf', CHILD, gate, kind, self.folder / 'outputs', SUMMARY)
        return dg.write_pending(self.folder, record).name, record

    def press(self, bridge, name, nonce, user=OPERATOR, action='hunt_gate_approve'):
        bridge.on_block_actions({'type': 'block_actions', 'user': {'id': user}, 'trigger_id': 'trigger-1',
                                 'channel': {'id': 'D0CARDS'}, 'actions': [{'action_id': action,
                                                                            'value': f'{name}|{nonce}'}]})

    def submit(self, bridge, name, nonce, choice='approve', user=OPERATOR, note=NOTE):
        bridge.on_view_submission({'type': 'view_submission', 'user': {'id': user}, 'view': {
            'callback_id': 'hunt_gate_note',
            'private_metadata': json.dumps({'record': name, 'nonce': nonce, 'choice': choice, 'channel': 'D0CARDS'}),
            'state': {'values': {'note': {'note': {'type': 'plain_text_input', 'value': note}}}}}})

    def notices(self):
        return [(call['user'], call['text']) for call in self.slack.named('chat_postEphemeral')]

    def folder_names(self, name):
        return sorted(path.name for path in (self.folder / name).glob('*'))

    def card_text(self):
        return json.dumps([call['blocks'] for call in self.slack.named('chat_postMessage')])

    def test_each_pending_record_is_posted_once_also_after_a_restart(self):
        scope, scope_record = self.open_gate()
        report, report_record = self.open_gate('wave-4', 'report')
        bridge = self.bridge()
        bridge.poll()
        bridge.poll()
        self.bridge().poll()
        posts = self.slack.named('chat_postMessage')
        self.assertEqual(len(posts), 2)
        buttons = {post['blocks'][-1]['elements'][0]['value']: [(button['action_id'], button['text']['text'])
                                                               for button in post['blocks'][-1]['elements']]
                   for post in posts}
        self.assertEqual(buttons, {
            f'{scope}|{scope_record["nonce"]}': [('hunt_gate_approve', 'Approve'), ('hunt_gate_deny', 'Reject')],
            f'{report}|{report_record["nonce"]}': [('hunt_gate_approve', 'Accept report'),
                                                   ('hunt_gate_deny', 'Reject report')]})
        self.assertEqual(self.folder_names('posted'), sorted([scope, report]))

    def test_a_new_record_for_the_same_gate_replaces_the_old_card(self):
        name, first = self.open_gate()
        bridge = self.bridge()
        bridge.poll()
        _, second = self.open_gate()
        bridge.poll()
        self.assertEqual(len(self.slack.named('chat_postMessage')), 2)
        self.assertIn('Replaced by a newer card', self.slack.named('chat_update')[0]['text'])
        self.press(bridge, name, first['nonce'])
        self.assertEqual(self.notices(), [(OPERATOR, sg.EXPIRED)])

    def test_minimal_cards_carry_ids_and_status_only_and_summary_cards_label_the_summary_bot_written(self):
        _, record = self.open_gate()
        self.bridge().poll()
        minimal = self.card_text()
        for value in (CHILD, 'wave-1 review (scope)', record['opened_at'], 'loop-wf'):
            self.assertIn(value, minimal)
        self.assertNotIn('Scope covers', minimal)
        self.assertNotIn('Bot-written', minimal)
        self.open_gate()
        self.slack.calls.clear()
        self.bridge(content='summary').poll()
        summary = self.card_text()
        self.assertIn('*Bot-written, unverified* (from the hunt output', summary)
        self.assertIn('>Bot-written, unverified: Scope covers ws-01 &amp; &lt;ws-02&gt;.', summary)

    def test_a_user_not_on_the_allowlist_is_refused_and_nothing_is_sent(self):
        name, record = self.open_gate()
        bridge = self.bridge()
        bridge.poll()
        self.press(bridge, name, record['nonce'], user=STRANGER)
        self.submit(bridge, name, record['nonce'], user=STRANGER)
        self.assertEqual(self.slack.named('views_open'), [])
        self.assertEqual(self.cli.calls, [])
        self.assertEqual([user for user, _ in self.notices()], [STRANGER, STRANGER])
        self.assertEqual(self.folder_names('pending'), [name])
        self.assertEqual(dg.read_decisions(self.folder), [])
        self.assertIn(f'refused: not allowlisted user={STRANGER}', [line.split(' ', 1)[1] for line in self.lines])

    def test_a_stale_nonce_or_a_missing_record_shows_expired(self):
        name, record = self.open_gate()
        bridge = self.bridge()
        bridge.poll()
        self.press(bridge, name, '0' * 32)
        self.submit(bridge, name, '0' * 32)
        (self.folder / 'pending' / name).unlink()
        self.press(bridge, name, record['nonce'])
        self.submit(bridge, name, record['nonce'])
        self.assertEqual(self.notices(), [(OPERATOR, sg.EXPIRED)] * 4)
        self.assertEqual(self.slack.named('views_open'), [])
        self.assertEqual(self.cli.calls, [])

    def test_a_valid_answer_sends_one_nonce_bound_decision_with_the_identity_note_logs_it_and_updates_the_card(self):
        name, record = self.open_gate()
        nonce = record['nonce']
        bridge = self.bridge()
        bridge.poll()
        self.press(bridge, name, nonce)
        [opened] = self.slack.named('views_open')
        self.assertEqual(opened['trigger_id'], 'trigger-1')
        self.assertEqual(opened['view']['title']['text'], 'Approve scope')
        meta = json.loads(opened['view']['private_metadata'])
        self.assertEqual((meta['record'], meta['nonce'], meta['choice']), (name, nonce, 'approve'))
        note_input = opened['view']['blocks'][-1]
        self.assertEqual((note_input['type'], note_input['label']['text'], note_input['element']['max_length']),
                         ('input', 'What did you check?', 1000))
        self.assertFalse(note_input.get('optional', False))

        self.submit(bridge, name, nonce)
        self.assertEqual(self.cli.calls[0][-2:], ['status', CHILD])
        [decision] = self.cli.decisions()
        self.assertEqual(len(self.cli.calls), 2)
        self.assertEqual(decision[:4], [sg.PYTHON, '-B', '-m', 'hermes_temporal.cli'])
        decision_id = f'{CHILD}:wave-1:review:{nonce}'
        self.assertEqual(decision[-12:-1], ['decision', CHILD, '--step-id', 'wave-1', '--phase', 'review',
                                            '--choice', 'approve', '--decision-id', decision_id, '--evidence-note'])
        note = decision[-1]
        self.assertRegex(note, r'^Decided by Ada Lovelace \(Slack user U0ADA\) via Slack at '
                               r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ; card ' + nonce + r'\. Checked: '
                         + re.escape(NOTE) + '$')
        [line] = dg.read_decisions(self.folder)
        self.assertEqual({key: line[key] for key in ('workflow', 'child', 'gate', 'phase', 'choice', 'decided_by',
                                                     'channel', 'slack_user', 'decision_id', 'note_sha256')},
                         {'workflow': 'loop-wf', 'child': CHILD, 'gate': 'wave-1', 'phase': 'review',
                          'choice': 'approve', 'decided_by': 'human: Ada Lovelace', 'channel': 'slack',
                          'slack_user': OPERATOR, 'decision_id': decision_id, 'note_sha256': dg.sha256_text(note)})
        [update] = self.slack.named('chat_update')
        self.assertEqual((update['channel'], update['ts']), ('D0CARDS', '1.1'))
        self.assertNotIn('actions', [block['type'] for block in update['blocks']])
        self.assertTrue(update['text'].startswith('Scope approved by Ada Lovelace (Slack user U0ADA) at '))
        for folder in ('pending', 'claimed', 'posted'):
            self.assertEqual(self.folder_names(folder), [], folder)
        self.assertNotIn(NOTE, '\n'.join(self.lines))

    def test_a_report_rejection_is_sent_as_deny(self):
        name, record = self.open_gate('wave-4', 'report')
        self.cli.gate = 'wave-4'
        bridge = self.bridge()
        bridge.poll()
        self.press(bridge, name, record['nonce'], action='hunt_gate_deny')
        self.assertEqual(self.slack.named('views_open')[0]['view']['title']['text'], 'Reject report')
        self.submit(bridge, name, record['nonce'], choice='deny')
        [decision] = self.cli.decisions()
        self.assertEqual(decision[decision.index('--choice') + 1], 'deny')
        self.assertTrue(self.slack.named('chat_update')[0]['text'].startswith('Report rejected by Ada Lovelace'))

    def test_a_second_answer_for_the_same_record_is_refused(self):
        name, record = self.open_gate()
        nonce = record['nonce']
        bridge = self.bridge()
        bridge.poll()
        # One answer arrives while the first is being sent, another after it.
        self.cli.during = lambda: self.submit(bridge, name, nonce, choice='deny')
        self.submit(bridge, name, nonce)
        self.submit(bridge, name, nonce)
        # Two answers that both passed the record check before either claimed it: the rename lets one through.
        with patch.object(bridge, 'current', return_value=record):
            self.submit(bridge, name, nonce)
        self.assertEqual(len(self.cli.decisions()), 1)
        self.assertEqual(self.notices(), [(OPERATOR, sg.EXPIRED), (OPERATOR, sg.EXPIRED), (OPERATOR, ALREADY)])
        self.assertEqual(len(dg.read_decisions(self.folder)), 1)

    def test_a_failed_decision_puts_the_record_back_and_shows_only_the_error_code(self):
        name, record = self.open_gate()
        bridge = self.bridge()
        bridge.poll()
        cases = (('decision exit', 'wave-1', (1, 'Traceback: connection refused'),
                  'Decision not sent (error decision_exit_1). The card stays open.', 1),
                 ('decision timeout', 'wave-1', None, 'Decision not sent (error decision_timeout). The card stays open.', 1),
                 ('gate moved on', 'wave-2', (0, '{}'), sg.EXPIRED, 0))
        for case, gate, decision, notice, sent in cases:
            with self.subTest(case):
                self.cli = bridge.run = FakeCli(gate, decision)
                self.slack.calls.clear()
                self.submit(bridge, name, record['nonce'])
                self.assertEqual(len(self.cli.decisions()), sent)
                self.assertEqual(self.notices(), [(OPERATOR, notice)])
                self.assertEqual((self.folder_names('pending'), self.folder_names('claimed')), ([name], []))
                self.assertEqual(self.slack.named('chat_update'), [])
                self.assertEqual(dg.read_decisions(self.folder), [])
        self.assertNotIn('Traceback', '\n'.join(self.lines))

    def test_tokens_never_reach_logs_argv_slack_text_or_the_decision_log(self):
        with patch.dict(os.environ, {'SLACK_BOT_TOKEN': BOT_TOKEN, 'SLACK_APP_TOKEN': APP_TOKEN}):
            name, record = self.open_gate()
            bridge = self.bridge()
            bridge.poll()
            self.press(bridge, name, record['nonce'])
            self.submit(bridge, name, record['nonce'])
            self.press(bridge, name, record['nonce'], user=STRANGER)
            seen = json.dumps([self.lines, self.cli.calls, self.slack.calls], default=str)
            seen += (self.folder / 'decisions.jsonl').read_text(encoding='utf-8')
            with patch.object(sg.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='{}')) as ran:
                sg.run_cli([sg.PYTHON, '-B', '-m', 'hermes_temporal.cli', 'status', CHILD])
        for token in (BOT_TOKEN, APP_TOKEN):
            self.assertNotIn(token, seen)
            self.assertNotIn(token, json.dumps(ran.call_args.args, default=str))
        self.assertFalse([key for key in ran.call_args.kwargs['env'] if key.upper().startswith('SLACK_')])

    def test_missing_or_malformed_tokens_exit_2_naming_the_variable_never_a_value(self):
        cases = (({}, 'SLACK_BOT_TOKEN'), ({'SLACK_BOT_TOKEN': BOT_TOKEN}, 'SLACK_APP_TOKEN'),
                 ({'SLACK_BOT_TOKEN': 'wrong-kind-of-secret', 'SLACK_APP_TOKEN': APP_TOKEN}, 'SLACK_BOT_TOKEN'))
        for env, variable in cases:
            with self.subTest(variable=variable, given=sorted(env)):
                err = io.StringIO()
                with patch.dict(os.environ, env, clear=True), redirect_stderr(err):
                    code = sg.main(['--operator-name', 'Ada', '--operator-user', OPERATOR,
                                    '--decision-dir', str(self.folder)])
                self.assertEqual(code, 2)
                self.assertIn(variable, err.getvalue())
                for value in (BOT_TOKEN, APP_TOKEN, 'wrong-kind-of-secret'):
                    self.assertNotIn(value, err.getvalue())

    def test_a_record_that_could_run_anything_but_a_loopback_decision_is_never_posted(self):
        tampered = {
            'another program': lambda argv: argv[:1] + ['-c', 'print(1)'] + argv[-6:],
            'a remote Temporal': lambda argv: argv[:4] + ['--address', '10.0.0.5:7233'] + argv[-6:],
            'another workflow': lambda argv: argv[:-5] + ['other-wf:round:001'] + argv[-4:],
            'an extra option': lambda argv: argv[:4] + ['--namespace', 'x'] + argv[-6:],
        }
        bridge = self.bridge()
        for case, change in tampered.items():
            with self.subTest(case):
                record = dg.pending_record('loop-wf', CHILD, 'wave-1', 'scope', self.folder / 'outputs')
                record['decision_cli'] = change(record['decision_cli'])
                name = dg.write_pending(self.folder, record).name
                bridge.poll()
                self.press(bridge, name, record['nonce'])
                self.submit(bridge, name, record['nonce'])
                self.assertEqual(self.slack.named('chat_postMessage'), [])
                self.assertEqual(self.cli.calls, [])
        self.assertTrue(any(line.split(' ', 1)[1].startswith(f'record ignored ({name})') for line in self.lines))

    def test_a_record_is_accepted_only_under_its_own_digest_name(self):
        record = dg.pending_record('loop-wf', CHILD, 'wave-1', 'scope', self.folder / 'outputs')
        name = dg.record_name(CHILD, 'wave-1')
        self.assertEqual(sg.check_record(name, record), record)
        twin = dg.record_name(CHILD.replace(':', '/'), 'wave-1')
        self.assertNotEqual(twin, name)
        for wrong in (twin, 'loop-wf_round_001__wave-1__review.json'):
            with self.subTest(wrong), self.assertRaises(ValueError):
                sg.check_record(wrong, record)

    def test_a_card_whose_record_disappears_is_closed(self):
        name, _ = self.open_gate()
        bridge = self.bridge()
        bridge.poll()
        (self.folder / 'pending' / name).unlink()
        bridge.poll()
        [update] = self.slack.named('chat_update')
        self.assertIn('No longer open', update['text'])
        self.assertNotIn('actions', [block['type'] for block in update['blocks']])
        self.assertEqual(self.folder_names('posted'), [])

    def test_a_claim_left_by_a_stopped_bridge_is_put_back_on_restart(self):
        name, record = self.open_gate()
        (self.folder / 'claimed').mkdir()
        (self.folder / 'pending' / name).rename(self.folder / 'claimed' / name)
        bridge = self.bridge()
        self.assertEqual((self.folder_names('pending'), self.folder_names('claimed')), ([name], []))
        bridge.poll()
        self.press(bridge, name, record['nonce'])
        self.assertEqual(len(self.slack.named('views_open')), 1)

    def test_the_listener_acknowledges_before_handling(self):
        bridge = self.bridge()
        order = []
        client = SimpleNamespace(send_socket_mode_response=lambda response: order.append(('ack', response)))
        bridge.on_block_actions = lambda payload: order.append(('handled', payload['type']))
        bridge.listener(client, SimpleNamespace(type='interactive', envelope_id='env-1',
                                                payload={'type': 'block_actions'}))
        self.assertEqual(order, [('ack', {'envelope_id': 'env-1'}), ('handled', 'block_actions')])

    def test_without_a_channel_the_cards_go_to_a_dm_with_the_operator(self):
        self.open_gate()
        self.bridge(channel=None).poll()
        self.assertEqual(self.slack.named('conversations_open'), [{'users': OPERATOR}])
        self.assertEqual(self.slack.named('chat_postMessage')[0]['channel'], 'D0CARDS')

    def test_only_slack_user_ids_are_accepted_on_the_allowlist(self):
        for argv in (['--operator-user', 'ada'], ['--operator-user', OPERATOR, '--channel', '#hunts'],
                     ['--operator-user', OPERATOR, '--operator-name', ' ']):
            with self.subTest(argv=argv), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as stopped:
                sg.parse_args(['--operator-name', 'Ada', *argv])
            self.assertEqual(stopped.exception.code, 2)
        self.assertEqual(sg.parse_args(['--operator-name', 'Ada', '--operator-user', OPERATOR, 'W0BOB']).operator_user,
                         [OPERATOR, 'W0BOB'])


if __name__ == '__main__':
    unittest.main()
