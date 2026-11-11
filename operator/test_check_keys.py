"""check_keys behavior: packets, reply validation and the disputed-groups report. Tiny synthetic case; no model."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import check_keys as ck

CASE = 'syn-keys-001'
P, Q = '{P}', '{Q}'
EVENTS = [
    {'event': {'id': 'evt-000001', 'category': ['process']}, 'process': {'entity_id': P, 'name': 'dropper.exe'}},
    {'event': {'id': 'evt-000002', 'category': ['file']}, 'process': {'entity_id': P, 'name': 'dropper.exe'},
     'file': {'path': r'C:\Temp\payload.bin'}},
    {'event': {'id': 'evt-000003', 'category': ['file']}, 'process': {'entity_id': P, 'name': 'dropper.exe'},
     'file': {'path': r'C:\Temp\payload.cfg'}},
    {'event': {'id': 'evt-000004', 'category': ['network']}, 'process': {'entity_id': Q, 'name': 'beacon.exe'}},
    {'event': {'id': 'evt-000005', 'category': ['network']}, 'process': {'entity_id': Q, 'name': 'beacon.exe'}},
    {'event': {'id': 'evt-000006', 'category': ['process']}, 'process': {'entity_id': '{R}', 'name': 'backup.exe'}},
    # A Sysmon file deletion winlogbeat failed to parse: no process field, only winlog.event_data.
    {'event': {'id': 'evt-000007', 'code': 26}, 'winlog': {'event_data': {'ProcessGuid': P}}},
]
TRUTH = {'schema_version': 1, 'case_id': CASE, 'facts': [
    {'fact_id': 'attack.drop', 'kind': 'attack', 'observation': 'dropper.exe wrote payload.bin.',
     'entities': {'processes': ['dropper.exe']}, 'evidence_event_groups': [['evt-000001'], ['evt-000002']]},
    {'fact_id': 'attack.beacon', 'kind': 'attack', 'observation': 'beacon.exe called out.',
     'entities': {'processes': ['beacon.exe']}, 'evidence_event_groups': [['evt-000004']]},
    {'fact_id': 'decoy.backup', 'kind': 'decoy', 'observation': 'The backup ran.',
     'entities': {'processes': ['backup.exe']}, 'evidence_event_groups': [['evt-000006']]},
]}


def reply(*items):
    return json.dumps([{'group': group, 'verdict': verdict, 'reason': 'r', 'better_event_ids': list(better)}
                       for group, verdict, better in items])


class CheckKeys(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='check-keys-test-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / 'cases' / CASE / 'evidence').mkdir(parents=True)
        (root / 'cases' / CASE / 'evidence' / 'events.jsonl').write_text(
            ''.join(json.dumps(event) + '\n' for event in EVENTS), encoding='utf-8')
        (root / 'operator-only' / CASE).mkdir(parents=True)
        self.truth_path = root / 'operator-only' / CASE / 'truth.json'
        self.truth_path.write_text(json.dumps(TRUTH), encoding='utf-8')
        self.out = root / 'out'
        for name, value in (('CASES', root / 'cases'), ('OPERATOR_ONLY', root / 'operator-only')):
            patcher = patch.object(ck, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.calls = []

    def reviewer(self, replies):
        def review(packet_path):
            packet = json.loads(packet_path.read_text(encoding='utf-8'))
            self.calls.append(packet)
            return replies[packet['fact']['fact_id']]
        return review

    def test_packets_hold_each_groups_events_and_only_the_same_processes_other_events(self):
        result = ck.run_check(CASE, self.out, self.reviewer({}), packets_only=True)
        self.assertEqual(self.calls, [])
        self.assertEqual(result['checked_facts'], ['attack.drop', 'attack.beacon'])
        drop, beacon = (json.loads(Path(path).read_text(encoding='utf-8')) for path in result['packets'])
        self.assertEqual([[e['event']['id'] for e in g['events']] for g in drop['groups']], [['evt-000001'], ['evt-000002']])
        self.assertEqual([e['event']['id'] for e in drop['process_events']], ['evt-000003', 'evt-000007'])
        self.assertEqual([e['event']['id'] for e in beacon['process_events']], ['evt-000005'])
        # Only the fact under review: no other fact's observation and no decoy reaches a packet.
        text = json.dumps(drop)
        for absent in ('beacon.exe called out', 'backup', 'evt-000006'):
            self.assertNotIn(absent, text)
        self.assertFalse((self.out / f'keys-{CASE}.json').exists())

    def test_disputed_groups_are_reported_and_the_key_is_unchanged(self):
        before = hashlib.sha256(self.truth_path.read_bytes()).hexdigest()
        replies = {'attack.drop': '```json\n' + reply((0, 'proves', ()), (1, 'partly', ('evt-000003',))) + '\n```',
                   'attack.beacon': 'Here is my answer: ' + reply((0, 'does_not_prove', ()))}
        result = ck.run_check(CASE, self.out, self.reviewer(replies))
        self.assertEqual(result['failures'], [])
        self.assertEqual([(item['fact_id'], item['group'], item['verdict'], item['better_event_ids']) for item in result['disputed']],
                         [('attack.drop', 1, 'partly', ['evt-000003']), ('attack.beacon', 0, 'does_not_prove', [])])
        self.assertEqual(len(result['groups']), 3)
        self.assertEqual(json.loads((self.out / f'keys-{CASE}.json').read_text(encoding='utf-8'))['disputed'], result['disputed'])
        self.assertEqual(hashlib.sha256(self.truth_path.read_bytes()).hexdigest(), before)

    def test_invalid_replies_are_failures_not_verdicts(self):
        replies = {'attack.drop': reply((0, 'proves', ()), (0, 'proves', ())),
                   'attack.beacon': reply((0, 'proves', ('evt-000006',)))}
        result = ck.run_check(CASE, self.out, self.reviewer(replies))
        self.assertEqual(result['groups'], [])
        problems = {item['fact_id']: item['problems'] for item in result['failures']}
        self.assertEqual(problems['attack.drop'], ['group listed more than once: [0]', 'group missing: [1]'])
        self.assertEqual(problems['attack.beacon'], ['item 0: better_event_ids must list only IDs from process_events'])

    def test_facts_limit_checks_only_the_first_attack_facts(self):
        result = ck.run_check(CASE, self.out, self.reviewer({'attack.drop': reply((0, 'proves', ()), (1, 'proves', ()))}),
                              facts_limit=1)
        self.assertEqual((result['checked_facts'], result['disputed'], len(self.calls)), (['attack.drop'], [], 1))

    def test_a_failed_rerun_leaves_no_earlier_reply_behind(self):
        ck.run_check(CASE, self.out, self.reviewer({'attack.drop': reply((0, 'proves', ()), (1, 'proves', ()))}), facts_limit=1)
        self.assertTrue((self.out / f'reply-{CASE}-1.txt').exists())

        def broken(packet_path):
            raise RuntimeError('omp exited 1')
        result = ck.run_check(CASE, self.out, broken, facts_limit=1)
        self.assertEqual(result['failures'], [{'fact_id': 'attack.drop', 'problems': ['omp exited 1']}])
        self.assertFalse((self.out / f'reply-{CASE}-1.txt').exists())

    def test_a_rerun_removes_only_this_cases_earlier_outputs(self):
        self.out.mkdir()
        stale = [f'packet-{CASE}-9.json', f'reply-{CASE}-9.txt', f'keys-{CASE}.json']
        kept = [f'packet-{CASE}-b-1.json', f'keys-{CASE}-b.json', 'notes.txt']
        for name in stale + kept:
            (self.out / name).write_text('old', encoding='utf-8')
        ck.run_check(CASE, self.out, self.reviewer({}), packets_only=True)
        self.assertEqual(sorted(path.name for path in self.out.iterdir()),
                         sorted(kept + [f'packet-{CASE}-1.json', f'packet-{CASE}-2.json']))

    def omp(self, settings, model):
        """Run one review with omp faked: settings answers `omp config get`; returns what the review call saw."""
        packet = self.out / 'packet-x.json'
        packet.parent.mkdir(parents=True, exist_ok=True)
        packet.write_text('{}', encoding='utf-8')
        seen = {}

        def run(command, cwd=None, **options):
            if command[1:3] == ['config', 'get']:
                value = settings.get(command[3])
                return SimpleNamespace(returncode=0 if value is not None else 1, stdout=json.dumps({'value': value}), stderr='')
            seen.update(command=command, files=sorted(path.name for path in Path(cwd).iterdir()),
                        overlay=json.loads((Path(cwd) / 'no-mcp.yml').read_text(encoding='utf-8')))
            return SimpleNamespace(returncode=0, stdout='[]', stderr='')
        with patch.object(ck.subprocess, 'run', run):
            review = ck.omp_reviewer(model)
            self.assertEqual(review(packet), '[]')
        return review, seen

    def test_omp_runs_without_tools_or_any_mcp_source_from_a_scratch_directory(self):
        review, seen = self.omp({'disabledProviders': ['google', {'path': '/w', 'id': 'github'}]}, 'claude-opus-5-5')
        self.assertEqual(seen['command'][:2], ['omp', '-p'])
        for flag in ('--no-tools', '--no-session', '--no-context-files', '--no-extensions'):
            self.assertIn(flag, seen['command'])
        self.assertEqual(seen['command'][seen['command'].index('--config') + 1], 'no-mcp.yml')
        self.assertEqual(seen['files'], ['no-mcp.yml', 'packet-x.json'])
        # The user's own entries are kept, and every discovery provider, cursor included, is added.
        self.assertEqual(seen['overlay']['disabledProviders'],
                         ['google', {'path': '/w', 'id': 'github'}] + list(ck.DISCOVERY_PROVIDERS) + ['cursor'])
        self.assertEqual(review.model, 'claude-opus-5-5')

    def test_a_cursor_reviewer_model_keeps_cursor_and_the_default_model_is_recorded(self):
        review, seen = self.omp({'modelRoles': {'default': 'cursor/composer-2'}}, None)
        self.assertNotIn('cursor', seen['overlay']['disabledProviders'])
        self.assertNotIn('--model', seen['command'])
        self.assertEqual(review.model, 'cursor/composer-2 (omp default model role)')
        self.assertEqual(self.omp({}, None)[0].model, 'unknown')


if __name__ == '__main__':
    unittest.main()
