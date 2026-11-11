"""check_keys behavior: packets, reply validation and the disputed-groups report. Tiny synthetic case; no model."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
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
        self.assertEqual([e['event']['id'] for e in drop['process_events']], ['evt-000003'])
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


if __name__ == '__main__':
    unittest.main()
