"""review_reports behavior the Q2 scores check depends on. Tiny synthetic cases only; no runtime folder, lab or model."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import review_reports as rr

CASE, WORKFLOW = 'syn-case-001', 'syn-run-1-syn-case-001'
# Nested, flattened and mixed ECS shapes, as real cases carry them.
EVENTS = [
    {'event': {'id': 'evt-000001'}, 'host': {'name': 'ws-01'}, 'user': {'name': 'a.lee'},
     'process': {'name': 'wscript.exe', 'parent': {'name': 'mailer.exe'}}},
    {'event.id': 'evt-000002', 'host.name': 'ws-01', 'destination.ip': '203.0.113.7', 'url.domain': 'sync.lab.example'},
    {'event': {'id': 'evt-000003'}, 'host.name': 'ws-02', 'dns': {'question.name': 'sync.lab.example'}},
    {'event': {'id': 'evt-000004'}, 'host': {'name': 'bk-01'}, 'process': {'name': 'backupd.exe'}},
]
OBSERVATIONS = {
    'attack.exec.script': 'A script host started from the mail client on ws-01 and reached out.',
    'attack.c2.resolve': 'Host ws-02 resolved the beacon domain sync.lab.example.',
    'decoy.backup.nightly': 'The nightly backup agent ran on bk-01 as scheduled.',
}


def truth(groups=None):
    groups = groups or {}
    facts = [
        {'fact_id': 'attack.exec.script', 'kind': 'attack', 'observation': OBSERVATIONS['attack.exec.script'],
         'entities': {'hosts': ['ws-01'], 'processes': ['wscript.exe']},
         'evidence_event_groups': groups.get('attack.exec.script', [['evt-000001'], ['evt-000002']])},
        {'fact_id': 'attack.c2.resolve', 'kind': 'attack', 'observation': OBSERVATIONS['attack.c2.resolve'],
         'entities': {'hosts': ['ws-02'], 'domains': ['sync.lab.example']},
         'evidence_event_groups': groups.get('attack.c2.resolve', [['evt-000003']])},
        {'fact_id': 'decoy.backup.nightly', 'kind': 'decoy', 'observation': OBSERVATIONS['decoy.backup.nightly'],
         'entities': {'hosts': ['bk-01']}, 'evidence_event_groups': [['evt-000004']]},
    ]
    return {'schema_version': 1, 'case_id': CASE, 'facts': facts}


def claim(suffix, statement, kind='finding'):
    return {'claim_id': f'incident:{suffix}', 'kind': kind, 'statement': statement, 'evidence_ids': ['lab-case-0001'],
            'entity_ids': [], 'contradicts': []}


CLAIMS = [
    claim('c1', 'On ws-01 wscript.exe ran and contacted 203.0.113.7 (evt-000001, evt-000002).'),
    claim('c2', 'ws-02 resolved sync.lab.example (evt-000003).', 'observed'),
    claim('c3', 'bk-01 beaconed out as well (evt-000001).', 'inference'),
    claim('c4', 'No lateral movement was seen in the window.', 'inference'),
]


class Lab:
    """A temporary runtime folder holding one case, its key, one saved final report and a rounds file."""

    def __init__(self, claims=CLAIMS, key=None):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.cases, self.keys, self.gates = root / 'cases', root / 'operator-only', root / 'gate-runs'
        self.out, self.rounds = root / 'review', root / 'rounds.jsonl'
        evidence = self.cases / CASE / 'evidence'
        evidence.mkdir(parents=True)
        (evidence / 'events.jsonl').write_text(''.join(json.dumps(e) + '\n' for e in EVENTS), encoding='utf-8')
        (self.keys / CASE).mkdir(parents=True)
        (self.keys / CASE / 'truth.json').write_text(json.dumps(key or truth()), encoding='utf-8')
        report = {'schema_version': 1, 'case_id': CASE, 'step_id': 'incident', 'profile': 'framework-incident-commander',
                  'claims': claims, 'reviews': [], 'disposition': 'review_ready', 'limitations': [],
                  'requested_decisions': []}
        outputs = self.gates / 'outputs' / WORKFLOW
        outputs.mkdir(parents=True)
        (outputs / '001-incident.txt').write_text('Final report follows.\n' + json.dumps(report), encoding='utf-8')
        self.rounds.write_text(json.dumps({'case': CASE, 'workflow': WORKFLOW}) + '\n', encoding='utf-8')
        self.patches = [patch.object(rr, 'CASES', self.cases), patch.object(rr, 'OPERATOR_ONLY', self.keys),
                        patch.object(rr, 'GATE_RUNS', self.gates)]

    def __enter__(self):
        for item in self.patches:
            item.start()
        return self

    def __exit__(self, *exc):
        for item in self.patches:
            item.stop()
        self.tmp.cleanup()

    def run(self, *args):
        with redirect_stdout(io.StringIO()) as printed:
            code = rr.main([*args, '--rounds', str(self.rounds), '--out', str(self.out)])
        self.printed = printed.getvalue()
        return code

    def read(self, name):
        return json.loads((self.out / name).read_text(encoding='utf-8'))

    def reply(self, task, run, items):
        (self.out / f'reply-{CASE}-{task}-{run}.json').write_text(json.dumps(items), encoding='utf-8')


class CheckTest(unittest.TestCase):
    def test_every_citation_existing_passes_and_a_fabricated_one_is_missing_and_fails_g21(self):
        with Lab() as lab:
            self.assertEqual(lab.run('check'), 0)
            checks = lab.read('checks.json')
        self.assertTrue(checks['goals']['G2.1']['pass'])
        self.assertEqual(checks['reports'][0]['missing_ids'], [])

        fabricated = CLAIMS + [claim('c5', 'ws-01 also ran a dropper (evt-000099).')]
        with Lab(claims=fabricated) as lab:
            self.assertEqual(lab.run('check'), 0)
            checks = lab.read('checks.json')
        report = checks['reports'][0]
        self.assertEqual(report['missing_ids'], ['evt-000099'])
        self.assertIn('evt-000099', report['cited_ids'])
        goal = checks['goals']['G2.1']
        self.assertFalse(goal['pass'])
        self.assertEqual((goal['reports_with_missing'], goal['missing_ids']), (1, 1))
        c5 = [c for c in report['citation_support']['claims'] if c['claim_id'] == 'incident:c5'][0]
        self.assertEqual((c5['missing_ids'], c5['status']), (['evt-000099'], 'unsupported'))

    def test_a_claim_naming_a_host_absent_from_its_cited_events_is_unsupported(self):
        with Lab() as lab:
            lab.run('check')
            report = lab.read('checks.json')['reports'][0]
        support = {c['claim_id']: c for c in report['citation_support']['claims']}
        self.assertEqual(support['incident:c1']['status'], 'supported')
        self.assertEqual(support['incident:c1']['entities_named'], ['203.0.113.7', 'ws-01', 'wscript.exe'])
        self.assertEqual(support['incident:c2']['status'], 'supported')
        self.assertEqual(support['incident:c3']['status'], 'unsupported')
        self.assertEqual(support['incident:c3']['entities_not_in_cited_events'], ['bk-01'])
        self.assertEqual(support['incident:c4']['status'], 'uncited')
        counts = report['citation_support']
        self.assertEqual((counts['supported'], counts['unsupported'], counts['uncited'], counts['supported_share']),
                         (2, 1, 1, 0.5))

    def test_a_key_with_a_nonexistent_event_fails_g22_and_names_the_fact(self):
        with Lab() as lab:
            lab.run('check')
            self.assertTrue(lab.read('checks.json')['goals']['G2.2']['pass'])
        broken = truth({'attack.c2.resolve': [['evt-000003', 'evt-000123']]})
        with Lab(key=broken) as lab:
            lab.run('check')
            checks = lab.read('checks.json')
        goal = checks['goals']['G2.2']
        self.assertFalse(goal['pass'])
        self.assertEqual((goal['facts'], goal['consistent']), (3, 2))
        self.assertEqual(goal['inconsistent'], [f'{CASE}:attack.c2.resolve'])
        facts = {f['fact_id']: f for f in checks['cases'][CASE]['key_consistency']['per_fact']}
        self.assertEqual(facts['attack.c2.resolve']['missing_event_ids'], ['evt-000123'])

    def test_a_key_entity_absent_from_its_facts_events_fails_g22(self):
        moved = truth({'attack.exec.script': [['evt-000002']]})  # wscript.exe is only in evt-000001
        with Lab(key=moved) as lab:
            lab.run('check')
            checks = lab.read('checks.json')
        facts = {f['fact_id']: f for f in checks['cases'][CASE]['key_consistency']['per_fact']}
        self.assertEqual(facts['attack.exec.script']['entities_absent'], ['wscript.exe'])
        self.assertFalse(checks['goals']['G2.2']['pass'])

    def test_the_scorer_status_per_fact_is_recorded(self):
        partial = truth({'attack.c2.resolve': [['evt-000003'], ['evt-000002', 'evt-000004']]})
        only_c2 = [claim('c1', 'ws-02 resolved sync.lab.example (evt-000003).')]
        with Lab(claims=only_c2, key=partial) as lab:
            lab.run('check')
            scorer = lab.read('checks.json')['reports'][0]['scorer']
        statuses = {f['fact_id']: f['status'] for f in scorer['facts']}
        self.assertEqual(statuses, {'attack.exec.script': 'missed', 'attack.c2.resolve': 'partial',
                                    'decoy.backup.nightly': 'missed'})


class PacketTest(unittest.TestCase):
    def test_the_claims_packet_carries_no_answer_key_text_and_the_facts_packet_does(self):
        with Lab() as lab:
            self.assertEqual(lab.run('packets', '--cases', CASE), 0)
            claims_text = (lab.out / f'packet-{CASE}-claims.json').read_text(encoding='utf-8')
            facts = lab.read(f'packet-{CASE}-facts.json')
        for fact_id, observation in OBSERVATIONS.items():
            self.assertNotIn(fact_id, claims_text)
            self.assertNotIn(observation, claims_text)
        self.assertNotIn('truth', claims_text)
        packet = json.loads(claims_text)
        c1 = packet['claims'][0]
        self.assertEqual([e for e in c1['events']], EVENTS[:2])
        self.assertEqual(c1['events_omitted'], 0)
        self.assertEqual(packet['reply_schema']['items']['properties']['verdict']['enum'], list(rr.VERDICTS))
        self.assertEqual([f['observation'] for f in facts['facts']], list(OBSERVATIONS.values()))
        self.assertEqual([c['claim_id'] for c in facts['claims']], [c['claim_id'] for c in CLAIMS])
        self.assertEqual(facts['reply_schema']['items']['properties']['established']['enum'], list(rr.ESTABLISHED))

    def test_cited_events_beyond_the_cap_are_counted_not_listed(self):
        with Lab() as lab, patch.object(rr, 'EVENT_CAP', 1):
            lab.run('packets', '--cases', CASE)
            c1 = lab.read(f'packet-{CASE}-claims.json')['claims'][0]
        self.assertEqual((len(c1['events']), c1['events_omitted']), (1, 1))


class AgreeTest(unittest.TestCase):
    @staticmethod
    def verdicts(changed=None):
        verdicts = {'incident:c1': 'correct', 'incident:c2': 'correct', 'incident:c3': 'unsupported',
                    'incident:c4': 'unsupported'} | (changed or {})
        return [{'claim_id': cid, 'verdict': v, 'reason': 'cited events checked'} for cid, v in verdicts.items()]

    @staticmethod
    def established(changed=None):
        # The scorer: attack.exec.script found, attack.c2.resolve found, decoy.backup.nightly missed.
        values = {'attack.exec.script': 'yes', 'attack.c2.resolve': 'yes', 'decoy.backup.nightly': 'no'} | (changed or {})
        return [{'fact_id': fid, 'established': v, 'reason': 'claims read'} for fid, v in values.items()]

    def test_self_agreement_and_the_per_fact_disputes_are_computed(self):
        with Lab() as lab:
            lab.run('packets', '--cases', CASE)
            lab.reply('claims', 1, self.verdicts())
            lab.reply('claims', 2, self.verdicts({'incident:c3': 'wrong'}))
            lab.reply('facts', 1, self.established({'attack.exec.script': 'no'}))
            lab.reply('facts', 2, self.established())
            self.assertEqual(lab.run('agree'), 0)
            result = lab.read('agreement.json')
        goals = result['goals']
        self.assertEqual((goals['G2.3']['replies_valid'], goals['G2.3']['replies_expected']), (4, 4))
        self.assertTrue(goals['G2.3']['pass'])
        self.assertEqual((goals['G2.4']['agreed'], goals['G2.4']['compared'], goals['G2.4']['share']), (3, 4, 0.75))
        self.assertFalse(goals['G2.4']['pass'])
        case = result['cases'][CASE]
        self.assertEqual(case['self_agreement']['differ'],
                         [{'claim_id': 'incident:c3', 'run_1': 'unsupported', 'run_2': 'wrong'}])
        self.assertEqual(case['claims_judged_wrong'], {'1': 0, '2': 1})
        self.assertEqual([(d['fact_id'], d['scorer'], d['reviewer']) for d in result['disputes']],
                         [('attack.exec.script', 'found', 'no')])
        self.assertEqual(result['disputes'][0]['observation'], OBSERVATIONS['attack.exec.script'])
        self.assertEqual(case['scorer_vs_reviewer']['agree'], 2)
        self.assertTrue(goals['G2.5']['pass'])

    def test_three_fact_disagreements_fail_g25(self):
        with Lab() as lab:
            lab.run('packets', '--cases', CASE)
            for run in rr.RUNS:
                lab.reply('claims', run, self.verdicts())
                lab.reply('facts', run, self.established({'attack.exec.script': 'no', 'attack.c2.resolve': 'partly',
                                                          'decoy.backup.nightly': 'yes'}))
            lab.run('agree')
            goals = lab.read('agreement.json')['goals']
        self.assertTrue(goals['G2.4']['pass'])
        self.assertEqual(goals['G2.5']['disagreements'], 3)
        self.assertFalse(goals['G2.5']['pass'])

    def test_a_malformed_reply_is_rejected_and_fails_g23(self):
        bad_verdict = self.verdicts({'incident:c2': 'maybe'})
        too_long = self.verdicts()
        too_long[0]['reason'] = 'x' * (rr.REASON_LIMIT + 1)
        with Lab() as lab:
            lab.run('packets', '--cases', CASE)
            lab.reply('claims', 1, bad_verdict)
            lab.reply('claims', 2, too_long)
            lab.reply('facts', 1, self.established()[:2])
            (lab.out / f'reply-{CASE}-facts-2.json').write_text('Here you go: [', encoding='utf-8')
            lab.run('agree')
            result = lab.read('agreement.json')
        replies = result['cases'][CASE]['replies']
        self.assertFalse(any(r['valid'] for r in replies.values()))
        self.assertIn('verdict', replies[f'reply-{CASE}-claims-1.json']['problems'][0])
        self.assertIn('longer than 300', replies[f'reply-{CASE}-claims-2.json']['problems'][0])
        self.assertIn('fact_id missing: decoy.backup.nightly', replies[f'reply-{CASE}-facts-1.json']['problems'])
        self.assertTrue(replies[f'reply-{CASE}-facts-2.json']['problems'][0].startswith('not JSON'))
        goals = result['goals']
        self.assertEqual((goals['G2.3']['replies_valid'], goals['G2.3']['pass']), (0, False))
        self.assertFalse(goals['G2.4']['pass'])
        self.assertFalse(goals['G2.5']['pass'])
        self.assertIn('error', result['cases'][CASE]['scorer_vs_reviewer'])

    def test_validate_reply_rejects_extra_keys_duplicates_and_non_lists(self):
        schema = rr.reply_schema('claim_id', ['a:1', 'a:2'], 'verdict', rr.VERDICTS)
        ok = [{'claim_id': 'a:1', 'verdict': 'correct', 'reason': ''}, {'claim_id': 'a:2', 'verdict': 'wrong', 'reason': 'r'}]
        self.assertEqual(rr.validate_reply(ok, schema), [])
        self.assertEqual(rr.validate_reply({'claims': ok}, schema), ['reply is not a JSON list'])
        extra = [dict(ok[0], note='x'), ok[1]]
        self.assertTrue(rr.validate_reply(extra, schema))
        self.assertIn('claim_id listed more than once: a:1', rr.validate_reply([ok[0], ok[0], ok[1]], schema))


class FieldTest(unittest.TestCase):
    def test_nested_flattened_and_mixed_paths_read_alike(self):
        for record in ({'process': {'parent': {'name': 'a.exe'}}}, {'process.parent.name': 'a.exe'},
                       {'process': {'parent.name': 'a.exe'}}, {'process.parent': {'name': 'a.exe'}}):
            self.assertEqual(rr.field_values(record, 'process.parent.name'), ['a.exe'])

    def test_an_event_naming_a_subdomain_shows_the_domain_but_not_a_lookalike(self):
        self.assertTrue(rr.in_event('"name": "1af5.0000.t.relay.test"', 't.relay.test'))
        self.assertFalse(rr.in_event('"name": "nott.relay.test"', 't.relay.test'))
        self.assertFalse(rr.in_event('"name": "t.relay.test.evil"', 't.relay.test'))

    def test_prose_before_the_handoff_is_skipped(self):
        report = rr.read_handoff('Summary {not json} then\n```json\n{"claims": [], "limitations": []}\n```')
        self.assertEqual(report, {'claims': [], 'limitations': []})


if __name__ == '__main__':
    unittest.main()
