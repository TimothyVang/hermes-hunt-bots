"""Invented lower-tier cases, generator determinism and answer-leakage checks."""
import copy
import re
import sys
import tempfile
import unittest
from pathlib import Path

from benchmark_contracts import (
    BenchmarkError, canonical_bytes, decode_json, digest_bytes, load_json, parse_utc,
    validate_public_bundle, validate_scenario, validate_stage_output, validate_truth,
)
from benchmark_difficulty import case_measurements, measure_case
from benchmark_scoring import edge_item_id, score_output


ROOT = Path(__file__).resolve().parent / 'benchmarks'
FIXTURES = ROOT / 'fixtures'
ALL_CASES = ('case-8b42', 'case-b060', 'case-5c21', 'case-d080', 'case-7d33',
             'case-9e44', 'case-e090', 'case-af55', 'case-c070')
CASES = ('case-8b42', 'case-5c21', 'case-7d33', 'case-b060', 'case-d080')
FILES = {'scenario.json', 'public/evidence.json', 'public/records.jsonl', 'evaluator/truth.json'}
ID_FIELDS = {'event_id': 'event', 'asset_id': 'asset', 'source_id': 'source', 'question_id': 'question'}
TOKEN = re.compile(r'([a-z]+)-([0-9a-f]{12})\Z')
REFERENCE = re.compile(r'(account|application|asset|binding|boot|change|connection|event|job|logon|object|'
                       r'principal|process|question|request|role|schedule|service|session|source|task)-')
JUDGEMENT = re.compile(r'unapproved|malicious|attacker|suspicious|benign|lookalike|noise', re.IGNORECASE)


def load_case(case_id):
    root = FIXTURES / case_id
    return (load_json(root / 'scenario.json'),
            load_json(root / 'public' / 'evidence.json'),
            load_json(root / 'evaluator' / 'truth.json'))


def records(case_id):
    return [decode_json(line) for line in
            (FIXTURES / case_id / 'public' / 'records.jsonl').read_bytes().splitlines()]


def events(bundle):
    return {event['event_id']: event for event in bundle['events']}


def support_events(bundle, truth, step_id, index=0):
    step = next(item for item in truth['steps'] if item['step_id'] == step_id)
    rows = events(bundle)
    return [rows[event_id] for event_id in step['support_sets'][index]]


def one(rows, **match):
    found = [row for row in rows if all(row.get(key, row['fields'].get(key)) == value
                                        for key, value in match.items())]
    if len(found) != 1:
        raise AssertionError('expected exactly one record matching {!r}, found {}'.format(match, len(found)))
    return found[0]


def label_for(bundle, truth, asset_id):
    question = next(item for item in bundle['assessment_questions'] if item['asset_id'] == asset_id)
    return truth['assessment_labels'][question['question_id']]


def receipt(rows, step):
    """The one documented rule: SHA-256 of canonical JSON of the step's support rows sorted by event_id."""
    ids = sorted({event_id for support in step['support_sets'] for event_id in support})
    by_id = {row['event_id']: row for row in rows}
    return digest_bytes(canonical_bytes([by_id[event_id] for event_id in ids]))


def check_case_files(test, case_id):
    """Strict schemas, digests, locators, clock normalization and receipts for one case."""
    root = FIXTURES / case_id
    test.assertEqual({path.relative_to(root).as_posix() for path in root.rglob('*') if path.is_file()}, FILES)
    scenario, bundle, truth = load_case(case_id)
    validate_scenario(scenario, load_json(ROOT / 'coverage.json'))
    validate_public_bundle(bundle, root / 'public')
    validate_truth(truth, bundle)
    digest = digest_bytes(canonical_bytes(bundle))
    test.assertEqual(scenario['evidence_manifest_sha256'], digest)
    test.assertEqual(truth['evidence_manifest_sha256'], digest)
    test.assertEqual((scenario['split'], scenario['provenance'], scenario['attack_release']),
                     ('development', 'synthetic', 'v20'))
    test.assertEqual(scenario['sophistication']['group_ids'], [])
    data = (root / 'public' / 'records.jsonl').read_bytes()
    rows = [decode_json(line) for line in data.splitlines()]
    test.assertEqual(len(rows), len(bundle['events']))
    offsets = {source['source_id']: source['clock_offset_seconds'] for source in bundle['sources']}
    for number, (row, event) in enumerate(zip(rows, bundle['events']), 1):
        test.assertEqual(row, {key: value for key, value in event.items() if key != 'locator'})
        test.assertEqual(event['locator'], {'record_id': str(number), 'file_sha256': digest_bytes(data)})
        original = parse_utc(event['fields']['timestamp_original'], 'timestamp_original')
        normalized = parse_utc(event['timestamp_utc'], 'timestamp_utc')
        test.assertEqual((original - normalized).total_seconds(), offsets[event['source_id']])
    test.assertEqual({source['source_sha256'] for source in bundle['sources']}, {digest_bytes(data)})
    for step in truth['steps']:
        test.assertEqual(step['source_receipt_sha256'], receipt(rows, step))
        if step['observability'] == 'sufficient':
            start = parse_utc(step['window_utc']['start_inclusive'], 'start')
            end = parse_utc(step['window_utc']['end_exclusive'], 'end')
            times = {parse_utc(row['timestamp_utc'], 'timestamp_utc') for row in rows
                     if any(row['event_id'] in support for support in step['support_sets'])}
            test.assertTrue(any(start <= moment < end for moment in times))
            test.assertLessEqual((end - start).total_seconds(), 61)
    test.assertEqual({q['asset_id'] for q in bundle['assessment_questions']},
                     {asset['asset_id'] for asset in bundle['assets']})
    test.assertEqual(set(truth['assessment_labels']), {q['question_id'] for q in bundle['assessment_questions']})
    return scenario, bundle, truth, rows


def fixture_handoff(bundle, truth):
    """Evaluator-built oracle, never a model-quality claim or public fixture."""
    findings = [dict(
        finding_id='finding-' + step['step_id'], asset_id=step['asset_id'],
        technique_id=step['technique_id'], window_utc=copy.deepcopy(step['window_utc']),
        disposition='suspicious', confidence=1.0, event_ids=step['support_sets'][0][:],
        rationale='Synthetic oracle recognizes the supported attempt, not a live compromise.',
    ) for step in truth['steps'] if step['observability'] == 'sufficient']
    for control in truth['controls']:
        findings.append(dict(
            finding_id='finding-' + control['control_id'], asset_id=control['asset_id'],
            technique_id=None, window_utc=copy.deepcopy(control['window_utc']),
            disposition=control['expected_disposition'], confidence=1.0,
            event_ids=[event['event_id'] for event in bundle['events']
                       if event['asset_id'] == control['asset_id']],
            rationale='Synthetic oracle for the independently authored control.',
        ))
    return dict(
        schema_version=1, stage_key='handoff', summary='Invented evaluator test oracle.',
        claims=[], findings=findings, hypotheses=[], gaps=[], limitations=[],
        requested_decision='approve',
        chain_edges=[['finding-' + left, 'finding-' + right] for left, right in truth['edges']],
        assessment_answers=[dict(question_id=qid, probability_suspicious=label)
                            for qid, label in truth['assessment_labels'].items()],
    )


def score_fixture(bundle, truth, output, unsupported=()):
    digest = digest_bytes(canonical_bytes(output))
    findings = {finding['finding_id']: finding for finding in output['findings']}
    items = [('finding', finding['finding_id'], finding['event_ids']) for finding in output['findings']]
    items += [('edge', edge_item_id(edge), sorted({eid for end in edge for eid in findings[end]['event_ids']}))
              for edge in output['chain_edges']]
    verdicts = [dict(trial_id='trial-fixture', output_sha256=digest, item_kind=kind, item_id=item_id,
                     verdict='contradicted' if item_id in unsupported else 'supported', event_ids=cited,
                     by='fixture-reviewer', note='Invented unit-test adjudication only.')
                for kind, item_id, cited in items]
    return score_output(output, truth, bundle, verdicts, trial_id='trial-fixture', output_sha256=digest)


def strings(value):
    """Every key and string value inside a JSON value."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)
    elif isinstance(value, str):
        yield value


def public_strings(bundle):
    """Every key and string a hunter can see, except the mandated fixed question text."""
    for key, value in bundle.items():
        yield key
        if key == 'assessment_questions':
            value = [{k: v for k, v in question.items() if k != 'question'} for question in value]
        yield from strings(value)


def leak_problems(cases):
    """Answer hints in public identifiers, ordering or wording; [] when none separates truth support.

    `cases` is a list of (case_id, bundle, truth, records_text).
    """
    problems, affixes, lengths, ranks = [], {}, {True: set(), False: set()}, []
    control_last, first_positive = [], []
    for case_id, bundle, truth, text in cases:
        relevant = {eid for step in truth['steps'] for support in step['support_sets'] for eid in support}
        identifiers = [('event_id', event['event_id']) for event in bundle['events']]
        identifiers += [('asset_id', asset['asset_id']) for asset in bundle['assets']]
        identifiers += [('source_id', source['source_id']) for source in bundle['sources']]
        identifiers += [('question_id', question['question_id']) for question in bundle['assessment_questions']]
        for field, value in identifiers:
            match = TOKEN.fullmatch(value)
            if not match or match.group(1) != ID_FIELDS[field]:
                problems.append('{}: {} {!r} is not an opaque token'.format(case_id, field, value))
        for event in bundle['events']:
            for value in strings(event['fields']):
                if REFERENCE.match(value) and not TOKEN.fullmatch(value):
                    problems.append('{}: reference {!r} is not an opaque token'.format(case_id, value))
        for value in list(public_strings(bundle)) + [text]:
            if JUDGEMENT.search(value):
                problems.append('{}: judgement word in {!r}'.format(case_id, value[:80]))
        ordered = sorted(event['event_id'] for event in bundle['events'])
        for event_id in ordered:
            flag = event_id in relevant
            lengths[flag].add(len(event_id))
            body = event_id.split('-', 1)[-1]
            for size in (1, 2, 3):
                for kind, part in (('prefix', body[:size]), ('suffix', body[-size:])):
                    affixes.setdefault((kind, part), []).append((flag, case_id))
        positions = [index for index, event_id in enumerate(ordered) if event_id in relevant]
        if len(positions) >= 3 and len(ordered) - len(positions) >= 3:
            if positions == list(range(len(positions))) or positions == list(range(len(ordered) - len(positions), len(ordered))):
                problems.append('{}: support events sort as one block at an end'.format(case_id))
        ranks += [index / float(len(ordered) - 1) for index in positions if len(ordered) > 1]
        if truth['steps']:
            assets = [asset['asset_id'] for asset in bundle['assets']]
            controls = [control['asset_id'] for control in truth['controls']]
            control_last.append(bool(controls) and assets.index(controls[-1]) == len(assets) - 1)
            first_positive.append(truth['assessment_labels'][bundle['assessment_questions'][0]['question_id']] == 1)
    for (kind, part), entries in sorted(affixes.items()):
        hits = [case for flag, case in entries if flag]
        if len(hits) >= 3 and len(set(hits)) >= 2 and all(flag for flag, _ in entries):
            problems.append('{} {!r} occurs only on support events in {} cases'.format(kind, part, len(set(hits))))
    if lengths[True] and lengths[False] and not lengths[True] & lengths[False]:
        problems.append('support event IDs have their own lengths {}'.format(sorted(lengths[True])))
    if ranks and not 0.25 <= sum(ranks) / len(ranks) <= 0.75:
        problems.append('support events cluster at mean sorted rank {:.2f}'.format(sum(ranks) / len(ranks)))
    if len(control_last) >= 2 and all(control_last):
        problems.append('the control asset is always listed last')
    if len(first_positive) >= 2 and all(first_positive):
        problems.append('the first assessment question is always positive')
    return problems


def all_fixture_cases():
    result = []
    for case_id in ALL_CASES:
        _, bundle, truth = load_case(case_id)
        text = (FIXTURES / case_id / 'public' / 'records.jsonl').read_text(encoding='utf-8')
        result.append((case_id, bundle, truth, text))
    return result


def rename_event(cases, case_id, old, new):
    """Rename one public event ID consistently in the bundle and truth of one case."""
    output = []
    for current, bundle, truth, text in cases:
        if current == case_id:
            bundle = decode_json(canonical_bytes(bundle).decode('utf-8').replace(old, new))
            truth = decode_json(canonical_bytes(truth).decode('utf-8').replace(old, new))
            text = text.replace(old, new)
        output.append((current, bundle, truth, text))
    return output


class FixtureGeneratorTests(unittest.TestCase):
    def test_generator_is_deterministic_and_matches_committed_files(self):
        tools = str(ROOT / 'tools')
        if tools not in sys.path:
            sys.path.insert(0, tools)
        import generate_fixtures
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            generate_fixtures.generate(first)
            generate_fixtures.generate(second)
            produced = {path.relative_to(first).as_posix() for path in Path(first).rglob('*') if path.is_file()}
            committed = {path.relative_to(FIXTURES).as_posix() for path in FIXTURES.rglob('*') if path.is_file()}
            self.assertEqual(produced, committed)
            for relative in sorted(produced):
                with self.subTest(file=relative):
                    data = (Path(first) / relative).read_bytes()
                    self.assertEqual(data, (Path(second) / relative).read_bytes())
                    self.assertEqual(data, (FIXTURES / relative).read_bytes())
        digests = {
            'coverage_sha256': digest_bytes(canonical_bytes(load_json(ROOT / 'coverage.json'))),
            'workflow_sha256': digest_bytes(canonical_bytes(load_json(ROOT / 'team-workflow.json'))),
            'prompt_contract_sha256': digest_bytes((ROOT / 'prompt-contract.txt').read_bytes()),
        }
        for name in generate_fixtures.EXAMPLES:
            experiment = load_json(ROOT / 'examples' / name)
            self.assertEqual({key: experiment[key] for key in digests}, digests)


class FixtureLeakageTests(unittest.TestCase):
    def test_no_public_pattern_or_wording_separates_support_events(self):
        self.assertEqual(leak_problems(all_fixture_cases()), [])

    def test_checker_flags_one_old_style_identifier(self):
        cases = all_fixture_cases()
        _, bundle, truth, _ = next(item for item in cases if item[0] == 'case-5c21')
        target = truth['steps'][0]['support_sets'][0][0]
        problems = leak_problems(rename_event(cases, 'case-5c21', target, 'event-101'))
        self.assertIn("case-5c21: event_id 'event-101' is not an opaque token", problems)
        session = events(bundle)[target]['fields']['session_id']
        problems = leak_problems(rename_event(cases, 'case-5c21', session, 'session-a'))
        self.assertIn("case-5c21: reference 'session-a' is not an opaque token", problems)

    def test_checker_flags_affix_ordering_and_wording_patterns(self):
        cases = all_fixture_cases()
        renamed = cases
        for case_id, bundle, truth, _ in cases:
            relevant = sorted({eid for step in truth['steps'] for support in step['support_sets'] for eid in support})
            for index, event_id in enumerate(relevant):
                renamed = rename_event(renamed, case_id, event_id, 'event-000{:09x}'.format(index))
        problems = leak_problems(renamed)
        self.assertTrue(any('occurs only on support events' in item for item in problems), problems)
        self.assertTrue(any('cluster at mean sorted rank' in item for item in problems), problems)
        self.assertTrue(any('sort as one block' in item for item in problems), problems)
        worded = copy.deepcopy(cases)
        worded[0][1]['events'][0]['fields']['parent_basename'] = 'unapproved-service.exe'
        self.assertTrue(any('judgement word' in item for item in leak_problems(worded)))
        shuffled = []
        for case_id, bundle, truth, text in copy.deepcopy(cases):
            if truth['steps'] and truth['controls']:
                control = truth['controls'][-1]['asset_id']
                bundle['assets'].sort(key=lambda item: item['asset_id'] == control)
            shuffled.append((case_id, bundle, truth, text))
        self.assertIn('the control asset is always listed last', leak_problems(shuffled))

    def test_receipts_follow_one_rule_in_every_case(self):
        for case_id in ALL_CASES:
            with self.subTest(case=case_id):
                rows = records(case_id)
                for step in load_case(case_id)[2]['steps']:
                    self.assertEqual(step['source_receipt_sha256'], receipt(rows, step))


class LowerFixtureContractTests(unittest.TestCase):
    def test_exact_files_strict_schemas_and_every_record_locator(self):
        for case_id in CASES:
            with self.subTest(case=case_id):
                check_case_files(self, case_id)
        # The skewed second-host clock is normalized, not silently copied.
        _, bundle, _ = load_case('case-5c21')
        skewed = [source for source in bundle['sources'] if source['clock_offset_seconds']]
        self.assertEqual([source['clock_offset_seconds'] for source in skewed], [3])
        shifted = [event for event in bundle['events'] if event['source_id'] == skewed[0]['source_id']]
        self.assertTrue(shifted)
        self.assertTrue(all(event['fields']['timestamp_original'] != event['timestamp_utc'] for event in shifted))

    def test_quantitative_bands_from_records_not_labels(self):
        expected = {
            'case-8b42': (8, 2, 1, 130, 0, 'D1', 'S1'),
            'case-5c21': (14, 2, 1, 600, 1, 'D2', 'S2'),
            'case-7d33': (27, 7, 3, 1199, 1, 'D3', 'S3'),
            'case-d080': (6, 1, 1, 0, 0, 'D1', 'S1'),
        }
        for case_id, facts in expected.items():
            with self.subTest(case=case_id):
                scenario, bundle, truth = load_case(case_id)
                measured = case_measurements(bundle, records(case_id), truth)
                self.assertEqual(tuple(measured[key] for key in
                                       ('benign_events', 'relevant_events', 'required_joins',
                                        'correlation_seconds', 'benign_lookalikes')), facts[:5])
                result = measure_case(bundle, records(case_id), truth)
                self.assertEqual(result, scenario['difficulty'])
                self.assertEqual(result['band'], facts[5])
                self.assertFalse(scenario['difficulty']['control'])
                self.assertEqual(scenario['sophistication']['band'], facts[6])
                self.assertFalse(measured['missing_records'])
                self.assertEqual(measured['unresolvable_questions'], 0)

    def test_windows_atomic_discovery_is_structural_not_named(self):
        scenario, bundle, truth = load_case('case-8b42')
        service, child = support_events(bundle, truth, 'step-a')
        if service['fields']['process_basename'] != child['fields']['parent_basename']:
            service, child = child, service
        self.assertEqual(service['fields']['parent_basename'], 'services.exe')
        self.assertEqual(child['fields']['parent_process_guid'], service['fields']['process_guid'])
        self.assertEqual(child['fields']['process_basename'], 'whoami.exe')
        self.assertEqual(child['fields']['user'], service['fields']['user'])
        # The same service binary starts on the other host without any child: name alone proves nothing.
        other = [event for event in bundle['events'] if event['asset_id'] != child['asset_id']]
        twin = one(other, process_basename=service['fields']['process_basename'])
        self.assertFalse(any(event['fields'].get('parent_process_guid') == twin['fields']['process_guid']
                             for event in bundle['events']))
        self.assertEqual(label_for(bundle, truth, child['asset_id']), 1)
        self.assertEqual(label_for(bundle, truth, twin['asset_id']), 0)
        self.assertEqual(len(scenario['sophistication']['steps']), 1)
        result = score_fixture(bundle, truth, fixture_handoff(bundle, truth))
        self.assertEqual((result['detection']['tp'], result['detection']['fp'], result['detection']['fn']),
                         (1, 0, 0))

    def test_linux_edge_requires_actual_process_ancestry_and_elapsed_time(self):
        scenario, bundle, truth = load_case('case-5c21')
        parent, child = sorted(support_events(bundle, truth, 'step-b'),
                               key=lambda event: event['fields']['process_basename'] != 'sh')
        self.assertEqual(child['fields']['parent_process_id'], parent['fields']['process_id'])
        self.assertEqual(child['fields']['parent_start_original'], parent['fields']['timestamp_original'])
        self.assertEqual(child['fields']['session_id'], parent['fields']['session_id'])
        self.assertEqual(child['fields']['user'], parent['fields']['user'])
        self.assertLess(parent['timestamp_utc'], child['timestamp_utc'])
        self.assertEqual(truth['edges'], [['step-a', 'step-b']])
        self.assertEqual(scenario['sophistication']['edges'], truth['edges'])
        self.assertEqual(len({step['boundary_id'] for step in scenario['sophistication']['steps']}), 1)
        self.assertEqual(len({step['asset_id'] for step in truth['steps']}), 1)
        # The competing inventory shell/id pair is curated, has the same shape, and is not support.
        lookalike = [events(bundle)[eid] for eid in truth['lookalike_event_ids'][0]]
        self.assertEqual(sorted(event['fields']['process_basename'] for event in lookalike), ['id', 'sh'])
        self.assertNotEqual({event['asset_id'] for event in lookalike}, {child['asset_id']})
        oracle = fixture_handoff(bundle, truth)
        self.assertEqual(score_fixture(bundle, truth, oracle)['chain_edges']['tp'], 1)
        oracle['findings'][1]['event_ids'] = [child['event_id']]
        result = score_fixture(bundle, truth, oracle)
        self.assertEqual((result['detection']['tp'], result['detection']['fp'], result['detection']['fn']),
                         (1, 1, 1))
        self.assertEqual(result['chain_edges']['tp'], 0)

    def test_ad_chain_crosses_identity_and_privilege_with_linking_records(self):
        scenario, bundle, truth = load_case('case-7d33')
        query, reply = sorted(support_events(bundle, truth, 'step-a'), key=lambda e: e['timestamp_utc'])
        primary = support_events(bundle, truth, 'step-b', 0)
        alternative = support_events(bundle, truth, 'step-b', 1)
        cred = one(primary, event_type='explicit_credential_use')
        ticket = one(alternative, event_type='kerberos_service_ticket')
        request = one(primary, event_type='remote_session_request')
        accepted = one(primary, event_type='remote_session_open')
        whoami = one(support_events(bundle, truth, 'step-c'), event_type='process_start')
        self.assertEqual(query['fields']['request_id'], reply['fields']['request_id'])
        self.assertEqual(request['fields']['directory_request_id'], reply['fields']['request_id'])
        self.assertEqual(request['fields']['target_object_id'], reply['fields']['returned_object_id'])
        self.assertEqual(request['fields']['server_ip'], reply['fields']['returned_address'])
        self.assertEqual({query['fields']['process_id'], cred['fields']['process_id'],
                          request['fields']['process_id']}, {query['fields']['process_id']})
        # Identity crossing: the service-account process presents another account's credential.
        self.assertEqual(cred['fields']['subject_account'], query['fields']['account'])
        self.assertNotEqual(cred['fields']['target_account'], query['fields']['account'])
        for linked in (ticket, request, accepted, whoami):
            self.assertEqual(linked['fields']['account'], cred['fields']['target_account'])
        for key in ('client_ip', 'client_port', 'server_ip', 'server_port'):
            self.assertEqual(request['fields'][key], accepted['fields'][key])
        # Privilege crossing: the accepted session is administrative and runs an elevated process.
        self.assertEqual(accepted['fields']['local_group'], 'Administrators')
        self.assertEqual(whoami['fields']['logon_id'], accepted['fields']['logon_id'])
        self.assertEqual(whoami['fields']['integrity_level'], 'High')
        self.assertLess(reply['timestamp_utc'], request['timestamp_utc'])
        self.assertLess(request['timestamp_utc'], accepted['timestamp_utc'])
        # Attribution: acting process host for the query and session; session host for the process.
        steps = {step['step_id']: step for step in truth['steps']}
        self.assertEqual(steps['step-a']['asset_id'], query['asset_id'])
        self.assertEqual(steps['step-b']['asset_id'], query['asset_id'])
        self.assertEqual(steps['step-c']['asset_id'], accepted['asset_id'])
        self.assertEqual(label_for(bundle, truth, query['asset_id']), 1)
        self.assertEqual(label_for(bundle, truth, accepted['asset_id']), 1)
        self.assertEqual(label_for(bundle, truth, reply['asset_id']), 0)
        kinds = {boundary['kind'] for boundary in scenario['sophistication']['boundaries']}
        self.assertTrue({'identity', 'privilege'} <= kinds)
        self.assertEqual(truth['edges'], scenario['sophistication']['edges'])
        # The internal authoritative zone is backed by actual DNS records.
        dns = [event for event in bundle['events'] if event['event_type'] == 'dns_query']
        self.assertTrue(dns and all(event['fields']['authoritative'] for event in dns))
        oracle = fixture_handoff(bundle, truth)
        result = score_fixture(bundle, truth, oracle)
        self.assertEqual(result['detection']['tp'], 3)
        self.assertEqual(result['chain_edges']['tp'], 2)
        oracle['findings'][1]['event_ids'] = [alternative_id['event_id'] for alternative_id in alternative]
        self.assertEqual(score_fixture(bundle, truth, oracle)['detection']['tp'], 3)
        oracle['findings'][1]['event_ids'] = [accepted['event_id']]
        partial = score_fixture(bundle, truth, oracle)
        self.assertEqual(partial['detection']['truth_correct_unsupported'], 1)
        self.assertEqual(partial['chain_edges']['tp'], 0)

    def test_benign_control_inherits_family_and_false_alarms_are_not_recall(self):
        scenario, bundle, truth = load_case('case-b060')
        matched, matched_bundle, _ = load_case('case-8b42')
        measured = case_measurements(bundle, records('case-b060'), truth)
        self.assertEqual((measured['benign_events'], measured['relevant_events']), (10, 0))
        self.assertEqual(scenario['family_id'], matched['family_id'])
        # Inherited scores describe the same window, asset count and source layout.
        self.assertEqual(bundle['window_utc'], matched_bundle['window_utc'])
        self.assertEqual(len(bundle['assets']), len(matched_bundle['assets']))
        self.assertEqual(sorted(s['telemetry'] for s in bundle['sources']),
                         sorted(s['telemetry'] for s in matched_bundle['sources']))
        self.assertEqual(scenario['difficulty'], measure_case(
            bundle, records('case-b060'), truth, {'matched_control': matched['difficulty']}))
        with self.assertRaises(BenchmarkError):
            measure_case(bundle, records('case-b060'), truth)
        self.assertEqual(scenario['sophistication']['band'], 'S0')
        self.assertEqual(truth['steps'], [])
        self.assertEqual(truth['edges'], [])
        self.assertEqual(set(truth['assessment_labels'].values()), {0})
        oracle = fixture_handoff(bundle, truth)
        result = score_fixture(bundle, truth, oracle)
        self.assertIsNone(result['detection']['recall'])
        self.assertEqual(result['controls']['benign']['correct_disposition_rate'], 1)
        self.assertEqual(result['controls']['benign']['false_alarm_rate'], 0)
        self.assertEqual(result['calibration']['brier'], 0)
        oracle['findings'][0].update(disposition='suspicious', technique_id='T1033')
        alarm = score_fixture(bundle, truth, oracle, unsupported=[oracle['findings'][0]['finding_id']])
        self.assertEqual(alarm['detection']['fp'], 1)
        self.assertEqual(alarm['controls']['benign']['false_alarms'], 1)
        self.assertEqual(alarm['controls']['benign']['false_alarm_rate'], 0.5)
        self.assertIsNone(alarm['detection']['recall'])

    def test_blocked_attempt_is_positive_but_not_successful_execution(self):
        scenario, bundle, truth = load_case('case-d080')
        matched, _, _ = load_case('case-5c21')
        self.assertEqual(scenario['family_id'], matched['family_id'])
        self.assertFalse(scenario['difficulty']['control'])
        (event,) = support_events(bundle, truth, 'step-a')
        self.assertEqual(event['fields']['result'], 'denied')
        self.assertEqual(event['fields']['errno'], 'EACCES')
        self.assertFalse(event['fields']['process_created'])
        self.assertEqual(truth['steps'][0]['execution_outcome'], 'blocked')
        self.assertEqual(label_for(bundle, truth, event['asset_id']), 1)
        result = score_fixture(bundle, truth, fixture_handoff(bundle, truth))
        self.assertEqual(result['detection']['tp'], 1)
        self.assertEqual(result['detection']['execution_outcomes']['blocked'],
                         {'eligible_steps': 1, 'matched_steps': 1})
        self.assertEqual(result['detection']['execution_outcomes']['succeeded'],
                         {'eligible_steps': 0, 'matched_steps': 0})
        self.assertIsNone(result['diagnostics']['execution_outcome_correctness'])
        failed = score_output(None, truth, bundle, [], trial_id='trial-failed',
                              output_sha256=None, completed=False)
        self.assertEqual(failed['detection']['fn'], 1)
        self.assertEqual(failed['detection']['f1'], 0)
        self.assertEqual(failed['controls']['benign']['missing_or_failed'], 1)

    def test_real_fixture_consumers_reject_answer_metadata_and_broken_support(self):
        _, bundle, truth = load_case('case-7d33')
        leaked = copy.deepcopy(bundle)
        leaked['events'][0]['fields']['assessment_labels'] = {bundle['assessment_questions'][0]['question_id']: 1}
        with self.assertRaises(BenchmarkError) as caught:
            validate_public_bundle(leaked)
        self.assertEqual(caught.exception.code, 'truth_public_overlap')
        broken = copy.deepcopy(truth)
        broken['steps'][0]['support_sets'] = [['event-000000000000']]
        with self.assertRaises(BenchmarkError) as caught:
            validate_truth(broken, bundle)
        self.assertEqual(caught.exception.code, 'unknown_reference')
        oracle = fixture_handoff(bundle, truth)
        validate_stage_output(oracle, public_bundle=bundle)
        oracle['assessment_answers'].pop()
        with self.assertRaises(BenchmarkError):
            validate_stage_output(oracle, public_bundle=bundle)


if __name__ == '__main__':
    unittest.main()
