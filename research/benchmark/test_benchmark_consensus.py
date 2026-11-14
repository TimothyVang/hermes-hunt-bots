"""Agent-consensus merge tests on INVENTED curations; no models, no network, no downloads."""
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone

import benchmark_consensus as consensus
import benchmark_import_attackdata as ad
import benchmark_import_otrf as otrf
from benchmark_contracts import TRUTH_ATTESTATIONS, BenchmarkError, decode_json, digest_bytes, load_json, validate_truth
from benchmark_paths import FRAMEWORK

HERE = Path(__file__).resolve().parent
SAMPLE = HERE / 'benchmarks' / 'importers' / 'sample'
DATASET = SAMPLE / 'sample_owner_discovery_2026-01-0100000000.json'
METADATA = SAMPLE / 'SDWIN-990101000001.yaml'
CURATION = SAMPLE / 'curation.json'
NX_DATASET = SAMPLE / 'sample_nxlog_discovery_2026-01-0100000000.json'
NX_METADATA = SAMPLE / 'SDWIN-990101000002.yaml'
NX_CURATION = SAMPLE / 'curation-nxlog.json'
NX_HOST = 'LABHOST03.lab.example.test'
SYSMON = 'Microsoft-Windows-Sysmon/Operational'
AUDIT = SAMPLE / 'attackdata_sample_auditd.log'
LINUX_META = SAMPLE / 'attackdata-sample-linux.yml'
AUDIT_CURATION = SAMPLE / 'curation-attackdata-auditd.json'
COVERAGE = HERE / 'benchmarks' / 'coverage.json'
SALT = bytes(range(32))
NOW = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)
# Opaque to the merge: only presence and equality between the drafts matter.
MATCHED_CONTROL = {'band': 'D2', 'control': True, 'factors': {}}
OTHER_CONTROL = {'band': 'D3', 'control': True, 'factors': {}}


def proposal(path, note):
    """An unreviewed agent proposal built from an invented sample curation."""
    value = json.loads(path.read_text('utf-8'))
    value.update(status=otrf.PROPOSAL_STATUS, curated_by=None, curated_utc=None, note=note)
    return value


def step(step_id, technique, lines, host='LABHOST01', start='2026-01-01T09:00:02Z', end='2026-01-01T09:00:03Z',
         boundary='boundary-host', phase='initial', outcome='succeeded', observability='sufficient'):
    return {'step_id': step_id, 'technique_id': technique, 'asset': {'hostname': host},
            'window_utc': {'start_inclusive': start, 'end_exclusive': end}, 'execution_outcome': outcome,
            'observability': observability, 'support_sets': [[{'line': line} for line in group] for group in lines],
            'boundary_id': boundary, 'phase': phase}


def lines(*groups):
    return {frozenset(group) for group in groups}


def side_files(outputs):
    """The draft import's evaluator side files the merge reads: (locators, template)."""
    return (decode_json(outputs['evaluator/locators.json']), decode_json(outputs['evaluator/curation-template.json']))


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = consensus.main([str(item) for item in argv])
    return code, out.getvalue(), err.getvalue()


class ConsensusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Draft imports of the invented samples supply locators.json and curation-template.json.
        fields = otrf.load_field_map()
        cls.flat = side_files(otrf.build_case(DATASET, METADATA, fields, SALT, draft_os_family='windows-client')[1])
        cls.nxlog = side_files(otrf.build_case(NX_DATASET, NX_METADATA, fields, SALT,
                                               draft_os_family='windows-client')[1])
        cls.audit = side_files(ad.build_case(AUDIT, LINUX_META, ad.load_field_map(), SALT)[1])

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.a = proposal(CURATION, 'draft A, written independently')
        self.b = proposal(CURATION, 'draft B, written independently')

    def tearDown(self):
        self.tmp.cleanup()

    def merge(self, a=None, b=None, fmt='otrf', sides=None):
        locators, template = sides or self.flat
        index = consensus.locator_index(locators)
        left = consensus.parse_draft(a or self.a, fmt, '0' * 64, 'a', index)
        right = consensus.parse_draft(b or self.b, fmt, '1' * 64, 'b', index)
        return consensus.merge_drafts(left, right, consensus.template_defaults(template), NOW)

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value, indent=2), 'utf-8')
        return path

    def side_paths(self, sides=None, prefix='flat'):
        locators, template = sides or self.flat
        return (self.write(prefix + '-locators.json', locators), self.write(prefix + '-template.json', template))

    def assertCode(self, code, call, *args, **kwargs):
        with self.assertRaises(BenchmarkError) as caught:
            call(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    # ------------------------------------------------------------- agreement
    def test_full_agreement_keeps_everything_and_is_labelled_agent_consensus(self):
        self.b['steps'][0]['support_sets'].reverse()
        curation, report = self.merge()
        self.assertNotIn('status', curation)
        self.assertEqual((curation['curated_by'], curation['attestation_hint'], curation['curated_utc']),
                         ('agent-consensus', 'agent_consensus', '2026-11-04T12:00:00+00:00'))
        self.assertIn('no human reviewed', curation['note'])
        merged = curation['steps'][0]
        self.assertEqual((merged['technique_id'], merged['asset'], merged['observability'],
                          merged['execution_outcome'], merged['support_sets']),
                         ('T1033', {'hostname': 'LABHOST01'}, 'sufficient', 'succeeded',
                          [[{'line': 3}], [{'line': 4}]]))
        self.assertEqual(len(curation['controls']), 1)
        self.assertEqual(curation['lookalike_event_ids'], [[{'line': 8}, {'line': 9}]])
        self.assertEqual((curation['excluded_locators'], curation['attack_release']), ([], 'v18'))
        self.assertNotIn('matched_control', curation)
        self.assertEqual((curation['sophistication']['band'], report['sophistication']['basis']), ('S1', 'drafts_agree'))
        self.assertEqual(report['disputed_steps'], [])
        self.assertEqual((report['steps'][0]['support_basis'], report['steps'][0]['support_set_jaccard']),
                         ('minimal_unions', 1.0))
        self.assertEqual(report['disputed_fields'], {'attack_release': None, 'coverage': [], 'asset_facts': [],
                                                     'matched_control': None, 'assessment_windows': None,
                                                     'clock_declaration': None})
        # One candidate technique x two assets: one shared yes, one shared no.
        kappa = report['kappa']
        self.assertEqual((kappa['items'], kappa['both'], kappa['neither'], kappa['kappa']), (2, 1, 1, 1.0))
        # The A/B labels only name the inputs: swapping them changes no truth field.
        swapped, _ = self.merge(self.b, self.a)
        for key in ('steps', 'edges', 'controls', 'lookalike_event_ids', 'excluded_locators', 'sophistication',
                    'assets', 'coverage', 'attack_release'):
            self.assertEqual(swapped[key], curation[key], key)

    def test_partial_agreement_drops_unpaired_steps_and_excludes_their_records(self):
        self.a['steps'].append(step('step-a2', 'T1057', [[6]]))
        self.b['steps'].append(step('step-b2', 'T1082', [[5]]))
        curation, report = self.merge()
        self.assertEqual([item['technique_id'] for item in curation['steps']], ['T1033'])
        self.assertEqual(sorted((item['draft'], item['step_id'], item['reason']) for item in report['disputed_steps']),
                         [('a', 'step-a2', 'no_counterpart'), ('b', 'step-b2', 'no_counterpart')])
        self.assertEqual(curation['excluded_locators'], [{'line': 5}, {'line': 6}])
        # Three candidate techniques x two assets: T1033@01 both, T1057@01 A only, T1082@01 B only.
        kappa = report['kappa']
        self.assertEqual((kappa['items'], kappa['both'], kappa['only_draft_a'], kappa['only_draft_b'],
                          kappa['neither']), (6, 1, 1, 1, 3))
        # po = 4/6, pe = 1/3*1/3 + 2/3*2/3 = 5/9, kappa = (2/3 - 5/9) / (4/9) = 1/4.
        self.assertEqual(kappa['kappa'], 0.25)

    def test_support_sets_merge_into_minimal_unions(self):
        agree = consensus.support_agreement
        # Main's real pair: [95,239,380] and [239] for one injection step.
        merged = agree(lines([95, 239, 380]), lines([239]))
        self.assertEqual((merged['basis'], merged['sets']), ('minimal_unions', [frozenset({95, 239, 380})]))
        self.assertEqual(agree(lines([1], [68]), lines([1]))['sets'], [frozenset({1})])
        # Unions {1,2} {1,3} {2} {2,3}: the supersets of {2} drop out; smallest first.
        self.assertEqual(agree(lines([1], [2]), lines([2], [3]))['sets'], [frozenset({2}), frozenset({1, 3})])
        # At most 16 sets, by size and then lexicographically.
        capped = agree({frozenset({line}) for line in range(1, 18)}, lines([100]))
        self.assertEqual((len(capped['sets']), capped['capped'], capped['sets'][0], capped['sets'][-1]),
                         (16, 1, frozenset({1, 100}), frozenset({16, 100})))
        self.assertEqual((agree(set(), set())['basis'], agree(lines([1]), set())['basis'], agree(lines([1]), set())['sets']),
                         ('both_empty', 'one_empty', []))
        # Jaccard is reported, never a filter: disjoint support still merges.
        disjoint = agree(lines([3]), lines([6]))
        self.assertEqual((disjoint['sets'], disjoint['locator_jaccard']), ([frozenset({3, 6})], 0))

    def test_different_support_keeps_the_step_with_complete_sets_for_both(self):
        self.a['steps'][0]['support_sets'] = [[{'line': 3}, {'line': 5}, {'line': 6}]]
        self.b['steps'][0]['support_sets'] = [[{'line': 5}]]
        curation, report = self.merge()
        self.assertEqual(curation['steps'][0]['support_sets'], [[{'line': 3}, {'line': 5}, {'line': 6}]])
        self.assertEqual((curation['excluded_locators'], report['disputed_steps']), ([], []))
        self.a['steps'][0]['support_sets'] = [[{'line': 3}], [{'line': 6}]]
        self.b['steps'][0]['support_sets'] = [[{'line': 3}]]
        curation, report = self.merge()
        self.assertEqual(curation['steps'][0]['support_sets'], [[{'line': 3}]])
        # A alone thought line 6 proves the step: disputed evidence, ignored by scoring.
        self.assertEqual(curation['excluded_locators'], [{'line': 6}])
        self.assertEqual(report['steps'][0]['support_set_jaccard'], 0.5)

    def test_windows_merge_to_their_hull_only_when_they_overlap(self):
        self.b['steps'][0]['window_utc'] = {'start_inclusive': '2026-01-01T09:00:01Z',
                                            'end_exclusive': '2026-01-01T09:00:02.500Z'}
        curation, _ = self.merge()
        self.assertEqual(curation['steps'][0]['window_utc'],
                         {'start_inclusive': '2026-01-01T09:00:01.000000+00:00',
                          'end_exclusive': '2026-01-01T09:00:03.000000+00:00'})
        self.b['steps'][0]['window_utc'] = {'start_inclusive': '2026-01-01T09:00:05Z',
                                            'end_exclusive': '2026-01-01T09:00:06Z'}
        for draft in (self.a, self.b):
            draft['matched_control'] = MATCHED_CONTROL
        curation, report = self.merge()
        self.assertEqual(curation['steps'], [])
        self.assertEqual({item['reason'] for item in report['disputed_steps']}, {'no_counterpart'})
        self.assertEqual(curation['excluded_locators'], [{'line': 3}, {'line': 4}])
        # No surviving step: only S0 is valid, so the drafts' S1 is recomputed.
        self.assertEqual((curation['sophistication']['band'], report['sophistication']['basis']),
                         ('S0', 'recomputed_from_surviving_steps'))

    def test_matched_control_is_required_exactly_without_a_sufficient_step(self):
        self.b['steps'][0]['observability'] = 'insufficient'
        error = self.assertCode('matched_control_unavailable', self.merge)
        self.assertEqual(error.field, 'curation.matched_control')
        self.b['matched_control'] = MATCHED_CONTROL
        curation, report = self.merge()
        self.assertEqual((curation['matched_control'], report['field_decisions']['matched_control']),
                         (MATCHED_CONTROL, 'draft_b'))
        self.assertEqual(report['disputed_fields']['matched_control'],
                         {'draft_a': None, 'draft_b': MATCHED_CONTROL, 'merged_from': 'draft_b'})
        self.a['matched_control'] = OTHER_CONTROL
        curation, report = self.merge()
        self.assertEqual((curation['matched_control'], report['field_decisions']['matched_control']),
                         (OTHER_CONTROL, 'draft_a'))
        self.a['matched_control'] = copy.deepcopy(MATCHED_CONTROL)
        curation, report = self.merge()
        self.assertEqual((curation['matched_control'], report['field_decisions']['matched_control'],
                          report['disputed_fields']['matched_control']), (MATCHED_CONTROL, 'agreed', None))
        # A sufficient merged step forbids it: dropped even though both drafts carry one.
        self.b['steps'][0]['observability'] = 'sufficient'
        curation, report = self.merge()
        self.assertNotIn('matched_control', curation)
        self.assertEqual(report['field_decisions']['matched_control'], 'not_needed')

    def test_conflicting_outcomes_become_unknown(self):
        self.b['steps'][0]['execution_outcome'] = 'failed'
        curation, report = self.merge()
        self.assertEqual(curation['steps'][0]['execution_outcome'], 'unknown')
        self.assertEqual(report['steps'][0]['execution_outcome'],
                         {'draft_a': 'succeeded', 'draft_b': 'failed', 'merged': 'unknown'})
        self.b['steps'][0]['execution_outcome'] = 'blocked'
        self.a['steps'][0]['execution_outcome'] = 'blocked'
        self.assertEqual(self.merge()[0]['steps'][0]['execution_outcome'], 'blocked')

    def test_observability_takes_the_more_conservative_claim(self):
        for left, right, merged in (('sufficient', 'sufficient', 'sufficient'),
                                    ('sufficient', 'insufficient', 'insufficient'),
                                    ('insufficient', 'absent', 'absent'),
                                    ('absent', 'unknown', 'unknown'),
                                    ('unknown', 'sufficient', 'unknown')):
            with self.subTest(left=left, right=right):
                a, b = copy.deepcopy(self.a), copy.deepcopy(self.b)
                a['steps'][0]['observability'], b['steps'][0]['observability'] = left, right
                a['matched_control'] = b['matched_control'] = MATCHED_CONTROL
                curation, report = self.merge(a, b)
                self.assertEqual(curation['steps'][0]['observability'], merged)
                self.assertEqual(report['steps'][0]['observability']['merged'], merged)
                self.assertEqual('matched_control' in curation, merged != 'sufficient')

    def test_edges_controls_and_sophistication_need_both_drafts(self):
        for draft in (self.a, self.b):
            draft['steps'].append(step('step-2', 'T1057', [[6]], start='2026-01-01T09:00:04Z',
                                       end='2026-01-01T09:00:05Z'))
        self.a['edges'] = [['step-1', 'step-2']]
        self.a['sophistication']['band'] = 'S2'
        self.b['controls'][0]['expected_disposition'] = 'insufficient'
        self.b['lookalike_event_ids'] = [[{'line': 8}]]
        curation, report = self.merge()
        self.assertEqual(len(curation['steps']), 2)
        self.assertEqual((curation['edges'], curation['controls'], curation['lookalike_event_ids']), ([], [], []))
        self.assertEqual(report['summary']['draft_a_edges'], 1)
        # Without the disputed edge only S1 is valid for the surviving steps.
        self.assertEqual((curation['sophistication']['band'], report['sophistication']['basis'],
                          report['sophistication']['structurally_supported']),
                         ('S1', 'recomputed_from_surviving_steps', ['S1']))
        self.b['edges'] = [['step-1', 'step-2']]
        self.b['sophistication']['band'] = 'S2'
        curation, report = self.merge()
        self.assertEqual((curation['edges'], curation['sophistication']['band'], report['sophistication']['basis']),
                         ([['step-1', 'step-2']], 'S2', 'drafts_agree'))

    def test_boundary_and_phase_disagreements_are_conservative(self):
        for draft in (self.a, self.b):
            draft['controls'] = []
            draft['lookalike_event_ids'] = []
            draft['steps'].append(step('step-2', 'T1021', [[8]], host='LABHOST02', start='2026-01-01T09:00:04Z',
                                       end='2026-01-01T09:00:06Z', boundary='boundary-remote'))
            draft['edges'] = [['step-1', 'step-2']]
            draft['sophistication']['boundaries'].append({'boundary_id': 'boundary-remote', 'kind': 'identity'})
            draft['sophistication']['band'] = 'S3'
        self.a['steps'][1]['phase'] = 'persistence'
        self.b['steps'][1]['phase'] = 'reentry'
        curation, report = self.merge()
        self.assertEqual((curation['sophistication']['band'], curation['steps'][1]['phase']), ('S3', 'initial'))
        self.assertEqual([item['field'] for item in report['sophistication']['conflicts']], ['phase'])
        # Same rubric class (the real SDWIN-201219070027 pair): the qualifying kind survives, draft A's, disputed.
        self.b['sophistication']['boundaries'][1]['kind'] = 'privilege'
        curation, report = self.merge()
        self.assertEqual((curation['sophistication']['band'], curation['sophistication']['boundaries'][1]['kind']),
                         ('S3', 'identity'))
        self.assertIn({'field': 'boundary_kind', 'boundary_id': 'boundary-2', 'drafts': ['identity', 'privilege'],
                       'merged': 'identity', 'step_ids': ['step-2']}, report['sophistication']['conflicts'])
        self.assertEqual(self.merge(self.b, self.a)[0]['sophistication']['boundaries'][1]['kind'], 'privilege')
        # Different classes fall back to `host`: the chain no longer crosses an identity or
        # privilege boundary, so the conservative merge keeps it as a linked chain (S2).
        self.b['sophistication']['boundaries'][1]['kind'] = 'segment'
        curation, report = self.merge()
        self.assertEqual((curation['sophistication']['band'], curation['sophistication']['boundaries'][1]['kind']),
                         ('S2', 'host'))

    def test_descriptive_disagreements_are_reported_not_refused(self):
        self.b['coverage']['dns_domain'] = ['recursive-forwarder']
        self.b['coverage']['network'] = ['flat-lan', 'ipv6']
        self.b['assets'][0]['os_version'] = 'Windows 11, invented sample'
        self.b['assets'][1]['architecture'] = None
        curation, report = self.merge()
        # No shared tag: the union, reported as disputed. Shared tags: the intersection only.
        self.assertEqual(curation['coverage']['dns_domain'], ['no-dns', 'recursive-forwarder'])
        self.assertEqual(curation['coverage']['network'], ['flat-lan'])
        self.assertEqual(report['disputed_fields']['coverage'],
                         [{'axis': 'dns_domain', 'draft_a': ['no-dns'], 'draft_b': ['recursive-forwarder'],
                           'merged': ['no-dns', 'recursive-forwarder']}])
        self.assertIn('dns_domain', curation['note'])
        # Unequal asset facts become null (unknown); equal ones stay.
        self.assertEqual([(item['os_version'], item['architecture'], item['vendor']) for item in curation['assets']],
                         [(None, 'x86_64', 'Invented sample'), ('Windows 10, invented sample', None, 'Invented sample')])
        self.assertEqual([(item['asset'], item['field']) for item in report['disputed_fields']['asset_facts']],
                         [('LABHOST01', 'os_version'), ('LABHOST02', 'architecture')])
        self.assertEqual((report['summary']['coverage_axes_disputed'], report['summary']['asset_facts_disputed']), (1, 2))

    def test_os_family_prefers_a_deliberate_change_from_the_template_default(self):
        # The draft template defaulted every asset to windows-client.
        self.b['assets'][0]['os_family'] = 'windows-server'
        curation, report = self.merge()
        self.assertEqual(curation['assets'][0]['os_family'], 'windows-server')
        self.assertEqual(report['disputed_fields']['asset_facts'],
                         [{'asset': 'LABHOST01', 'field': 'os_family', 'draft_a': 'windows-client',
                           'draft_b': 'windows-server', 'template_default': 'windows-client',
                           'merged': 'windows-server'}])
        # Swapped inputs: still the deliberate change, not draft A's untouched default.
        self.assertEqual(self.merge(self.b, self.a)[0]['assets'][0]['os_family'], 'windows-server')
        # Neither value is the default: draft A's.
        self.a['assets'][0]['os_family'] = 'linux'
        curation, report = self.merge()
        self.assertEqual(curation['assets'][0]['os_family'], 'linux')
        self.assertEqual(report['summary']['asset_facts_disputed'], 1)

    def test_attack_release_takes_the_newer_version(self):
        self.b['attack_release'] = 'v9'
        curation, report = self.merge()
        # Numeric, not lexical: v18 is newer than v9.
        self.assertEqual(curation['attack_release'], 'v18')
        self.assertEqual((report['disputed_fields']['attack_release'], report['field_decisions']['attack_release']),
                         ({'draft_a': 'v18', 'draft_b': 'v9', 'merged': 'v18'}, 'newer_draft'))
        self.b['attack_release'] = 'v18.1'
        self.assertEqual(self.merge()[0]['attack_release'], 'v18.1')

    def test_revoked_technique_ids_merge_under_their_canonical_replacement(self):
        self.a['steps'][0]['technique_id'] = 'T1070.001'
        self.b['steps'][0]['technique_id'] = 'T1685.005'
        curation, report = self.merge()
        self.assertEqual(curation['steps'][0]['technique_id'], 'T1685.005')
        self.assertEqual(report['steps'][0]['technique_written'], {'draft_a': 'T1070.001', 'draft_b': 'T1685.005'})
        # A renamed ID is only valid in the pinned release, so the merged release follows it.
        self.assertEqual((curation['attack_release'], report['field_decisions']['attack_release']),
                         ('v20', 'pinned_release_for_canonical_ids'))
        self.a['steps'][0]['technique_id'] = 'T1999.999'
        error = self.assertCode('unknown_technique', self.merge)
        self.assertEqual(error.field, 'draft_a.steps.technique_id')

    def test_locators_in_different_forms_resolve_to_original_lines(self):
        events = self.nxlog[0]['events'].values()
        line_of = {(entry['record_id'], entry['channel'].casefold(), entry['hostname']): entry['line']
                   for entry in events if entry['record_id'] is not None}
        sysmon = line_of[('5002', SYSMON.casefold(), NX_HOST)]
        security = line_of[('7001', 'security', NX_HOST)]
        a, b = proposal(NX_CURATION, 'draft A'), proposal(NX_CURATION, 'draft B')
        b['steps'][0]['support_sets'] = [[{'line': security}], [{'record_id': '5002'}]]
        curation, report = self.merge(a, b, sides=self.nxlog)
        self.assertEqual(curation['steps'][0]['support_sets'], [[{'line': line}] for line in sorted((sysmon, security))])
        self.assertEqual((report['steps'][0]['support_set_jaccard'], curation['excluded_locators']), (1.0, []))
        self.assertTrue(all(set(locator) == {'line'} for group in curation['lookalike_event_ids'] for locator in group))
        for locator, code in (({'line': 99999}, 'unresolved_locator'), ({'record_id': '424242'}, 'unresolved_locator'),
                              ({'record_id': '7001'}, 'ambiguous_locator'),
                              ({'record_id': '5002', 'channel': 'Security', 'hostname': NX_HOST},
                               'unresolved_locator')):
            with self.subTest(locator=locator):
                broken = copy.deepcopy(b)
                broken['steps'][0]['support_sets'] = [[locator]]
                error = self.assertCode(code, self.merge, a, broken, sides=self.nxlog)
                self.assertEqual(error.field, 'draft_b.steps.support_sets')
        # The line-form consensus imports through the real importer.
        output = self.root / 'merged-nx.json'
        locators, template = self.side_paths(self.nxlog, 'nx')
        consensus.merge(self.write('nx-a.json', a), self.write('nx-b.json', b), locators, template, output, now=NOW)
        _, outputs = otrf.build_case(NX_DATASET, NX_METADATA, otrf.load_field_map(), SALT, curation_path=output,
                                     coverage=load_json(COVERAGE))
        self.assertEqual(decode_json(outputs['evaluator/truth.json'])['attestation'], 'agent_consensus')

    def test_attackdata_curations_merge_by_asset_name(self):
        a, b = proposal(AUDIT_CURATION, 'draft A'), proposal(AUDIT_CURATION, 'draft B')
        curation, report = self.merge(a, b, fmt='attackdata', sides=self.audit)
        path_line = next(entry['line'] for entry in self.audit[0]['events'].values()
                         if entry['record_id'] == '104' and entry['record_type'] == 'PATH')
        self.assertEqual(curation['steps'][0]['asset'], {'asset_name': 'audit-host'})
        self.assertIn({'line': path_line}, curation['steps'][0]['support_sets'][0])
        self.assertIsNone(curation['clock_declaration'])
        # One asset and both drafts say yes to both techniques: chance agreement is 1, kappa undefined.
        self.assertEqual((report['kappa']['kappa'], report['kappa']['null_reason']), (None, 'chance_agreement_is_one'))
        del b['steps'][1]
        curation, report = self.merge(a, b, fmt='attackdata', sides=self.audit)
        self.assertEqual((len(curation['steps']), curation['excluded_locators']), (1, [{'line': 9}]))
        self.assertEqual(report['kappa']['kappa'], 0.0)
        # A disputed clock declaration takes the draft template's (null for this raw-epoch export).
        b['clock_declaration'] = {'offset_seconds': 0, 'uncertainty_seconds': 1}
        curation, report = self.merge(a, b, fmt='attackdata', sides=self.audit)
        self.assertIsNone(curation['clock_declaration'])
        self.assertEqual((report['disputed_fields']['clock_declaration']['basis'],
                          report['summary']['clock_declaration_disputed']), ('template_default', True))
        # Two different partitions are different cases: the only descriptive refusal left.
        a['partition_window'] = {'start_inclusive': '2026-01-01T00:00:00Z', 'end_exclusive': '2026-01-01T00:05:00Z'}
        b['partition_window'] = {'start_inclusive': '2026-01-01T00:00:00Z', 'end_exclusive': '2026-01-01T00:06:00Z'}
        error = self.assertCode('draft_conflict', self.merge, a, b, fmt='attackdata', sides=self.audit)
        self.assertEqual(error.field, 'curation.partition_window')

    def test_disputed_assessment_windows_take_the_template_default(self):
        # Regression: 21 real pairs were refused with draft_conflict on differing windows.
        template_windows = self.flat[1]['curation']['assessment_windows']
        self.b['assessment_windows'] = [{'start_inclusive': '2026-01-01T09:00:00Z',
                                         'end_exclusive': '2026-01-01T09:00:10Z'}]
        curation, report = self.merge()
        self.assertEqual(curation['assessment_windows'], template_windows)
        self.assertEqual(report['disputed_fields']['assessment_windows'],
                         {'draft_a': None, 'draft_b': self.b['assessment_windows'], 'merged': template_windows,
                          'basis': 'template_default'})
        self.assertTrue(report['summary']['assessment_windows_disputed'])
        self.assertIn('assessment_windows', curation['note'])
        # A template without windows leaves them unset: one whole-bundle window at import.
        locators, template = copy.deepcopy(self.flat)
        del template['curation']['assessment_windows']
        curation, _ = self.merge(sides=(locators, template))
        self.assertNotIn('assessment_windows', curation)
        # The same windows written differently are equal instants, not a dispute.
        self.a['assessment_windows'] = [{'start_inclusive': '2026-01-01T09:00:00+00:00',
                                         'end_exclusive': '2026-01-01T09:00:10.000Z'}]
        curation, report = self.merge()
        self.assertEqual((curation['assessment_windows'], report['disputed_fields']['assessment_windows']),
                         (self.a['assessment_windows'], None))

    def test_locator_maps_without_record_keys_are_line_only(self):
        # Regression: older flat exports' locators.json entries lack record_id/channel/hostname keys.
        locators, template = copy.deepcopy(self.flat)
        for entry in locators['events'].values():
            for key in ('record_id', 'channel', 'hostname'):
                entry.pop(key, None)
        curation, _ = self.merge(sides=(locators, template))
        self.assertEqual(curation['steps'][0]['support_sets'], [[{'line': 3}], [{'line': 4}]])
        self.b['steps'][0]['support_sets'] = [[{'record_id': '3'}]]
        self.assertCode('unresolved_locator', self.merge, sides=(locators, template))

    # -------------------------------------------------------------- refusals
    def test_mismatched_dataset_digests_are_refused(self):
        locators, template = self.side_paths()
        a = self.write('a.json', self.a)
        for key in ('dataset_sha256', 'metadata_sha256'):
            with self.subTest(key=key):
                b = copy.deepcopy(self.b)
                b[key] = 'f' * 64
                output = self.root / ('merged-' + key + '.json')
                code, stdout, stderr = run_cli('merge', '--draft-a', a, '--draft-b', self.write('b-' + key + '.json', b),
                                               '--locators', locators, '--template', template, '--output', output)
                self.assertEqual((code, stdout, stderr.strip()), (2, '', 'error: draft_dataset_mismatch: draft_b.' + key))
                self.assertFalse(output.exists())
        nx_locators, nx_template = self.side_paths(self.nxlog, 'nx')
        b = self.write('b.json', self.b)
        output = self.root / 'merged.json'
        self.assertCode('locators_dataset_mismatch', consensus.merge, a, b, nx_locators, template, output)
        self.assertCode('template_dataset_mismatch', consensus.merge, a, b, locators, nx_template, output)
        self.assertFalse(output.exists())

    def test_drafts_must_be_two_distinct_unreviewed_proposals(self):
        locators, template = self.side_paths()
        a = self.write('a.json', self.a)
        output = self.root / 'merged.json'
        self.assertCode('identical_drafts', consensus.merge, a, a, locators, template, output)
        self.assertCode('draft_not_proposal', consensus.merge, a, CURATION, locators, template, output)
        attackdata = self.write('ad.json', proposal(AUDIT_CURATION, 'draft B'))
        self.assertCode('format_mismatch', consensus.merge, a, attackdata, locators, template, output)
        broken = copy.deepcopy(self.b)
        broken['steps'][0]['observability'] = 'probably'
        error = self.assertCode('invalid_choice', consensus.merge, a, self.write('b.json', broken), locators,
                                template, output)
        self.assertEqual(error.field, 'draft_b.steps.observability')
        self.assertFalse(output.exists())

    # ------------------------------------------------------- output and import
    def test_cli_writes_new_validated_files_only(self):
        a, b = self.write('a.json', self.a), self.write('b.json', self.b)
        locators, template = self.side_paths()
        common = ('merge', '--draft-a', a, '--draft-b', b, '--locators', locators, '--template', template)
        output, report = self.root / 'merged.json', self.root / 'report.json'
        code, stdout, stderr = run_cli(*common, '--output', output, '--report', report)
        self.assertEqual((code, stderr), (0, ''))
        summary = decode_json(stdout)
        self.assertEqual(summary['attestation'], 'agent_consensus')
        self.assertIn('no human reviewed', summary['warning'])
        document = load_json(report)
        self.assertEqual(summary['curation_sha256'], digest_bytes(output.read_bytes()))
        self.assertEqual(document['curation_sha256'], summary['curation_sha256'])
        self.assertEqual(document['drafts'], {'a': {'sha256': digest_bytes(a.read_bytes())},
                                              'b': {'sha256': digest_bytes(b.read_bytes())}})
        self.assertEqual(document['inputs'], {'locators_sha256': digest_bytes(locators.read_bytes()),
                                              'template_sha256': digest_bytes(template.read_bytes())})
        for args, message in (
                (('--output', output), 'error: output_exists: output'),
                (('--output', self.root / 'other.json', '--report', report), 'error: output_exists: report'),
                (('--output', self.root / 'same.json', '--report', self.root / 'same.json'),
                 'error: conflicting_arguments: report'),
                (('--output', HERE / 'consensus-never-written.json'), 'error: output_in_source_tree: output'),
                (('--output', FRAMEWORK / 'consensus-never-written.json'), 'error: output_in_source_tree: output'),
                (('--output', self.root / 'missing' / 'x.json'), 'error: invalid_directory: output')):
            with self.subTest(args=args):
                code, stdout, stderr = run_cli(*common, *args)
                self.assertEqual((code, stdout, stderr.strip()), (2, '', message))
        self.assertFalse((self.root / 'other.json').exists() or (self.root / 'same.json').exists())
        self.assertFalse((HERE / 'consensus-never-written.json').exists()
                         or (FRAMEWORK / 'consensus-never-written.json').exists())

    def test_consensus_curation_imports_as_its_own_attestation(self):
        self.assertIn('agent_consensus', TRUTH_ATTESTATIONS)
        self.b['steps'].append(step('step-2', 'T1082', [[5]]))
        self.b['controls'][0]['expected_disposition'] = 'insufficient'
        output = self.root / 'merged.json'
        locators, template = self.side_paths()
        consensus.merge(self.write('a.json', self.a), self.write('b.json', self.b), locators, template, output, now=NOW)
        _, outputs = otrf.build_case(DATASET, METADATA, otrf.load_field_map(), SALT, curation_path=output,
                                     coverage=load_json(COVERAGE))
        truth = decode_json(outputs['evaluator/truth.json'])
        bundle = decode_json(outputs['public/evidence.json'])
        validate_truth(truth, bundle)
        self.assertEqual(truth['attestation'], 'agent_consensus')
        line_of = {event_id: entry['line'] for event_id, entry in
                   decode_json(outputs['evaluator/locators.json'])['events'].items()}
        self.assertEqual([line_of[event_id] for event_id in truth['disputed_event_ids']], [5])
        asset_of = {question['question_id']: question['asset_id'] for question in bundle['assessment_questions']}
        step_asset = truth['steps'][0]['asset_id']
        # LABHOST01 keeps its agreed step; the drafts disagreed on LABHOST02's control, so it is undecided.
        self.assertEqual({asset_of[key] == step_asset: label for key, label in truth['assessment_labels'].items()},
                         {True: 1, False: None})
        report = decode_json(outputs['evaluator/import-report.json'])
        self.assertEqual((report['curation']['attestation'], report['curation']['curated_by']),
                         ('agent_consensus', 'agent-consensus'))
        limitations = decode_json(outputs['scenario.json'])['sophistication']['emulation_limitations']
        self.assertIn(otrf.CONSENSUS_LIMITATION, limitations)
        # Stripping the hint must never turn the consensus into a human attestation.
        stripped = decode_json(output.read_bytes())
        del stripped['attestation_hint']
        with self.assertRaises(BenchmarkError) as caught:
            otrf.load_curation(self.write('stripped.json', stripped))
        self.assertIn(caught.exception.code, ('consensus_hint_missing', 'excluded_without_consensus'))
        del stripped['excluded_locators']
        self.assertCode('consensus_hint_missing', otrf.load_curation, self.write('stripped-all.json', stripped))

    def test_attackdata_consensus_output_validates_through_its_importer(self):
        a, b = proposal(AUDIT_CURATION, 'draft A'), proposal(AUDIT_CURATION, 'draft B')
        locators, template = self.side_paths(self.audit, 'audit')
        output = self.root / 'merged-ad.json'
        sha, report = consensus.merge(self.write('ad-a.json', a), self.write('ad-b.json', b), locators, template,
                                      output)
        loaded, data = ad.load_curation(output)
        self.assertEqual((loaded['attestation'], digest_bytes(data), report['format']),
                         ('agent_consensus', sha, 'attackdata'))


if __name__ == '__main__':
    unittest.main()
