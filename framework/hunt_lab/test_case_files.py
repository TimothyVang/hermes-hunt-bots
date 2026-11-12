"""hunt_lab.case_files: which case folders and evidence files the container lab loads.

Run from framework/: python -B -m unittest hunt_lab.test_case_files
"""
import json
from pathlib import Path
import tempfile
import unittest

from hunt_lab import case_files

FIXTURE = Path(case_files.__file__).parent / 'fixtures' / 'dns-lab-001'


class EvidenceFileTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='hermes-case-files-test-')
        self.addCleanup(temp.cleanup)
        self.evidence = Path(temp.name).resolve()
        for name in case_files.EVIDENCE_FILES:
            (self.evidence / name).write_bytes((FIXTURE / name).read_bytes())
        self.case = json.loads((FIXTURE / 'case.json').read_text(encoding='utf-8'))

    def write_case(self, **fields):
        (self.evidence / 'case.json').write_text(json.dumps(dict(self.case, **fields)), encoding='utf-8')

    def names(self):
        return {name for name, _ in case_files.evidence_files(self.evidence)}

    def test_only_allowlisted_evidence_is_loaded_and_the_pcap_is_required(self):
        (self.evidence / 'truth.json').write_text('{"facts": []}\n', encoding='utf-8')
        (self.evidence / 'intel.jsonl').write_text('{"indicator": {"type": "ip", "value": "198.51.100.7"}}\n',
                                                    encoding='utf-8')
        self.assertEqual(self.names(), {'events.jsonl', 'traffic.pcap', 'case.json', 'intel.jsonl'})
        (self.evidence / 'traffic.pcap').unlink()
        with self.assertRaises(FileNotFoundError):
            case_files.evidence_files(self.evidence)

    def test_case_without_capture_is_accepted_without_a_pcap(self):
        (self.evidence / 'traffic.pcap').unlink()
        self.write_case(network_capture='none')
        self.assertEqual(self.names(), {'events.jsonl', 'case.json'})
        self.assertEqual(case_files.case_metadata(self.evidence / 'case.json')['network_capture'], 'none')

    def test_case_saying_none_but_shipping_a_pcap_is_refused(self):
        self.write_case(network_capture='none')
        with self.assertRaisesRegex(case_files.CaseError, 'traffic.pcap is present'):
            case_files.evidence_files(self.evidence)

    def test_any_other_network_capture_value_is_refused(self):
        for value in ('pcap', 'None', '', None, False, ['none']):
            with self.subTest(value=value):
                self.write_case(network_capture=value)
                with self.assertRaisesRegex(case_files.CaseError, 'network_capture'):
                    case_files.case_metadata(self.evidence / 'case.json')
                with self.assertRaisesRegex(case_files.CaseError, 'network_capture'):
                    case_files.evidence_files(self.evidence)

    def test_data_origin_is_absent_or_a_known_origin_and_nothing_else(self):
        for value in ('public-dataset', 'work-export'):
            self.write_case(data_origin=value)
            self.assertEqual(case_files.case_metadata(self.evidence / 'case.json')['data_origin'], value)
        for value in ('synthetic', 'customer', '', None, ['public-dataset']):
            with self.subTest(value=value):
                self.write_case(data_origin=value)
                with self.assertRaisesRegex(case_files.CaseError, 'data_origin'):
                    case_files.case_metadata(self.evidence / 'case.json')

    def test_a_work_connected_case_is_never_loaded_into_the_container_lab(self):
        self.write_case(data_origin='work-connected')
        for check in (lambda: case_files.case_metadata(self.evidence / 'case.json'),
                      lambda: case_files.evidence_files(self.evidence)):
            with self.assertRaisesRegex(case_files.CaseError, 'never loaded into the container lab'):
                check()

    def test_case_id_and_time_range_are_checked(self):
        for fields in ({'case_id': 'Bad_Case'}, {'time_range_utc': {'start_inclusive': '2026-03-03T00:00:00Z',
                                                                     'end_exclusive': '2026-03-02T00:00:00Z'}}):
            with self.subTest(fields=fields):
                self.write_case(**fields)
                with self.assertRaises(case_files.CaseError):
                    case_files.case_metadata(self.evidence / 'case.json')

    def test_accepted_origins_are_the_hunt_origins(self):
        from hermes_temporal.contracts import DATA_ORIGINS
        self.assertEqual(case_files.DATA_ORIGINS, tuple(DATA_ORIGINS))

    def test_state_inside_the_source_workspace_is_refused(self):
        with self.assertRaisesRegex(case_files.CaseError, 'outside the source workspace'):
            case_files.state_location(str(case_files.SOURCE_ROOT / 'hunt-lab-container'))


if __name__ == '__main__':
    unittest.main()
