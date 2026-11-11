"""recount_usage rewrites a rounds file's usage from each round's status, rejected attempts included."""
import io
import json
import tempfile
import unittest
from pathlib import Path

import recount_usage
from test_tool_loops import rejection, result, usage


def status(results, rejections=()):
    return {'stage': 'completed', 'step_id': None, 'execution_id': None, 'results': list(results),
            'handoff_rejections': list(rejections)}


class RecountTest(unittest.TestCase):
    def run_file(self, items, statuses):
        """Run recount_usage over these hunts with a fake CLI answering status queries from statuses."""
        calls = []

        def fake_tcli(*args, **_):
            calls.append(args)
            if args[1] not in statuses:
                return 1, '', 'workflow not found'
            return 0, json.dumps(statuses[args[1]]), ''

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'k3.jsonl'
            original = ''.join(json.dumps(item) + '\n' for item in items)
            path.write_text(original, encoding='utf-8')
            out = io.StringIO()
            code = recount_usage.run(path, tcli=fake_tcli, out=out)
            self.assertEqual(path.read_text(encoding='utf-8'), original)
            fixed = [json.loads(line) for line in (Path(tmp) / 'k3.recounted.jsonl').read_text(encoding='utf-8').splitlines()]
        return code, fixed, out.getvalue(), calls

    def test_a_retried_round_is_recounted_and_the_original_is_untouched(self):
        old = {'total_tokens': 400, 'steps_without_usage': 0}
        items = [{'case': 'team-med-011', 'workflow': 'k3-011', 'completed': True, 'usage': old},
                 {'case': 'team-med-012', 'workflow': 'k3-012', 'completed': True, 'usage': {'total_tokens': 100}}]
        statuses = {
            'k3-011:round:001': status([result('a:0', 'sc', usage=usage(100, 1000)),
                                        result('a:1:retry', 'ev', usage=usage(300, 3000))],
                                       [rejection('evidence', 'retried', result('a:1', 'bad', usage=usage(200, 2000)))]),
            'k3-012:round:001': status([result('b:0', 'sc', usage=usage(100, 1000))])}
        code, fixed, printed, calls = self.run_file(items, statuses)
        self.assertEqual(code, 0)
        self.assertEqual(calls, [('status', 'k3-011:round:001'), ('status', 'k3-012:round:001')])
        self.assertEqual((fixed[0]['usage']['total_tokens'], fixed[0]['usage']['retried_attempts']), (600, 1))
        self.assertEqual(fixed[0]['case'], 'team-med-011')
        self.assertEqual(fixed[1]['usage']['total_tokens'], 100)
        self.assertIn('1: team-med-011 k3-011 total_tokens 400 -> 600 (retried attempts 1)', printed)
        self.assertIn('2: team-med-012 k3-012 total_tokens 100 -> 100 (retried attempts 0)', printed)

    def test_a_round_that_cannot_be_recounted_loses_its_old_usage(self):
        items = [{'case': 'team-med-013', 'workflow': 'gone', 'usage': {'total_tokens': 400}},
                 {'case': 'team-med-014', 'workflow': 'k3-014', 'round': 2, 'usage': {'total_tokens': 9}},
                 {'case': 'team-med-015'}]
        statuses = {'k3-014:round:002': status([result('c:0', 'sc')])}
        code, fixed, printed, calls = self.run_file(items, statuses)
        self.assertEqual(code, 1)
        self.assertEqual(calls, [('status', 'gone:round:001'), ('status', 'k3-014:round:002')])
        self.assertNotIn('usage', fixed[0])
        self.assertIn('workflow not found', fixed[0]['usage_recount_error'])
        self.assertEqual(fixed[1]['usage_recount_error'], 'status records no usage')
        self.assertEqual(fixed[2], {'case': 'team-med-015'})
        self.assertIn('[no workflow; copied unchanged]', printed)


if __name__ == '__main__':
    unittest.main()
