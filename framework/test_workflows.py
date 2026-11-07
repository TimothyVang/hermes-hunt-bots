"""Local CLI behavior tests; no agent, provider, browser, or network calls."""
from contextlib import closing
import copy
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest


BOT = Path(__file__).resolve().with_name('bot.py')


def step(key, role='researcher', depends_on=None):
    return {
        'key': key,
        'title': 'Task ' + key,
        'role': role,
        'scope': 'Step scope ' + key,
        'acceptance': 'Step acceptance ' + key,
        'depends_on': [] if depends_on is None else depends_on,
    }


def template():
    return {
        'version': 1,
        'name': 'local-example',
        'description': 'Benign local workflow fixture',
        'tasks': [step('research'), step('review', 'reviewer', ['research'])],
    }


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.workspace = self.directory / 'workspace'
        self.call('init')

    def call(self, *args, success=True):
        result = subprocess.run(
            [sys.executable, str(BOT), '-w', str(self.workspace), *map(str, args)],
            cwd=str(self.directory), capture_output=True, text=True,
            encoding='utf-8', errors='replace', timeout=30,
        )
        self.assertEqual(result.returncode == 0, success,
                         'stdout: ' + result.stdout + '\nstderr: ' + result.stderr)
        return result

    def rows(self, sql, args=()):
        with closing(sqlite3.connect(self.workspace / 'workflow.sqlite3')) as db:
            return db.execute(sql, args).fetchall()

    def snapshot(self):
        with closing(sqlite3.connect(self.workspace / 'workflow.sqlite3')) as db:
            return tuple(db.iterdump())

    def write_template(self, data, name='custom workflow.json'):
        path = self.directory / name
        path.write_text(json.dumps(data), encoding='utf-8')
        return path

    def create(self, source='research-review', title='Example workflow'):
        result = self.call('workflow', 'create', source, '--title', title,
                           '--scope', 'Operator source boundary',
                           '--acceptance', 'Operator expected outcome')
        match = re.search(r'^Created workflow (\d+):', result.stdout, re.MULTILINE)
        self.assertIsNotNone(match, result.stdout)
        mapping = {key: int(task_id) for key, task_id in
                   re.findall(r'^([^\s:]+): (\d+)\s*$', result.stdout, re.MULTILINE)}
        self.assertTrue(mapping, result.stdout)
        return int(match.group(1)), mapping

    def ready_ids(self):
        result = self.call('ready')
        return {int(value) for value in
                re.findall(r'^(\d+) \[pending\]', result.stdout, re.MULTILINE)}

    def decision(self, command, task_id, note='Local fixture decision'):
        return self.call(command, task_id, '--by', 'test human', '--note', note)

    def status(self, task_id):
        return self.rows('SELECT status FROM tasks WHERE id=?', (task_id,))[0][0]

    def test_catalog_and_show_need_no_workspace_and_do_not_create_one(self):
        self.workspace = self.directory / 'not-initialized'
        result = self.call('workflow', 'list')
        self.assertIn('threat-hunt', result.stdout)
        for name in ('research-review', 'build-review', 'threat-hunt'):
            with self.subTest(template=name):
                self.call('workflow', 'show', name)
        self.assertFalse(self.workspace.exists())

    def test_forward_dependencies_and_relative_filepath(self):
        data = template()
        data['tasks'] = [step('finish', 'coordinator', ['left', 'right']),
                         step('right', 'reviewer', ['root']),
                         step('left', 'builder', ['root']), step('root')]
        path = self.write_template(data)
        workflow_id, mapping = self.create(path.name)
        self.assertLess(mapping['root'], mapping['left'])
        self.assertLess(mapping['root'], mapping['right'])
        self.assertLess(mapping['left'], mapping['finish'])
        self.assertLess(mapping['right'], mapping['finish'])
        self.assertEqual(self.ready_ids(), {mapping['root']})
        self.call('start', mapping['root'])
        self.decision('submit', mapping['root'])
        self.decision('approve', mapping['root'])
        self.assertEqual(self.ready_ids(), {mapping['left'], mapping['right']})
        self.assertIn('blockers:', self.call('workflow', 'status', workflow_id).stdout)

    def test_invalid_templates_never_mutate_database(self):
        cases = []
        for label, field, value in [
            ('unsupported version', 'version', 2),
            ('boolean version', 'version', True),
            ('string version', 'version', '1'),
            ('empty name', 'name', '  '),
            ('nontext description', 'description', 17),
            ('empty tasks', 'tasks', []),
            ('wrong tasks type', 'tasks', {}),
            ('unknown executable field', 'command', 'do not execute'),
        ]:
            data = template()
            data[field] = value
            cases.append((label, json.dumps(data)))
        for label, field, value in [
            ('unknown task field', 'command', 'do not execute'),
            ('invalid role', 'role', 'administrator'),
            ('empty title', 'title', ''),
            ('empty scope', 'scope', ' '),
            ('empty acceptance', 'acceptance', '\n'),
            ('nontext key', 'key', 42),
            ('wrong dependency type', 'depends_on', 'research'),
            ('nontext dependency', 'depends_on', [42]),
            ('unknown dependency', 'depends_on', ['missing']),
            ('duplicate dependency', 'depends_on', ['research', 'research']),
            ('self dependency', 'depends_on', ['review']),
        ]:
            data = template()
            data['tasks'][1][field] = value
            cases.append((label, json.dumps(data)))
        for field in ('version', 'name', 'description', 'tasks'):
            data = template()
            del data[field]
            cases.append(('missing ' + field, json.dumps(data)))
        for field in ('key', 'title', 'role', 'scope', 'acceptance', 'depends_on'):
            data = template()
            del data['tasks'][0][field]
            cases.append(('missing task ' + field, json.dumps(data)))
        data = template()
        data['tasks'][0]['depends_on'] = ['review']
        cases.append(('cycle', json.dumps(data)))
        data = template()
        data['tasks'].append(copy.deepcopy(data['tasks'][0]))
        cases.append(('duplicate task key', json.dumps(data)))
        raw = json.dumps(template())
        cases.extend([
            ('duplicate root property', raw.replace('"version": 1', '"version": 1, "version": 1', 1)),
            ('duplicate task property', raw.replace('"key": "research"', '"key": "research", "key": "research"', 1)),
            ('non-object document', '[]'),
            ('non-object task', raw.replace(json.dumps(step('research')), 'null', 1)),
            ('malformed JSON', '{'),
        ])
        # Repeat after a successful creation: validation must not mutate either
        # a pre-workflow ledger or one with existing workflow records.
        for existing_workflow in (False, True):
            if existing_workflow:
                self.create()
            before = self.snapshot()
            for label, content in cases:
                with self.subTest(case=label, existing_workflow=existing_workflow):
                    path = self.directory / 'invalid.json'
                    path.write_text(content, encoding='utf-8')
                    self.call('workflow', 'show', path, success=False)
                    self.call('workflow', 'create', path, '--title', 'Invalid',
                              '--scope', 'Benign', '--acceptance', 'Reject', success=False)
                    self.assertEqual(self.snapshot(), before)

    def test_bad_operator_context_and_missing_template_leave_ledger_unchanged(self):
        before = self.snapshot()
        for title, scope, acceptance in [('', 'Scope', 'Accept'),
                                          ('Title', ' ', 'Accept'),
                                          ('Title', 'Scope', '\n')]:
            self.call('workflow', 'create', 'research-review', '--title', title,
                      '--scope', scope, '--acceptance', acceptance, success=False)
            self.assertEqual(self.snapshot(), before)
        self.call('workflow', 'create', './missing.json', '--title', 'Example',
                  '--scope', 'Scope', '--acceptance', 'Accept', success=False)
        self.call('workflow', 'status', '99999', success=False)
        self.assertEqual(self.snapshot(), before)

    def test_existing_manual_tasks_history_and_artifacts_are_preserved(self):
        self.call('add', '--title', 'Existing manual task', '--role', 'researcher',
                  '--scope', 'Keep the manual path', '--acceptance', 'Preserve this record')
        self.call('start', 1)
        artifact = self.directory / 'manual evidence.txt'
        artifact.write_text('Benign fixture evidence', encoding='utf-8')
        self.call('artifact', 1, '--path', artifact, '--description', 'Manual evidence')
        self.decision('submit', 1, 'Existing manual handoff')
        before = {name: self.rows('SELECT * FROM ' + name)
                  for name in ('tasks', 'dependencies', 'events', 'artifacts')}
        tables = self.rows("SELECT name FROM sqlite_master WHERE type='table'")
        self.assertNotIn(('workflow_runs',), tables)
        _, mapping = self.create()
        self.assertNotIn(1, mapping.values())
        for name, rows in before.items():
            with self.subTest(table=name):
                for row in rows:
                    self.assertIn(row, self.rows('SELECT * FROM ' + name))
        self.assertIn('Existing manual handoff', self.call('show', 1).stdout)
        self.decision('approve', 1)
        self.assertEqual(self.status(1), 'done')
        self.call('add', '--title', 'Manual dependent', '--role', 'reviewer',
                  '--scope', 'Review manual work', '--acceptance', 'Actual findings',
                  '--depends-on', 1)
        self.assertIn('Manual dependent', self.call('ready').stdout)

    def test_storage_failure_rolls_back_group_tasks_dependencies_and_schema(self):
        self.call('add', '--title', 'Keep manual work', '--role', 'researcher',
                  '--scope', 'Existing benign task', '--acceptance', 'Preserved unchanged')
        self.call('start', 1)
        self.decision('submit', 1, 'Manual handoff survives workflow storage failure')
        # A real SQLite storage constraint forces failure after earlier member
        # tasks have been inserted; a partial workflow must not survive the transaction.
        with closing(sqlite3.connect(self.workspace / 'workflow.sqlite3')) as db, db:
            db.execute("""CREATE TRIGGER reject_review BEFORE INSERT ON tasks
                          WHEN NEW.role = 'reviewer' BEGIN
                          SELECT RAISE(ABORT, 'fixture storage constraint'); END""")
        before = self.snapshot()
        self.call('workflow', 'create', 'threat-hunt', '--title', 'Atomic example',
                  '--scope', 'Benign', '--acceptance', 'All or nothing', success=False)
        self.assertEqual(self.snapshot(), before)

    def test_threat_hunt_branching_join_review_and_handoffs(self):
        workflow_id, mapping = self.create('threat-hunt')
        keys = {'scope', 'evidence', 'hypotheses', 'analysis', 'review', 'handoff'}
        self.assertEqual(set(mapping), keys)

        scope, evidence, hypotheses = (mapping[key] for key in
                                       ('scope', 'evidence', 'hypotheses'))
        self.call('start', scope)
        self.decision('submit', scope, 'Approved sources and bounded time range recorded')
        self.assertEqual(self.status(scope), 'review')
        self.assertEqual(self.ready_ids(), set())
        self.call('start', evidence, success=False)
        self.call('start', hypotheses, success=False)
        self.decision('approve', scope, 'Scope and supplied-source authority checked')
        self.assertEqual(self.ready_ids(), {evidence, hypotheses})

        self.call('start', evidence)
        self.decision('submit', evidence, 'EVIDENCE HANDOFF: record E-1 at source line 4')
        self.decision('approve', evidence, 'Evidence locator checked')
        self.assertEqual(self.ready_ids(), {hypotheses})
        analysis = mapping['analysis']
        self.call('start', analysis, success=False)

        self.call('start', hypotheses)
        self.decision('submit', hypotheses, 'HYPOTHESIS HANDOFF: benign alternative H-1')
        self.decision('approve', hypotheses, 'Competing explanation checked')
        self.assertEqual(self.ready_ids(), {analysis})
        self.call('start', analysis)
        analysis_prompt = self.call('prompt', analysis).stdout
        self.assertIn('EVIDENCE HANDOFF: record E-1', analysis_prompt)
        self.assertIn('HYPOTHESIS HANDOFF: benign alternative H-1', analysis_prompt)
        self.decision('submit', analysis,
                      'ANALYSIS HANDOFF: E-1 is ambiguous; H-1 remains plausible')
        self.decision('approve', analysis, 'Analysis and uncertainty checked')

        review, handoff = mapping['review'], mapping['handoff']
        self.assertEqual(self.ready_ids(), {review})
        self.call('start', review)
        self.decision('submit', review, 'Review handoff: E-1 locator checked')
        self.assertEqual(self.status(review), 'review')
        self.assertEqual(self.ready_ids(), set())
        self.decision('reject', review, 'Resolve the unaddressed telemetry gap')
        self.assertEqual(self.ready_ids(), set())
        self.call('start', handoff, success=False)
        self.decision('submit', review, 'Revised review: telemetry gap disposition recorded')
        self.decision('approve', review, 'Review findings and disposition checked')
        self.assertEqual(self.ready_ids(), {handoff})

        self.call('start', handoff)
        handoff_prompt = self.call('prompt', handoff).stdout
        self.assertIn('EVIDENCE HANDOFF: record E-1', handoff_prompt)
        self.assertIn('HYPOTHESIS HANDOFF: benign alternative H-1', handoff_prompt)
        self.assertIn('ANALYSIS HANDOFF: E-1 is ambiguous', handoff_prompt)
        self.assertIn('Revised review: telemetry gap disposition recorded', handoff_prompt)
        self.decision('submit', handoff, 'Final bounded disposition awaits human decision')
        self.decision('approve', handoff, 'Final handoff checked')
        self.assertEqual(self.call('workflow', 'status', workflow_id).stdout.count('[done]'), 6)

    def test_every_role_requires_review_and_human_approval(self):
        workflow_id, mapping = self.create('build-review')
        ordered = [mapping[key] for key in ('requirements', 'build', 'review', 'handoff')]
        for index, task_id in enumerate(ordered):
            self.assertEqual(self.ready_ids(), {task_id})
            before = self.snapshot()
            self.call('ready')
            self.call('workflow', 'status', workflow_id)
            self.assertEqual(self.snapshot(), before)
            for later in ordered[index + 1:]:
                self.call('start', later, success=False)
                self.assertEqual(self.status(later), 'pending')
            self.call('approve', task_id, '--by', 'test human', '--note', 'Too early', success=False)
            self.call('start', task_id)
            self.assertEqual(self.ready_ids(), set())
            self.call('approve', task_id, '--by', 'test human', '--note', 'Still too early', success=False)
            self.decision('submit', task_id, 'First fixture handoff')
            self.assertEqual(self.status(task_id), 'review')
            self.assertEqual(self.ready_ids(), set())
            if index + 1 < len(ordered):
                self.call('start', ordered[index + 1], success=False)
            self.decision('reject', task_id, 'Fixture needs a more precise source locator')
            self.assertEqual(self.status(task_id), 'active')
            self.assertEqual(self.ready_ids(), set())
            self.decision('submit', task_id, 'Revised fixture with source locator')
            self.decision('approve', task_id, 'Fixture handoff checked by the test operator')
            self.assertEqual(self.status(task_id), 'done')
        self.assertEqual(self.ready_ids(), set())
        board = self.call('workflow', 'status', workflow_id).stdout
        self.assertEqual(board.count('[done]'), 4)
        self.assertFalse((self.workspace / 'runs').exists())

    def test_prompt_includes_predecessor_handoff_not_artifact_contents(self):
        _, mapping = self.create()
        research, review = mapping['research'], mapping['review']
        artifact = self.directory / 'approved evidence.txt'
        artifact.write_text('FILE_CONTENT_MUST_NOT_BE_EMBEDDED', encoding='utf-8')
        self.call('start', research)
        self.call('artifact', research, '--path', artifact, '--description', 'Supplied evidence reference')
        self.decision('submit', research, 'HANDOFF: source line 3 establishes the bounded finding')
        self.decision('approve', research, 'DECISION: checked source line 3')
        self.call('start', review)
        before = self.snapshot()
        prompt = self.call('prompt', review).stdout
        self.assertIn('HANDOFF: source line 3 establishes the bounded finding', prompt)
        self.assertIn('DECISION: checked source line 3', prompt)
        self.assertIn(str(artifact.resolve()), prompt)
        self.assertIn('Supplied evidence reference', prompt)
        self.assertIn('untrusted', prompt.lower())
        self.assertIn('Operator source boundary', prompt)
        self.assertIn('Operator expected outcome', prompt)
        self.assertNotIn('FILE_CONTENT_MUST_NOT_BE_EMBEDDED', prompt)
        self.assertEqual(self.snapshot(), before)

    def test_template_text_is_literal_not_interpolated_or_executed(self):
        marker = self.directory / 'must-not-exist'
        literal = '${HOME} {{operator}} $(touch must-not-exist)'
        data = template()
        data['tasks'][0]['scope'] = literal
        _, mapping = self.create(self.write_template(data))
        self.assertIn(literal, self.call('prompt', mapping['research']).stdout)
        self.assertFalse(marker.exists())
        self.assertFalse((self.workspace / 'runs').exists())


if __name__ == '__main__':
    unittest.main()
