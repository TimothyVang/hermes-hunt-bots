"""Real ledger/SQLite/LangGraph subprocess tests; no provider or agent calls."""
from contextlib import closing
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
BOT = HERE / 'bot.py'
ORCHESTRATE = HERE / 'orchestrate.py'


def has_graph_runtime():
    if sys.version_info < (3, 10):
        return False
    try:
        return all(importlib.util.find_spec(name) is not None for name in
                   ('langgraph.graph', 'langgraph.checkpoint.sqlite', 'langsmith'))
    except ModuleNotFoundError:
        return False


class WorkspaceCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.workspace = self.directory / 'workspace'
        self.bot('init')

    def command(self, executable, *args, success=True, no_site=False):
        command = [sys.executable]
        if no_site:
            command.append('-S')
        result = subprocess.run(
            [*command, str(executable), '-w', str(self.workspace), *map(str, args)],
            cwd=str(self.directory), capture_output=True, text=True, encoding='utf-8',
            errors='replace', timeout=60,
        )
        self.assertEqual(result.returncode == 0, success, result.stdout + '\n' + result.stderr)
        return result

    def bot(self, *args, success=True):
        return self.command(BOT, *args, success=success)

    def graph(self, action='run', workflow=1, success=True):
        result = self.command(ORCHESTRATE, action, workflow, success=success)
        return json.loads(result.stdout) if success else result

    def create(self, template='research-review'):
        self.bot('workflow', 'create', template, '--title', 'Local workflow fixture',
                 '--scope', 'Benign local evidence only', '--acceptance', 'Human ledger decision')

    def decision(self, action, task_id):
        self.bot(action, task_id, '--by', 'fixture human', '--note', 'Local test decision, not real research evidence')

    def finish(self, task_id):
        self.bot('start', task_id)
        self.decision('submit', task_id)
        self.decision('approve', task_id)

    def dump(self, name='workflow.sqlite3'):
        with closing(sqlite3.connect(self.workspace / name)) as db:
            return tuple(db.iterdump())

    def checkpoint_count(self):
        with closing(sqlite3.connect(self.workspace / 'langgraph.sqlite3')) as db:
            return db.execute('SELECT count(*) FROM checkpoints').fetchone()[0]


class OptionalContextTests(WorkspaceCase):
    def test_old_workspace_and_missing_groups_do_not_create_checkpoint(self):
        before = self.dump()
        result = self.graph(success=False)
        self.assertIn('no workflow groups', result.stderr)
        self.assertEqual(before, self.dump())
        self.assertFalse((self.workspace / 'langgraph.sqlite3').exists())
        self.create()
        result = self.graph(workflow=999, success=False)
        self.assertIn('not found', result.stderr)
        self.assertFalse((self.workspace / 'langgraph.sqlite3').exists())

    def test_missing_workspace_fails_without_initializing(self):
        self.workspace = self.directory / 'absent'
        result = self.graph(success=False)
        self.assertIn('not initialized', result.stderr)
        self.assertFalse(self.workspace.exists())

    def test_missing_dependencies_keep_manual_ledger_usable(self):
        self.create()
        result = self.command(ORCHESTRATE, 'run', 1, success=False, no_site=True)
        self.assertTrue('optional dependencies unavailable' in result.stderr
                        or 'requires Python 3.10' in result.stderr, result.stderr)
        self.assertFalse((self.workspace / 'langgraph.sqlite3').exists())
        self.bot('start', 1)
        self.decision('submit', 1)
        self.decision('approve', 1)
        self.assertIn('[done]', self.bot('workflow', 'status', 1).stdout)


@unittest.skipUnless(has_graph_runtime(), 'install optional orchestration dependencies with Python 3.10+')
class DurableGraphTests(WorkspaceCase):
    def test_separate_process_resume_reject_block_and_complete_without_events(self):
        self.create()
        initial = self.dump()
        self.assertEqual(self.graph('status')['checkpoint'], 'not_started')
        self.assertFalse((self.workspace / 'langgraph.sqlite3').exists())
        state = self.graph()
        self.assertEqual(state['checkpoint'], 'waiting')
        self.assertEqual(state['next_nodes'], ['task_1'])
        self.assertEqual(state['completed_tasks'], [])
        self.assertEqual(self.dump(), initial)
        checkpoint = self.dump('langgraph.sqlite3')
        self.graph('status')
        self.assertEqual(checkpoint, self.dump('langgraph.sqlite3'))

        self.bot('start', 1)
        self.decision('block', 1)
        before = self.dump()
        self.assertEqual(self.graph()['next_nodes'], ['task_1'])
        self.assertEqual(before, self.dump())
        self.bot('resume', 1)
        self.decision('submit', 1)
        self.assertEqual(self.graph()['completed_tasks'], [])
        self.decision('reject', 1)
        before = self.dump()
        for _ in range(3):
            state = self.graph()
            self.assertEqual(state['next_nodes'], ['task_1'])
            self.assertEqual(state['tasks'][0]['status'], 'active')
            self.assertEqual(state['completed_tasks'], [])
        self.assertEqual(before, self.dump())
        self.decision('submit', 1)
        self.decision('approve', 1)
        before = self.dump()
        state = self.graph()
        self.assertEqual(state['completed_tasks'], [1])
        self.assertEqual(state['next_nodes'], ['task_2'])
        self.assertEqual(before, self.dump())
        for task_id in (2, 3):
            self.finish(task_id)
            before = self.dump()
            state = self.graph()
            self.assertEqual(before, self.dump())
            self.assertEqual(state['completed_tasks'], list(range(1, task_id + 1)))
        self.assertEqual(state['checkpoint'], 'complete')
        self.assertEqual(state['next_nodes'], [])
        checkpoint = self.dump('langgraph.sqlite3')
        count = self.checkpoint_count()
        self.assertEqual(self.graph()['checkpoint'], 'complete')
        self.assertEqual(self.graph('status')['checkpoint'], 'complete')
        self.assertEqual(self.checkpoint_count(), count)
        self.assertEqual(checkpoint, self.dump('langgraph.sqlite3'))
        self.assertEqual(before, self.dump())
        self.assertFalse((self.workspace / 'runs').exists())

    def test_preapproved_tasks_and_dependency_diamond(self):
        tasks = []
        for key, dependencies in [('finish', ['left', 'right']), ('right', ['root']),
                                  ('left', ['root']), ('root', [])]:
            tasks.append({'key': key, 'title': key, 'role': 'researcher',
                          'scope': 'Local fixture', 'acceptance': 'Human decision',
                          'depends_on': dependencies})
        path = self.directory / 'diamond.json'
        path.write_text(json.dumps({'version': 1, 'name': 'diamond',
                                    'description': 'Local dependency fixture', 'tasks': tasks}), encoding='utf-8')
        self.create(path)
        for task_id in range(1, 5):
            self.finish(task_id)
        before = self.dump()
        state = self.graph()
        self.assertEqual(state['checkpoint'], 'complete')
        self.assertEqual(state['completed_tasks'], [1, 2, 3, 4])
        self.assertEqual(before, self.dump())
        self.assertFalse((self.workspace / 'runs').exists())

    def test_failed_real_local_cli_is_never_replayed(self):
        self.create()
        self.bot('start', 1)
        # json.tool genuinely rejects the non-JSON role/task prompt. This is a
        # real stdlib executable failure, not a mock model or fake handoff.
        self.bot('run', '--adapter', 'generic', 1, '--', sys.executable, '-m', 'json.tool', success=False)
        before = self.dump()
        run_directories = tuple((self.workspace / 'runs').iterdir())
        self.assertEqual(len(run_directories), 1)
        output_bytes = {path: path.read_bytes() for path in run_directories[0].iterdir()}
        for _ in range(3):
            state = self.graph()
            self.assertEqual(state['tasks'][0]['status'], 'blocked')
            self.assertEqual(state['completed_tasks'], [])
        self.assertEqual(before, self.dump())
        self.assertEqual(run_directories, tuple((self.workspace / 'runs').iterdir()))
        self.assertEqual(output_bytes, {path: path.read_bytes() for path in run_directories[0].iterdir()})

    def test_changed_definition_and_ledger_regression_fail_closed(self):
        self.create()
        self.graph()
        checkpoint = self.dump('langgraph.sqlite3')
        with closing(sqlite3.connect(self.workspace / 'workflow.sqlite3')) as db, db:
            original = db.execute('SELECT scope FROM tasks WHERE id=1').fetchone()[0]
            db.execute("UPDATE tasks SET scope='Changed graph definition' WHERE id=1")
        for command in ('run', 'status'):
            self.assertIn('differs from its checkpoint', self.graph(command, success=False).stderr)
        self.assertEqual(checkpoint, self.dump('langgraph.sqlite3'))
        with closing(sqlite3.connect(self.workspace / 'workflow.sqlite3')) as db, db:
            db.execute('UPDATE tasks SET scope=? WHERE id=1', (original,))
        self.finish(1)
        self.graph()
        checkpoint = self.dump('langgraph.sqlite3')
        with closing(sqlite3.connect(self.workspace / 'workflow.sqlite3')) as db, db:
            db.execute("UPDATE tasks SET status='active' WHERE id=1")
        self.assertIn('no longer done', self.graph(success=False).stderr)
        self.assertEqual(checkpoint, self.dump('langgraph.sqlite3'))

    def test_invalid_cycles_and_external_dependencies_are_rejected(self):
        self.create()
        with closing(sqlite3.connect(self.workspace / 'workflow.sqlite3')) as db, db:
            db.execute('INSERT INTO dependencies(task_id, depends_on) VALUES(1, 3)')
        self.assertIn('cycle', self.graph(success=False).stderr)
        self.assertFalse((self.workspace / 'langgraph.sqlite3').exists())
        with closing(sqlite3.connect(self.workspace / 'workflow.sqlite3')) as db, db:
            db.execute('DELETE FROM dependencies WHERE task_id=1 AND depends_on=3')
        self.bot('add', '--title', 'Outside group', '--role', 'researcher',
                 '--scope', 'Benign fixture', '--acceptance', 'Human decision')
        with closing(sqlite3.connect(self.workspace / 'workflow.sqlite3')) as db, db:
            db.execute('INSERT INTO dependencies(task_id, depends_on) VALUES(1, 4)')
        self.assertIn('inside their workflow group', self.graph(success=False).stderr)

    def test_process_lock_blocks_concurrent_writer_and_releases_after_exit(self):
        self.create()
        self.graph()
        before = self.dump('langgraph.sqlite3')
        # A genuine other process holds the exact same public lock context.
        script = ('import sys; sys.path.insert(0, sys.argv[1]); '
                  'from pathlib import Path; from orchestrate import exclusive_run; '
                  'lock = exclusive_run(Path(sys.argv[2])); lock.__enter__(); '
                  'print("locked", flush=True); sys.stdin.read()')
        holder = subprocess.Popen([sys.executable, '-c', script, str(HERE), str(self.workspace)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True)
        try:
            self.assertEqual(holder.stdout.readline().strip(), 'locked')
            self.assertIn('busy', self.graph(success=False).stderr)
            self.assertEqual(before, self.dump('langgraph.sqlite3'))
            self.assertEqual(self.graph('status')['checkpoint'], 'waiting')
        finally:
            holder.kill()
            holder.communicate(timeout=10)
        self.assertEqual(self.graph()['checkpoint'], 'waiting')


if __name__ == '__main__':
    unittest.main()
