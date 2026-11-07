#!/usr/bin/env python3
"""Optional durable, sequential LangGraph cursors over human-operated workflows."""
import argparse
from collections import deque
from contextlib import closing, contextmanager
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
from typing import List, Optional, TypedDict


CHECKPOINT_FILE = 'langgraph.sqlite3'
LOCK_FILE = 'orchestration-lock.sqlite3'
RUNTIME_VERSION = 1
STATUSES = {'pending', 'active', 'running', 'blocked', 'review', 'done'}


class RuntimeProblem(Exception):
    """An operator-facing error containing only framework-authored text."""


class Progress(TypedDict):
    fingerprint: str
    completed: List[int]
    waiting: Optional[int]


def optional_runtime():
    if sys.version_info < (3, 10):
        raise RuntimeProblem('optional orchestration requires Python 3.10 or newer; the manual ledger still supports Python 3.9')
    # Override inherited tracing switches before importing optional packages.
    for name in ('LANGSMITH_TRACING', 'LANGCHAIN_TRACING', 'LANGCHAIN_TRACING_V2'):
        os.environ[name] = 'false'
    os.environ['LANGGRAPH_STRICT_MSGPACK'] = 'true'
    try:
        from langgraph.checkpoint.sqlite import SqliteSaver
        from langgraph.graph import END, START, StateGraph
        from langgraph.types import Command, interrupt
        from langsmith import tracing_context
    except ImportError:
        raise RuntimeProblem('optional dependencies unavailable; install requirements-orchestration.txt in a Python 3.10+ virtual environment') from None
    return SqliteSaver, StateGraph, START, END, Command, interrupt, tracing_context


def read_connection(path):
    return sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=10)


def load_workflow(workspace, workflow_id):
    """Read one consistent ledger snapshot; never create or modify its schema."""
    path = workspace / 'workflow.sqlite3'
    if not path.is_file():
        raise RuntimeProblem('workspace not initialized; use bot.py init first')
    with closing(read_connection(path)) as db:
        db.row_factory = sqlite3.Row
        db.execute('BEGIN')
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'workflow_runs', 'workflow_tasks'}.issubset(tables):
            raise RuntimeProblem('workspace has no workflow groups; use bot.py workflow create without reinitializing it')
        group = db.execute('SELECT id, title, template, created FROM workflow_runs WHERE id=?', (workflow_id,)).fetchone()
        if group is None:
            raise RuntimeProblem('workflow group not found; use the workflow ID, not a task ID')
        members = db.execute('''SELECT wt.task_key, wt.task_id, t.title, t.role,
            t.scope, t.acceptance, t.created, t.status FROM workflow_tasks wt
            LEFT JOIN tasks t ON t.id=wt.task_id WHERE wt.workflow_id=?
            ORDER BY wt.task_id''', (workflow_id,)).fetchall()
        if not members or any(row['status'] not in STATUSES for row in members):
            raise RuntimeProblem('workflow has missing tasks or invalid ledger statuses; inspect the ledger')
        tasks = {row['task_id']: dict(row, depends_on=[]) for row in members}
        edges = db.execute('''SELECT d.task_id, d.depends_on FROM dependencies d
            JOIN workflow_tasks wt ON wt.task_id=d.task_id
            WHERE wt.workflow_id=? ORDER BY d.task_id, d.depends_on''', (workflow_id,)).fetchall()
        for task_id, predecessor in edges:
            if predecessor not in tasks:
                raise RuntimeProblem('workflow dependencies must remain inside their workflow group')
            tasks[task_id]['depends_on'].append(predecessor)
    remaining = {task_id: len(item['depends_on']) for task_id, item in tasks.items()}
    successors = {task_id: [] for task_id in tasks}
    for task_id, item in tasks.items():
        for predecessor in item['depends_on']:
            successors[predecessor].append(task_id)
    ready = deque(task_id for task_id in tasks if not remaining[task_id])
    ordered = []
    while ready:
        task_id = ready.popleft()
        ordered.append(task_id)
        for successor in successors[task_id]:
            remaining[successor] -= 1
            if not remaining[successor]:
                ready.append(successor)
    if len(ordered) != len(tasks):
        raise RuntimeProblem('workflow dependencies contain a cycle; inspect the ledger')
    definition = {
        'runtime_version': RUNTIME_VERSION,
        'workflow': dict(group),
        'tasks': [{key: value for key, value in item.items() if key != 'status'}
                  for item in tasks.values()],
    }
    fingerprint = hashlib.sha256(json.dumps(definition, sort_keys=True,
                                            separators=(',', ':')).encode('utf-8')).hexdigest()
    return {'id': workflow_id, 'tasks': tasks, 'order': ordered, 'fingerprint': fingerprint}


@contextmanager
def exclusive_run(workspace):
    """A separate SQLite reserved lock serializes writers across processes.

    No lease, PID guessing or deletion recovery is needed: the OS releases the
    database lock when the owning process exits, including abrupt termination.
    """
    with closing(sqlite3.connect(str(workspace / LOCK_FILE), timeout=0)) as db:
        try:
            db.execute('BEGIN IMMEDIATE')
        except sqlite3.OperationalError:
            raise RuntimeProblem('orchestration is busy or its lock is unavailable; let the other invocation exit, then run again; never delete a live lock database') from None
        try:
            yield
        finally:
            db.rollback()


def check_progress(state, workflow):
    if state.get('fingerprint') != workflow['fingerprint']:
        raise RuntimeProblem('workflow definition differs from its checkpoint; restore the matching ledger/checkpoint backup or create a new workflow group; no automatic reset')
    completed = state.get('completed')
    if not isinstance(completed, list) or completed != workflow['order'][:len(completed)]:
        raise RuntimeProblem('checkpoint progress is inconsistent; inspect or restore its matching backup')
    if any(workflow['tasks'][task_id]['status'] != 'done' for task_id in completed):
        raise RuntimeProblem('a completed checkpoint task is no longer done in the ledger; reconcile the ledger or restore its matching backup')


def make_graph(workspace, workflow, saver, runtime):
    _, StateGraph, START, END, _, interrupt, _ = runtime
    graph = StateGraph(Progress)

    def make_node(task_id):
        def ledger_gate(state):
            current = load_workflow(workspace, workflow['id'])
            check_progress(state, current)
            item = current['tasks'][task_id]
            blockers = [predecessor for predecessor in item['depends_on']
                        if current['tasks'][predecessor]['status'] != 'done']
            if item['status'] != 'done' or blockers:
                # Resume values are wake-up signals, NEVER approval decisions.
                # On a rejected/still-pending task, route back to a fresh node
                # attempt so its next interrupt is durable, not an in-node loop.
                interrupt({'task_id': task_id, 'status': item['status'],
                           'blockers': blockers, 'action': 'complete human-led ledger review, then run again'})
                return {'waiting': task_id}
            return {'completed': state['completed'] + [task_id], 'waiting': None}
        return ledger_gate

    for index, task_id in enumerate(workflow['order']):
        name = 'task_' + str(task_id)
        successor = ('task_' + str(workflow['order'][index + 1])
                     if index + 1 < len(workflow['order']) else END)
        graph.add_node(name, make_node(task_id))
        graph.add_conditional_edges(name,
                                    lambda state: 'wait' if state['waiting'] is not None else 'advance',
                                    {'wait': name, 'advance': successor})
    graph.add_edge(START, 'task_' + str(workflow['order'][0]))
    return graph.compile(checkpointer=saver)


def describe(workflow, snapshot=None):
    values = snapshot.values if snapshot is not None else None
    if values:
        check_progress(values, workflow)
    completed = values['completed'] if values else []
    if snapshot is None or not snapshot.config.get('configurable', {}).get('checkpoint_id'):
        phase = 'not_started'
    elif not snapshot.next:
        if completed != workflow['order']:
            raise RuntimeProblem('checkpoint ended before all ledger tasks were reconciled; inspect its matching backup')
        phase = 'complete'
    elif any(task.interrupts for task in snapshot.tasks):
        phase = 'waiting'
    else:
        phase = 'paused'
    return {
        'workflow_id': workflow['id'],
        'fingerprint': workflow['fingerprint'],
        'checkpoint': phase,
        'checkpoint_id': snapshot.config.get('configurable', {}).get('checkpoint_id') if snapshot else None,
        'completed_tasks': completed,
        'next_nodes': list(snapshot.next) if snapshot else [],
        'tasks': [{'key': workflow['tasks'][task_id]['task_key'], 'id': task_id,
                   'status': workflow['tasks'][task_id]['status'],
                   'depends_on': workflow['tasks'][task_id]['depends_on']}
                  for task_id in workflow['order']],
    }


def operate(workspace, workflow_id, advance):
    workspace = Path(workspace).expanduser().resolve()
    workflow = load_workflow(workspace, workflow_id)
    runtime = optional_runtime()
    SqliteSaver, _, _, _, Command, _, tracing_context = runtime
    checkpoint_path = workspace / CHECKPOINT_FILE
    config = {'configurable': {'thread_id': 'workflow:' + str(workflow_id)},
              'callbacks': [], 'recursion_limit': len(workflow['order']) * 2 + 10}
    with tracing_context(enabled=False):
        if not advance:
            if not checkpoint_path.is_file():
                return describe(workflow)
            # SqliteSaver performs schema setup even on get_state. Work against
            # a consistent in-memory backup so status cannot migrate/write the
            # durable checkpointer or advance its cursor.
            with closing(read_connection(checkpoint_path)) as source, closing(sqlite3.connect(':memory:', check_same_thread=False)) as copy:
                source.backup(copy)
                # Read the ledger after the checkpoint snapshot: an approval
                # racing status must not look like a completed-task regression.
                workflow = load_workflow(workspace, workflow_id)
                graph = make_graph(workspace, workflow, SqliteSaver(copy), runtime)
                snapshot = graph.get_state(config)
                return describe(workflow, snapshot)
        with exclusive_run(workspace):
            workflow = load_workflow(workspace, workflow_id)
            with SqliteSaver.from_conn_string(str(checkpoint_path)) as saver:
                graph = make_graph(workspace, workflow, saver, runtime)
                snapshot = graph.get_state(config)
                if snapshot.values:
                    check_progress(snapshot.values, workflow)
                    if snapshot.next:
                        signal = Command(resume=True) if any(task.interrupts for task in snapshot.tasks) else None
                        graph.invoke(signal, config=config, durability='sync')
                elif snapshot.config.get('configurable', {}).get('checkpoint_id'):
                    raise RuntimeProblem('checkpoint initialization was interrupted; inspect or restore its matching backup before resuming')
                else:
                    graph.invoke({'fingerprint': workflow['fingerprint'], 'completed': [], 'waiting': None},
                                 config=config, durability='sync')
                current = load_workflow(workspace, workflow_id)
                return describe(current, graph.get_state(config))


def positive_id(value):
    try:
        result = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError('workflow ID must be a positive integer') from None
    if result <= 0:
        raise argparse.ArgumentTypeError('workflow ID must be a positive integer')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-w', '--workspace', default='./bot-workspace')
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('run', 'status'):
        child = sub.add_parser(command, help='reconcile ledger progress' if command == 'run' else 'inspect without advancing')
        child.add_argument('workflow_id', type=positive_id)
    args = parser.parse_args(argv)
    try:
        result = operate(args.workspace, args.workflow_id, args.command == 'run')
    except RuntimeProblem as exc:
        print('Error: ' + str(exc), file=sys.stderr)
        return 1
    except Exception:
        print('Error: optional orchestration failed; inspect dependency installation, workspace access and matching backups; no model or CLI was invoked', file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
