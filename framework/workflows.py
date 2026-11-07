"""Portable, data-only workflow templates; no execution or workspace access."""
import json
from collections import deque
from pathlib import Path

ROLES = ('coordinator', 'researcher', 'builder', 'reviewer')
BUNDLED_DIR = Path(__file__).resolve().parent / 'workflows'


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate JSON key: {key}')
        result[key] = value
    return result


def _constant(value):
    raise ValueError(f'invalid JSON constant: {value}')


def _fields(value, expected, label):
    if not isinstance(value, dict):
        raise ValueError(f'{label} must be an object')
    missing = expected - value.keys()
    unknown = value.keys() - expected
    if missing or unknown:
        details = []
        if missing:
            details.append('missing fields: ' + ', '.join(sorted(missing)))
        if unknown:
            details.append('unknown fields: ' + ', '.join(sorted(map(str, unknown))))
        raise ValueError(f'{label}: ' + '; '.join(details))


def _text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f'{label} must be nonempty text')


def validate_template(data):
    """Validate the complete schema and return a topologically ordered copy.

    All fields are literal data. Forward references are allowed, but no unknown
    fields, cycles, duplicate keys/dependencies, or unsupported roles/versions.
    JSON duplicate object keys are rejected by load_template before this step.
    """
    _fields(data, {'version', 'name', 'description', 'tasks'}, 'workflow')
    if type(data['version']) is not int or data['version'] != 1:
        raise ValueError('unsupported workflow version; expected integer 1')
    for field in ('name', 'description'):
        _text(data[field], f'workflow {field}')
    if not isinstance(data['tasks'], list) or not data['tasks']:
        raise ValueError('workflow tasks must be a nonempty array')

    tasks = {}
    fields = {'key', 'title', 'role', 'scope', 'acceptance', 'depends_on'}
    for index, step in enumerate(data['tasks']):
        label = f'task {index + 1}'
        _fields(step, fields, label)
        for field in ('key', 'title', 'role', 'scope', 'acceptance'):
            _text(step[field], f'{label} {field}')
        key = step['key']
        if key in tasks:
            raise ValueError(f'duplicate task key: {key}')
        if step['role'] not in ROLES:
            raise ValueError(f'invalid role for task {key}: {step["role"]}')
        if not isinstance(step['depends_on'], list):
            raise ValueError(f'task {key} depends_on must be an array')
        seen = set()
        for dependency in step['depends_on']:
            _text(dependency, f'task {key} dependency')
            if dependency in seen:
                raise ValueError(f'duplicate dependency for task {key}: {dependency}')
            seen.add(dependency)
        tasks[key] = dict(step, depends_on=list(step['depends_on']))

    successors = {key: [] for key in tasks}
    remaining = {}
    for key, step in tasks.items():
        remaining[key] = len(step['depends_on'])
        for dependency in step['depends_on']:
            if dependency not in tasks:
                raise ValueError(f'unknown dependency for task {key}: {dependency}')
            successors[dependency].append(key)
    ready = deque(key for key in tasks if not remaining[key])
    ordered = []
    while ready:
        key = ready.popleft()
        ordered.append(tasks[key])
        for successor in successors[key]:
            remaining[successor] -= 1
            if not remaining[successor]:
                ready.append(successor)
    if len(ordered) != len(tasks):
        raise ValueError('workflow dependencies must form a DAG; cycle detected')
    return dict(data, tasks=ordered)


def load_template(template):
    """Load a bundled name or a literal JSON path relative to the current cwd."""
    path = Path(template)
    if str(template) in {item.stem for item in BUNDLED_DIR.glob('*.json')}:
        path = BUNDLED_DIR / (str(template) + '.json')
    try:
        data = json.loads(path.read_text(encoding='utf-8'),
                          object_pairs_hook=_object, parse_constant=_constant)
    except RecursionError as exc:
        raise ValueError('workflow JSON is nested too deeply') from exc
    return validate_template(data)


def list_templates():
    """Read and validate bundled templates without opening a workspace."""
    return [load_template(path) for path in sorted(BUNDLED_DIR.glob('*.json'))]
