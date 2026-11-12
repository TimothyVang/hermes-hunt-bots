"""hermes-hunt-bots local pre-PR gate (no hosted CI): run before opening or updating a PR.

    python scripts/hunt_bots_check.py                 policy gate + framework and operator tests + gitleaks (if installed)
    python scripts/hunt_bots_check.py --policy        policy gate only (seconds)
    python scripts/hunt_bots_check.py --python EXE    run the tests with EXE (default: $HUNT_BOTS_PYTHON, else this Python)
    python scripts/hunt_bots_check.py --log FILE      also write every test's full output to FILE

The policy gate enforces HUNT-BOTS.md rules 1, 8 and 9: tracked framework/ files equal
framework/TRACKED-FILES.txt, nothing under runtime/ is tracked, no private-state files under
framework/, and THIRD-PARTY-NOTICES.md exists. The tests need a Python with
framework/requirements-hunt.lock installed; without one of its test packages the gate fails with
`missing: <module>` instead of skipping those suites. Paste the summary line into the PR's
Verification section. Stdlib only; run from anywhere inside the repository.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_SUFFIXES = {'.sqlite', '.sqlite3', '.db', '.env', '.pem', '.key', '.vhdx', '.qcow2', '.iso'}
PRIVATE_NAMES = {'.env', 'auth.json', 'credentials.json', 'cookies.json', 'state.db'}
# Synthetic fixtures that are part of the reviewed public file list.
ALLOWED_CAPTURES = {'framework/hunt_lab/fixtures/dns-lab-001/traffic.pcap'}
# Modules whose absence makes test suites skip themselves; the gate refuses to run without them.
REQUIRED_MODULES = ('temporalio', 'websockets', 'pycdlib')
SUITES = (('framework tests', 'framework'), ('operator tests', 'operator'))
FAILED_TEST = re.compile(r'^(?:FAIL|ERROR): .+$', re.MULTILINE)
MISSING_PROBE = (
    'import importlib, sys\n'
    'for name in sys.argv[1:]:\n'
    '    try:\n'
    '        importlib.import_module(name)\n'
    '    except Exception:\n'
    '        print(name)\n'
)


def tracked():
    out = subprocess.run(['git', 'ls-files', '-z'], cwd=ROOT, capture_output=True, check=True).stdout.decode('utf-8')
    return [p for p in out.split('\0') if p]


def policy_problems():
    files = tracked()
    problems = []
    listed = {line.strip() for line in (ROOT / 'framework/TRACKED-FILES.txt').read_text(encoding='utf-8').splitlines() if line.strip()}
    actual = {p[len('framework/'):] for p in files if p.startswith('framework/')}
    problems += [f'framework/{p} is tracked but not listed in framework/TRACKED-FILES.txt (rule 8)' for p in sorted(actual - listed)]
    problems += [f'framework/{p} is listed in framework/TRACKED-FILES.txt but not tracked' for p in sorted(listed - actual)]
    for path in files:
        pure = PurePosixPath(path)
        if pure.parts[0] == 'runtime':
            problems.append(f'{path}: runtime/ is local lab state and must never be committed (rule 1)')
        if pure.parts[0] == 'framework' and (pure.suffix.lower() in PRIVATE_SUFFIXES or pure.name.lower() in PRIVATE_NAMES):
            problems.append(f'{path}: private-state file type under framework/ (rule 1)')
        if pure.parts[0] == 'framework' and pure.suffix.lower() in {'.pcap', '.pcapng'} and path not in ALLOWED_CAPTURES:
            problems.append(f'{path}: packet captures must be reviewed synthetic fixtures (rule 1)')
    if not (ROOT / 'THIRD-PARTY-NOTICES.md').is_file():
        problems.append('THIRD-PARTY-NOTICES.md is missing (rule 9)')
    return len(files), problems


def missing_modules(python):
    """Return the required modules that do not import in `python`, or None if it does not run."""
    try:
        probe = subprocess.run([python, '-c', MISSING_PROBE, *REQUIRED_MODULES], capture_output=True, text=True,
                               errors='replace')
    except OSError:
        return None
    return probe.stdout.split() if probe.returncode == 0 else None


def run_suite(python, folder):
    return subprocess.run([python, '-B', '-m', 'unittest', 'discover', '-v'], cwd=ROOT / folder,
                          capture_output=True, text=True, errors='replace')


def main(argv=None):
    parser = argparse.ArgumentParser(description='hermes-hunt-bots local pre-PR gate')
    parser.add_argument('--policy', action='store_true', help='run the policy gate only')
    parser.add_argument('--python', default=os.environ.get('HUNT_BOTS_PYTHON') or sys.executable,
                        help='interpreter for the tests (default: $HUNT_BOTS_PYTHON, else this Python)')
    parser.add_argument('--log', type=Path, help='write the full test output to this file')
    args = parser.parse_args(argv)
    count, problems = policy_problems()
    for problem in problems:
        print('POLICY:', problem)
    results = [f'policy: {count} tracked files, {len(problems)} problem(s)']
    failed = bool(problems)
    if not args.policy:
        failed |= run_tests(args.python, args.log, results)
    print('hunt-bots-check: ' + '; '.join(results) + ('  -> FAIL' if failed else '  -> PASS'))
    return 1 if failed else 0


def run_tests(python, log_path, results):
    print(f'hunt-bots-check: testing with {python}', flush=True)
    missing = missing_modules(python)
    if missing is None:
        results.append(f'python: {python} does not run')
        return True
    if missing:
        results.append('missing: ' + ', '.join(missing))
        return True
    failed = False
    log = []
    for label, folder in SUITES:
        tests = run_suite(python, folder)
        tail = [line for line in tests.stderr.splitlines() if line.startswith(('Ran ', 'OK', 'FAILED'))]
        results.append(f'{label}: ' + (' '.join(tail[-2:]) or f'exit {tests.returncode}'))
        log += [f'===== {label} ({folder}/): {python} -B -m unittest discover -v, exit {tests.returncode}',
                tests.stdout, tests.stderr]
        if tests.returncode:
            failed = True
            names = FAILED_TEST.findall(tests.stderr)
            print(tests.stderr[-4000:])
            print(f'{label} failed: ' + ('; '.join(names) or f'exit {tests.returncode} before any test reported'))
    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text('\n'.join(log), encoding='utf-8')
    if shutil.which('gitleaks'):
        leaks = subprocess.run(['gitleaks', 'git', '--config', str(ROOT / '.gitleaks.toml'), '--log-opts',
                                'origin/hunt-bots..HEAD', str(ROOT)], capture_output=True, text=True)
        results.append('gitleaks: ' + ('clean' if leaks.returncode == 0 else 'LEAKS FOUND'))
        failed |= leaks.returncode != 0
    else:
        results.append('gitleaks: not installed (install it, or note this in the PR)')
    return failed


if __name__ == '__main__':
    sys.exit(main())
