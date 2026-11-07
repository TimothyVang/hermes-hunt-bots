"""hermes-hunt-bots local pre-PR gate (no hosted CI): run before opening or updating a PR.

    python scripts/hunt_bots_check.py            policy gate + framework test suite + gitleaks (if installed)
    python scripts/hunt_bots_check.py --policy   policy gate only (seconds)

The policy gate enforces HUNT-BOTS.md rules 1, 8 and 9: tracked framework/ files equal
framework/TRACKED-FILES.txt, nothing under runtime/ is tracked, no private-state files under
framework/, and THIRD-PARTY-NOTICES.md exists. Paste the summary line into the PR's
Verification section. Stdlib only; run from anywhere inside the repository.
"""
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_SUFFIXES = {'.sqlite', '.sqlite3', '.db', '.env', '.pem', '.key', '.vhdx', '.qcow2', '.iso'}
PRIVATE_NAMES = {'.env', 'auth.json', 'credentials.json', 'cookies.json', 'state.db'}
# Synthetic fixtures that are part of the reviewed public file list.
ALLOWED_CAPTURES = {'framework/hunt_lab/fixtures/dns-lab-001/traffic.pcap'}


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


def main():
    count, problems = policy_problems()
    for problem in problems:
        print('POLICY:', problem)
    results = [f'policy: {count} tracked files, {len(problems)} problem(s)']
    failed = bool(problems)
    if '--policy' not in sys.argv:
        tests = subprocess.run([sys.executable, '-B', '-m', 'unittest', 'discover'], cwd=ROOT / 'framework',
                               capture_output=True, text=True)
        tail = [line for line in tests.stderr.splitlines() if line.startswith(('Ran ', 'OK', 'FAILED'))]
        results.append('framework tests: ' + ' '.join(tail[-2:]))
        failed |= tests.returncode != 0
        if tests.returncode:
            print(tests.stderr[-4000:])
        if shutil.which('gitleaks'):
            leaks = subprocess.run(['gitleaks', 'git', '--config', str(ROOT / '.gitleaks.toml'), '--log-opts',
                                    'origin/hunt-bots..HEAD', str(ROOT)], capture_output=True, text=True)
            results.append('gitleaks: ' + ('clean' if leaks.returncode == 0 else 'LEAKS FOUND'))
            failed |= leaks.returncode != 0
        else:
            results.append('gitleaks: not installed (install it, or note this in the PR)')
    print('hunt-bots-check: ' + '; '.join(results) + ('  -> FAIL' if failed else '  -> PASS'))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
