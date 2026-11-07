"""imager_import.py and evidence-acquisition tests; local files only, no devices."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
BOT = HERE / 'bot.py'
IMPORT = HERE / 'imager_import.py'


def sha(data):
    return hashlib.sha256(data).hexdigest()


class LedgerCase(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.dir = Path(temp.name)
        self.workspace = self.dir / 'workspace'
        self.bot('init')
        out = self.bot('workflow', 'create', 'evidence-acquisition', '--title', 'Synthetic acquisition',
                       '--scope', 'Synthetic test files only', '--acceptance', 'Hashes recorded').stdout
        self.ids = dict(line.split(': ') for line in out.splitlines()[1:])
        self.ids = {key: int(value) for key, value in self.ids.items()}
        self.evidence = self.dir / 'evidence'
        self.evidence.mkdir()

    def run_py(self, script, *args, code=0):
        result = subprocess.run([sys.executable, str(script), '-w', str(self.workspace), *map(str, args)],
                                cwd=str(self.dir), capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=120)
        self.assertEqual(result.returncode, code, 'stdout: ' + result.stdout + '\nstderr: ' + result.stderr)
        return result

    def bot(self, *args, code=0):
        return self.run_py(BOT, *args, code=code)

    def importer(self, *args, code=0):
        return self.run_py(IMPORT, *args, code=code)

    def rows(self, sql, args=()):
        with closing(sqlite3.connect(str(self.workspace / 'workflow.sqlite3'))) as db:
            return db.execute(sql, args).fetchall()

    def artifacts(self, task_id):
        return self.rows('SELECT path, description FROM artifacts WHERE task_id=? ORDER BY id', (task_id,))

    def status(self, task_id):
        return self.rows('SELECT status FROM tasks WHERE id=?', (task_id,))[0][0]

    def activate_acquire(self):
        scope = self.ids['scope']
        self.bot('start', scope)
        self.bot('submit', scope, '--by', 'coordinator', '--note', 'scope recorded')
        self.bot('approve', scope, '--by', 'TEST HUMAN (unit test)', '--note', 'approved for test')
        self.bot('start', self.ids['acquire'])
        return self.ids['acquire']


class ImportTests(LedgerCase):
    def raw_image(self, segments=(b'A' * 4096, b'B' * 1000), schema=1, record_hash=None, bad=()):
        base = self.evidence / 'case'
        names = []
        for index, data in enumerate(segments, 1):
            name = f'case.{index:03d}'
            (self.evidence / name).write_bytes(data)
            names.append(name)
        whole = b''.join(segments)
        record = {'schema_version': schema, 'tool': 'imager test', 'format': 'raw', 'segments': names,
                  'bytes': len(whole), 'sectors': len(whole) // 512,
                  'hashes': {'md5': hashlib.md5(whole).hexdigest(), 'sha1': hashlib.sha1(whole).hexdigest(),
                             'sha256': sha(whole)},
                  'bad_sectors': list(bad),
                  'verification': {'hashes': {}, 'bytes': len(whole), 'match': True}}
        if schema is None:
            del record['schema_version']
        data = (json.dumps(record, indent=2) + '\n').encode()
        Path(str(base) + '.json').write_bytes(data)
        Path(str(base) + '.txt').write_text(f'imager log\nRecord SHA256: {record_hash or sha(data)}\n', encoding='utf-8')
        return Path(str(base) + '.json'), whole

    def test_template_listed_and_ordered(self):
        self.assertIn('evidence-acquisition', self.bot('workflow', 'list').stdout)
        shown = json.loads(self.bot('workflow', 'show', 'evidence-acquisition').stdout)
        self.assertEqual([t['key'] for t in shown['tasks']], ['scope', 'acquire', 'verify', 'handoff'])
        self.assertEqual([t['role'] for t in shown['tasks']], ['coordinator', 'builder', 'reviewer', 'coordinator'])
        self.assertIn('never', shown['tasks'][1]['scope'])
        # Acquisition is gated on human approval of scope.
        self.bot('start', self.ids['acquire'], code=1)

    def test_raw_image_import_registers_and_submits(self):
        task_id = self.activate_acquire()
        record, whole = self.raw_image(bad=[{'first_sector': 4, 'sector_count': 2}])
        out = self.importer(task_id, record, '--by', 'operator').stdout
        self.assertIn('Registered 4 artifact(s)', out)
        arts = self.artifacts(task_id)
        self.assertEqual(len(arts), 4)
        for path, description in arts:
            self.assertIn(f'sha256={sha(Path(path).read_bytes())}', description)
        self.assertEqual(self.status(task_id), 'review')
        note = self.rows("SELECT note FROM events WHERE task_id=? AND kind='submit'", (task_id,))[0][0]
        self.assertIn(f'sha256={sha(whole)}', note)
        self.assertIn('bad sectors=2', note)
        self.assertIn(f'sha256={sha(record.read_bytes())}', note)
        self.assertIn('matches the Record SHA256', note)
        self.assertNotIn('approve', [r[0] for r in self.rows('SELECT kind FROM events WHERE task_id=?', (task_id,))])

    def test_tampered_segment_refused(self):
        task_id = self.activate_acquire()
        record, _ = self.raw_image()
        (self.evidence / 'case.002').write_bytes(b'C' * 1000)
        result = self.importer(task_id, record, code=3)
        self.assertIn('REFUSED', result.stderr)
        self.assertEqual(self.artifacts(task_id), [])
        self.assertEqual(self.status(task_id), 'active')

    def test_record_hash_in_text_log_mismatch_refused(self):
        task_id = self.activate_acquire()
        record, _ = self.raw_image(record_hash='0' * 64)
        self.assertIn('Record SHA256', self.importer(task_id, record, code=3).stderr)
        self.assertEqual(self.artifacts(task_id), [])

    def test_schema_version_checked(self):
        task_id = self.activate_acquire()
        record, _ = self.raw_image(schema=2)
        self.assertIn('unsupported imager schema_version', self.importer(task_id, record, code=1).stderr)
        record.unlink()
        record, _ = self.raw_image(schema=None)
        self.assertIn('no valid schema_version', self.importer(task_id, record, code=1).stderr)
        self.assertEqual(self.artifacts(task_id), [])

    def test_missing_file_refused(self):
        task_id = self.activate_acquire()
        record, _ = self.raw_image()
        (self.evidence / 'case.001').unlink()
        self.assertIn('does not exist', self.importer(task_id, record, code=1).stderr)
        self.assertEqual(self.artifacts(task_id), [])

    def test_pending_task_gets_artifacts_but_no_submit(self):
        record, _ = self.raw_image()
        out = self.importer(self.ids['acquire'], record).stdout
        self.assertIn('not active; no submit', out)
        self.assertEqual(len(self.artifacts(self.ids['acquire'])), 4)
        self.assertEqual(self.status(self.ids['acquire']), 'pending')

    def collect_record(self, container=None, container_sha=None):
        copy_log, skip_log = self.evidence / 'CopyLog.csv', self.evidence / 'SkipLog.csv'
        copy_log.write_text('Source,Dest,SHA256\n', encoding='utf-8')
        skip_log.write_text('Source,Reason\n', encoding='utf-8')
        result = {'copied': 3, 'skipped': 1, 'failed': 0, 'bytes': 12345,
                  'copy_log': str(copy_log), 'skip_log': 'SkipLog.csv'}
        if container:
            result.update(container=container, container_sha256=container_sha,
                          copy_log='CopyLog.csv', skip_log='SkipLog.csv')
        path = self.evidence / 'collect.json'
        # PowerShell 5 redirection writes UTF-16LE with a BOM.
        path.write_bytes(json.dumps({'schema_version': 1, 'case': {}, 'result': result}).encode('utf-16'))
        return path

    def test_collect_record_utf16(self):
        task_id = self.activate_acquire()
        out = self.importer(task_id, self.collect_record()).stdout
        self.assertIn('Registered 3 artifact(s)', out)
        note = self.rows("SELECT note FROM events WHERE task_id=? AND kind='submit'", (task_id,))[0][0]
        self.assertIn('copied=3 skipped=1 failed=0', note)

    def test_collect_container_hash_checked(self):
        task_id = self.activate_acquire()
        (self.evidence / 'triage.zip').write_bytes(b'PK fake container')
        bad = self.collect_record('triage.zip', '1' * 64)
        self.importer(task_id, bad, code=3)
        good = self.collect_record('triage.zip', sha(b'PK fake container'))
        self.assertIn('Registered 2 artifact(s)', self.importer(task_id, good).stdout)

    def verify_record(self, verified=True, computed=None):
        image = self.evidence / 'disk.dd'
        image.write_bytes(b'Z' * 2048)
        path = self.evidence / 'verify.json'
        path.write_text(json.dumps({'schema_version': 1, 'image': 'disk.dd', 'format': 'raw', 'bytes': 2048,
                                    'computed': {'sha256': computed or sha(b'Z' * 2048)}, 'checks': [],
                                    'sidecar': '', 'verified': verified}), encoding='utf-8')
        return path

    def test_verify_records(self):
        self.importer(self.ids['scope'], self.verify_record(verified=False), '--no-submit', code=3)
        self.importer(self.ids['scope'], self.verify_record(computed='2' * 64), '--no-submit', code=3)
        self.assertEqual(self.artifacts(self.ids['scope']), [])
        self.importer(self.ids['scope'], self.verify_record(), '--no-submit')
        self.assertEqual(len(self.artifacts(self.ids['scope'])), 2)


@unittest.skipUnless(os.environ.get('IMAGER_BIN'), 'set IMAGER_BIN to a built imager binary')
class RealImagerTests(LedgerCase):
    def test_real_image_import_and_verify(self):
        imager = os.environ['IMAGER_BIN']
        source = self.dir / 'source.bin'
        source.write_bytes(os.urandom(1 << 20))
        base = self.evidence / 'img'
        subprocess.run([imager, 'image', '--source', str(source), '--out', str(base), '--format', 'raw',
                        '--quiet'], check=True, capture_output=True, timeout=300)
        task_id = self.activate_acquire()
        record = Path(str(base) + '.json')
        self.importer(task_id, record)
        rows = self.artifacts(task_id)
        segments = json.loads(record.read_text(encoding='utf-8'))['segments']
        self.assertEqual(len(rows), 2 + len(segments))
        for path, description in rows:
            self.assertIn(f'sha256={sha(Path(path).read_bytes())}', description)
        self.assertEqual(self.status(task_id), 'review')
        verify = subprocess.run([imager, 'verify', '--json', segments[0]], capture_output=True, timeout=300)
        self.assertEqual(verify.returncode, 0, verify.stderr)
        result = json.loads(verify.stdout)
        self.assertTrue(result['verified'])
        self.assertEqual(result['computed']['sha256'], sha(source.read_bytes()))
        saved = self.evidence / 'verify.json'
        saved.write_bytes(verify.stdout)
        self.importer(self.ids['verify'], saved, '--no-submit')
        self.assertEqual(len(self.artifacts(self.ids['verify'])), 3)
