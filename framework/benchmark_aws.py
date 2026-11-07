"""Guarded, fixed CloudTrail-stop driver and independent baseline collector.

Operator provisioning is mandatory: a dedicated real OS account/home, SSO-only
configuration, immutable binary pins and a build-provenance pin. No installation,
credential creation, endpoint overrides or arbitrary command arguments are accepted.
The controller owns durable reservations/authority; this module rechecks identity,
pins and effects. Transport stdout is private parser input, never a public receipt.
The build-provenance document is an operator pin, not cryptographic build attestation.
Collector provisioning also supplies an independently maintained S3 watermark at
<CloudTrail prefix>_benchmark/watermark.json. Its exact schema is
{schema_version: 1, window_utc: {start_inclusive, end_exclusive}, watermark_utc:
UTC string or null}. A future/stale watermark never proves export completeness.
Authorized Stratus warmup may initialize/download Terraform provider plugins under
the pinned upstream recipe constraints. Development never invokes these tools.
"""
import configparser
import datetime as dt
import getpass
import hashlib
import os
from pathlib import Path
import re
import stat
import time
import uuid
import zlib

from benchmark_contracts import BenchmarkError, canonical_bytes, decode_json, _no_alias, parse_utc

SOURCE_COMMIT = '92ff110d30bdc50f52fb7b8f4270bbde11fe8a56'
TECHNIQUE = 'aws.defense-evasion.cloudtrail-stop'
RECIPE = 'aws-test-trail-stop-v1'
IDENTITY_FIELDS = {'account_id', 'region', 'role_arn', 'session_name', 'baseline_trail_arn'}
LOGIN_FIELDS = {'os_home', 'os_user', 'sso_config', 'sso_credentials', 'profile'}
EXECUTOR_FIELDS = LOGIN_FIELDS | {'stratus', 'terraform', 'source_commit', 'provenance'}
COLLECTOR_FIELDS = LOGIN_FIELDS | IDENTITY_FIELDS | {'executable', 'poll_seconds', 'watermark_key'}
UTC = dt.timezone.utc


def _fail(code, field='aws'):
    raise BenchmarkError(code, field)


def _fields(value, keys, field):
    if type(value) is not dict or set(value) != keys:
        _fail('invalid_fields', field)


def _match(value, pattern, field):
    if type(value) is not str or re.fullmatch(pattern, value) is None:
        _fail('invalid_value', field)


def _text(value, field):
    if type(value) is not str or not value or any(ord(c) < 32 for c in value):
        _fail('invalid_value', field)


def _path(value, field):
    _text(value, field)
    if not Path(value).is_absolute() or '..' in Path(value).parts:
        _fail('unsafe_path', field)
    if os.name == 'nt' and (not re.fullmatch(r'[A-Za-z]:', Path(value).drive)
                            or any(':' in part for part in Path(value).parts[1:])):
        _fail('unsafe_path', field)


def _pin(value, executable=False):
    _fields(value, {'path', 'sha256', 'version'} if executable else {'path', 'sha256'}, 'aws.pin')
    _path(value['path'], 'aws.pin.path')
    _match(value['sha256'], r'[0-9a-f]{64}', 'aws.pin.sha256')
    if executable:
        _text(value['version'], 'aws.pin.version')
        if Path(value['path']).suffix.lower() in ('.bat', '.cmd', '.ps1', '.py', '.sh'):
            _fail('unsupported_executable', 'aws.pin.path')


def _identity(value):
    _fields(value, IDENTITY_FIELDS, 'aws.identity')
    _match(value['account_id'], r'[0-9]{12}', 'aws.identity.account_id')
    _match(value['region'], r'[a-z]{2}(?:-[a-z]+)+-[0-9]', 'aws.identity.region')
    _match(value['session_name'], r'[A-Za-z0-9_+=,.@-]{2,64}', 'aws.identity.session_name')
    _match(value['role_arn'], r'arn:aws:iam::' + value['account_id'] + r':role/[A-Za-z0-9_+=,.@/-]+', 'aws.identity.role_arn')
    _match(value['baseline_trail_arn'], r'arn:aws:cloudtrail:' + value['region'] + ':' + value['account_id'] + r':trail/[A-Za-z0-9_.-]+', 'aws.identity.baseline_trail_arn')


def _login(config):
    _path(config['os_home'], 'aws.os_home')
    _text(config['os_user'], 'aws.os_user')
    _match(config['profile'], r'[A-Za-z0-9_-]{1,64}', 'aws.profile')
    for name in ('sso_config', 'sso_credentials'):
        _pin(config[name])
        try:
            Path(config[name]['path']).relative_to(Path(config['os_home']))
        except ValueError:
            _fail('unsafe_path', 'aws.sso')


def validate_configuration(manifest):
    """Pure schema validation; does not probe files, accounts or executables."""
    if manifest.get('recipe_id') != RECIPE:
        _fail('unsupported_recipe', 'recipe_id')
    targets = manifest.get('targets')
    if type(targets) is not list or len(targets) != 1 or targets[0].get('kind') != 'aws':
        _fail('invalid_inventory', 'targets')
    _identity(targets[0]['identity'])
    executor = manifest['executor']
    if executor['transport'] != 'aws_cli' or executor['script_sha256'] is not None or executor['environment_names'] != []:
        _fail('unsupported_transport', 'executor')
    _pin(executor['executable'], True)
    config = executor['config']
    _fields(config, EXECUTOR_FIELDS, 'executor.config')
    _login(config)
    for name in ('stratus', 'terraform'):
        _pin(config[name], True)
    _pin(config['provenance'])
    if config['source_commit'] != SOURCE_COMMIT:
        _fail('unsupported_tool_version', 'executor.config.source_commit')
    cost = manifest['limits']['max_cloud_cost_usd']
    if type(cost) not in (int, float) or not 0 < cost < float('inf'):
        _fail('invalid_limit', 'limits.max_cloud_cost_usd')
    for collector in manifest['collectors']:
        if collector['kind'] == 'aws':
            validate_collector(manifest, collector)
            if collector['config']['profile'] == config['profile'] and collector['config']['os_home'] == config['os_home']:
                _fail('collector_identity_not_independent', 'collectors.config')
            if collector['config']['role_arn'] == targets[0]['identity']['role_arn']:
                _fail('collector_identity_not_independent', 'collectors.config.role_arn')


def validate_collector(manifest, collector):
    config = collector['config']
    _fields(config, COLLECTOR_FIELDS, 'collectors.config')
    _identity({key: config[key] for key in IDENTITY_FIELDS})
    _login(config)
    _pin(config['executable'], True)
    if type(config['poll_seconds']) not in (int, float) or not 0 < config['poll_seconds'] <= 60:
        _fail('invalid_limit', 'collectors.config.poll_seconds')
    _match(collector['bucket'], r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', 'collectors.bucket')
    prefix = collector['prefix']
    suffix = 'AWSLogs/{}/CloudTrail/{}/'.format(config['account_id'], config['region'])
    if type(prefix) is not str or not prefix.endswith(suffix) or prefix.startswith('/') or '..' in prefix.split('/') or not re.fullmatch(r'[A-Za-z0-9_./-]+', prefix):
        _fail('invalid_prefix', 'collectors.prefix')
    if config['watermark_key'] != prefix + '_benchmark/watermark.json':
        _fail('invalid_prefix', 'collectors.config.watermark_key')
    if collector['export_root'] is not None:
        _fail('invalid_export_root', 'collectors.export_root')
    matches = [target for target in manifest['targets'] if target['target_id'] == collector['target_id']]
    if len(matches) != 1 or matches[0]['kind'] != 'aws':
        _fail('invalid_inventory', 'collectors.target_id')
    target = matches[0]['identity']
    if any(target.get(key) != config[key] for key in ('account_id', 'region', 'baseline_trail_arn')):
        _fail('target_identity_mismatch', 'collectors.config')
    if manifest.get('recipe_id') == RECIPE and target.get('role_arn') == config['role_arn']:
        _fail('collector_identity_not_independent', 'collectors.config.role_arn')


def phase_steps(manifest, phase, context):
    validate_configuration(manifest)
    choices = {'preflight': ['identity'], 'run': ['warmup', 'detonate'], 'cleanup': ['cleanup']}
    if phase not in choices:
        _fail('unsupported_phase', 'phase')
    return choices[phase]


def _utc(value):
    result = parse_utc(value, 'aws.time')
    if result.utcoffset() != dt.timedelta(0):
        _fail('invalid_timestamp', 'aws.time')
    return result


def _file(path, max_bytes=16 * 1024 * 1024):
    path = Path(path)
    _no_alias(path, 'aws.path')
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > max_bytes:
            _fail('unsafe_file', 'aws.path')
        with path.open('rb') as stream:
            value = stream.read(max_bytes + 1)
        if len(value) > max_bytes:
            _fail('output_limit', 'aws.path')
        return value
    except OSError:
        _fail('missing_prerequisite', 'aws.path')


def _verify_pin(pin, executable=False, pins=None):
    """Verify a pin's bytes; with `pins`, re-hash only if the file identity changed.

    Executables may have st_nlink > 1 (inbox binaries are hard links); the SHA-256
    pin binds their bytes. Configuration files must remain single-link.
    """
    path = Path(pin['path'])
    _no_alias(path, 'aws.pin.path')
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or (not executable and info.st_nlink != 1):
            _fail('unsafe_file', 'aws.pin.path')
        identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, pin['sha256'])
        if pins is not None and pins.get(pin['path']) == identity:
            return
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        after = path.stat()
        if digest.hexdigest() != pin['sha256'] or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != identity[:4]:
            _fail('executable_hash_mismatch', 'aws.pin.sha256')
        if pins is not None:
            pins[pin['path']] = identity
    except OSError:
        _fail('missing_prerequisite', 'aws.pin.path')


def _environment(config, identity):
    # Ambient AWS/Stratus/Terraform selectors are rejected, not silently inherited.
    for name in os.environ:
        if name.startswith(('AWS_', 'STRATUS_', 'TF_')) or name in ('BOTO_CONFIG', 'BOTO_PATH'):
            _fail('ambient_credentials_or_override', 'aws.environment')
    home = Path(config['os_home'])
    _no_alias(home, 'aws.os_home')
    if getpass.getuser() != config['os_user'] or Path.home() != home or not home.is_dir():
        _fail('executor_account_mismatch', 'aws.os_home')
    for config_path in (home / '.terraformrc', home / 'terraform.rc',
                        home / 'AppData' / 'Roaming' / 'terraform.rc'):
        _no_alias(config_path, 'aws.terraform.config')
        if config_path.exists():
            _fail('ambient_configuration', 'aws.terraform.config')
    if os.name == 'posix':
        import pwd
        if Path(pwd.getpwuid(os.getuid()).pw_dir) != home or home.stat().st_uid != os.getuid():
            _fail('executor_account_mismatch', 'aws.os_home')
    for name in ('sso_config', 'sso_credentials'):
        _verify_pin(config[name])
    try:
        parser = configparser.RawConfigParser(interpolation=None, strict=True)
        parser.read_string(_file(config['sso_config']['path']).decode('utf-8'))
        credentials = configparser.RawConfigParser(interpolation=None, strict=True)
        credentials.read_string(_file(config['sso_credentials']['path']).decode('utf-8'))
        section = 'profile ' + config['profile']
        if credentials.sections() or credentials.defaults() or parser.defaults() or section not in parser:
            _fail('sso_required', 'aws.sso')
        profile = dict(parser[section])
        allowed = {'sso_session', 'sso_account_id', 'sso_role_name', 'region', 'output'}
        if set(profile) - allowed or not {'sso_session', 'sso_account_id', 'sso_role_name'}.issubset(profile):
            _fail('sso_required', 'aws.sso')
        session = 'sso-session ' + profile['sso_session']
        if set(parser.sections()) != {section, session}:
            _fail('sso_required', 'aws.sso')
        sso = dict(parser[session])
        if set(sso) - {'sso_start_url', 'sso_region', 'sso_registration_scopes'} or not {'sso_start_url', 'sso_region'}.issubset(sso):
            _fail('sso_required', 'aws.sso')
        if not re.fullmatch(r'https://[A-Za-z0-9.-]+\.awsapps\.com/start/?', sso['sso_start_url']):
            _fail('sso_required', 'aws.sso')
        if profile['sso_account_id'] != identity['account_id'] or profile.get('region', identity['region']) != identity['region']:
            _fail('target_identity_mismatch', 'aws.sso')
        role = identity['role_arn'].rsplit('/', 1)[-1]
        if not (role == profile['sso_role_name'] or role.startswith('AWSReservedSSO_' + profile['sso_role_name'] + '_')):
            _fail('target_identity_mismatch', 'aws.sso')
    except (configparser.Error, UnicodeError, KeyError):
        _fail('sso_required', 'aws.sso')
    cache = home / '.aws' / 'sso' / 'cache'
    _no_alias(cache, 'aws.sso.cache')
    if not cache.is_dir():
        _fail('sso_session_required', 'aws.sso.cache')
    # Inspect only this dedicated SSO cache; no user profile/credential discovery.
    for item in cache.iterdir():
        _no_alias(item, 'aws.sso.cache')
        if not item.is_file() or item.stat().st_nlink != 1:
            _fail('unsafe_file', 'aws.sso.cache')
    environment = {
        'HOME': str(home), 'USERPROFILE': str(home), 'AWS_PROFILE': config['profile'],
        'AWS_REGION': identity['region'], 'AWS_DEFAULT_REGION': identity['region'],
        'AWS_CONFIG_FILE': config['sso_config']['path'],
        'AWS_SHARED_CREDENTIALS_FILE': config['sso_credentials']['path'],
        'AWS_SDK_LOAD_CONFIG': '1', 'AWS_EC2_METADATA_DISABLED': 'true',
        'AWS_MAX_ATTEMPTS': '1', 'AWS_RETRY_MODE': 'standard', 'AWS_PAGER': '',
        'AWS_CLI_AUTO_PROMPT': 'off', 'TF_PLUGIN_CACHE_DIR': '', 'CHECKPOINT_DISABLE': '1',
    }
    # SDK trust stores and native binaries use OS system directories, never caller PATH.
    if os.name == 'nt':
        system = os.environ.get('SystemRoot', '')
        if not Path(system).is_absolute():
            _fail('missing_prerequisite', 'aws.system_root')
        environment.update(SystemRoot=system, WINDIR=system, PATH=str(Path(system) / 'System32'))
    else:
        environment['PATH'] = '/usr/bin:/bin'
        environment['LANG'] = 'C.UTF-8'
    return environment


class _Session:
    def __init__(self, manifest, config, identity, binary, context, transport, seconds, byte_limit):
        self.manifest = manifest
        self.config = config
        self.identity = identity
        self.binary = binary
        self.context = context
        self.transport = transport
        self.export_limit = byte_limit
        self.file_bytes = 0
        self.state_provenance = {}
        self.deadline = time.monotonic() + seconds
        self.byte_limit = min(byte_limit, 16 * 1024 * 1024)
        self.env = _environment(config, identity)
        self.mutated = False
        self.last_exit = None
        # Each pinned binary is hashed once per step; later calls compare file identity.
        self.pins = {}
        _verify_pin(binary, True, self.pins)

    def call(self, argv, json_result=True, optional=False, mutation=False):
        expiry = self.context.get('authorization_expires_utc')
        if expiry is not None and _utc(expiry) <= dt.datetime.now(UTC):
            _fail('authorization_expired', 'authorization.expires_utc')
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            _fail('phase_timeout', 'limits.max_phase_seconds')
        pins = [self.binary] + [self.config[name] for name in ('stratus', 'terraform') if name in self.config]
        selected = [pin for pin in pins if pin['path'] == argv[0]]
        if len(selected) != 1:
            _fail('unsupported_executable', 'aws.transport')
        _verify_pin(selected[0], True, self.pins)
        if mutation:
            self.mutated = True
        result = self.transport(argv, input_bytes=b'', env=dict(self.env), timeout=remaining,
                                max_output_bytes=self.byte_limit)
        if type(result.get('exit_code')) is int:
            self.last_exit = result['exit_code']
        if result.get('status') == 'unknown':
            _fail('transport_unknown', 'aws.transport')
        if result.get('status') != 'succeeded' or result.get('exit_code') != 0:
            if optional:
                return None
            _fail('transport_failed', 'aws.transport')
        data = result.get('stdout')
        if type(data) is not bytes or len(data) > self.byte_limit:
            _fail('output_limit', 'aws.transport')
        return decode_json(data) if json_result else data

    def aws(self, *arguments, **options):
        arguments = list(arguments)
        if arguments[0] == 's3api' and '--bucket' in arguments:
            arguments.extend(['--expected-bucket-owner', self.identity['account_id']])
        return self.call([self.binary['path']] + arguments + ['--output', 'json', '--no-cli-pager'], **options)

    def check_identity(self):
        identity = self.aws('sts', 'get-caller-identity')
        role = self.identity['role_arn'].rsplit('/', 1)[-1]
        expected = 'arn:aws:sts::{}:assumed-role/{}/{}'.format(self.identity['account_id'], role, self.identity['session_name'])
        if type(identity) is not dict or identity.get('Account') != self.identity['account_id'] or identity.get('Arn') != expected:
            _fail('target_identity_mismatch', 'aws.sts')
        version = self.call([self.binary['path'], '--version'], json_result=False)
        if version.decode('utf-8', 'replace').split(' ', 1)[0].strip() != self.binary['version']:
            _fail('unsupported_tool_version', 'aws.executable.version')

    def baseline(self, bucket=None):
        arn = self.identity['baseline_trail_arn']
        trail = self.aws('cloudtrail', 'get-trail', '--name', arn).get('Trail', {})
        if trail.get('TrailARN') != arn or not trail.get('S3BucketName') or (bucket is not None and trail.get('S3BucketName') != bucket):
            _fail('baseline_identity_mismatch', 'aws.baseline')
        status = self.aws('cloudtrail', 'get-trail-status', '--name', arn)
        if status.get('IsLogging') is not True:
            _fail('baseline_not_logging', 'aws.baseline')
        return trail['S3BucketName']

    def retention(self, bucket):
        versioning = self.aws('s3api', 'get-bucket-versioning', '--bucket', bucket, optional=True)
        lock = self.aws('s3api', 'get-object-lock-configuration', '--bucket', bucket, optional=True)
        if not versioning or not lock:
            return False
        config = lock.get('ObjectLockConfiguration', {})
        rule = config.get('Rule', {}).get('DefaultRetention', {})
        duration = rule.get('Days', 0) or rule.get('Years', 0)
        return versioning.get('Status') == 'Enabled' and config.get('ObjectLockEnabled') == 'Enabled' and rule.get('Mode') == 'COMPLIANCE' and type(duration) is int and duration > 0

    def state_root(self):
        correlation = self.context.get('aws_correlation_id')
        try:
            if type(correlation) is not str or str(uuid.UUID(correlation)) != correlation:
                raise ValueError()
        except (ValueError, AttributeError):
            _fail('missing_correlation_identity', 'aws.correlation')
        root = Path(self.config['os_home']) / '.stratus-red-team' / TECHNIQUE / correlation
        _no_alias(root, 'aws.state')
        self.env['STRATUS_RED_TEAM_CORRELATION_ID'] = correlation
        self.env['STRATUS_TERRAFORM_BINARY_PATH'] = self.config['terraform']['path']
        return root

    def tools(self):
        for name in ('stratus', 'terraform', 'provenance'):
            _verify_pin(self.config[name], name != 'provenance', self.pins)
        provenance = decode_json(_file(self.config['provenance']['path']))
        expected = {'source_commit': SOURCE_COMMIT,
                    'stratus_sha256': self.config['stratus']['sha256'],
                    'stratus_version': self.config['stratus']['version'],
                    'terraform_sha256': self.config['terraform']['sha256'],
                    'terraform_version': self.config['terraform']['version']}
        if provenance != expected:
            _fail('unsupported_tool_version', 'aws.provenance')
        version = self.call([self.config['terraform']['path'], 'version', '-json'])
        if version.get('terraform_version') != self.config['terraform']['version']:
            _fail('unsupported_tool_version', 'aws.terraform.version')

    def stratus(self, phase, mutation=False):
        if phase not in ('warmup', 'detonate', 'cleanup', 'status'):
            _fail('unsupported_phase', 'aws.stratus')
        return self.call([self.config['stratus']['path'], phase, TECHNIQUE], json_result=False, mutation=mutation)

    def resources(self, root):
        data = _file(root / 'terraform.tfstate')
        state = decode_json(data)
        if type(state) is not dict or state.get('version') != 4 or type(state.get('resources')) is not list:
            _fail('unsupported_state_schema', 'aws.state')
        found = {}
        for resource in state['resources']:
            if resource.get('mode') != 'managed':
                continue
            kind = resource.get('type')
            if kind not in ('aws_cloudtrail', 'aws_s3_bucket'):
                continue
            expected_name = {'aws_cloudtrail': 'trail', 'aws_s3_bucket': 'cloudtrail'}[kind]
            if resource.get('name') != expected_name:
                _fail('resource_identity_mismatch', 'aws.state')
            if kind in found or resource.get('module') or len(resource.get('instances', [])) != 1:
                _fail('ambiguous_resource_ownership', 'aws.state')
            instance = resource['instances'][0]
            if 'deposed' in instance:
                _fail('ambiguous_resource_ownership', 'aws.state')
            found[kind] = instance.get('attributes', {})
        if set(found) != {'aws_cloudtrail', 'aws_s3_bucket'}:
            _fail('missing_resource_identity', 'aws.state')
        trail, bucket = found['aws_cloudtrail'], found['aws_s3_bucket']
        name, bucket_name = trail.get('name'), bucket.get('bucket')
        _match(name, r'[A-Za-z0-9_.-]{3,128}', 'aws.state.trail')
        _match(bucket_name, r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', 'aws.state.bucket')
        suffix = 'stratus-red-team-ct-stop-' + self.context['aws_correlation_id'][:8]
        if not name.endswith(suffix + '-trail'):
            _fail('resource_identity_mismatch', 'aws.state.trail')
        prefix = name[:-len(suffix + '-trail')]
        if bucket_name != prefix + suffix + '-bucket':
            _fail('resource_identity_mismatch', 'aws.state.bucket')
        arn = 'arn:aws:cloudtrail:{}:{}:trail/{}'.format(self.identity['region'], self.identity['account_id'], name)
        if trail.get('arn') != arn or trail.get('s3_bucket_name') != bucket_name or bucket.get('arn') != 'arn:aws:s3:::' + bucket_name or arn == self.identity['baseline_trail_arn']:
            _fail('resource_identity_mismatch', 'aws.state')
        outputs = state.get('outputs', {})
        if outputs.get('cloudtrail_trail_name', {}).get('value') != name:
            _fail('resource_identity_mismatch', 'aws.state.outputs')
        state_hash = self.preserve_snapshot('state', data)
        lock = root / '.terraform.lock.hcl'
        _no_alias(lock, 'aws.terraform.lock')
        self.state_provenance['aws_terraform_lock_sha256'] = (
            self.preserve_snapshot('terraform-lock', _file(lock)) if lock.exists() else None)
        return {'trail_arn': arn, 'trail_name': name, 'bucket': bucket_name,
                'state_sha256': state_hash}

    def preserve_snapshot(self, kind, data):
        private = Path(self.context['private_root'])
        _no_alias(private, 'aws.private_root')
        if not private.is_absolute() or not private.is_dir():
            _fail('unsafe_path', 'aws.private_root')
        digest = hashlib.sha256(data).hexdigest()
        path = private / ('aws-' + kind + '-' + digest + '.bin')
        _no_alias(path, 'aws.snapshot')
        try:
            with path.open('xb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            if _file(path) != data:
                _fail('snapshot_changed', 'aws.snapshot')
        return digest

    def target_logging(self, resources, expected):
        trail = self.aws('cloudtrail', 'get-trail', '--name', resources['trail_arn']).get('Trail', {})
        if trail.get('TrailARN') != resources['trail_arn'] or trail.get('S3BucketName') != resources['bucket']:
            _fail('resource_identity_mismatch', 'aws.trail')
        status = self.aws('cloudtrail', 'get-trail-status', '--name', resources['trail_arn'])
        if status.get('IsLogging') is not expected:
            _fail('effect_not_verified', 'aws.trail.IsLogging')

    def absent(self, resources):
        trails = self.aws('cloudtrail', 'describe-trails', '--trail-name-list', resources['trail_arn'], '--no-include-shadow-trails')
        if trails.get('trailList') != []:
            _fail('cleanup_not_verified', 'aws.trail')
        token = None
        seen = set()
        while True:
            args = ['s3api', 'list-buckets', '--max-buckets', '1000', '--prefix', resources['bucket']]
            if token:
                args.extend(['--continuation-token', token])
            page = self.aws(*args)
            if type(page.get('Buckets')) is not list:
                _fail('unsupported_source_schema', 'aws.buckets')
            if any(bucket.get('Name') == resources['bucket'] for bucket in page['Buckets']):
                _fail('cleanup_not_verified', 'aws.bucket')
            token = page.get('ContinuationToken')
            if not token:
                return
            if type(token) is not str or token in seen:
                _fail('invalid_pagination', 'aws.buckets')
            seen.add(token)


def _result(outcome, observed=None, evidence=None, updates=None, exports=None):
    return {'execution_outcome': outcome, 'observed_target_sha256': observed,
            'effect_verified': outcome == 'succeeded', 'evidence': evidence or {},
            'raw_exports': exports or [], 'context_updates': updates or {}}


def _reconciled_cleanup(manifest, context):
    for item in reversed(context.get('reconciled_steps', [])):
        if item.get('phase') != 'run' or item.get('step_id') not in ('warmup', 'detonate') or item.get('outcome') not in ('completed', 'failed'):
            continue
        observation = item.get('observation', {})
        resources = observation.get('aws_resources')
        logging = observation.get('aws_target_logging')
        if type(resources) is not dict or set(resources) != {'trail_arn', 'trail_name', 'bucket', 'state_sha256'} or type(logging) is not bool:
            continue
        evidence = {'aws_resources': resources, 'aws_target_logging': logging}
        if (observation.get('effect_verified') is not True
                or observation.get('observed_target_sha256') != hashlib.sha256(canonical_bytes(manifest['targets'])).hexdigest()
                or observation.get('source_receipt_sha256') != hashlib.sha256(canonical_bytes(evidence)).hexdigest()
                or _utc(observation.get('observed_utc')) > dt.datetime.now(UTC)):
            _fail('reconciliation_evidence_mismatch', 'aws.reconciliation')
        return evidence
    return None


def _owned_resources(session, root):
    resources = session.resources(root)
    previous = session.context.get('aws_resources')
    if type(previous) is not dict or any(resources.get(key) != previous.get(key) for key in ('trail_arn', 'trail_name', 'bucket', 'state_sha256')):
        _fail('resource_identity_mismatch', 'aws.context')
    return resources


def _execute_action(session, phase, step_id):
    root = session.state_root()
    session.tools()
    session.check_identity()
    baseline_bucket = session.baseline()
    updates = {'aws_baseline_healthy': True}
    if phase == 'preflight' and step_id == 'identity':
        if root.exists():
            _fail('state_already_exists', 'aws.state')
        updates['aws_retention_verified'] = session.retention(baseline_bucket)
        return {'identity_verified': True, 'baseline_logging': True}, updates
    if phase == 'run' and step_id == 'warmup':
        if root.exists():
            _fail('state_already_exists', 'aws.state')
        session.stratus('warmup', mutation=True)
        session.stratus('status')
        resources = session.resources(root)
        if resources['bucket'] == baseline_bucket:
            _fail('shared_bucket_forbidden', 'aws.state.bucket')
        session.target_logging(resources, True)
        session.baseline(baseline_bucket)
        updates.update(aws_resources=resources, aws_warmup_verified=True)
        return {'target_logging': True, 'baseline_logging': True}, updates
    if phase == 'run' and step_id == 'detonate':
        if session.context.get('aws_warmup_verified') is not True:
            _fail('warmup_not_verified', 'aws.state')
        resources = _owned_resources(session, root)
        if resources['bucket'] == baseline_bucket:
            _fail('shared_bucket_forbidden', 'aws.state.bucket')
        session.target_logging(resources, True)
        session.stratus('detonate', mutation=True)
        session.stratus('status')
        session.target_logging(resources, False)
        session.baseline(baseline_bucket)
        # Preserve the post-phase Terraform snapshot identity for exact cleanup.
        after = session.resources(root)
        if any(after[key] != resources[key] for key in ('trail_arn', 'trail_name', 'bucket')):
            _fail('resource_identity_mismatch', 'aws.state')
        updates.update(aws_resources=after, aws_stop_verified=True)
        return {'target_logging_before': True, 'target_logging_after': False, 'baseline_logging': True}, updates
    if phase == 'cleanup' and step_id == 'cleanup':
        recovery = _reconciled_cleanup(session.manifest, session.context)
        if recovery is not None:
            resources = session.resources(root)
            if resources != recovery['aws_resources']:
                _fail('reconciliation_evidence_mismatch', 'aws.state')
        else:
            resources = _owned_resources(session, root)
        if resources['bucket'] == baseline_bucket:
            _fail('shared_bucket_forbidden', 'aws.state.bucket')
        logging = recovery['aws_target_logging'] if recovery is not None else session.context.get('aws_stop_verified') is not True
        session.target_logging(resources, logging)
        retained = session.retention(baseline_bucket)
        warmup_only_preserved = (recovery is None
                                 and session.context.get('aws_warmup_verified') is True
                                 and session.context.get('aws_stop_verified') is not True
                                 and session.context.get('aws_raw_preserved') is True)
        if session.context.get('aws_stop_exported') is not True and not retained and not warmup_only_preserved:
            _fail('independent_export_required', 'aws.cleanup')
        session.stratus('cleanup', mutation=True)
        session.stratus('status')
        session.absent(resources)
        session.baseline(baseline_bucket)
        updates.update(aws_cleanup_verified=True, aws_retention_verified=retained)
        return {'owned_trail_absent': True, 'owned_bucket_absent': True, 'baseline_logging': True}, updates
    _fail('unsupported_phase', 'aws.phase')


def _dates(window):
    start, end = _utc(window['start_inclusive']), _utc(window['end_exclusive'])
    if start >= end or end - start > dt.timedelta(days=31):
        _fail('invalid_window', 'collectors.window_utc')
    current = start.date()
    last = (end - dt.timedelta(microseconds=1)).date()
    result = []
    while current <= last:
        result.append(current.strftime('%Y/%m/%d/'))
        current += dt.timedelta(days=1)
    return result


def _inflate(data, limit):
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        result = decoder.decompress(data, limit + 1)
        if len(result) > limit or decoder.unconsumed_tail:
            _fail('output_limit', 'collectors.gzip')
        if not decoder.eof or decoder.unused_data:
            _fail('invalid_gzip', 'collectors.gzip')
        return result
    except zlib.error:
        _fail('invalid_gzip', 'collectors.gzip')


def _stop_event(record, resources, identity):
    if not resources or record.get('eventSource') != 'cloudtrail.amazonaws.com' or record.get('eventName') != 'StopLogging' or record.get('errorCode') is not None:
        return False
    request = record.get('requestParameters')
    return (type(request) is dict and request.get('name') in (resources['trail_name'], resources['trail_arn'])
            and record.get('recipientAccountId') == identity['account_id'] and record.get('awsRegion') == identity['region'])


def _watermark(session, collector, destination):
    key = collector['config']['watermark_key']
    metadata = session.aws('s3api', 'head-object', '--bucket', collector['bucket'], '--key', key, optional=True)
    if metadata is None:
        return None, None
    size, etag = metadata.get('ContentLength'), metadata.get('ETag')
    if type(size) is not int or not 0 < size <= 4096 or type(etag) is not str or not re.fullmatch(r'"[0-9a-fA-F]{32}(?:-[0-9]+)?"', etag):
        _fail('unsupported_source_schema', 'collectors.watermark')
    if session.file_bytes + size > session.export_limit:
        _fail('output_limit', 'collectors.max_bytes')
    session.file_bytes += size
    path = destination / ('watermark-' + uuid.uuid4().hex + '.json')
    response = session.aws('s3api', 'get-object', '--bucket', collector['bucket'], '--key', key,
                           '--if-match', etag, '--range', 'bytes=0-{}'.format(size - 1), str(path))
    data = _file(path, 4096)
    if len(data) != size or response.get('ETag') != etag:
        _fail('object_changed', 'collectors.watermark')
    marker = decode_json(data)
    _fields(marker, {'schema_version', 'window_utc', 'watermark_utc'}, 'collectors.watermark')
    if type(marker['schema_version']) is not int or marker['schema_version'] != 1 or marker['window_utc'] != collector['window_utc']:
        _fail('unsupported_source_schema', 'collectors.watermark')
    value = marker['watermark_utc']
    if value is not None and _utc(value) > dt.datetime.now(UTC):
        _fail('future_watermark', 'collectors.watermark')
    return value, hashlib.sha256(data).hexdigest()


def _collect(session, collector, readiness=False):
    session.check_identity()
    bucket = session.baseline(collector['bucket'])
    updates = {'aws_baseline_healthy': True, 'aws_retention_verified': session.retention(bucket)}
    dates = _dates(collector['window_utc'])
    private = Path(session.context['private_root'])
    _no_alias(private, 'collectors.private_root')
    if not private.is_absolute() or not private.is_dir():
        _fail('unsafe_path', 'collectors.private_root')
    destination = private / ('aws-objects-' + uuid.uuid4().hex)
    destination.mkdir(mode=0o700)
    watermark, watermark_hash = _watermark(session, collector, destination)
    if readiness:
        if watermark_hash is None:
            _fail('missing_watermark_prerequisite', 'collectors.watermark')
        session.aws('s3api', 'list-objects-v2', '--bucket', bucket, '--prefix', collector['prefix'] + dates[0], '--max-keys', '1', '--no-paginate')
        return {'collector_identity_verified': True, 'baseline_logging': True}, updates, []
    decoded_total = 0
    seen = set()
    content_seen = set()
    event_records = {}
    byte_limit = min(collector['max_bytes'], session.manifest['limits']['max_export_bytes'])
    records = []
    object_proofs = []
    stop_found = False
    filtered = 0
    from benchmark_evidence import supported_cloudtrail_events
    allowed_events = supported_cloudtrail_events()
    start, end = (_utc(collector['window_utc'][key]) for key in ('start_inclusive', 'end_exclusive'))
    require_stop = session.manifest.get('recipe_id') == RECIPE and session.context.get('aws_stop_verified') is True
    while True:
        for date in dates:
            prefix = collector['prefix'] + date
            token = None
            tokens = set()
            while True:
                args = ['s3api', 'list-objects-v2', '--bucket', bucket, '--prefix', prefix, '--max-keys', '1000', '--no-paginate']
                if token:
                    args.extend(['--continuation-token', token])
                page = session.aws(*args)
                if type(page) is not dict or type(page.get('Contents', [])) is not list or type(page.get('IsTruncated')) is not bool:
                    _fail('unsupported_source_schema', 'collectors.list')
                for item in page.get('Contents', []):
                    key, etag, size = item.get('Key'), item.get('ETag'), item.get('Size')
                    if type(key) is not str or not key.startswith(prefix) or '/' in key[len(prefix):] or not key.endswith('.json.gz') or '..' in key[len(prefix):]:
                        _fail('object_outside_window', 'collectors.key')
                    if type(etag) is not str or not re.fullmatch(r'"[0-9a-fA-F]{32}(?:-[0-9]+)?"', etag) or type(size) is not int or size <= 0:
                        _fail('unsupported_source_schema', 'collectors.object')
                    marker = (key, etag)
                    if marker in seen:
                        continue
                    if session.file_bytes + size > byte_limit:
                        _fail('output_limit', 'collectors.max_bytes')
                    path = destination / (uuid.uuid4().hex + '.json.gz')
                    response = session.aws('s3api', 'get-object', '--bucket', bucket, '--key', key,
                                           '--if-match', etag, '--range', 'bytes=0-{}'.format(size - 1), str(path))
                    data = _file(path, size)
                    if len(data) != size or response.get('ContentLength') != size or response.get('ETag') != etag:
                        _fail('object_changed', 'collectors.object')
                    content_hash = hashlib.sha256(data).hexdigest()
                    proof = {'key_sha256': hashlib.sha256(key.encode('utf-8')).hexdigest(), 'etag': etag,
                             'version_id': response.get('VersionId'), 'sha256': content_hash, 'byte_count': size}
                    if proof['version_id'] is not None and type(proof['version_id']) is not str:
                        _fail('unsupported_source_schema', 'collectors.object')
                    seen.add(marker)
                    session.file_bytes += size
                    object_proofs.append(proof)
                    if content_hash in content_seen:
                        continue
                    content_seen.add(content_hash)
                    decoded = _inflate(data, byte_limit - decoded_total)
                    decoded_total += len(decoded)
                    document = decode_json(decoded)
                    if type(document) is not dict or set(document) != {'Records'} or type(document['Records']) is not list:
                        _fail('unsupported_source_schema', 'collectors.cloudtrail')
                    for record in document['Records']:
                        if type(record) is not dict or type(record.get('eventID')) is not str or type(record.get('eventVersion')) is not str or not record['eventVersion'].startswith('1.'):
                            _fail('unsupported_source_schema', 'collectors.cloudtrail')
                        event_time = _utc(record.get('eventTime'))
                        if not start <= event_time < end:
                            continue
                        if record.get('recipientAccountId') != session.identity['account_id'] or record.get('awsRegion') != session.identity['region']:
                            _fail('target_identity_mismatch', 'collectors.cloudtrail')
                        previous = event_records.get(record['eventID'])
                        if previous is not None and previous != record:
                            _fail('conflicting_event_identity', 'collectors.cloudtrail')
                        stop_found = stop_found or _stop_event(record, session.context.get('aws_resources'), session.identity)
                        if previous is None:
                            event_records[record['eventID']] = record
                            # Only event names the sealer can map are exported; the filter is
                            # recorded with the export, and the excluded count in evidence.
                            if record.get('eventName') in allowed_events:
                                records.append(record)
                            else:
                                filtered += 1
                if not page['IsTruncated']:
                    break
                token = page.get('NextContinuationToken')
                if type(token) is not str or not token or token in tokens:
                    _fail('invalid_pagination', 'collectors.list')
                tokens.add(token)
        current_watermark, current_hash = _watermark(session, collector, destination)
        if watermark is not None and (current_watermark is None or _utc(current_watermark) < _utc(watermark)):
            _fail('watermark_regressed', 'collectors.watermark')
        watermark, watermark_hash = current_watermark, current_hash
        complete = watermark is not None and _utc(watermark) >= end and (not require_stop or stop_found)
        if complete:
            break
        remaining = session.deadline - time.monotonic()
        if remaining <= session.config['poll_seconds'] + 1:
            break
        time.sleep(session.config['poll_seconds'])
    baseline_failure = None
    try:
        session.baseline(bucket)
    except BenchmarkError as error:
        baseline_failure = error.code
        complete = False
        updates['aws_baseline_healthy'] = False
    if stop_found:
        updates['aws_stop_exported'] = True
    updates['aws_raw_preserved'] = True
    records.sort(key=lambda record: (record['eventTime'], record['eventID']))
    exports = [{'source_id': collector['source_id'], 'records': records,
                'window_utc': collector['window_utc'], 'watermark_utc': watermark, 'complete': complete,
                'filter': {'event_names': allowed_events}}]
    evidence = {'objects': object_proofs, 'record_count': len(records), 'stop_logging_exported': stop_found,
                'watermark_sha256': watermark_hash, 'complete': complete,
                'filtered_record_count': filtered}
    if not complete:
        evidence['failure_reason'] = baseline_failure or 'incomplete_export'
    return evidence, updates, exports


def execute_step(manifest, range_kit, phase, step_id, context, transport):
    """Execute one already-reserved fixed step; failures never trigger retries.

    The controller supplies a transport with its durable process-start callback.
    Raw records and downloaded gzip objects remain in evaluator-private storage.
    A mutation followed by any uncertain observation is quarantined as unknown.
    """
    session = None
    observed = None
    try:
        if phase != 'preflight' and context.get('authorization_expires_utc') is None:
            _fail('authorization_required', 'authorization.expires_utc')
        if phase == 'run' and _utc(manifest['limits']['latest_cleanup_utc']) <= dt.datetime.now(UTC):
            _fail('cleanup_deadline_passed', 'limits.latest_cleanup_utc')
        collector = context.get('collector')
        if collector is not None:
            validate_collector(manifest, collector)
            if phase not in ('collect', 'preflight') or step_id != collector['source_id']:
                _fail('unsupported_phase', 'collectors.phase')
            config = collector['config']
            identity = {key: config[key] for key in IDENTITY_FIELDS}
            session = _Session(manifest, config, identity, config['executable'], context, transport,
                               min(collector['max_seconds'], manifest['limits']['max_phase_seconds']),
                               min(collector['max_bytes'], manifest['limits']['max_export_bytes']))
            evidence, updates, exports = _collect(session, collector, phase == 'preflight')
            targets = [target for target in manifest['targets'] if target['target_id'] == collector['target_id']]
            evidence['transport_exit'] = session.last_exit
            if updates.get('aws_baseline_healthy') is False:
                # Baseline logging failed: stop new work and require human reconciliation.
                observed = hashlib.sha256(canonical_bytes(targets)).hexdigest()
                return _result('unknown', observed, evidence, {}, exports)
            if evidence.get('complete') is False:
                observed = hashlib.sha256(canonical_bytes(targets)).hexdigest()
                return _result('blocked', observed, evidence, updates, exports)
        else:
            validate_configuration(manifest)
            executor = manifest['executor']
            session = _Session(manifest, executor['config'], manifest['targets'][0]['identity'], executor['executable'], context, transport,
                               manifest['limits']['max_phase_seconds'], manifest['limits']['max_export_bytes'])
            evidence, updates = _execute_action(session, phase, step_id)
            evidence['transport_exit'] = session.last_exit
            updates.update(session.state_provenance)
            exports = []
            targets = manifest['targets']
        observed = hashlib.sha256(canonical_bytes(targets)).hexdigest()
        return _result('succeeded', observed, evidence, updates, exports)
    except BenchmarkError as error:
        baseline = (phase != 'preflight' and session is not None
                    and error.code in ('baseline_not_logging', 'baseline_identity_mismatch'))
        unknown = session is not None and (session.mutated or error.code == 'transport_unknown' or baseline)
        return _result('unknown' if unknown else 'blocked', observed,
                       {'failure_reason': error.code, 'field': error.field,
                        'transport_exit': session.last_exit if session is not None else None})
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        unknown = session is not None and session.mutated
        return _result('unknown' if unknown else 'blocked', observed,
                       {'failure_reason': 'invalid_runtime_evidence', 'field': 'aws',
                        'transport_exit': session.last_exit if session is not None else None})
