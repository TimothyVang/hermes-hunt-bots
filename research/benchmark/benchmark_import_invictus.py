"""Import Invictus AWS CloudTrail Dataset as Mechanical `publisher_labels` Benchmark Cases.

Invictus AWS (`invictus-ir/aws_dataset`) contains real AWS CloudTrail `Records`
combining background Terraform/service operations with Stratus Red Team cloud
intrusion executions tagged mechanically in the raw logs via `stratus-red-team_<uuid>`
in `userAgent`.

Anti-leakage & sanitization rules:
- Raw `stratus-red-team_<uuid>` in `userAgent` is used ONLY in the importer to
  identify publisher-labeled attack executions, then replaced in `public/` with
  a realistic AWS SDK Go client string (`aws-sdk-go-v2/1.21.0 ...`).
- Every `[A-Za-z0-9_.-]*stratus[A-Za-z0-9_.-]*` resource/role/secret identifier
  anywhere in `userIdentity`, `requestParameters`, `responseElements`, or
  `resources` is pseudonymized via HMAC-SHA256 (`resource-<16hex>`), and an
  assertion verifies `'stratus'` never appears anywhere in `public/`.
- AWS 12-digit account IDs, ARNs, access keys, principals, and client IPs are
  pseudonymized consistently via `CasePseudonymizer`.
"""
import argparse
import datetime as dt
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import sys

import benchmark_paths  # noqa: F401
from benchmark_case_writer import (
    DEFAULT_COVERAGE, MAX_ARCHIVE_MEMBER_BYTES, CasePseudonymizer,
    derive_sophistication_band, format_utc, read_regular_bytes, write_curated_case,
)
from benchmark_contracts import BenchmarkError, decode_json, parse_utc

SOURCE_REF = 'https://github.com/invictus-ir/aws_dataset'

_STRATUS_UA_RE = re.compile(r'(?i)[^\s"]*stratus-red-team_[0-9a-f-]{8,64}[^\s"]*')
_STRATUS_TOKEN_RE = re.compile(r'(?i)[A-Za-z0-9_.-]*stratus[A-Za-z0-9_.-]*')
_ARN_RE = re.compile(r'arn:aws:[a-z0-9-]+:[a-z0-9-]*:([0-9]{12}|aws)?:([^\s"\',;\]}]+)')
_ACCOUNT_RE = re.compile(r'(?<![0-9A-Za-z])[0-9]{12}(?![0-9A-Za-z])')

NORMALIZED_SDK_UA = 'aws-sdk-go-v2/1.21.0 os/linux lang/go#1.20.5 md/GOOS#linux'

# Mechanical mapping of Stratus Red Team CloudTrail (eventSource, eventName) ->
# (step_group_key, ATT&CK v20 technique_id, plane_key, boundary_id, phase)
STRATUS_ACTION_MAP = {
    # IAM & Identity Privilege / Persistence
    ('iam.amazonaws.com', 'CreateUser'): ('iam-create-user', 'T1136.003', 'iam', 'bnd-cloud-identity', 'persistence'),
    ('iam.amazonaws.com', 'CreateLoginProfile'): ('iam-backdoor-creds', 'T1098.001', 'iam', 'bnd-cloud-privilege', 'persistence'),
    ('iam.amazonaws.com', 'CreateAccessKey'): ('iam-backdoor-creds', 'T1098.001', 'iam', 'bnd-cloud-privilege', 'persistence'),
    ('iam.amazonaws.com', 'AttachRolePolicy'): ('iam-role-escalation', 'T1098.003', 'iam', 'bnd-cloud-privilege', 'persistence'),
    ('iam.amazonaws.com', 'AttachUserPolicy'): ('iam-role-escalation', 'T1098.003', 'iam', 'bnd-cloud-privilege', 'persistence'),
    ('iam.amazonaws.com', 'PutRolePolicy'): ('iam-role-escalation', 'T1098.003', 'iam', 'bnd-cloud-privilege', 'persistence'),
    ('iam.amazonaws.com', 'UpdateAssumeRolePolicy'): ('iam-trust-policy', 'T1098.003', 'iam', 'bnd-cloud-identity', 'persistence'),
    ('sts.amazonaws.com', 'AssumeRole'): ('sts-assume-role', 'T1078.004', 'iam', 'bnd-cloud-identity', 'initial'),
    # Secrets & Credential Theft
    ('ec2.amazonaws.com', 'GetPasswordData'): ('ec2-password-data', 'T1552', 'compute', 'bnd-cloud-segment', 'initial'),
    ('secretsmanager.amazonaws.com', 'GetSecretValue'): ('secrets-harvest', 'T1555.006', 'storage', 'bnd-cloud-segment', 'initial'),
    ('ssm.amazonaws.com', 'GetParameter'): ('ssm-param-harvest', 'T1555.006', 'storage', 'bnd-cloud-segment', 'initial'),
    ('ssm.amazonaws.com', 'GetParameters'): ('ssm-param-harvest', 'T1555.006', 'storage', 'bnd-cloud-segment', 'initial'),
    # Execution & Serverless Persistence
    ('ssm.amazonaws.com', 'SendCommand'): ('ssm-remote-exec', 'T1651', 'compute', 'bnd-cloud-segment', 'reentry'),
    ('lambda.amazonaws.com', 'UpdateFunctionCode20150331v2'): ('lambda-backdoor', 'T1525', 'compute', 'bnd-cloud-segment', 'persistence'),
    # Defense Evasion (Audit / Flow Log Tampering)
    ('cloudtrail.amazonaws.com', 'StopLogging'): ('audit-impair-logging', 'T1562.008', 'audit', 'bnd-cloud-control', 'initial'),
    ('cloudtrail.amazonaws.com', 'DeleteTrail'): ('audit-impair-logging', 'T1562.008', 'audit', 'bnd-cloud-control', 'initial'),
    ('ec2.amazonaws.com', 'DeleteFlowLogs'): ('audit-impair-logging', 'T1562.008', 'audit', 'bnd-cloud-control', 'initial'),
    # Exfiltration / External Sharing
    ('ec2.amazonaws.com', 'ModifySnapshotAttribute'): ('snapshot-exfil', 'T1537', 'storage', 'bnd-cloud-segment', 'reentry'),
    ('rds.amazonaws.com', 'ModifyDBSnapshotAttribute'): ('snapshot-exfil', 'T1537', 'storage', 'bnd-cloud-segment', 'reentry'),
    ('s3.amazonaws.com', 'PutBucketPolicy'): ('s3-policy-exposure', 'T1537', 'storage', 'bnd-cloud-segment', 'initial'),
}


def _fail(code, field='invictus'):
    raise BenchmarkError(code, field) from None


def _plane_for_source(event_source):
    src = str(event_source or '').lower()
    if any(src.startswith(p) for p in ('iam.', 'sts.', 'signin.', 'rolesanywhere.', 'organizations.')):
        return 'iam'
    if any(src.startswith(p) for p in ('cloudtrail.', 'logs.')):
        return 'audit'
    if any(src.startswith(p) for p in ('s3.', 'secretsmanager.', 'rds.')):
        return 'storage'
    return 'compute'


_CLOUDTRAIL_SECRET_KEYS = frozenset({
    'password', 'newpassword', 'oldpassword', 'masteruserpassword', 'secretaccesskey',
    'sessiontoken', 'privatekey', 'certificatebody', 'certificatechain', 'secretstring',
    'secretbinary', 'clientsecret', 'plaintext', 'keymaterial', 'accesstoken',
    'refreshtoken', 'authtoken', 'apikey', 'credentials',
})


def _redact_cloudtrail_struct(value, depth=0):
    """Recursively redact structured CloudTrail secret keys before JSON serialization."""
    if depth > 24:
        return '[REDACTED:depth]'
    if isinstance(value, dict):
        cleaned = {}
        for k, v in value.items():
            key_norm = str(k).casefold().replace('-', '').replace('_', '')
            if key_norm in _CLOUDTRAIL_SECRET_KEYS:
                cleaned[str(k)] = '[REDACTED:secret]'
            else:
                cleaned[str(k)] = _redact_cloudtrail_struct(v, depth + 1)
        return cleaned
    if isinstance(value, list):
        return [_redact_cloudtrail_struct(item, depth + 1) for item in value]
    return value


def _scrub_aws_text(text, pseudo):
    if not text:
        return ''
    s = _STRATUS_UA_RE.sub(NORMALIZED_SDK_UA, str(text))

    def _replace_stratus(m):
        return pseudo.pseudonymize('resource', m.group(0))

    s = _STRATUS_TOKEN_RE.sub(_replace_stratus, s)

    def _replace_arn(m):
        acct = m.group(1)
        rest = m.group(2)
        acct_tok = pseudo.pseudonymize('account', acct) if acct and acct != 'aws' else (acct or '')
        rest_tok = pseudo.pseudonymize('resource', rest)
        return 'arn:aws:service:region:{}:{}'.format(acct_tok, rest_tok)

    s = _ARN_RE.sub(_replace_arn, s)
    s = _ACCOUNT_RE.sub(lambda m: pseudo.pseudonymize('account', m.group(0)), s)
    return pseudo.clean_content(s)


def import_invictus_case(
    json_files,
    output_root,
    *,
    split='development',
    control_only=False,
    ioc_regime='novel_apt_zero_ioc',
    extra_iocs=(),
    salt=None,
    case_seed='invictus-cloudtrail',
    max_records=450,
    coverage_path=DEFAULT_COVERAGE,
):
    if not json_files:
        _fail('invalid_array', 'json_files')
    pseudo = CasePseudonymizer(salt=salt)

    plane_assets = {
        'iam': pseudo.pseudonymize('resource', 'aws-iam-sts-plane'),
        'compute': pseudo.pseudonymize('resource', 'aws-compute-ssm-plane'),
        'storage': pseudo.pseudonymize('resource', 'aws-secrets-storage-plane'),
        'audit': pseudo.pseudonymize('resource', 'aws-audit-logging-plane'),
    }
    assets = [
        {
            'asset_id': plane_assets['iam'],
            'os_family': 'not-applicable',
            'os_version': None,
            'architecture': None,
            'vendor': 'AWS IAM and STS Control Plane',
        },
        {
            'asset_id': plane_assets['compute'],
            'os_family': 'not-applicable',
            'os_version': None,
            'architecture': None,
            'vendor': 'AWS EC2, SSM, and Lambda Plane',
        },
        {
            'asset_id': plane_assets['storage'],
            'os_family': 'not-applicable',
            'os_version': None,
            'architecture': None,
            'vendor': 'AWS Secrets Manager, S3, and RDS Plane',
        },
        {
            'asset_id': plane_assets['audit'],
            'os_family': 'not-applicable',
            'os_version': None,
            'architecture': None,
            'vendor': 'AWS CloudTrail and CloudWatch Audit Plane',
        },
    ]

    combined_hash = hashlib.sha256()
    loaded_records = []
    for file_idx, fpath in enumerate(sorted(Path(p) for p in json_files), 1):
        fsha, raw_bytes = read_regular_bytes(fpath, field=fpath.name)
        combined_hash.update(raw_bytes)
        if fpath.name.lower().endswith('.gz'):
            chunks = []
            total_unz = 0
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(raw_bytes)) as gz_fh:
                    while True:
                        chunk = gz_fh.read(65536)
                        if not chunk:
                            break
                        total_unz += len(chunk)
                        if total_unz > MAX_ARCHIVE_MEMBER_BYTES:
                            _fail('member_too_large', fpath.name)
                        chunks.append(chunk)
            except OSError:
                _fail('invalid_archive', fpath.name)
            json_bytes = b''.join(chunks)
        else:
            json_bytes = raw_bytes
        doc = decode_json(json_bytes)
        recs = doc.get('Records', []) if isinstance(doc, dict) else doc
        if not isinstance(recs, list):
            _fail('invalid_array', fpath.name)
        for idx, rec in enumerate(recs, 1):
            is_stratus = 'stratus-red-team' in str(rec.get('userAgent') or '').lower()
            if control_only and is_stratus:
                _fail('unexpected_attack_in_control', fpath.name)
            loaded_records.append((file_idx, idx, fsha, rec, is_stratus))

    subsampled = False
    # Keep all mapped Stratus attack records first, then fill background records up to max_records
    if len(loaded_records) > max_records:
        subsampled = True
        mapped = [
            item for item in loaded_records
            if item[4] and (item[3].get('eventSource'), item[3].get('eventName')) in STRATUS_ACTION_MAP
        ]
        others = [
            item for item in loaded_records
            if not (item[4] and (item[3].get('eventSource'), item[3].get('eventName')) in STRATUS_ACTION_MAP)
        ]
        keep_other = max(0, max_records - len(mapped))
        stride = max(1, len(others) // max(keep_other, 1))
        sampled_others = others[::stride][:keep_other]
        loaded_records = mapped + sampled_others

    sources = [{
        'source_id': 'aws-cloudtrail-us-east-1',
        'asset_ids': [plane_assets['iam'], plane_assets['compute'], plane_assets['storage'], plane_assets['audit']],
        'telemetry': 'cloud-audit',
        'clock_offset_seconds': 0.0,
        'clock_uncertainty_seconds': 1.0,
        'sensor_version': 'AWS-CloudTrail-1.08',
        'config_version': 'management-events',
        'completeness': 'partial' if subsampled else 'complete',
        'source_sha256': combined_hash.hexdigest(),
    }]

    raw_events = []
    grouped_steps = {}
    lookalike_tags = []

    for file_idx, idx, fsha, rec, is_stratus in loaded_records:
        ts_raw = str(rec.get('eventTime') or '')
        stamp = parse_utc(ts_raw, 'cloudtrail.eventTime')
        esrc = str(rec.get('eventSource') or 'aws.amazonaws.com')
        ename = str(rec.get('eventName') or 'UnknownOperation')
        action_pair = (esrc, ename)

        if is_stratus and action_pair in STRATUS_ACTION_MAP:
            skey, tech_id, plane, bnd_id, phase = STRATUS_ACTION_MAP[action_pair]
        else:
            skey = None
            plane = _plane_for_source(esrc)
            if esrc == 'ssm.amazonaws.com' and ename in ('GetParameter', 'GetParameters', 'PutParameter'):
                plane = 'storage'

        asset_id = plane_assets[plane]
        tag = 'f{}:{}'.format(file_idx, idx)

        uid = rec.get('userIdentity') or {}
        raw_ua = str(rec.get('userAgent') or '')
        clean_ua = _scrub_aws_text(raw_ua, pseudo)
        req_params = _scrub_aws_text(
            json.dumps(_redact_cloudtrail_struct(rec.get('requestParameters')), sort_keys=True)
            if rec.get('requestParameters') else '',
            pseudo,
        )
        resp_elems = _scrub_aws_text(
            json.dumps(_redact_cloudtrail_struct(rec.get('responseElements')), sort_keys=True)
            if rec.get('responseElements') else '',
            pseudo,
        )
        principal_str = _scrub_aws_text(
            str(uid.get('arn') or uid.get('principalId') or uid.get('userName') or uid.get('type') or ''),
            pseudo,
        )

        fields = {
            'timestamp_original': ts_raw,
            'event_source': esrc,
            'event_name': ename,
            'aws_region': str(rec.get('awsRegion') or 'us-east-1'),
            'identity_type': str(uid.get('type') or 'Unknown'),
            'principal': principal_str or 'aws-service',
            'source_ip': _scrub_aws_text(str(rec.get('sourceIPAddress') or ''), pseudo) or '0.0.0.0',
            'user_agent': clean_ua or 'aws-internal',
        }
        if rec.get('errorCode'):
            fields['error_code'] = pseudo.clean_content(str(rec['errorCode']))
        if rec.get('errorMessage'):
            fields['error_message'] = _scrub_aws_text(str(rec['errorMessage']), pseudo)
        if req_params:
            fields['request_parameters'] = req_params
        if resp_elems:
            fields['response_elements'] = resp_elems

        raw_events.append({
            'tag': tag,
            'timestamp_utc': format_utc(stamp),
            'source_id': 'aws-cloudtrail-us-east-1',
            'asset_id': asset_id,
            'event_type': '{}:{}'.format(esrc.split('.')[0], ename),
            'fields': fields,
            'record_id': str(rec.get('eventID') or tag),
            'file_sha256': fsha,
        })

        if skey is not None:
            entry = grouped_steps.setdefault(skey, {
                'step_id': 'step-' + skey,
                'technique_id': tech_id,
                'asset_id': asset_id,
                'boundary_id': bnd_id,
                'phase': phase,
                'support_tags': [],
                'first_stamp': stamp,
            })
            entry['support_tags'].append(tag)
            if stamp < entry['first_stamp']:
                entry['first_stamp'] = stamp
        elif not is_stratus and ename in ('AssumeRole', 'GetCallerIdentity', 'DescribeInstances'):
            lookalike_tags.append(tag)

    ordered_steps = sorted(grouped_steps.values(), key=lambda x: (x['first_stamp'], x['step_id']))
    step_specs = []
    for st in ordered_steps:
        step_specs.append({
            'step_id': st['step_id'],
            'technique_id': st['technique_id'],
            'asset_id': st['asset_id'],
            'boundary_id': st['boundary_id'],
            'phase': st['phase'],
            'support_tags': st['support_tags'],
        })

    edges = []
    for i in range(len(step_specs) - 1):
        edges.append([step_specs[i]['step_id'], step_specs[i + 1]['step_id']])

    boundaries = [
        {'boundary_id': 'bnd-cloud-identity', 'kind': 'identity'},
        {'boundary_id': 'bnd-cloud-privilege', 'kind': 'privilege'},
        {'boundary_id': 'bnd-cloud-segment', 'kind': 'segment'},
        {'boundary_id': 'bnd-cloud-control', 'kind': 'cloud'},
    ]
    is_ctrl = bool(control_only or not step_specs)
    soph_band = derive_sophistication_band(step_specs, boundaries, control_case=is_ctrl)
    if soph_band in ('S0', 'S1'):
        edges = []

    known_gaps = []
    if subsampled and raw_events:
        ev_stamps = sorted(parse_utc(e['timestamp_utc'], 'ev') for e in raw_events)
        g0 = ev_stamps[0]
        g1 = max(ev_stamps[-1], g0 + dt.timedelta(seconds=1))
        known_gaps.append({
            'source_id': 'aws-cloudtrail-us-east-1',
            'asset_id': plane_assets['iam'],
            'window_utc': {'start_inclusive': format_utc(g0), 'end_exclusive': format_utc(g1)},
            'reason': 'source_subsampled: background management events were stride-sampled to fit inline bundle limits.',
        })

    coverage_tags = {
        'os': ['not-applicable'],
        'execution_platform': ['cloud-control-plane', 'serverless'],
        'network': ['cloud-vpc', 'encrypted-traffic', 'ipv4'],
        'identity_domain': ['cloud-iam', 'machine-service-identity'],
        'operational_domain': ['cloud-saas', 'enterprise-it'],
        'dns_domain': ['owned-public-zone'],
        'telemetry': ['cloud-audit'],
    }
    difficulty_factors = {
        'noise': {'score': 1 if control_only else 2, 'rationale': 'Concurrent AWS Terraform/service reconnaissance and Describe* calls interleave with mutating APIs.'},
        'joins': {'score': 0 if control_only else 2, 'rationale': 'Requires joining assumed-role sessions across IAM, EC2, Secrets Manager, SSM, and CloudTrail planes.'},
        'time_span': {'score': 1, 'rationale': 'Multi-minute cloud API burst window.'},
        'gaps': {'score': 1, 'rationale': 'S3 data-event object reads and in-guest EC2 OS telemetry are absent from management CloudTrail.'},
        'ambiguity': {'score': 2, 'rationale': 'All attacker calls use standard AWS SDK clients indistinguishable by userAgent from automation.'},
    }
    sophistication = {
        'band': soph_band,
        'boundaries': boundaries if step_specs else [],
        'preconditions': [] if control_only else ['Compromised initial AWS IAM programmatic credential in target account.'],
        'emulation_limitations': [
            'Invictus AWS CloudTrail dataset generated with Stratus Red Team modules; mechanical userAgent marker stripped and verified absent from public bundle.',
        ],
        'group_ids': [],
    }

    report = write_curated_case(
        output_root,
        case_seed=case_seed,
        pseudonymizer=pseudo,
        split=split,
        provenance='public_replay',
        family_id='invictus-aws-cloudtrail-control' if control_only else 'invictus-aws-cloudtrail-intrusion',
        coverage_tags=coverage_tags,
        difficulty_factors=difficulty_factors,
        control_case=bool(control_only or not step_specs),
        sophistication=sophistication,
        source_references=[SOURCE_REF],
        assets=assets,
        sources=sources,
        raw_events=raw_events,
        step_specs=step_specs,
        edges=edges,
        known_gaps=known_gaps,
        lookalike_tags=lookalike_tags[:16],
        attestation='publisher_labels',
        num_windows=1 if control_only else 2,
        track='inline',
        ioc_regime=ioc_regime,
        extra_iocs=extra_iocs,
        import_notes={'dataset': 'Invictus AWS CloudTrail', 'files': [Path(p).name for p in json_files]},
        coverage_path=coverage_path,
    )

    # Hard anti-contamination gate: verify 'stratus' never leaked into public/
    pub_dir = Path(report['case_dir']) / 'public'
    for pub_file in pub_dir.iterdir():
        if pub_file.is_file() and 'stratus' in pub_file.read_text(encoding='utf-8').lower():
            _fail('truth_public_overlap', pub_file.name)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description='Import Invictus AWS CloudTrail benchmark case.')
    parser.add_argument('--files', nargs='+', required=True)
    parser.add_argument('--output-root', required=True)
    parser.add_argument('--split', choices=('development', 'holdout'), default='development')
    parser.add_argument('--control-only', action='store_true')
    parser.add_argument('--ioc-regime', choices=('known_ioc_pivot', 'novel_apt_zero_ioc'),
                        default='novel_apt_zero_ioc')
    parser.add_argument('--case-seed', default='invictus-cloudtrail')
    args = parser.parse_args(argv)
    report = import_invictus_case(
        args.files,
        args.output_root,
        split=args.split,
        control_only=args.control_only,
        ioc_regime=args.ioc_regime,
        case_seed=args.case_seed,
    )
    sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
