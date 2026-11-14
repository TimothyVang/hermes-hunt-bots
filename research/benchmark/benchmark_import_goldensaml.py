"""Import OTRF SimuLand GoldenSAMLADFSMailAccess as an S5 Hybrid APT Benchmark Case.

Models the full on-premises AD FS -> Active Directory -> Entra ID -> Microsoft 365
Exchange hybrid intrusion chain:
1. On-premises AD FS DKM key extraction via PowerShell LDAP query (`T1552.004`).
2. Domain Controller directory-service replication / AD object access (`T1003.006`).
3. Cloud Entra ID OAuth application permission grant & secret injection (`T1098.001`,
   persistence across federated identity boundary after offline Golden SAML minting).
4. Cloud M365 Exchange Graph REST mailbox collection (`T1114.002`, reentry).

Sanitizes all SimuLand lab hostnames, domains, UPNs, application names, and GUIDs
through per-case HMAC-SHA256 pseudonyms (`CasePseudonymizer`).
"""
import argparse
import datetime as dt
import io
import json
from pathlib import Path
import sys
import zipfile

import benchmark_paths  # noqa: F401
from benchmark_case_writer import (
    DEFAULT_COVERAGE, CasePseudonymizer, format_utc, read_bounded_zip_member,
    read_regular_bytes, write_curated_case,
)
from benchmark_contracts import BenchmarkError, decode_json, parse_utc

SOURCE_REF = 'https://github.com/OTRF/Security-Datasets'


def _fail(code, field='goldensaml'):
    raise BenchmarkError(code, field) from None


def _read_zip_jsonl(zip_path):
    p = Path(zip_path)
    file_sha, raw = read_regular_bytes(p, field=p.name)
    rows = []
    if p.suffix.lower() == '.json':
        text = raw.decode('utf-8')
    else:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            json_members = [m for m in zf.namelist() if not m.endswith('/') and m.lower().endswith('.json')]
            if len(json_members) != 1:
                _fail('ambiguous_archive', p.name)
            member_bytes = read_bounded_zip_member(zf, json_members[0], field=p.name)
            text = member_bytes.decode('utf-8')
    for idx, line in enumerate(text.splitlines(), 1):
        if line.strip():
            rows.append((idx, file_sha, decode_json(line)))
    if not rows:
        _fail('empty_events', p.name)
    return rows


def _find_zip(dataset_dir, stem):
    d = Path(dataset_dir)
    for cand in (d / (stem + '.Zip'), d / (stem + '.zip'), d / (stem + '.json')):
        if cand.is_file():
            return cand
    for item in sorted(d.iterdir()):
        if item.name.lower() == (stem + '.zip').lower():
            return item
    _fail('file_not_found', stem)


def import_goldensaml_case(
    dataset_dir,
    output_root,
    *,
    split='development',
    ioc_regime='novel_apt_zero_ioc',
    extra_iocs=(),
    salt=None,
    case_seed='goldensaml-adfs-m365',
    coverage_path=DEFAULT_COVERAGE,
):
    pseudo = CasePseudonymizer(salt=salt)
    for alias_kind, alias_val in (
        ('domain', 'simulandlabs.com'),
        ('domain', 'simulandlabs'),
        ('resource', 'SimuLandApp'),
        ('user', 'pgustavo'),
        ('user', 'adfsadmin'),
        ('host', 'adfs01.simulandlabs.com'),
        ('host', 'dc01.simulandlabs.com'),
    ):
        pseudo.register_alias(alias_kind, alias_val)

    adfs_asset = pseudo.pseudonymize('host', 'adfs01.simulandlabs.com')
    dc_asset = pseudo.pseudonymize('host', 'dc01.simulandlabs.com')
    entra_asset = pseudo.pseudonymize('resource', 'entra-tenant-directory')
    m365_asset = pseudo.pseudonymize('resource', 'm365-exchange-online')

    win_rows = _read_zip_jsonl(_find_zip(dataset_dir, 'WindowsEvents'))
    mde_rows = _read_zip_jsonl(_find_zip(dataset_dir, 'Microsoft365DefenderEvents'))
    aad_rows = _read_zip_jsonl(_find_zip(dataset_dir, 'AADAuditEvents'))
    o365_rows = _read_zip_jsonl(_find_zip(dataset_dir, 'OfficeActivityEvents'))

    assets = [
        {
            'asset_id': adfs_asset,
            'os_family': 'windows-server',
            'os_version': 'Windows Server 2019 AD FS',
            'architecture': 'x86_64',
            'vendor': 'Microsoft',
        },
        {
            'asset_id': dc_asset,
            'os_family': 'windows-server',
            'os_version': 'Windows Server 2019 Domain Controller',
            'architecture': 'x86_64',
            'vendor': 'Microsoft',
        },
        {
            'asset_id': entra_asset,
            'os_family': 'not-applicable',
            'os_version': None,
            'architecture': None,
            'vendor': 'Microsoft Entra ID',
        },
        {
            'asset_id': m365_asset,
            'os_family': 'not-applicable',
            'os_version': None,
            'architecture': None,
            'vendor': 'Microsoft Exchange Online',
        },
    ]

    sources = [
        {
            'source_id': 'win-security-adfs',
            'asset_ids': [adfs_asset, dc_asset],
            'telemetry': 'windows-security',
            'clock_offset_seconds': 0.0,
            'clock_uncertainty_seconds': 1.0,
            'sensor_version': 'Windows-EventLog',
            'config_version': 'adfs-auditing-v1',
            'completeness': 'partial',
            'source_sha256': win_rows[0][1],
        },
        {
            'source_id': 'mde-identity-edr',
            'asset_ids': [adfs_asset, dc_asset, entra_asset, m365_asset],
            'telemetry': 'identity-audit',
            'clock_offset_seconds': 0.0,
            'clock_uncertainty_seconds': 1.0,
            'sensor_version': 'M365-Defender',
            'config_version': 'default',
            'completeness': 'partial',
            'source_sha256': mde_rows[0][1],
        },
        {
            'source_id': 'entra-audit-logs',
            'asset_ids': [entra_asset],
            'telemetry': 'cloud-audit',
            'clock_offset_seconds': 0.0,
            'clock_uncertainty_seconds': 2.0,
            'sensor_version': 'AzureAD-AuditLogs',
            'config_version': 'v1',
            'completeness': 'complete',
            'source_sha256': aad_rows[0][1],
        },
        {
            'source_id': 'm365-office-activity',
            'asset_ids': [m365_asset],
            'telemetry': 'saas-audit',
            'clock_offset_seconds': 0.0,
            'clock_uncertainty_seconds': 2.0,
            'sensor_version': 'Office365-Management-Activity',
            'config_version': 'ExchangeItemAggregated',
            'completeness': 'complete',
            'source_sha256': o365_rows[0][1],
        },
    ]

    raw_events = []
    step1_tags = []
    step2_tags = []
    step3_tags = []
    step4_tags = []
    lookalike_tags = []

    for idx, fsha, obj in win_rows:
        ts_raw = str(obj.get('TimeGenerated') or '')
        stamp = parse_utc(ts_raw, 'win.TimeGenerated')
        comp = str(obj.get('Computer') or '').lower()
        asset_id = dc_asset if comp.startswith('dc') else adfs_asset
        eid_num = obj.get('EventID')
        tag = 'win-{}'.format(idx)
        fields = pseudo.clean_fields({
            'timestamp_original': ts_raw,
            'event_code': eid_num,
            'channel': obj.get('Channel'),
            'provider': obj.get('EventSourceName'),
            'account': pseudo.pseudonymize('user', obj.get('Account') or obj.get('TargetUserName') or ''),
            'ip_address': pseudo.pseudonymize('ip', obj.get('IpAddress') or ''),
            'logon_type': obj.get('LogonType'),
            'activity': obj.get('Activity'),
            'event_data': obj.get('EventData_dynamic') or obj.get('EventData'),
        })
        fields['timestamp_original'] = ts_raw
        raw_events.append({
            'tag': tag,
            'timestamp_utc': format_utc(stamp),
            'source_id': 'win-security-adfs',
            'asset_id': asset_id,
            'event_type': 'windows_event_{}'.format(eid_num),
            'fields': fields,
            'record_id': 'win-security-adfs:{}'.format(idx),
            'file_sha256': fsha,
        })
        if eid_num == 4662 and asset_id == dc_asset:
            step2_tags.append(tag)
        elif eid_num in (412, 501) and asset_id == adfs_asset:
            lookalike_tags.append(tag)

    for idx, fsha, obj in mde_rows:
        ts_raw = str(obj.get('Timestamp') or '')
        stamp = parse_utc(ts_raw, 'mde.Timestamp')
        action = str(obj.get('ActionType') or 'mde_event').strip() or 'mde_event'
        dev = str(obj.get('DeviceName') or '').lower()
        action_l = action.lower()
        if 'mailitemsaccessed' in action_l:
            asset_id = m365_asset
        elif any(k in action_l for k in ('permission grant', 'app role assignment', 'service principal', 'application')):
            asset_id = entra_asset
        elif dev.startswith('dc'):
            asset_id = dc_asset
        else:
            asset_id = adfs_asset

        add_raw = json.dumps(
            obj.get('AdditionalFields_dynamic') or obj.get('AdditionalFields_string') or '',
            ensure_ascii=False,
        )
        tag = 'mde-{}'.format(idx)
        fields = pseudo.clean_fields({
            'timestamp_original': ts_raw,
            'action_type': action,
            'account_name': pseudo.pseudonymize('user', obj.get('AccountName') or ''),
            'account_upn': pseudo.pseudonymize('user', obj.get('AccountUpn') or ''),
            'initiating_process': obj.get('InitiatingProcessFileName'),
            'initiating_cmdline': obj.get('InitiatingProcessCommandLine'),
            'process_cmdline': obj.get('ProcessCommandLine'),
            'additional_fields': obj.get('AdditionalFields_dynamic') or obj.get('AdditionalFields_string'),
        })
        fields['timestamp_original'] = ts_raw
        raw_events.append({
            'tag': tag,
            'timestamp_utc': format_utc(stamp),
            'source_id': 'mde-identity-edr',
            'asset_id': asset_id,
            'event_type': 'mde_' + action_l.replace(' ', '_').rstrip('.'),
            'fields': fields,
            'record_id': 'mde-identity-edr:{}'.format(idx),
            'file_sha256': fsha,
        })
        if action == 'LdapSearch' and ('CN=ADFS' in add_raw or 'thumbnailphoto' in add_raw.lower()):
            step1_tags.append(tag)
        elif 'permission grant' in action_l or 'app role assignment' in action_l or 'service principal credentials' in action_l:
            step3_tags.append(tag)
        elif 'mailitemsaccessed' in action_l:
            step4_tags.append(tag)

    for idx, fsha, obj in aad_rows:
        ts_raw = str(obj.get('TimeGenerated') or obj.get('ActivityDateTime') or '')
        stamp = parse_utc(ts_raw, 'aad.TimeGenerated')
        op = str(obj.get('OperationName') or 'aad_audit').strip() or 'aad_audit'
        op_l = op.lower()
        op_tok = (op_l.split() or ['audit'])[0]
        tag = 'aad-{}'.format(idx)
        fields = pseudo.clean_fields({
            'timestamp_original': ts_raw,
            'operation_name': op,
            'category': obj.get('Category'),
            'result_type': obj.get('ResultType'),
            'initiated_by': obj.get('InitiatedBy'),
            'target_resources': obj.get('TargetResources'),
            'modified_property': obj.get('ModifiedPropertyName'),
        })
        fields['timestamp_original'] = ts_raw
        raw_events.append({
            'tag': tag,
            'timestamp_utc': format_utc(stamp),
            'source_id': 'entra-audit-logs',
            'asset_id': entra_asset,
            'event_type': 'entra_' + op_tok,
            'fields': fields,
            'record_id': 'entra-audit-logs:{}'.format(idx),
            'file_sha256': fsha,
        })
        if any(k in op_l for k in (
            'permission grant', 'app role assignment', 'service principal credentials',
            'certificates and secrets', 'add owner to application', 'update application',
        )):
            step3_tags.append(tag)

    for idx, fsha, obj in o365_rows:
        ts_raw = str(obj.get('TimeGenerated') or obj.get('CreationTime') or '')
        stamp = parse_utc(ts_raw, 'o365.TimeGenerated')
        op = str(obj.get('Operation') or 'MailItemsAccessed').strip() or 'MailItemsAccessed'
        tag = 'o365-{}'.format(idx)
        fields = pseudo.clean_fields({
            'timestamp_original': ts_raw,
            'operation': op,
            'workload': obj.get('Workload') or 'Exchange',
            'user_id': pseudo.pseudonymize('user', obj.get('UserId') or ''),
            'mailbox_owner': pseudo.pseudonymize('user', obj.get('MailboxOwnerUPN') or ''),
            'client_ip': pseudo.pseudonymize('ip', obj.get('Client_IPAddress') or ''),
            'client_info': obj.get('ClientInfoString'),
            'app_id': obj.get('AppId'),
            'folders': obj.get('Folders'),
        })
        fields['timestamp_original'] = ts_raw
        raw_events.append({
            'tag': tag,
            'timestamp_utc': format_utc(stamp),
            'source_id': 'm365-office-activity',
            'asset_id': m365_asset,
            'event_type': 'o365_' + op.lower(),
            'fields': fields,
            'record_id': 'm365-office-activity:{}'.format(idx),
            'file_sha256': fsha,
        })
        if op == 'MailItemsAccessed':
            step4_tags.append(tag)

    # Neutral telemetry gap: interactive cloud sign-in logs are absent from this export
    stamps = sorted(parse_utc(ev['timestamp_utc'], 'ev') for ev in raw_events)
    gap_start = stamps[0]
    gap_end = max(stamps[-1], gap_start + dt.timedelta(seconds=1))
    known_gaps = [{
        'source_id': 'entra-audit-logs',
        'asset_id': entra_asset,
        'window_utc': {
            'start_inclusive': format_utc(gap_start),
            'end_exclusive': format_utc(gap_end),
        },
        'reason': (
            'Interactive cloud sign-in logs were not collected in this export; '
            'cross-plane identity activity is recorded only in directory and workload audit streams.'
        ),
    }]

    step_specs = [
        {
            'step_id': 'step-1-adfs-dkm-read',
            'technique_id': 'T1552.004',
            'asset_id': adfs_asset,
            'boundary_id': 'bnd-onprem-adfs',
            'phase': 'initial',
            'support_tags': step1_tags,
        },
        {
            'step_id': 'step-2-dc-directory-access',
            'technique_id': 'T1003.006',
            'asset_id': dc_asset,
            'boundary_id': 'bnd-ad-domain',
            'phase': 'initial',
            'support_tags': step2_tags,
        },
        {
            'step_id': 'step-3-entra-app-credentials',
            'technique_id': 'T1098.001',
            'asset_id': entra_asset,
            'boundary_id': 'bnd-federated-identity',
            'phase': 'persistence',
            'support_tags': step3_tags,
        },
        {
            'step_id': 'step-4-exchange-mail-collection',
            'technique_id': 'T1114.002',
            'asset_id': m365_asset,
            'boundary_id': 'bnd-cloud-saas',
            'phase': 'reentry',
            'support_tags': step4_tags,
        },
    ]
    edges = [
        ['step-1-adfs-dkm-read', 'step-2-dc-directory-access'],
        ['step-2-dc-directory-access', 'step-3-entra-app-credentials'],
        ['step-3-entra-app-credentials', 'step-4-exchange-mail-collection'],
    ]

    coverage_tags = {
        'os': ['windows-server', 'not-applicable'],
        'execution_platform': ['virtual-machine', 'cloud-control-plane', 'saas'],
        'network': ['hybrid', 'encrypted-traffic', 'ipv4'],
        'identity_domain': ['ad-single-domain', 'entra-hybrid', 'federated-sso'],
        'operational_domain': ['enterprise-it', 'cloud-saas'],
        'dns_domain': ['internal-authoritative', 'owned-public-zone'],
        'telemetry': ['windows-security', 'identity-audit', 'cloud-audit', 'saas-audit'],
    }
    difficulty_factors = {
        'noise': {'score': 1, 'rationale': 'Routine AD FS 412/501 token events and DC 4624 logons interleave with key theft.'},
        'joins': {'score': 2, 'rationale': 'Requires correlating on-prem AD FS LDAP DKM reads, DC 4662 access, Entra app changes, and Exchange REST mail access.'},
        'time_span': {'score': 1, 'rationale': '30-minute multi-plane progression with delayed cloud persistence.'},
        'gaps': {'score': 2, 'rationale': 'Offline Golden SAML token minting and Entra SignInLogs are unobserved.'},
        'ambiguity': {'score': 2, 'rationale': 'PowerShell LDAP queries and Graph REST operations use legitimate enterprise protocols without malware binaries.'},
    }
    sophistication = {
        'band': 'S5',
        'boundaries': [
            {'boundary_id': 'bnd-onprem-adfs', 'kind': 'on-prem'},
            {'boundary_id': 'bnd-ad-domain', 'kind': 'domain'},
            {'boundary_id': 'bnd-federated-identity', 'kind': 'identity'},
            {'boundary_id': 'bnd-cloud-saas', 'kind': 'cloud'},
        ],
        'preconditions': [
            'Privileged foothold on on-premises AD FS server permitting AD FS token-signing certificate and DKM container read.',
        ],
        'emulation_limitations': [
            'SimuLand lab emulation export (OTRF Security-Datasets); compact background volume compared to multi-thousand-seat production tenants.',
        ],
        'group_ids': [],
    }

    return write_curated_case(
        output_root,
        case_seed=case_seed,
        pseudonymizer=pseudo,
        split=split,
        provenance='public_replay',
        family_id='otrf-simuland-goldensaml',
        coverage_tags=coverage_tags,
        difficulty_factors=difficulty_factors,
        control_case=False,
        sophistication=sophistication,
        source_references=[SOURCE_REF],
        assets=assets,
        sources=sources,
        raw_events=raw_events,
        step_specs=step_specs,
        edges=edges,
        known_gaps=known_gaps,
        lookalike_tags=lookalike_tags,
        attestation='publisher_labels',
        num_windows=2,
        track='inline',
        ioc_regime=ioc_regime,
        extra_iocs=extra_iocs,
        import_notes={'dataset': 'OTRF GoldenSAMLADFSMailAccess'},
        coverage_path=coverage_path,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description='Import OTRF GoldenSAML S5 hybrid APT case.')
    parser.add_argument('--dataset-dir', required=True)
    parser.add_argument('--output-root', required=True)
    parser.add_argument('--split', choices=('development', 'holdout'), default='development')
    parser.add_argument('--ioc-regime', choices=('known_ioc_pivot', 'novel_apt_zero_ioc'),
                        default='novel_apt_zero_ioc')
    args = parser.parse_args(argv)
    report = import_goldensaml_case(
        args.dataset_dir, args.output_root, split=args.split, ioc_regime=args.ioc_regime
    )
    sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
