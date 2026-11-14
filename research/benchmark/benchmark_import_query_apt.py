"""Wave 2 SQLite Query-Track Whole-Campaign APT Importers (`query_store`).

Builds full multi-host APT campaign cases backed by `public/events.sqlite3` +
`public/overview.json` from three real telemetry datasets:
1. OTRF `APT29 Day 2` (`apt29_evals_day2_manual.zip` + `segmentation/day2.json`):
   4-host Windows AD domain (`UTICA`, `NEWYORK` DC, `SCRANTON`, `NASHUA`) S4 kill chain.
2. `DEDALE` (`system_logs_labels.zip` + `system_logs_winlogbeat.zip` +
   `system_logs_auditbeat.zip` + `suricata_alerts.zip`): multi-OS Windows + Linux +
   Suricata S4 intrusion with publisher event labels.
3. `FullAPT-2025` (`apt-N-labeled-datasets.tar.gz`): 4-host Windows domain Sysmon
   campaigns with per-event ATT&CK labels (strictly stripped from `public/`).
"""
import argparse
import bz2
import csv
import datetime as dt
import io
import json
from pathlib import Path
import re
import sqlite3
import sys
import tarfile
import zipfile

import benchmark_paths  # noqa: F401
from benchmark_case_writer import (
    DEFAULT_COVERAGE, CasePseudonymizer, canonical_valid_technique,
    derive_sophistication_band, format_utc, iter_bounded_lines,
    read_regular_bytes, stream_file_sha256, validate_archive_member_name,
    write_curated_case,
)
from benchmark_contracts import BenchmarkError, decode_json, parse_utc

APT29_REF = 'https://github.com/OTRF/Security-Datasets'
DEDALE_REF = 'https://zenodo.org/records/15044577'
FULLAPT_REF = 'https://zenodo.org/records/15392412'

_NXLOG_TIME_RE = re.compile(r'\A(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})\Z')

# APT29 Day 2 group -> (step_suffix, v20 technique_id, boundary_id, phase)
_APT29_GROUP_SPECS = {
    11: ('initial-stager', 'T1059.001', 'bnd-host-initial', 'initial'),
    14: ('uac-wmi-cred-exec', 'T1548.002', 'bnd-host-privilege', 'initial'),
    15: ('wmi-persistence', 'T1546.003', 'bnd-host-privilege', 'persistence'),
    16: ('dc-winrm-dcsync', 'T1021.006', 'bnd-ad-domain', 'reentry'),
    17: ('archive-staging', 'T1560.001', 'bnd-host-privilege', 'initial'),
    18: ('exfil-web-service', 'T1048', 'bnd-host-privilege', 'initial'),
    20: ('golden-ticket-reentry', 'T1558.001', 'bnd-ad-domain', 'reentry'),
}


def _fail(code, field='query_apt'):
    raise BenchmarkError(code, field) from None


class _BoundedBinaryReader(io.RawIOBase):
    """Wrap a compressed stream to enforce a strict cumulative byte limit."""

    def __init__(self, raw_stream, max_bytes, field='archive_stream'):
        self._raw = raw_stream
        self._max = max_bytes
        self._seen = 0
        self._field = field

    def readable(self):
        return True

    def readinto(self, b):
        data = self._raw.read(len(b))
        if not data:
            return 0
        self._seen += len(data)
        if self._seen > self._max:
            _fail('member_too_large', self._field)
        n = len(data)
        b[:n] = data
        return n


# ---------------------------------------------------------------------------
# 1. APT29 Day 2 (Windows Domain S4 Query-Track)
# ---------------------------------------------------------------------------

def import_apt29_day2_query_case(
    zip_path,
    segmentation_path,
    output_root,
    *,
    split='development',
    ioc_regime='novel_apt_zero_ioc',
    extra_iocs=(),
    salt=None,
    case_seed='apt29-day2-query',
    max_events=32000,
    coverage_path=DEFAULT_COVERAGE,
):
    zp = Path(zip_path)
    sp = Path(segmentation_path)
    zip_sha = stream_file_sha256(zp, field='apt29_inputs')
    _, seg_bytes = read_regular_bytes(sp, field='apt29_inputs')
    seg = decode_json(seg_bytes)

    pseudo = CasePseudonymizer(salt=salt)
    for k, v in (
        ('domain', 'dmevals.local'),
        ('domain', 'dmevals'),
        ('user', 'dschrute'),
        ('user', 'pbeesly'),
        ('host', 'UTICA.dmevals.local'),
        ('host', 'NEWYORK.dmevals.local'),
        ('host', 'SCRANTON.dmevals.local'),
        ('host', 'NASHUA.dmevals.local'),
    ):
        pseudo.register_alias(k, v)

    host_map = {
        'UTICA': pseudo.pseudonymize('host', 'UTICA.dmevals.local'),
        'NEWYORK': pseudo.pseudonymize('host', 'NEWYORK.dmevals.local'),
        'SCRANTON': pseudo.pseudonymize('host', 'SCRANTON.dmevals.local'),
        'NASHUA': pseudo.pseudonymize('host', 'NASHUA.dmevals.local'),
    }

    line_to_group = {}
    for grp in seg.get('groups', []):
        gno = int(grp['group'])
        if gno in _APT29_GROUP_SPECS:
            for rec in grp.get('span_records', []):
                line_to_group[int(rec['line'])] = (gno, str(rec['host']).upper())

    must_rows = []
    high_rows = []
    bg_rows = []

    with zipfile.ZipFile(zp) as zf:
        json_mems = [m for m in zf.namelist() if not m.endswith('/') and m.lower().endswith('.json')]
        if not json_mems:
            _fail('missing_archive_member', zp.name)
        json_member = json_mems[0]
        validate_archive_member_name(json_member, zp.name)
        with zf.open(json_member) as fh:
            for line_no, raw_line in iter_bounded_lines(fh, max_bytes=2 * 1024 * 1024 * 1024, field=json_member):
                # Quick pre-filter when background pool is already large and line is not an anchor
                is_anchor = line_no in line_to_group
                if not is_anchor and len(high_rows) >= max_events and (line_no % 17 != 0):
                    continue
                obj = json.loads(raw_line.decode('utf-8', 'replace'))
                et_str = str(obj.get('EventTime') or '')
                m_t = _NXLOG_TIME_RE.match(et_str)
                if m_t:
                    naive = dt.datetime.fromisoformat(m_t.group(1) + 'T' + m_t.group(2))
                    stamp = (naive + dt.timedelta(seconds=14400)).replace(tzinfo=dt.timezone.utc)
                elif obj.get('@timestamp'):
                    stamp = parse_utc(str(obj['@timestamp']), 'apt29.timestamp')
                else:
                    continue

                raw_host = str(obj.get('Hostname') or 'UTICA').split('.', 1)[0].upper()
                host_key = raw_host if raw_host in host_map else 'UTICA'
                channel = str(obj.get('Channel') or 'Security')
                eid_num = int(obj.get('EventID') or 0)
                norm_chan = 'Security' if channel.lower() == 'security' else channel

                is_high = (
                    (norm_chan.endswith('Sysmon/Operational') and eid_num in (1, 3, 8, 11, 17, 18, 20, 21))
                    or (norm_chan.endswith('PowerShell/Operational') and eid_num == 4104)
                    or (norm_chan == 'Security' and eid_num in (4624, 4625, 4648, 4662, 4672, 4720, 4732))
                    or ('WMI-Activity' in norm_chan)
                )
                if not is_anchor and not is_high and (line_no % 29 != 0):
                    continue

                if norm_chan.endswith('Sysmon/Operational'):
                    src_id = 'win-sysmon'
                elif norm_chan == 'Security':
                    src_id = 'win-security'
                else:
                    src_id = 'win-powershell-wmi'

                fields = pseudo.clean_fields({
                    'timestamp_original': et_str or format_utc(stamp),
                    'channel': norm_chan,
                    'event_code': eid_num,
                    'image': obj.get('Image') or obj.get('NewProcessName'),
                    'command_line': obj.get('CommandLine') or obj.get('ProcessCommandLine'),
                    'parent_image': obj.get('ParentImage') or obj.get('ParentProcessName'),
                    'script_block': (str(obj.get('ScriptBlockText') or ''))[:2048] or None,
                    'user': pseudo.pseudonymize('user', obj.get('User') or obj.get('TargetUserName') or obj.get('SubjectUserName') or ''),
                    'dest_ip': pseudo.pseudonymize('ip', obj.get('DestinationIp') or obj.get('IpAddress') or ''),
                    'dest_port': obj.get('DestinationPort') or obj.get('IpPort'),
                    'target_filename': obj.get('TargetFilename'),
                    'target_object': obj.get('TargetObject'),
                    'consumer': obj.get('Consumer') or obj.get('Destination'),
                })
                fields['timestamp_original'] = et_str or format_utc(stamp)
                ev_entry = {
                    'tag': 'line-{}'.format(line_no),
                    'line_no': line_no,
                    'host_key': host_key,
                    'timestamp_utc': format_utc(stamp),
                    'source_id': src_id,
                    'asset_id': host_map[host_key],
                    'event_type': '{}:{}'.format(norm_chan.rsplit('/', 1)[-1].lower(), eid_num),
                    'fields': fields,
                    'record_id': '{}:{}'.format(src_id, line_no),
                    'file_sha256': zip_sha,
                }
                if is_anchor:
                    must_rows.append(ev_entry)
                elif is_high:
                    high_rows.append(ev_entry)
                else:
                    bg_rows.append(ev_entry)

    budget_high = max(0, max_events - len(must_rows))
    if len(high_rows) > budget_high:
        stride = max(1, len(high_rows) // max(budget_high, 1))
        chosen_high = high_rows[::stride][:budget_high]
    else:
        chosen_high = high_rows
    rem_bg = max(0, max_events - len(must_rows) - len(chosen_high))
    if len(bg_rows) > rem_bg and rem_bg > 0:
        stride_b = max(1, len(bg_rows) // rem_bg)
        chosen_bg = bg_rows[::stride_b][:rem_bg]
    else:
        chosen_bg = bg_rows[:rem_bg]

    selected = must_rows + chosen_high + chosen_bg

    # Build steps per (group, host_key)
    grouped_steps = {}
    for ev in must_rows:
        gno, anchor_host = line_to_group[ev['line_no']]
        suffix, tech_id, bnd_id, phase = _APT29_GROUP_SPECS[gno]
        # Differentiate NEWYORK DC lateral movement vs UTICA DCSync in group 16
        if gno == 16 and anchor_host == 'UTICA':
            tech_use = 'T1003.006'
            bnd_use = 'bnd-domain-identity'
            phase_use = 'initial'
            s_id = 'step-g16-utica-dcsync'
        elif gno == 16 and anchor_host == 'NEWYORK':
            tech_use = 'T1021.006'
            bnd_use = 'bnd-ad-domain'
            phase_use = 'reentry'
            s_id = 'step-g16-newyork-winrm'
        elif gno == 20 and anchor_host == 'SCRANTON':
            tech_use = 'T1136.001'
            bnd_use = 'bnd-ad-domain'
            phase_use = 'reentry'
            s_id = 'step-g20-scranton-account'
        else:
            tech_use = tech_id
            bnd_use = bnd_id
            phase_use = phase
            s_id = 'step-g{:02d}-{}-{}'.format(gno, anchor_host.lower(), suffix)

        st_obj = grouped_steps.setdefault((gno, s_id), {
            'step_id': s_id,
            'technique_id': tech_use,
            'asset_id': host_map[anchor_host],
            'boundary_id': bnd_use,
            'phase': phase_use,
            'support_tags': [],
        })
        st_obj['support_tags'].append(ev['tag'])

    step_specs = [grouped_steps[k] for k in sorted(grouped_steps)]
    edges = [[step_specs[i]['step_id'], step_specs[i + 1]['step_id']] for i in range(len(step_specs) - 1)]

    all_assets = [host_map['UTICA'], host_map['NEWYORK'], host_map['SCRANTON'], host_map['NASHUA']]
    assets = [
        {'asset_id': host_map['UTICA'], 'os_family': 'windows-client', 'os_version': 'Windows 10 Enterprise Workstation', 'architecture': 'x86_64', 'vendor': 'Microsoft'},
        {'asset_id': host_map['NEWYORK'], 'os_family': 'windows-server', 'os_version': 'Windows Server 2019 Domain Controller', 'architecture': 'x86_64', 'vendor': 'Microsoft'},
        {'asset_id': host_map['SCRANTON'], 'os_family': 'windows-client', 'os_version': 'Windows 10 Enterprise Workstation', 'architecture': 'x86_64', 'vendor': 'Microsoft'},
        {'asset_id': host_map['NASHUA'], 'os_family': 'windows-client', 'os_version': 'Windows 10 Enterprise Workstation', 'architecture': 'x86_64', 'vendor': 'Microsoft'},
    ]
    used_src = {e['source_id'] for e in selected}
    all_sources = [
        {
            'source_id': 'win-sysmon',
            'asset_ids': all_assets,
            'telemetry': 'sysmon',
            'clock_offset_seconds': -14400.0,
            'clock_uncertainty_seconds': 36.8,
            'sensor_version': 'Sysmon-10.42',
            'config_version': 'collector-v1',
            'completeness': 'partial',
            'source_sha256': zip_sha,
        },
        {
            'source_id': 'win-security',
            'asset_ids': all_assets,
            'telemetry': 'windows-security',
            'clock_offset_seconds': -14400.0,
            'clock_uncertainty_seconds': 36.8,
            'sensor_version': 'Windows-Security-Auditing',
            'config_version': 'collector-v1',
            'completeness': 'partial',
            'source_sha256': zip_sha,
        },
        {
            'source_id': 'win-powershell-wmi',
            'asset_ids': all_assets,
            'telemetry': 'identity-audit',
            'clock_offset_seconds': -14400.0,
            'clock_uncertainty_seconds': 36.8,
            'sensor_version': 'PowerShell-Operational-WMI',
            'config_version': 'collector-v1',
            'completeness': 'partial',
            'source_sha256': zip_sha,
        },
    ]
    sources = [s for s in all_sources if s['source_id'] in used_src]

    coverage_tags = {
        'os': ['windows-client', 'windows-server'],
        'execution_platform': ['virtual-machine'],
        'network': ['flat-lan', 'encrypted-traffic', 'ipv4'],
        'identity_domain': ['ad-single-domain', 'ldap-kerberos'],
        'operational_domain': ['enterprise-it'],
        'dns_domain': ['internal-authoritative'],
        'telemetry': sorted({s['telemetry'] for s in sources if s['telemetry']}),
    }
    difficulty_factors = {
        'noise': {'score': 2, 'rationale': 'Tens of thousands of multi-host Sysmon, Security, and PowerShell events require targeted query-tool triage.'},
        'joins': {'score': 2, 'rationale': 'Spans workstation breach, WMI persistence, WinRM lateral movement to DC, KRBTGT theft, and Golden Ticket reentry on a third host.'},
        'time_span': {'score': 2, 'rationale': '40-minute whole-campaign recording including host reboot and persistence firing.'},
        'gaps': {'score': 1, 'rationale': 'External OneDrive cloud telemetry for step 18 exfiltration is outside the on-prem domain capture.'},
        'ambiguity': {'score': 2, 'rationale': 'Living-off-the-land PowerShell, WinRM, and WMI administration blend with normal domain activity.'},
    }
    sophistication = {
        'band': 'S4',
        'boundaries': [
            {'boundary_id': 'bnd-host-initial', 'kind': 'host'},
            {'boundary_id': 'bnd-host-privilege', 'kind': 'privilege'},
            {'boundary_id': 'bnd-domain-identity', 'kind': 'identity'},
            {'boundary_id': 'bnd-ad-domain', 'kind': 'domain'},
        ],
        'preconditions': ['User execution of initial LNK/stager on domain workstation UTICA.'],
        'emulation_limitations': ['OTRF MITRE ATT&CK Evaluations Round 2 (APT29 Day 2) lab recording; public walkthroughs exist (development split only).'],
        'group_ids': [],
    }

    return write_curated_case(
        output_root,
        case_seed=case_seed,
        pseudonymizer=pseudo,
        split=split,
        provenance='public_replay',
        family_id='otrf-apt29-day2-whole-campaign',
        coverage_tags=coverage_tags,
        difficulty_factors=difficulty_factors,
        control_case=False,
        sophistication=sophistication,
        source_references=[APT29_REF],
        assets=assets,
        sources=sources,
        raw_events=selected,
        step_specs=step_specs,
        edges=edges,
        attestation='publisher_labels',
        num_windows=3,
        track='query',
        ioc_regime=ioc_regime,
        extra_iocs=extra_iocs,
        import_notes={'dataset': 'OTRF APT29 Day 2 Query Track', 'total_indexed': len(selected)},
        coverage_path=coverage_path,
    )


# ---------------------------------------------------------------------------
# 2. DEDALE (Windows + Linux + Suricata S4 Query-Track)
# ---------------------------------------------------------------------------

def import_dedale_query_case(
    dedale_raw_dir,
    output_root,
    *,
    split='development',
    ioc_regime='novel_apt_zero_ioc',
    extra_iocs=(),
    salt=None,
    case_seed='dedale-hybrid-apt-query',
    max_events=25000,
    coverage_path=DEFAULT_COVERAGE,
):
    raw_dir = Path(dedale_raw_dir)
    labels_zip = raw_dir / 'system_logs_labels.zip'
    labels_sha = stream_file_sha256(labels_zip, field='system_logs_labels.zip')

    pseudo = CasePseudonymizer(salt=salt)
    for k, v in (
        ('host', 'CLIENT1'),
        ('host', 'CLIENT2'),
        ('host', 'internalserver'),
        ('user', 'client1'),
        ('user', 'client2'),
    ):
        pseudo.register_alias(k, v)

    host_assets = {
        'CLIENT1': pseudo.pseudonymize('host', 'CLIENT1'),
        'CLIENT2': pseudo.pseudonymize('host', 'CLIENT2'),
        'internalserver': pseudo.pseudonymize('host', 'internalserver'),
    }

    mal_events = []
    seen_sigs = set()
    step_buckets = {}

    def _add_step_tag(skey, tech, host_k, bnd, phase, tag, stamp):
        st = step_buckets.setdefault(skey, {
            'step_id': 'step-' + skey,
            'technique_id': tech,
            'asset_id': host_assets[host_k],
            'boundary_id': bnd,
            'phase': phase,
            'support_tags': [],
            'first_stamp': stamp,
        })
        if len(st['support_tags']) < 48:
            st['support_tags'].append(tag)
        if stamp < st['first_stamp']:
            st['first_stamp'] = stamp

    with zipfile.ZipFile(labels_zip) as zf:
        # Windows malicious events
        win_mems = [m for m in zf.namelist() if m.endswith('clients_1_and_2/malicious_events_class_1.jsonl')]
        if not win_mems:
            _fail('missing_archive_member', 'dedale.win_labels')
        win_mem = win_mems[0]
        validate_archive_member_name(win_mem, 'system_logs_labels.zip')
        with zf.open(win_mem) as fh:
            for lno, raw in iter_bounded_lines(fh, field=win_mem):
                obj = json.loads(raw.decode('utf-8', 'replace'))
                ts_raw = str(obj.get('@timestamp') or '')
                if not ts_raw:
                    continue
                stamp = parse_utc(ts_raw, 'dedale.win.ts')
                ag = str((obj.get('agent') or {}).get('hostname') or 'CLIENT2').upper()
                host_k = ag if ag in ('CLIENT1', 'CLIENT2') else 'CLIENT2'
                proc = obj.get('process') or {}
                exe = str(proc.get('executable') or '')
                cmd = str(proc.get('command_line') or exe)
                ev_meta = obj.get('event') or {}
                sig = (ts_raw, host_k, str(ev_meta.get('code') or ''), cmd[:80])
                seen_sigs.add(sig)

                tag = 'dedale-win-mal-{}'.format(lno)
                exe_l = (exe + ' ' + cmd).lower()
                matched_step = False
                if 'svcmon.exe' in exe_l:
                    _add_step_tag('win-svcmon-persist-' + host_k.lower(), 'T1036.005', host_k, 'bnd-win-privilege', 'persistence', tag, stamp)
                    matched_step = True
                elif 'openssh\\ssh.exe' in exe_l or exe_l.strip().endswith('ssh.exe'):
                    _add_step_tag('win-ssh-pivot-' + host_k.lower(), 'T1021.004', host_k, 'bnd-win-identity', 'initial', tag, stamp)
                    matched_step = True
                elif 'tar.exe' in exe_l:
                    _add_step_tag('win-tar-stage-' + host_k.lower(), 'T1560.001', host_k, 'bnd-win-host', 'initial', tag, stamp)
                    matched_step = True
                elif 'powershell.exe' in exe_l:
                    _add_step_tag('win-ps-exec-' + host_k.lower(), 'T1059.001', host_k, 'bnd-win-host', 'initial', tag, stamp)
                    matched_step = True

                if not matched_step and (lno % 5 != 0):
                    continue

                fields = pseudo.clean_fields({
                    'timestamp_original': ts_raw,
                    'event_code': ev_meta.get('code') if ev_meta.get('code') is not None else 0,
                    'provider': str(ev_meta.get('provider') or 'Windows'),
                    'executable': exe or '-',
                    'command_line': cmd or '-',
                    'message': str(obj.get('message') or '-')[:1024],
                })
                fields['timestamp_original'] = ts_raw
                mal_events.append({
                    'tag': tag,
                    'timestamp_utc': format_utc(stamp),
                    'stamp': stamp,
                    'source_id': 'win-winlogbeat',
                    'asset_id': host_assets[host_k],
                    'event_type': 'winlogbeat_{}'.format(ev_meta.get('code') or 'event'),
                    'fields': fields,
                    'record_id': 'win-winlogbeat:a{}'.format(lno),
                    'file_sha256': labels_sha,
                })

        # Linux internalserver malicious events
        lin_mems = [m for m in zf.namelist() if m.endswith('internal_server/malicious_events_class_1.jsonl')]
        if not lin_mems:
            _fail('missing_archive_member', 'dedale.lin_labels')
        lin_mem = lin_mems[0]
        validate_archive_member_name(lin_mem, 'system_logs_labels.zip')
        with zf.open(lin_mem) as fh:
            for lno, raw in iter_bounded_lines(fh, field=lin_mem):
                obj = json.loads(raw.decode('utf-8', 'replace'))
                ts_raw = str(obj.get('@timestamp') or '')
                if not ts_raw:
                    continue
                stamp = parse_utc(ts_raw, 'dedale.lin.ts')
                proc = obj.get('process') or {}
                exe = str(proc.get('executable') or '')
                args_list = proc.get('args')
                cmd = ' '.join(str(x) for x in args_list) if isinstance(args_list, list) else str(proc.get('command_line') or exe)
                ev_meta = obj.get('event') or {}
                sig = (ts_raw, 'internalserver', str(ev_meta.get('action') or ''), cmd[:80])
                seen_sigs.add(sig)

                tag = 'dedale-lin-mal-{}'.format(lno)
                exe_l = (exe + ' ' + cmd).lower()
                matched_step = False
                if 'pdbedit' in exe_l:
                    _add_step_tag('linux-pdbedit-creds', 'T1003', 'internalserver', 'bnd-linux-segment', 'reentry', tag, stamp)
                    matched_step = True
                elif '/sshd' in exe_l:
                    _add_step_tag('linux-sshd-reentry', 'T1021.004', 'internalserver', 'bnd-linux-segment', 'reentry', tag, stamp)
                    matched_step = True
                elif '/scp' in exe_l:
                    _add_step_tag('linux-scp-transfer', 'T1105', 'internalserver', 'bnd-linux-segment', 'reentry', tag, stamp)
                    matched_step = True

                if not matched_step and (lno % 5 != 0):
                    continue

                fields = pseudo.clean_fields({
                    'timestamp_original': ts_raw,
                    'action': str(ev_meta.get('action') or 'event'),
                    'executable': exe or '-',
                    'command_line': cmd or '-',
                    'user': pseudo.pseudonymize('user', str((obj.get('user') or {}).get('name') or '')) or 'unknown',
                })
                fields['timestamp_original'] = ts_raw
                mal_events.append({
                    'tag': tag,
                    'timestamp_utc': format_utc(stamp),
                    'stamp': stamp,
                    'source_id': 'linux-auditbeat',
                    'asset_id': host_assets['internalserver'],
                    'event_type': 'auditbeat_{}'.format(str(ev_meta.get('action') or 'event').replace('-', '_')),
                    'fields': fields,
                    'record_id': 'linux-auditbeat:a{}'.format(lno),
                    'file_sha256': labels_sha,
                })

    if not mal_events:
        _fail('empty_events', 'dedale')

    min_mal = min(e['stamp'] for e in mal_events) - dt.timedelta(hours=1)
    max_mal = max(e['stamp'] for e in mal_events) + dt.timedelta(hours=1)

    bg_events = []
    bg_budget = max(0, max_events - len(mal_events))

    # Optional benign background slices from winlogbeat / auditbeat / suricata zips if present
    win_source_sha = labels_sha
    lin_source_sha = labels_sha
    suri_source_sha = labels_sha

    win_bg_zip = raw_dir / 'system_logs_winlogbeat.zip'
    if win_bg_zip.is_file() and len(bg_events) < bg_budget // 2:
        win_source_sha = stream_file_sha256(win_bg_zip, field='system_logs_winlogbeat.zip')
        with zipfile.ZipFile(win_bg_zip) as zf:
            cands = [m for m in sorted(zf.namelist()) if '2025-01-06' in m or '2025-01-10' in m][:4]
            for mem_idx, mem in enumerate(cands, 1):
                if len(bg_events) >= bg_budget // 2:
                    break
                validate_archive_member_name(mem, 'system_logs_winlogbeat.zip')
                with zf.open(mem) as zfh:
                    stream = bz2.BZ2File(zfh) if mem.endswith('.bz2') else zfh
                    for lno, raw_ln in iter_bounded_lines(stream, max_bytes=1024 * 1024 * 1024, field=mem):
                        if len(bg_events) >= bg_budget // 2 or lno > 80000:
                            break
                        if lno % 4 != 1:
                            continue
                        ln = raw_ln.decode('utf-8', 'replace')
                        if not ln.strip():
                            continue
                        obj = json.loads(ln)
                        ts_raw = str(obj.get('@timestamp') or '')
                        if not ts_raw:
                            continue
                        st = parse_utc(ts_raw, 'win_bg.ts')
                        if not (min_mal <= st <= max_mal):
                            continue
                        ag = str((obj.get('agent') or {}).get('hostname') or 'CLIENT1').upper()
                        host_k = ag if ag in ('CLIENT1', 'CLIENT2') else 'CLIENT1'
                        proc = obj.get('process') or {}
                        cmd = str(proc.get('command_line') or proc.get('executable') or '')
                        ev_meta = obj.get('event') or {}
                        sig = (ts_raw, host_k, str(ev_meta.get('code') or ''), cmd[:80])
                        if sig in seen_sigs:
                            continue
                        fields = pseudo.clean_fields({
                            'timestamp_original': ts_raw,
                            'event_code': ev_meta.get('code') if ev_meta.get('code') is not None else 0,
                            'provider': str(ev_meta.get('provider') or 'Windows'),
                            'executable': str(proc.get('executable') or '-'),
                            'command_line': cmd or '-',
                            'message': str(obj.get('message') or '-')[:1024],
                        })
                        fields['timestamp_original'] = ts_raw
                        bg_events.append({
                            'tag': 'win-bg-{}-{}'.format(mem_idx, lno),
                            'timestamp_utc': format_utc(st),
                            'stamp': st,
                            'source_id': 'win-winlogbeat',
                            'asset_id': host_assets[host_k],
                            'event_type': 'winlogbeat_{}'.format(ev_meta.get('code') or 'event'),
                            'fields': fields,
                            'record_id': 'win-winlogbeat:b{}_{}'.format(mem_idx, lno),
                            'file_sha256': win_source_sha,
                        })

    lin_bg_zip = raw_dir / 'system_logs_auditbeat.zip'
    if lin_bg_zip.is_file() and len(bg_events) < (bg_budget * 3) // 4:
        lin_source_sha = stream_file_sha256(lin_bg_zip, field='system_logs_auditbeat.zip')
        with zipfile.ZipFile(lin_bg_zip) as zf:
            cands = [m for m in sorted(zf.namelist()) if '2025-01-10' in m][:3]
            for mem_idx, mem in enumerate(cands, 1):
                if len(bg_events) >= (bg_budget * 3) // 4:
                    break
                validate_archive_member_name(mem, 'system_logs_auditbeat.zip')
                with zf.open(mem) as zfh:
                    stream = bz2.BZ2File(zfh) if mem.endswith('.bz2') else zfh
                    for lno, raw_ln in iter_bounded_lines(stream, max_bytes=1024 * 1024 * 1024, field=mem):
                        if len(bg_events) >= (bg_budget * 3) // 4 or lno > 80000:
                            break
                        if lno % 4 != 1:
                            continue
                        ln = raw_ln.decode('utf-8', 'replace')
                        if not ln.strip():
                            continue
                        obj = json.loads(ln)
                        ts_raw = str(obj.get('@timestamp') or '')
                        if not ts_raw:
                            continue
                        st = parse_utc(ts_raw, 'lin_bg.ts')
                        if not (min_mal <= st <= max_mal):
                            continue
                        proc = obj.get('process') or {}
                        exe = str(proc.get('executable') or '')
                        args_list = proc.get('args')
                        cmd = ' '.join(str(x) for x in args_list) if isinstance(args_list, list) else str(proc.get('command_line') or exe)
                        ev_meta = obj.get('event') or {}
                        sig = (ts_raw, 'internalserver', str(ev_meta.get('action') or ''), cmd[:80])
                        if sig in seen_sigs:
                            continue
                        fields = pseudo.clean_fields({
                            'timestamp_original': ts_raw,
                            'action': str(ev_meta.get('action') or 'event'),
                            'executable': exe or '-',
                            'command_line': cmd or '-',
                            'user': pseudo.pseudonymize('user', str((obj.get('user') or {}).get('name') or '')) or 'unknown',
                        })
                        fields['timestamp_original'] = ts_raw
                        bg_events.append({
                            'tag': 'lin-bg-{}-{}'.format(mem_idx, lno),
                            'timestamp_utc': format_utc(st),
                            'stamp': st,
                            'source_id': 'linux-auditbeat',
                            'asset_id': host_assets['internalserver'],
                            'event_type': 'auditbeat_{}'.format(str(ev_meta.get('action') or 'event').replace('-', '_')),
                            'fields': fields,
                            'record_id': 'linux-auditbeat:b{}_{}'.format(mem_idx, lno),
                            'file_sha256': lin_source_sha,
                        })

    suri_zip = raw_dir / 'suricata_alerts.zip'
    if suri_zip.is_file() and len(bg_events) < bg_budget:
        suri_source_sha = stream_file_sha256(suri_zip, field='suricata_alerts.zip')
        with zipfile.ZipFile(suri_zip) as zf:
            smems = [m for m in zf.namelist() if not m.endswith('/') and m.endswith('.jsonl')]
            if not smems:
                _fail('missing_archive_member', 'suricata_alerts.zip')
            smem = smems[0]
            validate_archive_member_name(smem, 'suricata_alerts.zip')
            with zf.open(smem) as fh:
                for lno, raw in iter_bounded_lines(fh, field=smem):
                    if len(bg_events) >= bg_budget:
                        break
                    obj = json.loads(raw.decode('utf-8', 'replace'))
                    ts_val = obj.get('@timestamp') or obj.get('timestamp')
                    if isinstance(ts_val, (int, float)):
                        st = dt.datetime.fromtimestamp(float(ts_val) / 1000.0, tz=dt.timezone.utc)
                        ts_raw = str(ts_val)
                    elif isinstance(ts_val, str) and ts_val:
                        st = parse_utc(ts_val, 'suri.ts')
                        ts_raw = ts_val
                    else:
                        continue
                    if not (min_mal <= st <= max_mal):
                        continue
                    fields = pseudo.clean_fields({
                        'timestamp_original': ts_raw,
                        'src_ip': pseudo.pseudonymize('ip', str(obj.get('src_ip') or '')),
                        'dest_ip': pseudo.pseudonymize('ip', str(obj.get('dest_ip') or '')),
                        'dest_port': obj.get('dest_port'),
                        'alert_signature': str((obj.get('alert') or {}).get('signature') or ''),
                    })
                    fields['timestamp_original'] = ts_raw
                    bg_events.append({
                        'tag': 'suri-{}'.format(lno),
                        'timestamp_utc': format_utc(st),
                        'stamp': st,
                        'source_id': 'network-suricata',
                        'asset_id': host_assets['internalserver'],
                        'event_type': 'suricata_alert',
                        'fields': fields,
                        'record_id': 'network-suricata:{}'.format(lno),
                        'file_sha256': suri_source_sha,
                    })

    # Unify file_sha256 per source_id so label-archive origin is indistinguishable from background rows
    src_sha_map = {
        'win-winlogbeat': win_source_sha,
        'linux-auditbeat': lin_source_sha,
        'network-suricata': suri_source_sha,
    }
    for ev in mal_events:
        ev['file_sha256'] = src_sha_map.get(ev['source_id'], labels_sha)

    selected = sorted(mal_events + bg_events, key=lambda e: (e['stamp'], e['source_id'], e['record_id']))
    per_src_seq = {}
    for ev in selected:
        src = ev['source_id']
        per_src_seq[src] = per_src_seq.get(src, 0) + 1
        ev['record_id'] = '{}:{}'.format(src, per_src_seq[src])
    ordered_steps = sorted(step_buckets.values(), key=lambda x: (x['first_stamp'], x['step_id']))
    step_specs = [{
        'step_id': s['step_id'],
        'technique_id': s['technique_id'],
        'asset_id': s['asset_id'],
        'boundary_id': s['boundary_id'],
        'phase': s['phase'],
        'support_tags': s['support_tags'],
    } for s in ordered_steps]
    edges = [[step_specs[i]['step_id'], step_specs[i + 1]['step_id']] for i in range(len(step_specs) - 1)]

    all_assets = [host_assets['CLIENT1'], host_assets['CLIENT2'], host_assets['internalserver']]
    assets = [
        {'asset_id': host_assets['CLIENT1'], 'os_family': 'windows-client', 'os_version': 'Windows 10 Workstation', 'architecture': 'x86_64', 'vendor': 'Microsoft'},
        {'asset_id': host_assets['CLIENT2'], 'os_family': 'windows-client', 'os_version': 'Windows 10 Workstation', 'architecture': 'x86_64', 'vendor': 'Microsoft'},
        {'asset_id': host_assets['internalserver'], 'os_family': 'linux', 'os_version': 'Debian Internal File/Auth Server', 'architecture': 'x86_64', 'vendor': 'Debian'},
    ]
    used_src = {e['source_id'] for e in selected}
    all_sources = [
        {
            'source_id': 'win-winlogbeat',
            'asset_ids': [host_assets['CLIENT1'], host_assets['CLIENT2']],
            'telemetry': 'sysmon',
            'clock_offset_seconds': 0.0,
            'clock_uncertainty_seconds': 2.0,
            'sensor_version': 'Winlogbeat-7.10.2',
            'config_version': 'collector-v1',
            'completeness': 'partial',
            'source_sha256': win_source_sha,
        },
        {
            'source_id': 'linux-auditbeat',
            'asset_ids': [host_assets['internalserver']],
            'telemetry': 'linux-audit',
            'clock_offset_seconds': 0.0,
            'clock_uncertainty_seconds': 2.0,
            'sensor_version': 'Auditbeat-7.3.2',
            'config_version': 'collector-v1',
            'completeness': 'partial',
            'source_sha256': lin_source_sha,
        },
        {
            'source_id': 'network-suricata',
            'asset_ids': all_assets,
            'telemetry': 'suricata',
            'clock_offset_seconds': 0.0,
            'clock_uncertainty_seconds': 2.0,
            'sensor_version': 'Suricata',
            'config_version': 'collector-v1',
            'completeness': 'partial',
            'source_sha256': suri_source_sha,
        },
    ]
    sources = [s for s in all_sources if s['source_id'] in used_src]

    coverage_tags = {
        'os': ['windows-client', 'linux'],
        'execution_platform': ['virtual-machine'],
        'network': ['segmented-vlan', 'ipv4'],
        'identity_domain': ['workgroup-local'],
        'operational_domain': ['enterprise-it'],
        'dns_domain': ['internal-authoritative'],
        'telemetry': sorted({s['telemetry'] for s in sources if s['telemetry']}),
    }
    difficulty_factors = {
        'noise': {'score': 2, 'rationale': 'Multi-day Windows Winlogbeat, Linux Auditbeat, and Suricata events require targeted SQLite search.'},
        'joins': {'score': 2, 'rationale': 'Cross-OS pivot from Windows workstations (svcmon.exe + OpenSSH) into Linux internalserver (sshd + pdbedit).'},
        'time_span': {'score': 2, 'rationale': 'Multi-day dwell time across Windows persistence and Linux lateral movement.'},
        'gaps': {'score': 1, 'rationale': 'Encrypted SSH tunnel contents are opaque on the wire; requires joining endpoint process telemetry on both OSes.'},
        'ambiguity': {'score': 2, 'rationale': 'Standard OpenSSH, tar, and Python binaries blend with developer/admin workflows.'},
    }
    sophistication = {
        'band': 'S4',
        'boundaries': [
            {'boundary_id': 'bnd-win-host', 'kind': 'host'},
            {'boundary_id': 'bnd-win-privilege', 'kind': 'privilege'},
            {'boundary_id': 'bnd-win-identity', 'kind': 'identity'},
            {'boundary_id': 'bnd-linux-segment', 'kind': 'segment'},
        ],
        'preconditions': ['Initial execution foothold on Windows workstation in client VLAN.'],
        'emulation_limitations': ['DEDALE benchmark dataset; publisher malicious_events_class_1 labels joined mechanically against hourly host logs.'],
        'group_ids': [],
    }

    return write_curated_case(
        output_root,
        case_seed=case_seed,
        pseudonymizer=pseudo,
        split=split,
        provenance='public_replay',
        family_id='dedale-multi-os-apt',
        coverage_tags=coverage_tags,
        difficulty_factors=difficulty_factors,
        control_case=False,
        sophistication=sophistication,
        source_references=[DEDALE_REF],
        assets=assets,
        sources=sources,
        raw_events=selected,
        step_specs=step_specs,
        edges=edges,
        attestation='publisher_labels',
        num_windows=2,
        track='query',
        ioc_regime=ioc_regime,
        extra_iocs=extra_iocs,
        import_notes={'dataset': 'DEDALE Multi-OS APT Query Track', 'total_indexed': len(selected)},
        coverage_path=coverage_path,
    )


# ---------------------------------------------------------------------------
# 3. FullAPT-2025 (4-Host Windows Domain Labeled Sysmon S4 Query-Track)
# ---------------------------------------------------------------------------

# Focus truth steps on core actionable APT kill-chain techniques (rather than noisy OS discovery)
_FULLAPT_KEY_TECHNIQUES = {
    'T1659': ('bnd-host-initial', 'initial'),
    'T1059.001': ('bnd-host-initial', 'initial'),
    'T1059.003': ('bnd-host-initial', 'initial'),
    'T1003.001': ('bnd-host-privilege', 'initial'),
    'T1003.002': ('bnd-host-privilege', 'initial'),
    'T1555.004': ('bnd-host-privilege', 'initial'),
    'T1021.001': ('bnd-domain-segment', 'reentry'),
    'T1021.002': ('bnd-domain-segment', 'reentry'),
    'T1070.004': ('bnd-host-privilege', 'persistence'),
    'T1105': ('bnd-domain-segment', 'reentry'),
    'T1041': ('bnd-domain-segment', 'reentry'),
    'T1048.003': ('bnd-domain-segment', 'reentry'),
}


def import_fullapt_query_case(
    tar_gz_path,
    output_root,
    *,
    run_substr=None,
    split='development',
    ioc_regime='novel_apt_zero_ioc',
    extra_iocs=(),
    salt=None,
    case_seed='fullapt-2025-query',
    max_events=30000,
    coverage_path=DEFAULT_COVERAGE,
):
    tp = Path(tar_gz_path)
    archive_sha = stream_file_sha256(tp, field=tp.name)

    pseudo = CasePseudonymizer(salt=salt)
    pseudo.register_alias('domain', 'boombox.local')
    pseudo.register_alias('domain', 'boombox')

    chosen_member_name = None
    mal_rows = []
    bg_rows = []
    computers_seen = set()
    step_groups = {}
    subsampled = False

    with tarfile.open(tp, 'r:gz') as tf:
        for mem in tf:
            if not mem.isfile() or not mem.name.endswith('-labeled.csv') or 'sysmon' not in mem.name:
                continue
            if run_substr and run_substr not in mem.name:
                continue
            validate_archive_member_name(mem.name, tp.name)
            if mem.size > 2 * 1024 * 1024 * 1024:
                _fail('member_too_large', mem.name)
            chosen_member_name = mem.name
            raw_mem = tf.extractfile(mem)
            if raw_mem is None:
                _fail('missing_archive_member', mem.name)
            bounded_mem = io.BufferedReader(_BoundedBinaryReader(raw_mem, 2 * 1024 * 1024 * 1024, mem.name))
            fh = io.TextIOWrapper(bounded_mem, encoding='utf-8', errors='replace')
            old_csv_lim = csv.field_size_limit(2 * 1024 * 1024)
            try:
                reader = csv.DictReader(fh)
                for rno, row in enumerate(reader, 1):
                    comp_raw = str(row.get('Computer') or '').strip()
                    if not comp_raw:
                        continue
                    computers_seen.add(comp_raw)
                    asset_id = pseudo.pseudonymize('host', comp_raw)

                    ts_ms = str(row.get('timestamp') or '').strip()
                    if not ts_ms:
                        continue
                    if ts_ms.isdigit():
                        stamp = dt.datetime.fromtimestamp(int(ts_ms) / 1000.0, tz=dt.timezone.utc)
                        ts_orig = ts_ms
                    else:
                        try:
                            val_f = float(ts_ms)
                            if val_f > 1e11:
                                stamp = dt.datetime.fromtimestamp(val_f / 1000.0, tz=dt.timezone.utc)
                            else:
                                stamp = dt.datetime.fromtimestamp(val_f, tz=dt.timezone.utc)
                            ts_orig = ts_ms
                        except (ValueError, OSError, OverflowError):
                            try:
                                stamp = parse_utc(ts_ms, 'fullapt.timestamp')
                                ts_orig = ts_ms
                            except BenchmarkError:
                                continue

                    tech_raw = str(row.get('Technique') or '').strip()
                    label_raw = str(row.get('Label') or '').strip()
                    is_mal = bool(
                        tech_raw and tech_raw.lower() not in ('benign', 'normal', 'none', '0')
                    ) or (label_raw.lower() not in ('', 'benign', 'normal', '0'))

                    if not is_mal and len(bg_rows) >= max_events and (rno % 19 != 0):
                        subsampled = True
                        continue

                    eid_num = str(row.get('EventID') or '1').strip()
                    tag = 'row-{}'.format(rno)

                    ct = canonical_valid_technique(tech_raw) if is_mal else None
                    is_key_step = ct in _FULLAPT_KEY_TECHNIQUES

                    if is_mal and not is_key_step and (rno % 4 != 0):
                        subsampled = True
                        continue
                    if not is_mal and int(eid_num or '0') in (10, 7) and (rno % 9 != 0):
                        subsampled = True
                        continue

                    # Strip ALL label columns (Tactic, Technique, Label, Seed_Event)!
                    raw_fields = {
                        'timestamp_original': ts_orig,
                        'event_code': int(eid_num) if eid_num.isdigit() else eid_num,
                        'image': row.get('Image') or row.get('SourceImage'),
                        'command_line': row.get('CommandLine'),
                        'parent_image': row.get('ParentImage'),
                        'parent_command_line': row.get('ParentCommandLine'),
                        'user': pseudo.pseudonymize('user', row.get('User') or row.get('SourceUser') or row.get('TargetUser') or ''),
                        'hashes': row.get('Hashes') or row.get('Hash'),
                        'src_ip': pseudo.pseudonymize('ip', row.get('SourceIp') or ''),
                        'dest_ip': pseudo.pseudonymize('ip', row.get('DestinationIp') or ''),
                        'dest_port': row.get('DestinationPort'),
                        'target_filename': row.get('TargetFilename'),
                        'target_object': row.get('TargetObject'),
                        'pipe_name': row.get('PipeName'),
                    }
                    ev_item = {
                        'tag': tag,
                        'timestamp_utc': format_utc(stamp),
                        'stamp': stamp,
                        'source_id': 'win-sysmon-domain',
                        'asset_id': asset_id,
                        'event_type': 'sysmon_{}'.format(eid_num),
                        'raw_fields': raw_fields,
                        'ts_orig': ts_orig,
                        'record_id': 'win-sysmon-domain:{}'.format(rno),
                        'file_sha256': archive_sha,
                    }
                    if is_mal:
                        mal_rows.append(ev_item)
                        if is_key_step:
                            bnd_id, phase = _FULLAPT_KEY_TECHNIQUES[ct]
                            gkey = (asset_id, ct)
                            st = step_groups.setdefault(gkey, {
                                'step_id': 'step-{}-{}'.format(asset_id[-6:], ct.lower().replace('.', '-')),
                                'technique_id': ct,
                                'asset_id': asset_id,
                                'boundary_id': bnd_id,
                                'phase': phase,
                                'support_tags': [],
                                'first_stamp': stamp,
                            })
                            if len(st['support_tags']) < 48:
                                st['support_tags'].append(tag)
                            if stamp < st['first_stamp']:
                                st['first_stamp'] = stamp
                    else:
                        bg_rows.append(ev_item)
            finally:
                csv.field_size_limit(old_csv_lim)
            break

    if chosen_member_name is None or not step_groups:
        _fail('empty_events', tp.name)

    bg_budget = max(0, max_events - len(mal_rows))
    if len(bg_rows) > bg_budget:
        subsampled = True
        stride = max(1, len(bg_rows) // max(bg_budget, 1))
        chosen_bg = bg_rows[::stride][:bg_budget]
    else:
        chosen_bg = bg_rows
    selected = mal_rows + chosen_bg

    ordered_steps = sorted(step_groups.values(), key=lambda x: (x['first_stamp'], x['step_id']))[:10]
    step_specs = [{
        'step_id': s['step_id'],
        'technique_id': s['technique_id'],
        'asset_id': s['asset_id'],
        'boundary_id': s['boundary_id'],
        'phase': s['phase'],
        'support_tags': s['support_tags'],
    } for s in ordered_steps]
    edges = [[step_specs[i]['step_id'], step_specs[i + 1]['step_id']] for i in range(len(step_specs) - 1)]

    sorted_comps = sorted(computers_seen)
    assets = [{
        'asset_id': pseudo.pseudonymize('host', c),
        'os_family': 'windows-server' if idx == 0 else 'windows-client',
        'os_version': 'Windows Domain Host',
        'architecture': 'x86_64',
        'vendor': 'Microsoft',
    } for idx, c in enumerate(sorted_comps)]
    all_asset_ids = [a['asset_id'] for a in assets]

    for ev in selected:
        cleaned_fields = pseudo.clean_fields(ev.pop('raw_fields'))
        cleaned_fields['timestamp_original'] = ev.pop('ts_orig')
        ev['fields'] = cleaned_fields

    sources = [{
        'source_id': 'win-sysmon-domain',
        'asset_ids': all_asset_ids,
        'telemetry': 'sysmon',
        'clock_offset_seconds': 0.0,
        'clock_uncertainty_seconds': 1.0,
        'sensor_version': 'Sysmon-15.0',
        'config_version': 'collector-v1',
        'completeness': 'partial' if subsampled else 'complete',
        'source_sha256': archive_sha,
    }]

    known_gaps = []
    if subsampled and selected:
        sel_stamps = sorted(ev['stamp'] for ev in selected)
        g0 = sel_stamps[0]
        g1 = max(sel_stamps[-1], g0 + dt.timedelta(seconds=1))
        known_gaps.append({
            'source_id': 'win-sysmon-domain',
            'asset_id': all_asset_ids[0],
            'window_utc': {'start_inclusive': format_utc(g0), 'end_exclusive': format_utc(g1)},
            'reason': 'source_subsampled: high-frequency Sysmon background rows were stride-sampled.',
        })

    boundaries = [
        {'boundary_id': 'bnd-host-initial', 'kind': 'host'},
        {'boundary_id': 'bnd-host-privilege', 'kind': 'privilege'},
        {'boundary_id': 'bnd-domain-identity', 'kind': 'identity'},
        {'boundary_id': 'bnd-domain-segment', 'kind': 'domain'},
    ]
    soph_band = derive_sophistication_band(step_specs, boundaries, control_case=False)
    if soph_band in ('S0', 'S1'):
        edges = []

    family_slug = Path(tp.name).name.split('.')[0].replace('_', '-')
    coverage_tags = {
        'os': sorted({a['os_family'] for a in assets}),
        'execution_platform': ['virtual-machine'],
        'network': ['flat-lan', 'ipv4'],
        'identity_domain': ['ad-single-domain'],
        'operational_domain': ['enterprise-it'],
        'dns_domain': ['internal-authoritative'],
        'telemetry': ['sysmon'],
    }
    difficulty_factors = {
        'noise': {'score': 2, 'rationale': 'Tens of thousands of multi-host Sysmon process, image-load, and network rows require FTS/indexed triage.'},
        'joins': {'score': 2, 'rationale': 'Multi-host lateral movement (RDP/SMB), LSASS/SAM credential dumping, defense evasion, and exfiltration across 4 domain endpoints.'},
        'time_span': {'score': 2, 'rationale': 'Extended multi-stage domain APT campaign.'},
        'gaps': {'score': 1, 'rationale': 'Packet captures and Windows Security 4624 logs are absent; lateral movement must be reconstructed from Sysmon 1/3/11/13.'},
        'ambiguity': {'score': 2, 'rationale': 'Built-in Windows utilities (cmd, rundll32, mstsc, net) overlap with normal domain operations.'},
    }
    sophistication = {
        'band': soph_band,
        'boundaries': boundaries,
        'preconditions': ['Initial payload delivery on first domain endpoint.'],
        'emulation_limitations': ['FullAPT-2025 cyber-range Sysmon dataset; publisher Tactic/Technique/Label columns strictly stripped from public SQLite store.'],
        'group_ids': [],
    }

    report = write_curated_case(
        output_root,
        case_seed=case_seed,
        pseudonymizer=pseudo,
        split=split,
        provenance='public_replay',
        family_id='fullapt-2025-' + family_slug,
        coverage_tags=coverage_tags,
        difficulty_factors=difficulty_factors,
        control_case=False,
        sophistication=sophistication,
        source_references=[FULLAPT_REF],
        assets=assets,
        sources=sources,
        raw_events=selected,
        step_specs=step_specs,
        edges=edges,
        known_gaps=known_gaps,
        attestation='publisher_labels',
        num_windows=2,
        track='query',
        ioc_regime=ioc_regime,
        extra_iocs=extra_iocs,
        import_notes={'dataset': 'FullAPT-2025 Query Track', 'member': chosen_member_name, 'total_indexed': len(selected)},
        coverage_path=coverage_path,
    )

    # Anti-contamination check on events.sqlite3
    db_path = Path(report['case_dir']) / 'public' / 'events.sqlite3'
    conn = sqlite3.connect(str(db_path))
    try:
        leak = conn.execute(
            "SELECT COUNT(*) FROM events WHERE fields_json LIKE '%Seed_Event%' OR fields_json LIKE '%\"Tactic\"%' OR fields_json LIKE '%\"Technique\"%'"
        ).fetchone()[0]
    finally:
        conn.close()
    if leak:
        _fail('truth_public_overlap', 'events.sqlite3')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description='Import Wave 2 SQLite query-track APT cases.')
    sub = parser.add_subparsers(dest='source', required=True)

    p_apt = sub.add_parser('apt29')
    p_apt.add_argument('--zip-path', required=True)
    p_apt.add_argument('--segmentation-path', required=True)
    p_apt.add_argument('--output-root', required=True)
    p_apt.add_argument('--ioc-regime', choices=('known_ioc_pivot', 'novel_apt_zero_ioc'), default='novel_apt_zero_ioc')

    p_ded = sub.add_parser('dedale')
    p_ded.add_argument('--dedale-raw-dir', required=True)
    p_ded.add_argument('--output-root', required=True)
    p_ded.add_argument('--split', choices=('development', 'holdout'), default='development')
    p_ded.add_argument('--ioc-regime', choices=('known_ioc_pivot', 'novel_apt_zero_ioc'), default='novel_apt_zero_ioc')

    p_fa = sub.add_parser('fullapt')
    p_fa.add_argument('--tar-gz-path', required=True)
    p_fa.add_argument('--output-root', required=True)
    p_fa.add_argument('--run-substr', default=None)
    p_fa.add_argument('--split', choices=('development', 'holdout'), default='development')
    p_fa.add_argument('--ioc-regime', choices=('known_ioc_pivot', 'novel_apt_zero_ioc'), default='novel_apt_zero_ioc')

    args = parser.parse_args(argv)
    if args.source == 'apt29':
        rep = import_apt29_day2_query_case(args.zip_path, args.segmentation_path, args.output_root, ioc_regime=args.ioc_regime)
    elif args.source == 'dedale':
        rep = import_dedale_query_case(args.dedale_raw_dir, args.output_root, split=args.split, ioc_regime=args.ioc_regime)
    else:
        rep = import_fullapt_query_case(args.tar_gz_path, args.output_root, run_substr=args.run_substr, split=args.split, ioc_regime=args.ioc_regime)
    sys.stdout.write(json.dumps(rep, indent=2, sort_keys=True) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
