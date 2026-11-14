"""Import CAM-LDS Multi-Host Linux APT Scenario Zips as `publisher_labels` Cases.

CAM-LDS (`scenario_3_ssh_apt.zip`, `scenario_3_vnc_apt.zip`, etc.) pairs real
multi-host Linux telemetry (`reposerver`, `linuxshare`, `inetfw`, `corpdns`,
`wazuh`) with machine-recorded AttackMate execution timelines (`attackmate.json`,
JSON Lines).

Safety & anti-contamination rules:
- Strictly refuses to import any archive member under `/configs/` (which holds
  lab SSH private keys and TLS certs) or `/attacker/` into public telemetry.
- `attackmate.json` is read strictly for evaluator-only `publisher_labels` ground
  truth and never enters `public/`.
- Clips post-scenario log-harvest `rsync` collection artifacts (`last_attack + 180s`),
  and supports `--control-pre-attack` to extract clean pre-attack S0 benign
  multi-host Linux control cases.
"""
import argparse
import binascii
import datetime as dt
import io
import json
from pathlib import Path
import re
import sys
import zipfile

import benchmark_paths  # noqa: F401
from benchmark_case_writer import (
    DEFAULT_COVERAGE, CasePseudonymizer, canonical_valid_technique,
    derive_sophistication_band, format_utc, iter_bounded_lines,
    read_bounded_zip_member, read_regular_bytes, validate_archive_member_name,
    write_curated_case,
)
from benchmark_contracts import BenchmarkError, decode_json, parse_utc

SOURCE_REF = 'https://zenodo.org/records/14850600'

_MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12,
}
_SYSLOG_TRAD_RE = re.compile(
    r'\A([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+(.*)\Z'
)
_SYSLOG_ISO_RE = re.compile(
    r'\A(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+(\S+)\s+(.*)\Z'
)
_DPKG_RE = re.compile(
    r'\A(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(.*)\Z'
)
_APACHE_RE = re.compile(
    r'\A(\S+)\s+\S+\s+\S+\s+\[(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}:\d{2}:\d{2})\s+([+-]\d{4})\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)'
)
_AUDIT_PROCTITLE_RE = re.compile(
    r'type=PROCTITLE\s+msg=audit\((\d+\.\d+):(\d+)\):\s+proctitle=([0-9A-Fa-f]+|"[^"]*")'
)
_AUDIT_SYSCALL_RE = re.compile(
    r'type=SYSCALL\s+msg=audit\((\d+\.\d+):(\d+)\):.*?\bexe="([^"]+)".*?\bUID="([^"]+)"'
)


def _fail(code, field='camlds'):
    raise BenchmarkError(code, field) from None


def _norm_tz_iso(ts_str):
    s = ts_str.strip()
    if re.search(r'[+-]\d{4}\Z', s):
        s = s[:-2] + ':' + s[-2:]
    return s


def _parse_am_stamp(val):
    if not val:
        return None
    s = str(val).strip()
    if not s.endswith('Z') and '+' not in s[10:] and '-' not in s[10:]:
        s += 'Z'
    return parse_utc(s, 'attackmate.datetime')


def _decode_proctitle(raw_val):
    if raw_val.startswith('"') and raw_val.endswith('"'):
        return raw_val[1:-1]
    try:
        raw_bytes = binascii.unhexlify(raw_val)
        parts = [p.decode('utf-8', 'replace') for p in raw_bytes.split(b'\x00') if p]
        return ' '.join(parts)
    except (binascii.Error, ValueError):
        return raw_val


def import_camlds_case(
    zip_path,
    output_root,
    *,
    split='development',
    control_pre_attack=False,
    ioc_regime='novel_apt_zero_ioc',
    extra_iocs=(),
    salt=None,
    case_seed=None,
    max_inline_events=600,
    coverage_path=DEFAULT_COVERAGE,
):
    zp = Path(zip_path)
    zip_sha, raw_zip = read_regular_bytes(zp, field=zp.name)

    pseudo = CasePseudonymizer(salt=salt)
    for alias_k, alias_v in (
        ('domain', 'attackbed.com'),
        ('host', 'fw.attackbed.com'),
        ('host', 'puppet'),
        ('host', 'reposerver'),
        ('host', 'linuxshare'),
        ('host', 'inetfw'),
        ('host', 'corpdns'),
        ('user', 'aecid'),
        ('user', 'john'),
        ('password', 'rambo'),
    ):
        pseudo.register_alias(alias_k, alias_v)

    host_assets = {
        'reposerver': pseudo.pseudonymize('host', 'reposerver'),
        'linuxshare': pseudo.pseudonymize('host', 'linuxshare'),
        'inetfw': pseudo.pseudonymize('host', 'inetfw'),
        'corpdns': pseudo.pseudonymize('host', 'corpdns'),
    }

    with zipfile.ZipFile(io.BytesIO(raw_zip)) as zf:
        names = zf.namelist()
        am_members = [n for n in names if n.endswith('/attackmate.json') or n == 'attackmate.json']
        if not am_members:
            _fail('missing_attackmate', zp.name)
        am_bytes = read_bounded_zip_member(zf, am_members[0], field='attackmate.json')
        am_lines = [
            decode_json(ln)
            for ln in am_bytes.decode('utf-8').splitlines()
            if ln.strip()
        ]

        am_stamps = [
            _parse_am_stamp(a.get('start-datetime'))
            for a in am_lines
            if a.get('start-datetime')
        ]
        am_stamps = [s for s in am_stamps if s is not None]
        if not am_stamps:
            _fail('empty_attackmate', zp.name)

        first_attack = min(am_stamps)
        last_attack = max(am_stamps)
        ref_year = first_attack.year

        if control_pre_attack:
            win_start = first_attack - dt.timedelta(seconds=720)
            win_end = first_attack - dt.timedelta(seconds=20)
        else:
            win_start = first_attack - dt.timedelta(seconds=60)
            win_end = last_attack + dt.timedelta(seconds=150)

        collected = []

        def _in_win(st):
            return win_start <= st < win_end

        for member in sorted(names):
            validate_archive_member_name(member, zp.name)
            if member.endswith('/') or '/configs/' in member or '/attacker/' in member:
                continue
            parts = member.split('/')
            if len(parts) < 3:
                continue
            host_key = parts[1]
            rel_sub = '/'.join(parts[2:])

            # 1. Wazuh alerts.json (centralized host/IDS alerts)
            if host_key == 'wazuh' and rel_sub == 'logs/alerts/alerts.json':
                text = read_bounded_zip_member(zf, member, field=member).decode('utf-8', 'replace')
                for lno, ln in enumerate(text.splitlines(), 1):
                    if not ln.strip():
                        continue
                    try:
                        obj = decode_json(ln)
                    except BenchmarkError:
                        continue
                    ts_raw = _norm_tz_iso(str(obj.get('timestamp') or ''))
                    if not ts_raw:
                        continue
                    st = parse_utc(ts_raw, 'wazuh.timestamp')
                    if not _in_win(st):
                        continue
                    ag_name = str((obj.get('agent') or {}).get('name') or 'inetfw').lower()
                    target_host = ag_name if ag_name in host_assets else 'inetfw'
                    rule = obj.get('rule') or {}
                    mitre_ids = []
                    for tid in ((rule.get('mitre') or {}).get('id') or []):
                        ct = canonical_valid_technique(tid)
                        if ct:
                            mitre_ids.append(ct)
                    fields = pseudo.clean_fields({
                        'timestamp_original': ts_raw,
                        'rule_id': str(rule.get('id') or ''),
                        'rule_level': int(rule.get('level') or 0),
                        'description': str(rule.get('description') or ''),
                        'location': str(obj.get('location') or ''),
                        'full_log': str(obj.get('full_log') or '')[:1024],
                    })
                    fields['timestamp_original'] = ts_raw
                    if mitre_ids:
                        fields['detector_attack_ids'] = sorted(set(mitre_ids))
                    collected.append({
                        'tag': 'wazuh:{}'.format(lno),
                        'host_key': target_host,
                        'timestamp_utc': format_utc(st),
                        'stamp': st,
                        'source_id': 'linux-syslog-wazuh',
                        'asset_id': host_assets[target_host],
                        'event_type': 'wazuh_alert',
                        'fields': fields,
                        'record_id': 'wazuh:{}'.format(lno),
                        'raw_match_text': str(obj.get('full_log') or rule.get('description') or ''),
                        'priority': 2 if int(rule.get('level') or 0) >= 5 else 0,
                    })

            elif host_key in host_assets:
                # 2. auth.log & cron.log
                if rel_sub in ('logs/log/auth.log', 'logs/log/cron.log'):
                    ev_kind = 'linux_auth' if rel_sub.endswith('auth.log') else 'linux_cron'
                    text = read_bounded_zip_member(zf, member, field=member).decode('utf-8', 'replace')
                    for lno, ln in enumerate(text.splitlines(), 1):
                        m_iso = _SYSLOG_ISO_RE.match(ln)
                        m_trad = None if m_iso else _SYSLOG_TRAD_RE.match(ln)
                        if m_iso:
                            ts_raw = _norm_tz_iso(m_iso.group(1))
                            st = parse_utc(ts_raw, 'syslog.iso')
                            msg = m_iso.group(3)
                        elif m_trad:
                            mon = _MONTHS.get(m_trad.group(1), 12)
                            day = int(m_trad.group(2))
                            hh, mm, ss = int(m_trad.group(3)), int(m_trad.group(4)), int(m_trad.group(5))
                            yr = ref_year + 1 if (mon == 1 and first_attack.month == 12) else (
                                ref_year - 1 if (mon == 12 and first_attack.month == 1) else ref_year
                            )
                            try:
                                st = dt.datetime(yr, mon, day, hh, mm, ss, tzinfo=dt.timezone.utc)
                            except ValueError:
                                continue
                            ts_raw = '{} {:2d} {:02d}:{:02d}:{:02d}'.format(
                                m_trad.group(1), day, hh, mm, ss
                            )
                            msg = m_trad.group(7)
                        else:
                            continue
                        if not _in_win(st) or 'rsync --server --sender' in msg:
                            continue
                        fields = pseudo.clean_fields({
                            'timestamp_original': ts_raw,
                            'log_file': rel_sub.rsplit('/', 1)[-1],
                            'message': msg,
                        })
                        fields['timestamp_original'] = ts_raw
                        prio = 3 if any(w in msg.lower() for w in ('accepted', 'failed', 'sudo', 'session opened', 'curl', 'userdel', 'healthcheck')) else 1
                        collected.append({
                            'tag': '{}:{}:{}'.format(host_key, ev_kind, lno),
                            'host_key': host_key,
                            'timestamp_utc': format_utc(st),
                            'stamp': st,
                            'source_id': 'linux-syslog-wazuh',
                            'asset_id': host_assets[host_key],
                            'event_type': ev_kind,
                            'fields': fields,
                            'record_id': 'syslog:{}:{}'.format(ev_kind, lno),
                            'raw_match_text': msg,
                            'priority': prio,
                        })

                # 3. dpkg.log
                elif rel_sub == 'logs/log/dpkg.log':
                    text = read_bounded_zip_member(zf, member, field=member).decode('utf-8', 'replace')
                    for lno, ln in enumerate(text.splitlines(), 1):
                        m = _DPKG_RE.match(ln)
                        if not m:
                            continue
                        ts_raw = '{}T{}Z'.format(m.group(1), m.group(2))
                        st = parse_utc(ts_raw, 'dpkg.timestamp')
                        if not _in_win(st):
                            continue
                        msg = m.group(3)
                        fields = pseudo.clean_fields({
                            'timestamp_original': '{} {}'.format(m.group(1), m.group(2)),
                            'dpkg_action': msg,
                        })
                        fields['timestamp_original'] = '{} {}'.format(m.group(1), m.group(2))
                        collected.append({
                            'tag': '{}:dpkg:{}'.format(host_key, lno),
                            'host_key': host_key,
                            'timestamp_utc': format_utc(st),
                            'stamp': st,
                            'source_id': 'linux-syslog-wazuh',
                            'asset_id': host_assets[host_key],
                            'event_type': 'dpkg_package',
                            'fields': fields,
                            'record_id': 'dpkg:{}'.format(lno),
                            'raw_match_text': msg,
                            'priority': 3,
                        })

                # 4. apache2/access.log
                elif rel_sub == 'logs/log/apache2/access.log':
                    text = read_bounded_zip_member(zf, member, field=member).decode('utf-8', 'replace')
                    for lno, ln in enumerate(text.splitlines(), 1):
                        m = _APACHE_RE.match(ln)
                        if not m:
                            continue
                        client_ip, dd, mon_s, yyyy, hms, tz_s, req, status_c, _sz = m.groups()
                        mon = _MONTHS.get(mon_s, 12)
                        iso_s = '{}-{:02d}-{:02d}T{}{}:{}'.format(
                            int(yyyy), mon, int(dd), hms, tz_s[:3], tz_s[3:]
                        )
                        st = parse_utc(iso_s, 'apache.timestamp')
                        if not _in_win(st):
                            continue
                        fields = pseudo.clean_fields({
                            'timestamp_original': iso_s,
                            'client_ip': pseudo.pseudonymize('ip', client_ip),
                            'http_request': req,
                            'status_code': int(status_c),
                        })
                        fields['timestamp_original'] = iso_s
                        collected.append({
                            'tag': '{}:apache:{}'.format(host_key, lno),
                            'host_key': host_key,
                            'timestamp_utc': format_utc(st),
                            'stamp': st,
                            'source_id': 'linux-syslog-wazuh',
                            'asset_id': host_assets[host_key],
                            'event_type': 'http_access',
                            'fields': fields,
                            'record_id': 'apache:{}'.format(lno),
                            'raw_match_text': req,
                            'priority': 3 if '.deb' in req else 1,
                        })

                # 5. audit/audit.log (order-independent PROCTITLE + SYSCALL pairing)
                elif rel_sub == 'logs/log/audit/audit.log':
                    audit_pairs = {}
                    with zf.open(member) as fh:
                        for lno, raw_line in iter_bounded_lines(fh, field=member):
                            ln = raw_line.decode('utf-8', 'replace').strip()
                            ms = _AUDIT_SYSCALL_RE.search(ln)
                            if ms:
                                epoch_s, serial_s, exe_s, uid_s = ms.groups()
                                st = dt.datetime.fromtimestamp(float(epoch_s), tz=dt.timezone.utc)
                                if _in_win(st):
                                    rec = audit_pairs.setdefault(serial_s, {'lno': lno, 'epoch_s': epoch_s, 'st': st})
                                    rec['exe_s'] = exe_s
                                    rec['uid_s'] = uid_s
                                continue
                            mp = _AUDIT_PROCTITLE_RE.search(ln)
                            if mp:
                                epoch_s, serial_s, pt_raw = mp.groups()
                                st = dt.datetime.fromtimestamp(float(epoch_s), tz=dt.timezone.utc)
                                if _in_win(st):
                                    rec = audit_pairs.setdefault(serial_s, {'lno': lno, 'epoch_s': epoch_s, 'st': st})
                                    rec['lno'] = lno
                                    rec['epoch_s'] = epoch_s
                                    rec['st'] = st
                                    rec['cmdline'] = _decode_proctitle(pt_raw)
                    for serial_s, rec in sorted(audit_pairs.items(), key=lambda kv: kv[1]['lno']):
                        cmdline = rec.get('cmdline')
                        if not cmdline:
                            continue
                        if 'rsync --server --sender' in cmdline or 'collectd' in cmdline:
                            continue
                        exe_s = rec.get('exe_s', '')
                        uid_s = rec.get('uid_s', '')
                        lno = rec['lno']
                        epoch_s = rec['epoch_s']
                        st = rec['st']
                        is_interesting = any(
                            kw in cmdline.lower()
                            for kw in (
                                'sudo', 'shadow', 'passwd', 'tcpdump', 'dpkg', 'healthcheck',
                                'curl', 'donotcry', 'python', 'bash', 'userdel', 'rm -rf',
                                'exim4', 'ca_key', 'puppet', 'ssh', 'vnc', 'xterm', 'apt',
                            )
                        )
                        fields = pseudo.clean_fields({
                            'timestamp_original': epoch_s,
                            'audit_serial': int(serial_s),
                            'exe': exe_s,
                            'user': pseudo.pseudonymize('user', uid_s),
                            'command_line': cmdline,
                        })
                        fields['timestamp_original'] = epoch_s
                        collected.append({
                            'tag': '{}:audit:{}'.format(host_key, lno),
                            'host_key': host_key,
                            'timestamp_utc': format_utc(st),
                            'stamp': st,
                            'source_id': 'linux-auditd',
                            'asset_id': host_assets[host_key],
                            'event_type': 'auditd_exec',
                            'fields': fields,
                            'record_id': 'auditd:{}'.format(lno),
                            'raw_match_text': cmdline + ' ' + exe_s,
                            'priority': 4 if is_interesting else 0,
                        })

                # 6. suricata/eve.json (alert, ssh, http, dns)
                elif rel_sub == 'logs/log/suricata/eve.json':
                    with zf.open(member) as fh:
                        for lno, raw_line in iter_bounded_lines(fh, field=member):
                            ln = raw_line.decode('utf-8', 'replace').strip()
                            if not ln:
                                continue
                            try:
                                obj = decode_json(ln)
                            except BenchmarkError:
                                continue
                            etype = str(obj.get('event_type') or '')
                            if etype not in ('alert', 'ssh', 'http', 'dns'):
                                continue
                            ts_raw = _norm_tz_iso(str(obj.get('timestamp') or ''))
                            if not ts_raw:
                                continue
                            st = parse_utc(ts_raw, 'suricata.timestamp')
                            if not _in_win(st):
                                continue
                            alert_sig = str((obj.get('alert') or {}).get('signature') or '')
                            http_url = str((obj.get('http') or {}).get('url') or '')
                            fields = pseudo.clean_fields({
                                'timestamp_original': ts_raw,
                                'src_ip': pseudo.pseudonymize('ip', obj.get('src_ip') or ''),
                                'src_port': obj.get('src_port'),
                                'dest_ip': pseudo.pseudonymize('ip', obj.get('dest_ip') or ''),
                                'dest_port': obj.get('dest_port'),
                                'proto': obj.get('proto'),
                                'alert_signature': alert_sig,
                                'http_url': http_url,
                            })
                            fields['timestamp_original'] = ts_raw
                            collected.append({
                                'tag': '{}:suricata:{}'.format(host_key, lno),
                                'host_key': host_key,
                                'timestamp_utc': format_utc(st),
                                'stamp': st,
                                'source_id': 'network-suricata',
                                'asset_id': host_assets[host_key],
                                'event_type': 'suricata_' + etype,
                                'fields': fields,
                                'record_id': 'suricata:{}'.format(lno),
                                'raw_match_text': alert_sig + ' ' + http_url,
                                'priority': 3 if etype in ('alert', 'http', 'ssh') else 1,
                            })

    if not collected:
        _fail('empty_events', zp.name)

    # Map AttackMate steps onto host events (when not control_pre_attack)
    step_specs = []
    edges = []
    must_keep_tags = set()

    if not control_pre_attack:
        grouped = {}
        for am in am_lines:
            md = (am.get('parameters') or {}).get('metadata') or {}
            tech_field = str(md.get('techniques') or '').strip()
            if not tech_field:
                continue
            primary_tech = None
            for cand in [t.strip() for t in tech_field.split(',') if t.strip()]:
                ct = canonical_valid_technique(cand)
                if ct:
                    primary_tech = ct
                    break
            if not primary_tech:
                continue

            st0 = _parse_am_stamp(am.get('start-datetime'))
            if st0 is None:
                continue
            sess = str((am.get('parameters') or {}).get('session') or '')
            cmd_str = str(am.get('cmd') or (am.get('parameters') or {}).get('action') or '').strip()

            if sess == 'movement':
                target_hosts = ('linuxshare',)
                bnd_id = 'bnd-internal-segment'
                phase = 'reentry'
                lead_s, trail_s = 5, 40
            elif primary_tech in ('T1072', 'T1053.003'):
                target_hosts = ('linuxshare', 'reposerver')
                bnd_id = 'bnd-internal-segment'
                phase = 'persistence'
                lead_s, trail_s = 5, 240
            elif primary_tech in ('T1078.003', 'T1003.008'):
                target_hosts = ('reposerver',)
                bnd_id = 'bnd-host-privilege'
                phase = 'initial'
                lead_s, trail_s = 5, 35
            else:
                target_hosts = ('reposerver', 'inetfw')
                bnd_id = 'bnd-perimeter-identity'
                phase = 'initial'
                lead_s, trail_s = 10, 35

            cmd_tokens = [
                tok.lower()
                for tok in re.split(r'[^A-Za-z0-9_.-]+', cmd_str)
                if len(tok) >= 4 and tok.lower() not in ('bash', 'echo', 'export', 'sudo')
            ]
            cmd_lower = cmd_str.strip().lower()
            has_sudo_token = bool(re.search(r'\bsudo\b', cmd_lower))
            is_sudo_root_shell = bool(
                re.search(r'\bsudo\s+(?:-[a-z0-9]+\s+)*(?:-i|-s|su\b|(?:/usr)?/bin/(?:ba)?sh)\b', cmd_lower)
            )
            action_type = str(am.get('type') or '').lower()

            matched = []
            for ev in collected:
                if ev['host_key'] not in target_hosts:
                    continue
                dt_s = (ev['stamp'] - st0).total_seconds()
                if not (-lead_s <= dt_s <= trail_s):
                    continue
                txt_l = ev['raw_match_text'].lower()
                if cmd_tokens and any(tok in txt_l for tok in cmd_tokens):
                    matched.append((0, ev))
                elif (not cmd_tokens and is_sudo_root_shell and (
                    re.search(r'\bsudo\s+(?:-[a-z0-9]+\s+)*(?:-i|-s|su\b|(?:/usr)?/bin/(?:ba)?sh)\b', txt_l)
                    or ('sudo' in txt_l and 'user=root' in txt_l and any(
                        sh in txt_l for sh in ('command=/bin/bash', 'command=/bin/sh', 'command=/usr/bin/su', 'command=/bin/su')
                    ))
                )):
                    matched.append((0, ev))
                elif (not cmd_tokens and not has_sudo_token and primary_tech.startswith('T1078')
                      and action_type in ('ssh', 'vnc')
                      and ('accepted ' in txt_l or ('sshd' in txt_l and 'session opened' in txt_l))):
                    matched.append((1, ev))

            if not matched:
                continue
            matched.sort(key=lambda pair: (pair[0], abs((pair[1]['stamp'] - st0).total_seconds())))
            chosen_host = matched[0][1]['host_key']
            host_matches = [ev['tag'] for _rank, ev in matched if ev['host_key'] == chosen_host][:16]

            gkey = (chosen_host, primary_tech)
            g_entry = grouped.setdefault(gkey, {
                'step_id': 'step-{}-{}'.format(chosen_host, primary_tech.lower().replace('.', '-')),
                'technique_id': primary_tech,
                'asset_id': host_assets[chosen_host],
                'boundary_id': bnd_id,
                'phase': phase,
                'support_tags': [],
                'first_stamp': st0,
            })
            for t in host_matches:
                if t not in g_entry['support_tags']:
                    g_entry['support_tags'].append(t)
                must_keep_tags.add(t)

        ordered = sorted(grouped.values(), key=lambda x: (x['first_stamp'], x['step_id']))
        for item in ordered[:8]:
            step_specs.append({
                'step_id': item['step_id'],
                'technique_id': item['technique_id'],
                'asset_id': item['asset_id'],
                'boundary_id': item['boundary_id'],
                'phase': item['phase'],
                'support_tags': item['support_tags'],
            })
        for i in range(len(step_specs) - 1):
            edges.append([step_specs[i]['step_id'], step_specs[i + 1]['step_id']])

    subsampled = False
    # Bound inline event count while keeping 100% of step support tags + high-priority events across all 4 hosts
    if len(collected) > max_inline_events:
        subsampled = True
        must = [ev for ev in collected if ev['tag'] in must_keep_tags]
        rest = [ev for ev in collected if ev['tag'] not in must_keep_tags]
        rest.sort(key=lambda ev: (-ev['priority'], ev['stamp']))
        budget = max(0, max_inline_events - len(must))
        selected = must + rest[:budget]
    else:
        selected = collected

    used_sources = {ev['source_id'] for ev in selected}
    all_asset_ids = [host_assets['reposerver'], host_assets['linuxshare'], host_assets['inetfw'], host_assets['corpdns']]
    assets = [
        {'asset_id': host_assets['reposerver'], 'os_family': 'linux', 'os_version': 'Ubuntu 22.04 LTS', 'architecture': 'x86_64', 'vendor': 'Canonical'},
        {'asset_id': host_assets['linuxshare'], 'os_family': 'linux', 'os_version': 'Ubuntu 22.04 LTS', 'architecture': 'x86_64', 'vendor': 'Canonical'},
        {'asset_id': host_assets['inetfw'], 'os_family': 'linux', 'os_version': 'Ubuntu 22.04 LTS', 'architecture': 'x86_64', 'vendor': 'Canonical'},
        {'asset_id': host_assets['corpdns'], 'os_family': 'linux', 'os_version': 'Ubuntu 22.04 LTS', 'architecture': 'x86_64', 'vendor': 'Canonical'},
    ]

    all_source_defs = [
        {
            'source_id': 'linux-auditd',
            'asset_ids': all_asset_ids,
            'telemetry': 'linux-audit',
            'clock_offset_seconds': 0.0,
            'clock_uncertainty_seconds': 1.0,
            'sensor_version': 'auditd-3.0.7',
            'config_version': 'collector-v1',
            'completeness': 'partial',
            'source_sha256': zip_sha,
        },
        {
            'source_id': 'linux-syslog-wazuh',
            'asset_ids': all_asset_ids,
            'telemetry': 'journald',
            'clock_offset_seconds': 0.0,
            'clock_uncertainty_seconds': 1.0,
            'sensor_version': 'rsyslog-wazuh-4.7',
            'config_version': 'collector-v1',
            'completeness': 'partial' if subsampled else 'complete',
            'source_sha256': zip_sha,
        },
        {
            'source_id': 'network-suricata',
            'asset_ids': all_asset_ids,
            'telemetry': 'suricata',
            'clock_offset_seconds': 0.0,
            'clock_uncertainty_seconds': 1.0,
            'sensor_version': 'Suricata-7.0',
            'config_version': 'eve-json',
            'completeness': 'partial',
            'source_sha256': zip_sha,
        },
    ]
    sources = [s for s in all_source_defs if s['source_id'] in used_sources]

    known_gaps = []
    if subsampled and selected:
        sel_stamps = sorted(ev['stamp'] for ev in selected)
        g0 = sel_stamps[0]
        g1 = max(sel_stamps[-1], g0 + dt.timedelta(seconds=1))
        first_src = sources[0]['source_id']
        known_gaps.append({
            'source_id': first_src,
            'asset_id': host_assets['reposerver'],
            'window_utc': {'start_inclusive': format_utc(g0), 'end_exclusive': format_utc(g1)},
            'reason': 'source_subsampled: low-priority background log events were capped to fit inline bundle limits.',
        })

    boundaries = [
        {'boundary_id': 'bnd-perimeter-identity', 'kind': 'identity'},
        {'boundary_id': 'bnd-host-privilege', 'kind': 'privilege'},
        {'boundary_id': 'bnd-internal-segment', 'kind': 'segment'},
    ]
    is_ctrl = bool(control_pre_attack or not step_specs)
    soph_band = derive_sophistication_band(step_specs, boundaries, control_case=is_ctrl)
    if soph_band in ('S0', 'S1'):
        edges = []

    telemetry_used = sorted({s['telemetry'] for s in sources if s['telemetry']})
    coverage_tags = {
        'os': ['linux'],
        'execution_platform': ['virtual-machine'],
        'network': ['segmented-vlan', 'dmz', 'ipv4'],
        'identity_domain': ['workgroup-local', 'machine-service-identity'],
        'operational_domain': ['enterprise-it'],
        'dns_domain': ['internal-authoritative'],
        'telemetry': telemetry_used,
    }
    difficulty_factors = {
        'noise': {'score': 2, 'rationale': 'Wazuh CIS SCA benchmark alerts, cron jobs, and Puppet/APT background activity interleave across 4 Linux hosts.'},
        'joins': {'score': 0 if control_pre_attack else 2, 'rationale': 'Requires linking perimeter SSH/VNC entry, repository .deb trojaning, and downstream package installation + cron execution.'},
        'time_span': {'score': 1, 'rationale': '20-to-30 minute multi-host campaign with delayed package/cron manifestation.'},
        'gaps': {'score': 1, 'rationale': 'Raw packet payloads and attacker-host logs are excluded; encrypted SSH session stdin is only visible via host auditd.'},
        'ambiguity': {'score': 2, 'rationale': 'Legitimate Debian package management (dpkg/apt), cron scheduling, and rsync administration mimic supply-chain pivot steps.'},
    }
    sophistication = {
        'band': soph_band,
        'boundaries': boundaries if step_specs else [],
        'preconditions': [] if control_pre_attack else ['Reachable perimeter forwarding service and internal Debian package trust between linuxshare and reposerver.'],
        'emulation_limitations': [
            'CAM-LDS cyber-range scenario with AttackMate automated orchestration; configs/ and attacker/ directories strictly excluded from public evidence.',
        ],
        'group_ids': [],
    }

    seed = case_seed or ('camlds-{}-{}'.format(zp.stem, 'ctrl' if control_pre_attack else 'apt'))
    return write_curated_case(
        output_root,
        case_seed=seed,
        pseudonymizer=pseudo,
        split=split,
        provenance='public_replay',
        family_id='camlds-linux-control' if control_pre_attack else 'camlds-' + zp.stem.replace('_', '-'),
        coverage_tags=coverage_tags,
        difficulty_factors=difficulty_factors,
        control_case=bool(control_pre_attack or not step_specs),
        sophistication=sophistication,
        source_references=[SOURCE_REF],
        assets=assets,
        sources=sources,
        raw_events=selected,
        step_specs=step_specs,
        edges=edges,
        known_gaps=known_gaps,
        attestation='publisher_labels',
        num_windows=1 if control_pre_attack else 2,
        track='inline',
        ioc_regime=ioc_regime,
        extra_iocs=extra_iocs,
        import_notes={'dataset': 'CAM-LDS', 'archive': zp.name, 'control_pre_attack': control_pre_attack},
        coverage_path=coverage_path,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description='Import CAM-LDS multi-host Linux APT case.')
    parser.add_argument('--zip-path', required=True)
    parser.add_argument('--output-root', required=True)
    parser.add_argument('--split', choices=('development', 'holdout'), default='development')
    parser.add_argument('--control-pre-attack', action='store_true')
    parser.add_argument('--ioc-regime', choices=('known_ioc_pivot', 'novel_apt_zero_ioc'),
                        default='novel_apt_zero_ioc')
    parser.add_argument('--case-seed', default=None)
    args = parser.parse_args(argv)
    report = import_camlds_case(
        args.zip_path,
        args.output_root,
        split=args.split,
        control_pre_attack=args.control_pre_attack,
        ioc_regime=args.ioc_regime,
        case_seed=args.case_seed,
    )
    sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
