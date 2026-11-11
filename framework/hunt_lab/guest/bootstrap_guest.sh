#!/bin/bash
# Runs only inside the dedicated native Hermes lab guest. No host shares or live capture.
# Safe to re-run on every new cloud-init instance (one per reseeded case): each
# step is idempotent and the loaded case comes from evidence/case.json.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
ROOT=/opt/hermes-hunt-lab
ELASTIC=http://172.30.91.2:9200
cd "$ROOT"
CASE_ID=$(python3 - <<'PY'
import json
import re
case = json.load(open('/opt/hermes-hunt-lab/evidence/case.json', encoding='utf-8'))
if not isinstance(case.get('case_id'), str) or not re.fullmatch(r'[a-z0-9-]{3,64}', case['case_id']):
    raise SystemExit('stage=failed_case_metadata')
print(case['case_id'])
PY
)
# "network_capture": "none" marks a case that ships no traffic.pcap; any other value is refused.
CAPTURE=$(python3 - <<'PY'
import json
case = json.load(open('/opt/hermes-hunt-lab/evidence/case.json', encoding='utf-8'))
if 'network_capture' in case and case['network_capture'] != 'none':
    raise SystemExit('stage=failed_case_metadata')
print(case.get('network_capture', 'pcap'))
PY
)
PCAP_SHA=
if [ "$CAPTURE" != none ]; then
    PCAP_SHA=$(sha256sum "$ROOT/evidence/traffic.pcap" | cut -c1-16)
elif [ -e "$ROOT/evidence/traffic.pcap" ]; then
    echo 'stage=failed_case_metadata'; exit 1
fi
printf 'stage=loading_case case_id=%s\n' "$CASE_ID"
printf 'stage=installing_guest_packages\n'
# A reseeded instance already has the packages; only a first boot needs the network.
# tshark decodes the saved case capture for packet_fields (read-only, -r only). Under
# noninteractive debconf, wireshark-common keeps dumpcap root-only: no user may capture.
INSTALLED=$(dpkg-query -W -f='${Status}\n' docker.io docker-compose python3 curl tshark 2>/dev/null | grep -c '^install ok installed$' || true)
if [ "$INSTALLED" = 5 ]; then
    printf 'stage=guest_packages_present\n'
else
    apt-get update -q
    apt-get install -y -q docker.io docker-compose python3 curl tshark
fi
systemctl enable --now docker
sysctl -w vm.max_map_count=262144
printf 'vm.max_map_count=262144\n' >/etc/sysctl.d/70-hermes-hunt-lab.conf

# Offline operator media and managed guest-pull media are explicit alternatives.
# A failed offline load never falls back to a network pull.
if [ -f /media/lab-setup/lab-images.tar ]; then
    docker load -i /media/lab-setup/lab-images.tar
fi
python3 - <<'PY'
import json
import os
import re
import subprocess
with open('image-lock.json', encoding='utf-8') as source:
    images = json.load(source)['images']
def local_id(tag):
    result = subprocess.run(['docker', 'image', 'inspect', '--format', '{{.Id}}', tag],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else None
for image in images:
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image['manifest_digest']):
        raise SystemExit('stage=failed_image_lock')
    expected = {image['config_digest'], image['manifest_digest']}
    # Reseeded instances reuse the verified local image; pull only when absent or different.
    if not os.path.isfile('/media/lab-setup/lab-images.tar') and local_id(image['tag']) not in expected:
        repository = image['tag'].rsplit(':', 1)[0]
        pinned = repository + '@' + image['manifest_digest']
        subprocess.run(['docker', 'pull', pinned], check=True, timeout=1200)
        subprocess.run(['docker', 'tag', pinned, image['tag']], check=True, timeout=30)
    if local_id(image['tag']) not in expected:
        raise SystemExit('stage=failed_image_integrity')
print('stage=verified_locked_images')
PY
printf 'stage=starting_elasticsearch\n'
docker-compose -p hermes-hunt-lab up -d elasticsearch
for n in $(seq 1 120); do
    if docker-compose -p hermes-hunt-lab exec -T elasticsearch curl -fsS http://localhost:9200/_cluster/health >/dev/null; then
        break
    fi
    if [ "$n" -eq 120 ]; then echo 'stage=failed_elasticsearch_start'; exit 1; fi
    sleep 2
done
# Kibana boots (and migrates its saved objects) while the case loads; kibana_setup.py waits for it.
printf 'stage=starting_kibana\n'
docker-compose -p hermes-hunt-lab up -d kibana
ARKIME=ghcr.io/arkime/arkime/arkime:v6.9.1
printf 'stage=initializing_arkime\n'
docker run --rm --network hermes-hunt-lab_backend "$ARKIME" /opt/arkime/db/db.pl http://elasticsearch:9200 init --ifneeded --shards 1 --replicas 0

# Operator ingest uses guest-local Python; the answer sheet is never transferred.
printf 'stage=ingesting_reviewed_fixture case_id=%s\n' "$CASE_ID"
python3 "$ROOT/ingest.py" --elasticsearch "$ELASTIC" --case "$ROOT/evidence/case.json" --events "$ROOT/evidence/events.jsonl"
if [ -f "$ROOT/evidence/intel.jsonl" ]; then
    printf 'stage=ingesting_case_intel case_id=%s\n' "$CASE_ID"
    python3 "$ROOT/ingest.py" --elasticsearch "$ELASTIC" --case "$ROOT/evidence/case.json" --intel "$ROOT/evidence/intel.jsonl"
fi

# Network sessions carry the Arkime tag case:<case_id>; one marker per case and pcap digest.
# A dns-lab-001 pcap imported before tagging (global marker only) is kept as is and
# served by its case time window instead of being imported a second time.
SCOPE=tag
MARKER="$ROOT/pcap-imported-$CASE_ID-$PCAP_SHA"
if [ "$CAPTURE" = none ]; then
    printf 'stage=case_sessions_skipped_no_capture case_id=%s\n' "$CASE_ID"
elif [ "$CASE_ID" = dns-lab-001 ] && [ -f "$ROOT/pcap-imported" ] && ! ls "$ROOT/pcap-imported-$CASE_ID-"* >/dev/null 2>&1; then
    SCOPE=window
    printf 'stage=legacy_untagged_pcap case_id=%s\n' "$CASE_ID"
elif [ ! -f "$MARKER" ]; then
    if ls "$ROOT/pcap-imported-$CASE_ID-"* >/dev/null 2>&1; then
        # Same case, changed pcap: drop only this case's tagged sessions first.
        printf 'stage=replacing_case_sessions case_id=%s\n' "$CASE_ID"
        CASE_ID="$CASE_ID" ELASTIC="$ELASTIC" python3 - <<'PY'
import json
import os
from urllib.request import Request, urlopen
body = json.dumps({'query': {'term': {'tags': 'case:' + os.environ['CASE_ID']}}}).encode()
url = os.environ['ELASTIC'] + '/arkime_sessions3-*/_delete_by_query?refresh=true&conflicts=proceed'
with urlopen(Request(url, data=body, method='POST', headers={'Content-Type': 'application/json'}), timeout=300) as response:
    if json.load(response).get('failures'):
        raise SystemExit('stage=failed_case_session_replace')
PY
        rm -f "$ROOT/pcap-imported-$CASE_ID-"*
    fi
    printf 'stage=importing_case_pcap case_id=%s\n' "$CASE_ID"
    docker run --rm --network hermes-hunt-lab_backend -v "$ROOT/arkime.ini:/opt/arkime/etc/config.ini:ro" \
        -v "$ROOT/evidence:/evidence:ro" -v hermes-hunt-lab_arkime-pcap:/opt/arkime/raw "$ARKIME" \
        /opt/arkime/bin/capture -c /opt/arkime/etc/config.ini -n hermes-lab -r /evidence/traffic.pcap --copy \
        -t "case:$CASE_ID"
    touch "$MARKER"
else
    printf 'stage=case_pcap_already_imported case_id=%s\n' "$CASE_ID"
fi

# Integrity: the served scope must contain this case's sessions before the API restarts.
if [ "$CAPTURE" != none ]; then
    CASE_ID="$CASE_ID" SCOPE="$SCOPE" ELASTIC="$ELASTIC" python3 - <<'PY'
import json
import os
import time
from datetime import datetime
from urllib.request import Request, urlopen
case = json.load(open('/opt/hermes-hunt-lab/evidence/case.json', encoding='utf-8'))
bounds = case['time_range_utc']
def millis(value):
    return int(datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp() * 1000)
filters = [{'range': {'firstPacket': {'gte': millis(bounds['start_inclusive']), 'lt': millis(bounds['end_exclusive'])}}}]
if os.environ['SCOPE'] == 'tag':
    filters.append({'term': {'tags': 'case:' + os.environ['CASE_ID']}})
body = json.dumps({'query': {'bool': {'filter': filters}}}).encode()
for attempt in range(60):
    request = Request(os.environ['ELASTIC'] + '/arkime_sessions3-*/_count?ignore_unavailable=true', data=body,
                      method='POST', headers={'Content-Type': 'application/json'})
    with urlopen(request, timeout=30) as response:
        count = json.load(response)['count']
    if count > 0:
        print('stage=verified_case_sessions case_id=%s sessions=%d' % (os.environ['CASE_ID'], count))
        break
    time.sleep(2)
else:
    raise SystemExit('stage=failed_case_sessions')
PY
fi
docker-compose -p hermes-hunt-lab up -d arkime
cat >/etc/systemd/system/hermes-hunt-lab-api.service <<UNIT
[Unit]
Description=Read-only synthetic hunting evidence API
After=docker.service
Requires=docker.service

[Service]
Type=simple
User=nobody
Group=nogroup
Environment=LAB_ELASTICSEARCH=$ELASTIC
ExecStart=/usr/bin/python3 /opt/hermes-hunt-lab/lab_server.py --bind 0.0.0.0 --port 8765 --case /opt/hermes-hunt-lab/evidence/case.json --network-scope $SCOPE
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable hermes-hunt-lab-api
# Restart (not just start): a reseeded instance must serve the new case.
systemctl restart hermes-hunt-lab-api
printf 'stage=lab_services_started case_id=%s network_scope=%s\n' "$CASE_ID" "$SCOPE"
# Kibana last: the lab API serves the case even while Kibana is still coming up.
python3 "$ROOT/kibana_setup.py" --elasticsearch "$ELASTIC" --kibana http://127.0.0.1:5601 --case "$ROOT/evidence/case.json"
