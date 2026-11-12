#!/usr/bin/env python3
"""Export one time window from a work Elasticsearch and import it as a lab hunt case; standard library only.

CLI (run from framework/):
  python -m hunt_lab.import_elastic export --url https://HOST:9200 --index PATTERN --start ISO --end ISO \
      --output FILE.ndjson [--hosts NAME,NAME] [--max-events 200000] [--ca-file CA.pem] \
      [--api-key-env HUNT_ELASTIC_API_KEY]
  python -m hunt_lab.import_elastic import --input FILE.ndjson --case-id ID --start ISO --end ISO \
      --evidence-dir DIR [--max-events 200000]

export is read-only. It sends GET / (the version), POST /PATTERN/_pit?keep_alive=2m, then
POST /_search pages of 5000 inside that point in time, sorted on @timestamp and _shard_doc
and continued with search_after, and finally DELETE /_pit, also when the export fails.
Point-in-time search needs Elasticsearch 7.12 or later (8.x recommended); older versions and
OpenSearch are refused. Only HTTPS is used, always with certificate and hostname verification
against the system trust store or, with --ca-file, that CA bundle alone; redirects are refused.
The API key is read only from the environment variable named by --api-key-env and sent as
"Authorization: ApiKey ...". It is never printed, logged, written or put in an error; an error
from Elasticsearch is reported only as its HTTP status and Elasticsearch error type.
The window is [start, end) on @timestamp; --hosts keeps only those exact host.name values.
A window holding more than --max-events documents is refused before any document is
downloaded, and nothing is written: narrow the window or hosts, or raise the cap.
The output holds one {"_index", "_id", "_source"} object per line; <output>.meta.json records
the cluster host, index pattern, window, hosts, document count, Elasticsearch version and the
SHA-256 of the NDJSON. Neither file may exist yet. Keep both under runtime/, never in the repo.

import reads that NDJSON, NDJSON of raw _source documents, or one saved _search response
(hits.hits). Dotted field names are expanded into objects, as Elasticsearch reads them.
Records with @timestamp in [start, end) are sorted by (@timestamp, host.name, _index, _id),
given event.id evt-NNNNNN in that order (a source event.id moves to event.original_id) and
event.dataset = case id; _index, _id and other search metadata are dropped. The evidence
directory, which must not exist yet, gets events.jsonl and case.json with
"data_origin": "work-export"; there is no truth file, since work data has no answer key.
Output is byte-identical for the same arguments and input. A JSON summary is printed on stdout.
"""

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import sys
from urllib import error, parse, request

from hunt_lab.import_dedale import QUESTION, event_id, field, format_time, parse_time
from hunt_lab.scenario import CASE_ID_PATTERN, SCHEMA_VERSION, json_bytes


DEFAULT_MAX_EVENTS = 200000
PAGE_SIZE = 5000
KEEP_ALIVE = "2m"
API_KEY_ENV = "HUNT_ELASTIC_API_KEY"
TIMEOUT_SECONDS = 120
MAX_ERROR_BODY = 65536
MINIMUM_VERSION = (7, 12)
DATA_ORIGIN = "work-export"
INDEX_PATTERN = re.compile(r"[A-Za-z0-9*][A-Za-z0-9._*,:+-]{0,254}\Z")
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
ERROR_TYPE = re.compile(r"[a-z_]{1,100}\Z")
VERSION = re.compile(r"(\d+)\.(\d+)")
SORT = [{"@timestamp": {"order": "asc", "numeric_type": "date_nanos"}}, {"_shard_doc": "asc"}]
# Bot-visible: no cluster address or index names.
COVERAGE = "Real ECS records exported from the operator's work Elastic: %d records from %d hosts%s; no packet capture, no intel feed."
MAX_LISTED_DATASETS = 12


class ExportError(ValueError):
    """A refused or failed export; the message never holds the API key or a response body."""


class _NoRedirect(request.HTTPRedirectHandler):
    # A redirect would resend the Authorization header to wherever it points.
    def redirect_request(self, *_args, **_kwargs):
        return None


def https_transport(ca_file=None, timeout=TIMEOUT_SECONDS):
    """send(method, url, headers, body) -> (status, body bytes) over verified HTTPS, without redirects."""
    context = ssl.create_default_context(cafile=ca_file)
    if ca_file:
        # Elastic 8's auto-generated http_ca.crt has no keyUsage extension, which OpenSSL's strict
        # RFC 5280 checks reject; the chain and the hostname are still verified against that CA.
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    opener = request.build_opener(request.HTTPSHandler(context=context), _NoRedirect())

    def send(method, url, headers, body):
        try:
            with opener.open(request.Request(url, data=body, method=method, headers=headers), timeout=timeout) as response:
                return response.status, response.read()
        except error.HTTPError as failure:
            with failure:
                return failure.code, failure.read(MAX_ERROR_BODY)

    return send


def cluster_base(url):
    """(base URL, host:port) of an https URL without credentials, query or fragment."""
    parts = parse.urlsplit(url) if isinstance(url, str) else None
    if parts is None or parts.scheme != "https" or not parts.hostname:
        raise ExportError("--url must be an https:// Elasticsearch address")
    if "@" in parts.netloc or "?" in url or "#" in url:
        raise ExportError("--url must not carry credentials, a query or a fragment; the API key comes from the environment")
    try:
        parts.port
    except ValueError:
        raise ExportError("--url has an invalid port") from None
    return "https://" + parts.netloc + parts.path.rstrip("/"), parts.netloc


def window(start, end):
    start_ns, end_ns = parse_time(start), parse_time(end)
    if start_ns >= end_ns:
        raise ValueError("--start must be earlier than --end")
    return start_ns, end_ns


def host_names(hosts):
    if hosts is None:
        return None
    names = sorted({host.strip() for host in hosts if host.strip()})
    if not names:
        raise ValueError("--hosts names no host")
    return names


def check_version(info):
    version = info.get("version") if isinstance(info, dict) else None
    number = version.get("number") if isinstance(version, dict) else None
    match = VERSION.match(number) if isinstance(number, str) else None
    if not match or version.get("distribution", "elasticsearch") != "elasticsearch":
        raise ExportError("the server did not identify itself as Elasticsearch")
    if (int(match.group(1)), int(match.group(2))) < MINIMUM_VERSION:
        raise ExportError("Elasticsearch %s lacks point-in-time search; 7.12 or later is required" % number)
    return number


def read_api_key(environ, name):
    """The API key held in environment variable `name`; refused if absent or unsafe for a header."""
    api_key = environ.get(name, "")
    if not api_key:
        raise ExportError(f"environment variable {name} holds no API key")
    if not api_key.isascii() or any(character.isspace() or not character.isprintable() for character in api_key):
        raise ExportError(f"the API key in {name} holds whitespace, a line break or a non-ASCII character")
    return api_key


def export_window(url, index, start, end, output, *, hosts=None, max_events=DEFAULT_MAX_EVENTS,
                  api_key_env=API_KEY_ENV, ca_file=None, transport=None, environ=None, page_size=PAGE_SIZE):
    base, host = cluster_base(url)
    if not isinstance(index, str) or not INDEX_PATTERN.match(index):
        raise ExportError("--index must be an index name or pattern such as logs-*")
    if type(max_events) is not int or max_events < 1:
        raise ExportError("--max-events must be a positive integer")
    if type(page_size) is not int or not 1 <= page_size <= 10000:
        raise ExportError("page size must be from 1 through 10000")
    start_ns, end_ns = window(start, end)
    hosts = host_names(hosts)
    if not isinstance(api_key_env, str) or not ENV_NAME.match(api_key_env):
        raise ExportError("--api-key-env must name an environment variable")
    api_key = read_api_key(os.environ if environ is None else environ, api_key_env)
    output = Path(output)
    meta = output.with_name(output.name + ".meta.json")
    for path in (output, meta):
        if path.exists() or path.is_symlink():
            raise ExportError("output file already exists: " + str(path))
    if ca_file is not None and not Path(ca_file).is_file():
        raise ExportError("--ca-file is not a file: " + str(ca_file))
    send = transport or https_transport(ca_file)
    authorization = "ApiKey " + api_key

    def call(method, path, body, action):
        headers = {"Accept": "application/json", "Authorization": authorization}
        data = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
            headers["Content-Type"] = "application/json"
        try:
            status, payload = send(method, base + path, headers, data)
        except (OSError, http.client.HTTPException) as failure:
            reason = str(getattr(failure, "reason", failure)).replace(api_key, "[redacted]")
            raise ExportError("%s: cannot reach Elasticsearch at %s: %s" % (action, host, reason)) from None
        try:
            value = json.loads(payload)
        except ValueError:
            value = None
        if not 200 <= status < 300:
            kind = field(value, "error", "type")
            raise ExportError("%s: Elasticsearch returned HTTP %d%s" % (
                action, status, " (%s)" % kind if isinstance(kind, str) and ERROR_TYPE.match(kind) else ""))
        if not isinstance(value, dict):
            raise ExportError("%s: Elasticsearch did not return a JSON object" % action)
        return value

    version = check_version(call("GET", "/", None, "read cluster version"))
    pit = call("POST", "/" + parse.quote(index, safe="*,:+") + "/_pit?keep_alive=" + KEEP_ALIVE, None,
               "open point in time").get("id")
    if not isinstance(pit, str) or not pit:
        raise ExportError("open point in time: Elasticsearch returned no point-in-time id")

    filters = [{"range": {"@timestamp": {"gte": format_time(start_ns), "lt": format_time(end_ns),
                                         "format": "strict_date_optional_time_nanos"}}}]
    if hosts is not None:
        filters.append({"terms": {"host.name": hosts}})
    query = {"bool": {"filter": filters}}
    written = []
    try:
        count, size, digest = 0, 0, hashlib.sha256()
        with output.open("xb") as handle:
            written.append(output)
            search_after = None
            while True:
                body = {"size": page_size, "pit": {"id": pit, "keep_alive": KEEP_ALIVE}, "query": query, "sort": SORT,
                        "track_total_hits": max_events + 1 if search_after is None else False}
                if search_after is not None:
                    body["search_after"] = search_after
                page = call("POST", "/_search", body, "search")
                renewed, hits = page.get("pit_id", pit), field(page, "hits", "hits")
                if not isinstance(renewed, str) or not renewed or not isinstance(hits, list):
                    raise ExportError("search: Elasticsearch returned no hits list or point-in-time id")
                pit = renewed
                if search_after is None:
                    total = field(page, "hits", "total", "value")
                    if type(total) is not int:
                        raise ExportError("search: Elasticsearch returned no hit total")
                    if total > max_events:
                        raise ExportError("the window holds more than --max-events %d documents; nothing written. "
                                          "Narrow the window or --hosts, or raise --max-events" % max_events)
                if count + len(hits) > max_events:
                    raise ExportError("the window returned more than --max-events %d documents; nothing written"
                                      % max_events)
                chunk = []
                for hit in hits:
                    if (not isinstance(hit, dict) or not isinstance(hit.get("_index"), str)
                            or not isinstance(hit.get("_id"), str) or not isinstance(hit.get("_source"), dict)
                            or not isinstance(hit.get("sort"), list)):
                        raise ExportError("search: a hit lacks _index, _id, _source or sort; the index must keep _source")
                    chunk.append((json.dumps({key: hit[key] for key in ("_index", "_id", "_source")},
                                             sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8"))
                data = b"".join(chunk)
                handle.write(data)
                digest.update(data)
                size += len(data)
                count += len(hits)
                if len(hits) < page_size:
                    break
                search_after = hits[-1]["sort"]
        record = {
            "schema_version": SCHEMA_VERSION, "kind": "elastic-export", "host": host, "index": index,
            "time_range_utc": {"start_inclusive": format_time(start_ns), "end_exclusive": format_time(end_ns)},
            "hosts": hosts, "event_count": count, "max_events": max_events, "elastic_version": version,
            "ndjson": {"file": output.name, "bytes": size, "sha256": digest.hexdigest()},
        }
        with meta.open("xb") as handle:
            written.append(meta)
            handle.write(json_bytes(record))
    except BaseException:
        for path in written:
            path.unlink(missing_ok=True)
        try:
            call("DELETE", "/_pit", {"id": pit}, "close point in time")
        except ExportError:
            pass
        raise
    try:
        call("DELETE", "/_pit", {"id": pit}, "close point in time")
        closed = True
    except ExportError:
        # The export is complete; an unclosed point in time expires after its keep-alive.
        closed = False
    return dict(record, output=str(output), meta=str(meta), point_in_time_closed=closed)


def _merge(target, key, value, where):
    if key not in target:
        target[key] = value
    elif isinstance(target[key], dict) and isinstance(value, dict):
        for name, item in value.items():
            _merge(target[key], name, item, where)
    else:
        raise ValueError("%s: field %s is given twice (dotted and nested)" % (where, key))


def expand_dotted(value, where):
    """Nest dotted field names ("host.name") as Elasticsearch reads them; a conflicting duplicate is refused."""
    if isinstance(value, list):
        return [expand_dotted(item, where) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        item = expand_dotted(item, where)
        parts = key.split(".")
        if not all(parts):
            parts = [key]
        for part in reversed(parts[1:]):
            item = {part: item}
        _merge(result, parts[0], item, where)
    return result


def split_record(value, where):
    """(_index, _id, _source) of an exported hit, or of a raw _source document with empty _index and _id."""
    if not isinstance(value, dict):
        raise ValueError("%s: not a JSON object" % where)
    if "_source" not in value:
        return "", "", value
    index, identifier, source = value.get("_index", ""), value.get("_id", ""), value["_source"]
    if not isinstance(index, str) or not isinstance(identifier, str) or not isinstance(source, dict):
        raise ValueError("%s: _index and _id must be strings and _source an object" % where)
    return index, identifier, source


def read_records(path, digest):
    """Yield (location, value) for every record of NDJSON or one _search response; digest hashes the bytes read."""
    path = Path(path)
    with path.open("rb") as stream:
        first = b""
        for first in stream:
            if first.strip():
                break
        try:
            head = json.loads(first) if first.strip() else None
        except ValueError:
            head = None
    if first.strip() and (head is None or isinstance(field(head, "hits", "hits"), list)):
        data = path.read_bytes()
        digest.update(data)
        try:
            hits = field(json.loads(data), "hits", "hits")
        except ValueError as failure:
            raise ValueError("input is neither NDJSON nor a _search response: %s" % failure) from None
        if not isinstance(hits, list):
            raise ValueError("input is neither NDJSON nor a _search response with hits.hits")
        for number, hit in enumerate(hits):
            if not isinstance(hit, dict) or "_source" not in hit:
                raise ValueError("hits.hits[%d] has no _source" % number)
            yield "hits.hits[%d]" % number, hit
        return
    with path.open("rb") as stream:
        for number, line in enumerate(stream, 1):
            digest.update(line)
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except ValueError as failure:
                raise ValueError("invalid JSON at line %d: %s" % (number, failure)) from None
            yield "line %d" % number, value


def scan_records(path, start, end, max_events, digest):
    """(sorted rows, records read, records outside the window).

    Each row is (timestamp ns, host.name, _index, _id, canonical source text); the text is the
    last sort key, so records with equal keys still order deterministically."""
    rows, seen, read, matched, outside = [], set(), 0, 0, 0
    for where, value in read_records(path, digest):
        read += 1
        index, identifier, source = split_record(value, where)
        if index and identifier:
            if (index, identifier) in seen:
                raise ValueError("%s: document %s/%s appears twice" % (where, index, identifier))
            seen.add((index, identifier))
        source = expand_dotted(source, where)
        try:
            timestamp = parse_time(source.get("@timestamp"))
        except ValueError as failure:
            raise ValueError("%s: %s" % (where, failure)) from None
        if not start <= timestamp < end:
            outside += 1
            continue
        matched += 1
        if matched > max_events:
            continue
        host = field(source, "host", "name")
        rows.append((timestamp, host if isinstance(host, str) else "", index, identifier,
                     json.dumps(source, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)))
    if matched > max_events:
        raise ValueError("%d records match the window, more than --max-events %d; nothing written" % (matched, max_events))
    rows.sort()
    return rows, read, outside


def import_case(source, case_id, start, end, evidence_dir, max_events=DEFAULT_MAX_EVENTS):
    if not isinstance(case_id, str) or not CASE_ID_PATTERN.match(case_id):
        raise ValueError("case id must match [a-z0-9-]{3,64}")
    if type(max_events) is not int or max_events < 1:
        raise ValueError("--max-events must be a positive integer")
    start_ns, end_ns = window(start, end)
    evidence = Path(evidence_dir)
    if evidence.exists() or evidence.is_symlink():
        raise ValueError("output directory already exists: " + str(evidence))
    input_digest = hashlib.sha256()
    rows, read, outside = scan_records(source, start_ns, end_ns, max_events, input_digest)
    if not rows:
        raise ValueError("no records match the window")

    files = {}
    created = False
    try:
        evidence.mkdir(parents=True)
        created = True
        path = evidence / "events.jsonl"
        digest, size, hosts, datasets = hashlib.sha256(), 0, set(), set()
        with path.open("xb") as handle:
            chunk = []
            for position, (_, host, _, _, text) in enumerate(rows):
                record = json.loads(text)
                event = record.setdefault("event", {})
                if not isinstance(event, dict):
                    raise ValueError("record %s has a non-object event field" % event_id(position))
                if "id" in event:
                    if "original_id" in event:
                        raise ValueError("record %s has both event.id and event.original_id" % event_id(position))
                    event["original_id"] = event.pop("id")
                event["id"] = event_id(position)
                event["dataset"] = case_id
                if host:
                    hosts.add(host.lower())
                dataset = field(record, "data_stream", "dataset")
                dataset = dataset if isinstance(dataset, str) else field(record, "event", "module")
                if isinstance(dataset, str) and dataset:
                    datasets.add(dataset)
                try:
                    chunk.append((json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                                  + "\n").encode("utf-8"))
                except UnicodeEncodeError:
                    raise ValueError("record %s holds text that is not valid UTF-8" % event_id(position)) from None
                if len(chunk) >= 5000:
                    data = b"".join(chunk)
                    handle.write(data)
                    digest.update(data)
                    size += len(data)
                    chunk = []
            data = b"".join(chunk)
            handle.write(data)
            digest.update(data)
            size += len(data)
        files[path.name] = {"path": str(path), "bytes": size, "sha256": digest.hexdigest()}
        listed = sorted(datasets)
        if listed:
            more = len(listed) - MAX_LISTED_DATASETS
            listed = "; datasets: " + ", ".join(listed[:MAX_LISTED_DATASETS]) + (" and %d more" % more if more > 0 else "")
        else:
            listed = ""
        data = json_bytes({
            "schema_version": SCHEMA_VERSION, "case_id": case_id, "question": QUESTION,
            "time_range_utc": {"start_inclusive": format_time(start_ns), "end_exclusive": format_time(end_ns)},
            "network_capture": "none",
            # Real work telemetry: lab-input exports it only with the operator's --data-origin work-export.
            "data_origin": DATA_ORIGIN,
            "sources": [{"artifact": "events.jsonl", "coverage": COVERAGE % (len(rows), len(hosts), listed)}],
        })
        path = evidence / "case.json"
        with path.open("xb") as handle:
            handle.write(data)
        files[path.name] = {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    except BaseException:
        if created:
            for name in ("events.jsonl", "case.json"):
                (evidence / name).unlink(missing_ok=True)
            try:
                evidence.rmdir()
            except OSError:
                pass
        raise

    return {
        "schema_version": SCHEMA_VERSION, "case_id": case_id, "data_origin": DATA_ORIGIN,
        "time_range_utc": {"start_inclusive": format_time(start_ns), "end_exclusive": format_time(end_ns)},
        "event_count": len(rows), "host_count": len(hosts), "records_read": read, "outside_window": outside,
        "input": {"path": str(source), "sha256": input_digest.hexdigest()},
        "files": files,
    }


def main(argv=None, *, transport=None, environ=None):
    class JsonParser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError(message)

    parser = JsonParser(prog="python -m hunt_lab.import_elastic", description=__doc__,
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export", help="read-only pull of one window from Elasticsearch into NDJSON")
    export.add_argument("--url", required=True, help="https://host:port of the Elasticsearch deployment")
    export.add_argument("--index", required=True, help="index name or pattern, e.g. logs-*")
    export.add_argument("--start", required=True)
    export.add_argument("--end", required=True)
    export.add_argument("--hosts", help="comma-separated exact host.name values (default: every host)")
    export.add_argument("--max-events", type=int, default=DEFAULT_MAX_EVENTS)
    export.add_argument("--output", required=True, help="new NDJSON path under runtime/; <output>.meta.json is written beside it")
    export.add_argument("--ca-file", help="PEM CA bundle to verify the server with instead of the system trust store")
    export.add_argument("--api-key-env", default=API_KEY_ENV, help="environment variable holding the API key")
    load = commands.add_parser("import", help="NDJSON or a _search response -> a lab case")
    load.add_argument("--input", required=True)
    load.add_argument("--case-id", required=True)
    load.add_argument("--start", required=True)
    load.add_argument("--end", required=True)
    load.add_argument("--evidence-dir", required=True)
    load.add_argument("--max-events", type=int, default=DEFAULT_MAX_EVENTS)
    try:
        args = parser.parse_args(argv)
        if args.command == "export":
            result = export_window(args.url, args.index, args.start, args.end, args.output,
                                   hosts=args.hosts.split(",") if args.hosts is not None else None,
                                   max_events=args.max_events, api_key_env=args.api_key_env, ca_file=args.ca_file,
                                   transport=transport, environ=environ)
        else:
            result = import_case(args.input, args.case_id, args.start, args.end, args.evidence_dir, args.max_events)
    except (OSError, ValueError) as failure:
        print(json.dumps({"error": str(failure)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
