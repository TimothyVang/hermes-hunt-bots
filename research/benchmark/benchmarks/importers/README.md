# OTRF Security-Datasets importer (development split only)

`benchmark_import_otrf.py` turns one recorded attack simulation from
[OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) (formerly Mordor) into a benchmark case:
a public evidence bundle, evaluator-only truth, and a scenario. Every imported case is
`split: development`, `provenance: public_replay` (a public recording, not a private lab-derived replay). It never
produces a holdout.

OTRF labels a **whole dataset** with ATT&CK techniques (metadata `attack_mappings`). It has no per-event labels.
Per-event truth (steps, support sets, controls, lookalikes) therefore comes **only** from a human-written
curation file. Without one, the importer writes a draft that scoring refuses.

## License and attribution

The repository `LICENSE` file (checked at commit `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`) is the **MIT License**,
`Copyright (c) 2021 Open Threat Research Forge`. GitHub also reports MIT. The repository README has a heading
"License: GPL-3.0", but that heading links to the same MIT `LICENSE` file. This importer treats the LICENSE file text
as authoritative. Review the discrepancy yourself before you redistribute data.

Attribution requirement (MIT): keep the copyright notice and the permission notice with all copies or substantial
portions. The importer copies this notice into each `evaluator/import-report.json`. Keep
`LICENSE.OTRF-Security-Datasets.txt` beside any downloaded data. **Never commit downloaded data into this source
tree.** The only files here are an INVENTED sample and a field allowlist.

## Contamination caveat

These datasets have been public since 2019–2020, and models were very likely trained on them, including the
dataset write-ups, the Threat Hunter Playbook notebooks, and the metadata `adversary_view` text. Use imported cases
only for development: iterating on prompts, the pipeline, or scoring. Never use them as a holdout, and never as
evidence of a model's hunting ability on unseen activity. Record training contamination as `unknown`. The
importer refuses public output that still contains the dataset ID, title, or file names. It also pseudonymizes
technique-labelled path segments (for example Atomic Red Team `\T1033\` folders). A model can still recognise a
famous public sequence of events.

## Verified data format (inspected, not assumed)

Inspected on 2026-11-02/03 in the downloaded datasets listed in `provenance.json` in the data directory.

### Supported and unsupported layouts

| Layout | Status |
| --- | --- |
| `flat-timecreated`: 2020-10+ `.zip`/`.json` JSON lines with `TimeCreated` | Supported. |
| `nxlog-eventtime`: 2019–2020 `.zip` JSON lines from NXLog `im_msvistalog` via a WEC collector and Logstash (`EventTime`, `RecordNumber`, `host`/`port`/`tags`; Empire/Covenant/MSF datasets) | Supported since `otrf-import-2`. |
| A file mixing both shapes | Refused: `mixed_record_shapes` at the first line of the other shape. |
| Any other record shape (no time field, both time fields, `EventTime` without `SourceModuleType: im_msvistalog`, nested objects) | Refused: `unsupported_record_shape`. |
| Older `.tar.gz` Mordor exports (nested winlogbeat JSON), JSON arrays, nested archives | Refused (`unsupported_dataset_layout` / archive errors). |

The shape is detected per record from the first non-blank line and recorded in
`evaluator/import-report.json` → `record_shape` (`shape`, `time_field`, `record_id_field`, `collectors`,
`channel_spellings_normalized`, `aliased_fields`, `envelope_collisions_dropped`, `message_fields_parsed`).

### `flat-timecreated`

- Each published `.zip` contains exactly one JSON-lines member with CRLF line endings. Each line is one flat JSON
  object with string, integer or null values.
- Fields common to every record: `Channel`, `EventID`, `Hostname`, `TimeCreated`, `@timestamp`, `SourceName`,
  `ProviderGuid`, `Task`, `Level`, `Keywords`, `Message`. The remaining fields are the event's own EventData
  names, for example Security 4688 `NewProcessName`/`CommandLine`/`SubjectUserName` and Sysmon 1
  `Image`/`CommandLine`/`ParentImage`/`User`/`Hashes`.
- The inspected exports have no `EventRecordID`/`RecordNumber`, so records are located by **original line number**.
- `TimeCreated` is **local 12-hour time labelled `Z`**. One dataset writes it with no zone at all
  (`--naive-timestamps-utc`, recorded as an operator assumption). Sysmon's own `UtcTime` differs by a constant
  offset (−57600, −61200, −18000 and −57600 s in the first four datasets).

### `nxlog-eventtime`

- Each `.zip` contains one JSON-lines member with LF line endings. Values are strings/integers/booleans, except
  `tags`, a list of strings (accepted only in this shape, never imported).
- Envelope: NXLog `EventTime`, `EventReceivedTime`, `RecordNumber`, `SourceModuleName` (`eventlog`),
  `SourceModuleType` (`im_msvistalog`), `Severity`, `SeverityValue`, `EventType`, `Keywords`, `Opcode`,
  `OpcodeValue`, `Category`, `ExecutionProcessID`, `ThreadID`, `Version`, `Task`, `ProviderGuid`, `SourceName`, and
  `AccountName`/`AccountType`/`Domain`/`UserID` when the event carries a user SID; Logstash `@timestamp`, `@version`,
  `host` (the forwarding collector, one value per export), `port`, `tags`. `Hostname`, `Channel`, `EventID` and the
  EventData field names are as in the flat shape.
- `EventTime` is the collector's **zone-less local wall clock, truncated to whole seconds**. In all seven inspected
  exports `EventTime − UtcTime` is −14400 s with under 5 s spread. `@timestamp` is Logstash ingest time (UTC,
  0.1–6 s after the event) and `EventReceivedTime` is NXLog receive time; neither is used as event time.
- `RecordNumber` (integer) is on every record. It is unique per channel per computer, **not** per export: two of
  the seven exports repeat numbers across hosts.
- Some hosts spell the Security channel `security`. Same provider, same field names and one `RecordNumber`
  sequence per host, so the importer matches channels case-insensitively (Windows channel names are
  case-insensitive) and publishes the allowlist spelling.
- Field names differ from the flat shape in one inspected place: Security 5156 `ProcessId` (flat: `ProcessID`;
  same Windows field, the filtered application's PID). It is mapped through `shape_aliases` (below).
- NXLog's own `EventType` (`INFO`, `AUDIT_SUCCESS`) collides with the Sysmon 12/13/17/18 EventData `EventType`.
  When the event has one, the export moves NXLog's value to `EventTypeOrignal` (spelling as exported).

### Event data carried only in `Message` (inspected 2026-11-07, all 23 datasets)

Some events have no EventData fields in the export; their data exists only in the rendered `Message`:

- **Classic `Windows PowerShell` 400/600/800** (435 × 800, 20 × 600, 3 × 400; NXLog shape). The message is a
  header sentence followed by `\tKey=Value` lines: `HostName`, `HostVersion`, `HostId`, `HostApplication` (the full
  host command line, for example `powershell.exe -noP -sta -w 1 -enc <base64>`), `EngineVersion`, `RunspaceId`,
  `PipelineId`, `ScriptName`, `CommandLine`, `SequenceNumber`, plus `NewEngineState`/`PreviousEngineState` (400)
  or `ProviderName`/`NewProviderState` (600). 800 groups them under `Context Information:` (with `DetailSequence`,
  `DetailTotal` and `UserId=DOMAIN\user`) and ends with a `Details:` block of `CommandInvocation(...)` /
  `ParameterBinding(...)` lines. A value continues across `\r\n` until the next key; script newlines inside
  `CommandLine` are bare `\n`. 26 more 800 records have no `Message` at all (`ERROR_EVT_UNRESOLVED`).
- **PowerShell/Operational 4103** in the NXLog shape: 355 records carry `Payload`/`ContextInfo`; 2 carry only
  `Message` = `<Payload>\r\n\r\n\r\nContext:\r\n<ContextInfo>`.
- **WMI-Activity 5857/5858** (NXLog): `<provider> provider started with result code <code>. HostProcess = …;
  ProcessID = …; ProviderPath = …` and `Id = …; ClientMachine = …; User = …; ClientProcessId = …; Component = …;
  Operation = …; ResultCode = …; PossibleCause = …`.
- **TerminalServices-LocalSessionManager 24/40** (NXLog): `User:` / `Session ID:` / `Source Network Address:`
  lines, or `Session <n> has been disconnected, reason code <n>`.
- **Application, MSExchange Management and Exchange ActiveMonitoring/HighAvailability** (SDWIN-210314014019, flat):
  no EventData at all. MSExchange Management 1 (`MSExchange CmdletLogs`) messages hold the executed cmdlet and its
  parameters; Application 4 holds a request URL, the current user and a stack trace.

The allowlist's `message_fields` names a parser for these events (see [Message parsers](#message-parsers-and-metadata-only-events)); the Message itself is published
only where it is the event's only content (Application and MSExchange Management, flat shape).

### Timestamps (both shapes)

The importer measures `time field − UtcTime` on every Sysmon record. It applies that offset, rounded to the
quarter-hour, to every record and publishes it as the source `clock_offset_seconds`, with the measured residual as
`clock_uncertainty_seconds`. A spread above 300 s (for example a 12-hour wrap) fails with `inconsistent_timestamps`.
A flat export without Sysmon keeps a `null` (unknown) offset. An NXLog export without Sysmon is refused
(`no_clock_reference`), because a zone-less collector wall clock cannot be placed in UTC; `--naive-timestamps-utc`
is refused for NXLog exports (`conflicting_arguments`). One collector renders every `EventTime`, so one offset
applies to all hosts; an export with more than one `host` value is refused (`multiple_collectors`). Each event keeps
its original value as `fields.timestamp_original`.

### Metadata

- Metadata YAML: `title`, `id`, `contributors`, `creation_date`, `modification_date`, `platform`, `type`, `tags`,
  `description`, `attack_mappings` (`technique`, quoted 3-digit `sub-technique`, `tactics`), `notebooks`,
  `files` (`type`, `link`), `simulation`, `references`, and occasionally `datasets`. The `simulation.adversary_view`
  block can contain captured credential material. The importer never parses or copies it.

## YAML safety decision

No YAML library is used. A strict hand-written subset parser interprets only `id`, `title`, `type`, `platform`,
`attack_mappings` and `files`. Other known top-level blocks are skipped by indentation without being parsed.
The parser refuses:

- unknown top-level keys and duplicate keys
- anchors, aliases, tags and flow collections
- block scalars in interpreted keys
- document markers
- tab indentation
- files over 256 KiB

An unparseable real metadata file is a hard failure, never a best-effort guess.

## Workflow

Run from `research/benchmark/` (`python3` instead of `py -3` on macOS/Linux).

1. **Download** the dataset `.zip` and its `datasets/atomic/_metadata/<ID>.yaml` from a pinned commit, into a
   directory outside every source tree, for example `C:/Users/<you>/Desktop/bot-framework-data/otrf/<ID>/`. Record the URL,
   the commit and the SHA-256 of each file in a `provenance.json` there. Downloads are data: never execute or open
   them with tools that run embedded content.

2. **Draft import** (no curation): writes public evidence, a draft truth and a curation template.
   ```powershell
   py -3 benchmark_import_otrf.py --dataset $data/cmd_discover_iexplorer_version_registry.zip --metadata $data/SDWIN-201021232814.yaml --draft-os-family windows-client --output $work/draft-SDWIN-201021232814
   ```
   Add `--naive-timestamps-utc` only when a flat export's `TimeCreated` has no zone. This is recorded as an operator
   assumption; it is refused for NXLog exports. `--draft-os-family` is an operator declaration for the draft only.
   OTRF metadata says just "Windows".

3. **Curate** (human step). Copy `evaluator/curation-template.json` → its `curation` object into a new file. Then
   decide every `null` from the original records. Candidate events are all imported events, not a heuristic
   selection. To keep asset and event IDs identical to the draft, reuse the draft's salt in the next step.

   3a. **Sign** (human attestation). Tick every line under the review sheet's "Reviewer checklist" heading
   (`- [x]`) yourself, then:
   ```powershell
   py -3 benchmark_import_otrf.py sign --proposal $p/curation.PROPOSED.json --review $p/review.md --by $you --note $decisions --output $work/curation-<ID>.json
   ```
   Running this command is your attestation that you reviewed the answer key. It refuses an unticked or missing
   checklist, a sheet that does not name the proposal's dataset SHA-256, an existing output, an output inside the
   source tree, and empty or model-like names. It removes `status`, sets `curated_by`, `curated_utc` and `note`,
   validates the result as a curation, and prints its SHA-256. It never imports and never runs automatically.

4. **Curated import**:
   ```powershell
   py -3 benchmark_import_otrf.py --dataset $data/cmd_discover_iexplorer_version_registry.zip --metadata $data/SDWIN-201021232814.yaml --curation $work/curation-SDWIN-201021232814.json --salt-file $work/draft-SDWIN-201021232814/<case_id>/evaluator/salt.json --output $cases
   ```
   `$cases` must not exist. The case lands in `$cases/<case_id>/`. The importer validates every output with
   `benchmark_contracts.validate_public_bundle`, `validate_truth` and `validate_scenario`. It sets difficulty with
   `benchmark_difficulty.measure_case`.

   4a. **Unreviewed proposal.** `--curation` also accepts a `curation.PROPOSED.json` directly (no flag): its
   `status` must be `PROPOSED_UNREVIEWED_NOT_FOR_SCORING` and `curated_by`/`curated_utc` must stay null. The
   output truth gets `"attestation": "unreviewed_proposal"`, the scenario gets an `emulation_limitations` line
   saying the answer key is unreviewed, and `evaluator/import-report.json` (`curation.attestation`) plus the CLI
   summary record it. Every score from it carries `truth_attestation: "unreviewed_proposal"`, a cohort control:
   it is never compared or ranked with human-attested truth. Signed curations (step 3a) are unchanged: no
   `attestation` key in truth, `human_attested` in the report.

   4b. **Agent consensus.** `--curation` also accepts the output of `benchmark_consensus.py merge`: two
   independently written proposals merged by deterministic agreement (see
   [Agent consensus answer keys](#agent-consensus-answer-keys-both-importers)). Its truth gets
   `"attestation": "agent_consensus"`, a separate cohort from both human-attested and unreviewed truth.

5. **Run it as an experiment.** Create the manifest over all cases with
   `py -3 benchmark.py corpus-experiment --cases $cases --team $team --experiment-id $id --output $cases/experiment.json`
   (repetitions default to 1; see the benchmark README for the `$team` file), then:
   ```powershell
   py -3 benchmark.py validate --experiment $cases/experiment.json --bundle-root $cases
   py -3 benchmark.py --state-root $state init --experiment $cases/experiment.json --bundle-root $cases --truth $cases
   py -3 benchmark.py --state-root $state advance --experiment $experiment --allow-model-execution
   ```
   `$cases` is also the `--truth` directory (`<case_id>/evaluator/truth.json`); `init` freezes it automatically
   before any trial exists. Pseudonymization is not declassification.

Exit codes: `0` success; `2` validation failure (`error: <code>: <field>`; values from the data are never echoed).

**Antivirus.** Restored Empire/Covenant stagers are real malware text. Microsoft Defender detects them
(`Trojan:PowerShell/Boxter.KN!MTB`) both as raw `-EncodedCommand` base64 and as decoded text, and quarantines the
written `evidence.json`. The importer reads every output file back after writing it. A read or write that fails
with `EINVAL` or `ERROR_VIRUS_INFECTED`/`ERROR_VIRUS_DELETED` (winerror 225/226) fails with
`error: blocked_by_antivirus: <relative path>`, and the partial output is removed. The default
`--encoded-payloads preview` publishes each payload as length, digest and a sanitized 512-character decoded preview,
which Defender left readable on the real datasets. `--encoded-payloads full` keeps the base64 payload; use it only
with `--output` in a directory the operator has excluded from antivirus scanning. The importer never adds
exclusions. The chosen mode is recorded in `import-report.json` → `assumptions.encoded_payloads`.

## Output layout

```
$OUTPUT/<case_id>/
  scenario.json                     curated only (development, public_replay)
  public/evidence.json              public bundle
  public/records.jsonl              line N mirrors ORIGINAL dataset line N (sanitized event or explicit stub)
  evaluator/truth.json              curated only
  evaluator/truth.DRAFT.json        draft only: status DRAFT_NOT_VALID_FOR_SCORING, no steps
  evaluator/curation-template.json  draft only: NOT_VALID_FOR_SCORING
  evaluator/curation.json           curated only: exact curation bytes
  evaluator/import-report.json      digests, counts, dropped fields, sanitizer totals, clock, assumptions, license
  evaluator/locators.json           record shape; event_id -> original line, line SHA-256, record_id, channel, hostname
  evaluator/pseudonyms.json         original -> pseudonym map
  evaluator/salt.json               per-import 32-byte HMAC salt
```

Keep `evaluator/` away from hunters. Each event's public `locator.record_id` is its original line number in the
dataset member. That number is also its line in `public/records.jsonl`. Every record is imported: allowlisted event
types with their allowlisted fields, any other event type or channel **metadata-only** (see below). Only blank
lines remain explicit stubs. A content value longer than 16384 bytes is cut with an explicit
` …[truncated N bytes]` marker; its source is marked `completeness: partial` and gets a `content_truncated`
`known_gaps` entry. Nothing is silently truncated.

### Locators

Locators are stable: they depend only on the dataset bytes, never on the salt or importer run.

- **Original line number** (1-based, blank lines counted) works for every shape: curation `{"line": N}`.
- **Record number**: when the export carries `RecordNumber` (NXLog shape) or `EventRecordID`, `locators.json` records
  it as `record_id` (string) with the canonical `channel` and the record's `hostname` (null `record_id` when absent).
  Curation may cite `{"record_id": "N", "channel": "Security", "hostname": "HOST"}`; channel and hostname match
  case-insensitively. Windows record numbers are unique per log per computer, so the qualified form is always
  unambiguous. The bare `{"record_id": "N"}` works only when that number occurs once in the export; otherwise it
  fails with `ambiguous_locator`.
- Step `source_receipt_sha256` hashes the cited original lines and their line SHA-256, whichever locator form the
  curation used.

## Drafts are refused for scoring

`truth.DRAFT.json` has `"status": "DRAFT_NOT_VALID_FOR_SCORING"`, `truth_revision: 0` and no steps.
`benchmark_contracts.validate_truth` refuses it as an unknown field. Scoring loads only
`<case_id>/evaluator/truth.json`, which a draft never writes. The importer also checks at build time that the
contract still refuses the draft (`draft_not_refused` otherwise). `benchmark_import_otrf.refuse_draft(truth)` is
the explicit gate for any other consumer. A draft has no `scenario.json`, so it cannot join an experiment.

## Field allowlist and pseudonyms

`otrf-fields.json` maps `Channel` → `EventID` → `{field: transform}` for Security, Sysmon, System,
PowerShell/Operational, classic Windows PowerShell, WMI-Activity, TaskScheduler, TerminalServices-LocalSessionManager,
Application and the Exchange channels. Unlisted fields are dropped and counted in the report (`dropped_fields`).

**Content fields reach the hunter.** Command lines, script blocks and module payloads are evidence, so they use the
`content` transform instead of being dropped (they were omitted up to `otrf-fields-4`):

| Event | Content fields |
| --- | --- |
| Sysmon 1, Security 4688 | `CommandLine`, `ParentCommandLine` (Sysmon; 4688 has no parent command line) |
| PowerShell/Operational 4104 | `ScriptBlockText`; `MessageNumber`, `MessageTotal`, `ScriptBlockId` stay so multi-part blocks can be joined |
| PowerShell/Operational 4103 | `Payload`, `ContextInfo` |
| Windows PowerShell 400/403/600/800 | `HostApplication`, `CommandLine`, 800 `Details`; `ScriptName`/`CommandPath` use `path` |
| Sysmon 13 / 22 | `Details` / `QueryResults` |
| Sysmon 19 / 20 / 21 | `Query` / `Destination` / `Consumer` |
| System 7045, Security 4697 | `ImagePath`, `ServiceFileName` |
| Security 4698 / 4702 | `TaskContent` / `TaskContentNew` (the real 4702 field name) |
| Security 4627, 4657, 4661, 4662, 5447 | `GroupMembership`; `NewValue`/`OldValue`; `Properties`; `Properties`/`AdditionalInfo*`; `Conditions` |
| WMI-Activity 5858/5860/5861 | `Operation`, `Query`, `ESS`, `CONSUMER`, `PossibleCause` |
| Application, MSExchange Management 1 | `Message` (no other content exists in these exports) |

Still absent: Sysmon `RuleName` (detector labels, often `technique_id=`), `CallTrace`, `AccessReason` and security
descriptors, and `Message` everywhere else.

### Content sanitizer (`benchmark_sanitize.py`)

`benchmark_sanitize.sanitize_text(value, pseudonymize, max_bytes=16384, identities=...)` is shared with the
attack_data importer and the lab sealer. It is deterministic and runs, in order:

1. Normalise to text; NUL is refused (`invalid_text`); newlines are kept.
2. **Secrets → `[REDACTED:<kind>]`**: password arguments and literals (`-Password X`, `--password X`/`--password=X`,
   `/p:X`, `/password:X`, `-p X` only after net/runas/psexec/sshpass/mysql/useradd-like tools, archiver passwords
   `rar`/`7z` `-p<pass>` and `-hp<pass>` and `zip`/`unzip` `-P <pass>`, `net user [/add] <name> <password>` (also
   with a quoted `"…\net.exe"` image path), `net use \\host\share <password>`, `password=`/`pwd=`/`pass=`/`secret=`
   also inside joined keys (`quick_password=`, `confirm_password=`, `client_secret=`, `newpassword=`, `password2=`)
   and percent-encoded inside URLs (`%26password%3D<pw>%26`, also cmd.exe-doubled `%%26password%%3D`),
   `ConvertTo-SecureString '<x>'` and `'<x>' | ConvertTo-SecureString`, URL `user:pass@`),
   NTLM/LM `LM:NT` pairs and 32-hex hashes after `:` or a hash keyword (`/ntlm:`, `-Hash`, `rc4`), Kerberos
   (`$krb5tgs$…`, `/aes256:`, base64 `doI…` tickets), private-key PEM blocks, AWS `AKIA`/`ASIA` keys and 40-character
   secret keys in key context (`aws_secret_access_key`, `SecretAccessKey`, `secret_key`), JWTs,
   `Authorization:`/`Cookie:` values, connection-string passwords. A PowerShell
   `-EncodedCommand` payload (any unambiguous prefix: `-e`, `-ec`, `-en`, `-enc` … `-EncodedCommand`, any case) is
   decoded to scan for secrets. A payload whose decoded text holds one becomes `[REDACTED:encoded_secret]` in both
   modes. Otherwise `--encoded-payloads preview` (default) replaces a UTF-16LE payload with
   `[ENCODED_COMMAND utf16le_chars=<n> sha256=<16 hex of the decoded bytes>] decoded_preview="<first 512
   characters, sanitized by steps 2–4, control characters escaped>"`, plus ` …[preview of 512 chars]` when the
   script is longer; payloads that are not UTF-16LE text stay as they are. `full` keeps the base64 payload (see
   Antivirus above). Previews are counted as `encoded_previewed` in the sanitizer totals.
3. **Identities → the import's own pseudonyms** (`Pseudonyms.content`): SIDs (also when joined by `_` or followed by
   `-<word>`, as in `S-1-5-21-…-1107_Classes` hive names and `…PIPE_S-1-5-21-…_` pipe names), `DOMAIN\user`, `user@domain`, UNC
   `\\host\`, `\Users\<name>\` and `/home/<name>/` profiles, IPv4/IPv6 literals (loopback, unspecified and version
   numbers such as `Version=4.0.0.0` or `Chrome/103.0.0.0` kept), and every original the import has already
   pseudonymized (users, NetBIOS names, DNS names, IPs, mapped GUIDs, opaque names) plus the export's hostnames
   and DNS domains. So `C:\Users\<name>\` in a command line carries the same `user-…` token as the event's `User`
   field. Content values are re-sanitized from their originals until no new pseudonym appears (at most 4 passes),
   because a command line can name an identity first seen in a later record.
4. **ATT&CK leakage → `T####`**: technique IDs and Atomic Red Team names (`AtomicRedTeam`, `atomics`,
   `Invoke-AtomicTest`).
5. **Bounded**: over 16384 UTF-8 bytes the value keeps its first 16384 bytes and ends with ` …[truncated N bytes]`.

The report's `sanitizer` section records per field (`"Channel:EventID Field"`) the number of values, redactions by
kind, pseudonymized identities, masked ATT&CK tokens, truncated values and original bytes, plus
`structured_identity_rewrites`: kept/path values in which an identity revealed by content was pseudonymized (for
example a profile user that also names a kernel object in a 4674 `ObjectName`), which would otherwise fail the leak
check.

### Message parsers and metadata-only events

`message_fields` (`{channel: {event_id: parser}}`) names a parser for the events whose data is only in `Message`
(previous section): `powershell-classic` (400/403/600/800), `powershell-module` (4103), `wmi-activity`
(5857/5858/5860/5861; the 5860/5861 message keys are renamed to the UserData names `NamespaceName`, `Query`, `User`,
`processid`, `MachineName`, `ESS`, `CONSUMER`) and `terminal-services` (21/24/25/39/40). Parsed fields fill only
names the record does not carry, then pass the allowlist and transforms like any other field; the NXLog envelope
collision rule does not apply to them. Records parsed are counted in `record_shape.message_fields_parsed`.

An event type with no allowlist entry, or a record from a channel the allowlist does not list, is imported as a
**metadata-only event**: `timestamp_original`, `Channel`, `EventID` and the System-element fields `SourceName`,
`Level`, `Severity`, `Task`, `Opcode` (whichever the shape carries), with its timestamp, asset and original-line
locator. Its other fields are dropped and counted in `counts.metadata_only_dropped_fields`; types are counted in
`counts.metadata_only_by_type`. An unlisted channel becomes source `channel:<channel>` with telemetry `null`.
There is no stub and no gap for them any more.

`otrf-fields-5` (with importer `otrf-import-3`) adds the content fields above, the channels classic Windows
PowerShell, WMI-Activity, TaskScheduler (106/129/140/141/200/201), TerminalServices-LocalSessionManager
(21/24/25/39/40), Application (4/47/48/1000/1001/1002/2303/4007/9000), MSExchange Management 1 and the Exchange
ActiveMonitoring (2/3/4/5) / HighAvailability (1001/1013/1014/1015) channels, PowerShell/Operational
40961/40962/53504, Security 1100/4611/4627/4657/4661/4662/4674/4719/4738/4778/4779/4798/4799/4800/4801/4957/4985/5447
and System 10/11/7000/7009/7034. Exchange and Application channels carry `SourceName`/`Level`/`Task` and have
telemetry `null` (no coverage-catalog claim); the other new channels are `windows-security`. Field names were
verified against the 23 downloaded datasets where the event occurs; 403, 1000, 141, 200, 201, 21, 25, 39, 5860,
5861, 4662, 4719, 4738, 4778, 4798, 4801 and 7034 do not occur in them and follow the Windows schemas. The import
report's `counts.not_imported` now has only `blank_line`; `skipped_by_type` is replaced by `metadata_only_by_type`.

Measured on three real datasets re-imported with their draft salts (drafts, not written to the data directory;
after: default `--encoded-payloads preview`, `full` in parentheses):

| Dataset | Events before → after | Stubs | Fields kept | evidence.json bytes |
| --- | --- | --- | --- | --- |
| SDWIN-201102041306 (PowerShell HTTP listener) | 110 → 110 | 0 → 0 | 1264 → 1280 | 81,635 → 82,089 |
| SDWIN-200722001847 (Empire Run key) | 576 → 657 | 81 → 0 | 7504 → 9018 | 408,522 → 672,867 (1,281,853) |
| SDWIN-201018195009 (comsvcs LSASS dump) | 184 → 184 | 0 → 0 | 2244 → 2262 | 141,713 → 142,550 |

`otrf-fields-2` adds Security 4946/4948 (firewall rule added/deleted), inspected in SDWIN-201021001911:
`ProfileChanged` is kept, `RuleName` is pseudonymized (`opaque`, it is operator-chosen text), and `RuleId` is kept
literal because the same random rule GUID appears in the `...\FirewallPolicy\FirewallRules` registry path of
Sysmon 12/13 records, which the `path` transform does not rewrite.

`otrf-fields-3` (with importer `otrf-import-2`) adds the optional `shape_aliases` object:
`{shape: {channel: {event_id: {original_field: allowlisted_field}}}}`. An alias renames one original field of one
record shape to the allowlisted name of the **same** Windows field; the target must be allowlisted for that event and
the source must not be. The only alias is `nxlog-eventtime` Security 5156 `ProcessId` → `ProcessID`. A record with
both names fails with `duplicate_field_alias`; uses are counted in `record_shape.aliased_fields`. Further rules for
the NXLog shape:

- Envelope fields used for detection, time, locators and collector identity are never imported.
- An allowlisted field whose name NXLog also fills from the event's System element (for example `AccountName` on
  System 7045) cannot be told apart and is dropped, counted in `record_shape.envelope_collisions_dropped`. The one
  exception is `EventType`: it is imported only when `EventTypeOrignal` is present, which shows that the export moved
  NXLog's own value aside.
- Channel names match the allowlist case-insensitively (`security` → `Security`), counted in
  `record_shape.channel_spellings_normalized`. This applies to both shapes.

`otrf-import-2` also extends the `path` transform (both shapes): the DNS suffixes of the export's own FQDN hostnames
are pseudonymized wherever they appear in a path segment (for example SYSVOL `\<domain>\Policies\...` or an ADSI
schema cache file `<domain>.sch`), and LDAP `DC=a,DC=b` runs become one DNS pseudonym. Two NXLog exports
were refused with `pseudonymization_leak` without this. The flat-shape drafts re-imported with the same salt are
byte-identical.

`otrf-fields-4` changes two Security entries (output changes for any export containing them):

- 4769 `TargetUserName` uses the `account` transform. Kerberos writes it as `user@REALM`; `user` pseudonymized the
  whole string, so the same user had a different pseudonym than in 4624/5140/paths. `account` splits it into the
  shared user pseudonym `@` a DNS pseudonym of the realm.
- `AccessReason` is removed from 4656 and 5145. It is access-check text that embeds security descriptors (SDDL,
  possibly with domain SIDs), which the policy above excludes. It is now dropped and counted in `dropped_fields`.

Field names for event types that were absent from the inspected datasets follow the Windows/Sysmon schemas. They
are unverified against an OTRF export. A changed allowlist (`--fields FILE`) is an explicit release decision by
its author. Transforms:

| Transform | Effect |
| --- | --- |
| `keep` | Value unchanged (strings ≤ 4096 characters). |
| `content` | `benchmark_sanitize.sanitize_text` (above): secrets redacted, identities pseudonymized, ATT&CK masked, ≤ 16384 bytes with an explicit marker. |
| `basename` | Last path component. |
| `path` | Full path with SID, `\Users\<name>\` profile, UNC host, ATT&CK-labelled segments, the export's own DNS domains and LDAP `DC=` runs pseudonymized. |
| `account` | `DOMAIN\user` / `user@dns` / `MACHINE$`. |
| `user`, `domain`, `host` | Single-name identifiers. |
| `sid` | `S-1-5-21-…` domain part pseudonymized, RID kept; well-known SIDs kept. |
| `guid`, `ip` | Loopback/unspecified IPs kept. |
| `dns`, `opaque` | Pseudonymized. |

Pseudonyms are `HMAC-SHA256(salt, namespace, casefolded value)` truncated to 64 bits. Host, NetBIOS-domain and
`MACHINE$` names share one namespace, so the same machine correlates across fields and sources. Well-known
principals (`SYSTEM`, `NT AUTHORITY`, `LOCAL SERVICE`, `DWM-1`, and others) stay literal. Public output fails with
`pseudonymization_leak` if any pseudonymized original (four characters or more) still appears (content included),
and with `attack_token_in_field` if a kept value carries an ATT&CK ID.

## Archive and input limits

Archive members:

- exactly one regular `.json` member
- no `..`, absolute, drive or backslash names
- no symlinks
- no nested archives
- no encryption
- stored or deflated compression only

Size limits:

| Item | Limit |
| --- | --- |
| Input file | 64 MiB |
| Decompressed member | 256 MiB (`--max-member-bytes`); also enforced on the streamed output, not just the header |
| Compression ratio | 200:1 |
| Line | 1 MiB |
| Records | 500,000 |

## Curation schema (`schema_version: 1`, strict: unknown fields refused)

| Field | Meaning |
| --- | --- |
| `dataset_sha256`, `metadata_sha256` | SHA-256 of the exact `--dataset` file (zip or json) and metadata file; mismatch → `curation_dataset_mismatch`. |
| `curated_by`, `curated_utc`, `note` | Who curated, when (UTC with offset), and the validation note. |
| `revision`, `truth_revision` | Positive integers (scenario revision / truth revision). |
| `attack_release` | Pinned ATT&CK release, for example `v18`. |
| `coverage` | All seven coverage axes; values from `benchmarks/coverage.json`. |
| `assets` | One entry per dataset `Hostname`: `hostname`, `os_family` (coverage OS value), `os_version`, `architecture`, `vendor` (null when unknown). |
| `steps` | `step_id`, `technique_id`, `asset: {"hostname"}`, `window_utc`, `execution_outcome` (`succeeded/blocked/failed/unknown`), `observability` (`sufficient/insufficient/absent/unknown`), `support_sets` (list of alternative lists of locators, see [Locators](#locators): `{"line": N}`, `{"record_id": "N", "channel": "...", "hostname": "..."}` or `{"record_id": "N"}`; every cited record must be imported), `boundary_id`, `phase` (`initial/persistence/reentry`). |
| `edges` | Ordered `[step_id, step_id]` pairs. |
| `controls` | `control_id`, `asset: {"hostname"}`, `window_utc`, `expected_disposition` (`benign/insufficient`). |
| `lookalike_event_ids` | Groups of original-record locators. Each group is one curator-validated benign lookalike. Converted to event IDs; must not overlap support sets. |
| `sophistication` | `band` (S0–S5), `boundaries`, `preconditions`, `emulation_limitations`, `group_ids`, `source_references`. |
| `source_references` | HTTPS references, including the pinned dataset URL. Metadata links and ATT&CK technique URLs are added. |
| `assessment_windows` | Optional list of windows; default is one whole-bundle window. Questions cover every asset × window. |
| `matched_control` | Difficulty object of the matched attack family (passed to `measure_case`). Required when no step is `sufficient` (zero-step controls and cases whose steps are all `insufficient`/`absent`/`unknown`); refused with `unexpected_matched_control` otherwise. |
| `family_id` | Optional reviewer override of the metadata-derived bootstrap family, for when the OTRF mapping is wrong. Pattern `otrf-` followed by one or more lowercase technique tokens (`t1555`, `t1003-001`) joined by `-`, sorted and unique exactly as the derivation produces them; otherwise `invalid_identifier`. The report records `curation.family_id` (`value`, `metadata_derived`, `source`). |

Assessment labels are derived, never guessed:

- A question overlapping a `sufficient` step → `1`.
- A question overlapping only non-sufficient steps → `null`.
- A question covered by a `benign` control → `0`.
- A question covered by an `insufficient` control → `null`.
- A question with neither a step nor a control fails with `unlabeled_question`.

A case whose steps are all non-`sufficient` has no relevant events to measure, so it inherits the matched family's
difficulty (`matched_control`, as for zero-step controls). Unlike a zero-step control it keeps `difficulty.control:
false` and its S band from its steps. Observability is decided from the evidence alone; the importer never forces it.

`family_id` is `otrf-<declared techniques>` (sorted, `.` → `-`, lowercase), unless the curation overrides it.
Datasets for the same techniques form one bootstrap cluster; repeats are not independent attacks.

## Invented sample

`sample/` contains **invented** metadata, JSON-lines exports and curations in both record shapes: the flat sample
(`SDWIN-990101000001.yaml`, `sample_owner_discovery_*.json`, `curation.json`) and the NXLog-shaped sample
(`SDWIN-990101000002.yaml`, `sample_nxlog_discovery_*.json`, `curation-nxlog.json`, cited by qualified record
locators). They exist for `test_benchmark_import_otrf.py` only. All of their hosts, users, addresses, hashes and
records are fictitious, and they carry no information about any model or real environment. Content, message-parser
and metadata-only tests append further invented records (secrets, profiles, classic PowerShell, WMI and session
messages) to a temporary copy; `test_benchmark_sanitize.py` uses invented strings only.

## Compound recordings: OTRF APT29 evaluation (`compound`, `compound-plan`)

`datasets/compound/apt29` is a multi-host, multi-step APT replay: MITRE ATT&CK Evaluations Round 2 APT29, emulated
again by Roberto Rodriguez (OTRF). Day 1 runs Pupy and Meterpreter (spearphish payload, smash-and-grab collection, a
stealth toolkit, lateral movement, persistence fired after a reboot); day 2 runs PoshC2 (low-and-slow breach,
domain takeover, persistence). Step-by-step ground truth is the emulation plan
`datasets/compound/apt29/emulationplans/apt29.xlsx` in the same repository. Licence: the same MIT `LICENSE` file as
the atomic datasets (byte-identical at the pinned commit); keep the notice with every copy.

### Verified data format (inspected 2026-11-07, commit `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`)

| | Day 1 `day1/apt29_evals_day1_manual.zip` | Day 2 `day2/apt29_evals_day2_manual.zip` |
| --- | --- | --- |
| zip / member | 13,944,973 B; one member, 385,334,029 B | 43,033,041 B; one member, 1,714,987,031 B |
| SHA-256 | `98a07314…fbe5` | `377f8cba…65f9` |
| records | 196,081 (no blank lines, LF) | 587,286 |
| hosts | SCRANTON 131,119; NASHUA 29,056; NEWYORK (DC) 23,935; UTICA 11,971 | UTICA 480,297; SCRANTON 66,419; NEWYORK 29,207; NASHUA 11,363 |
| EventTime span (local) | 2020-05-01 22:55:23–23:28:17 (33 min) | 2020-05-02 03:50:47–04:29:22 (39 min) |
| clock | −14400 s against 143,883 Sysmon `UtcTime`; residual 27.0 s | −14400 s against 407,263 records; residual 36.8 s |

Both zips are plain Git blobs (not LFS, not split). Every record is the `nxlog-eventtime` shape (one WEC collector,
`RecordNumber`, `tags` list). Channels: Sysmon (73 % / 69 %), Security spelled `Security` and `security`, PowerShell
Operational, classic Windows PowerShell, System, WMI-Activity, TerminalServices, Windows Firewall and BITS. The
recordings contain only the four Windows hosts; the plan's attacker servers and OneDrive were not instrumented, and
the pcaps/Zeek folders are not imported. The residual is Sysmon's write delay: `EventTime` trails Sysmon's own
`UtcTime` by up to 27 s (day 1) and 37 s (day 2), so record order inside a few seconds is not event order.

The atomic path cannot read these files (member above 256 MiB, day 2 above 500,000 records, no metadata YAML),
and a whole day cannot be one case: the activity runs at about 100 (day 1) and 250 (day 2) records per second.

### Mode and partition semantics

`benchmark_import_otrf.py compound` streams the zip twice (64 MiB input, 2 GiB member, 1,000,000 records, 1 MiB
line, ratio 200:1). The first pass checks every line and measures the clock on the WHOLE recording. The second pass
keeps one explicit UTC window. The metadata is the compound `README.md`: only the `# Adversary` name and the `.zip`
links are read, and the input file name must be one of those links. Semantics follow the attack_data partitions:

- `--window-start/--window-end` are UTC with offset, start inclusive, end exclusive, compared with clock-corrected
  time. Every record outside the window is excluded and stated: one `outside_partition_window` known gap per asset
  with its count, and per-host counts plus the imported original line ranges in `import-report.json` → `partition`.
- `--collection-profile live-collector` keeps only the event IDs the pinned live-lab collector collects
  (`benchmark_evidence.supported_event_ids`: Sysmon 1/3/13/22, Security logon/process/Kerberos, PowerShell
  4103/4104/400/403/600/800, WMI-Activity, TaskScheduler, System 7036). Every other record inside the window is
  excluded and stated as a `collection_profile_filter` known gap per source and asset (`source_id` null for a
  channel the profile drops entirely), with per-host counts by type in `import-report.json` → `collection_profile`.
  Replay and live-lab cases therefore share one collection convention. Nothing inside the window and profile is
  sampled.
- Every host of the recording is an asset of every partition, even one with no record in the window, so questions
  and attribution stay comparable across partitions. Each event sits on the computer that logged it.
- `public/records.jsonl` is an index, one line `{"event_id", "line"}` per imported record in original order. Each
  record's sanitized fields are published once, in `evidence.json`. Locators keep the original line number.
- The prompt projection (evidence plus records file, exactly as `benchmark_corpus.public_prompt_bytes` measures it)
  must fit `--max-public-bytes` (default and maximum 1 MiB), else `public_bundle_too_large`. Nothing is truncated.
- A curation must declare the same `partition_window` and `collection_profile` (`partition_mismatch`); the
  consensus merge requires both drafts to agree on them (`draft_conflict`). A support record outside the partition
  or profile fails with `support_record_not_imported`. An atomic import refuses either key.
- `scenario_id` is `otrf-compound-<adversary>-<dataset stem>-p<12 hex>`. Every partition of one recording keeps
  the family `otrf-compound-<adversary>-<dataset stem>` (one bootstrap cluster, no `family_id` override), and the
  scenario's limitations state the partition and the profile exclusions.

`compound-plan` measures a window and splits it into the fewest contiguous whole-second partitions that fit the cap
(greedy, binary search on measured sizes). `EventTime` has whole-second resolution, so a single second whose records
alone exceed the cap cannot be split: the plan lists it under `unpublishable` and no case covers it.

```powershell
py -3 benchmark_import_otrf.py compound-plan --dataset $data/day1/apt29_evals_day1_manual.zip --metadata $data/README.md --window-start 2020-05-02T02:55:26+00:00 --window-end 2020-05-02T02:56:16+00:00 --collection-profile live-collector --output $work/day1-g01.plan.json
py -3 benchmark_import_otrf.py compound --dataset $data/day1/apt29_evals_day1_manual.zip --metadata $data/README.md --window-start 2020-05-02T02:55:26+00:00 --window-end 2020-05-02T02:56:16+00:00 --collection-profile live-collector --draft-os-family windows-client --output $work/drafts/day1-g01-p01
py -3 benchmark_consensus.py merge --draft-a $p/curation.PROPOSED.json --draft-b $pb/curation.PROPOSED.json --locators $case/evaluator/locators.json --template $case/evaluator/curation-template.json --output $work/consensus/day1-g01-p01/curation.json --report $work/consensus/day1-g01-p01/report.json
py -3 benchmark_import_otrf.py compound --dataset $data/day1/apt29_evals_day1_manual.zip --metadata $data/README.md --window-start 2020-05-02T02:55:26+00:00 --window-end 2020-05-02T02:56:16+00:00 --collection-profile live-collector --curation $work/consensus/day1-g01-p01/curation.json --salt-file $case/evaluator/salt.json --output $work/import-day1-g01-p01
```

In Git Bash, set `MSYS_NO_PATHCONV=1`: MSYS otherwise rewrites the colon-separated timestamps as path lists.

### Segmentation rule

One case group per emulation-plan step number (day 1: 1–10, day 2: 11–20). The group's evidence span is the first
to last clock-corrected time of its step-action records (process creations, script blocks, registry sets, logons
and C2 connections on the attacker's process lineage), found before any answer key was written and stored with the
data (`segmentation/<day>.json`). The window is that span plus a fixed 30 s lead and trail, clipped at the
whole-second midpoint to the neighbouring group, so groups never overlap and the background around each step stays
in its case. `compound-plan` then splits each group window. A partition without an attack step is a benign control;
it always lies inside a step-group window.

### Limits

- The collection profile drops Sysmon 10 (LSASS access), 11 (file creation), 12 (registry key create/delete),
  System 7045 and most Security object-access events. Steps evidenced only there become `insufficient`.
- Day 2's PoshC2 module loads write about 1,000 PowerShell 4103 plus 1,000 classic 800 records per second; such a
  second alone holds up to 9 MB of public evidence and is unpublishable under the 1 MiB prompt cap.
- The emulation plan uses pre-v7 ATT&CK IDs; answer keys use `benchmark_attack.canonical_technique` (v20).

### Imported result (2026-11-07)

Day 1: ten step-group windows (02:55:26–03:22:02 UTC) split into 34 partitions; the seconds 03:19:30 and 03:19:31
(SCRANTON boot, 3,714 and 2,168 benign registry-set records) are unpublishable. Each partition got two independent
agent drafts; 31 merged into `agent_consensus` keys (Cohen's kappa 0.27–1.0 where defined) and validate as one
development experiment. Three merges were refused: g08-p01 (`sophistication_unsupported`: the agreed edges do not
connect the lateral-movement chain) and g10-p02/p03 (`matched_control_unavailable`: one draft keyed the reboot service
start as T1543.003, the other as T1569.002). Day 2 was not imported: its ten group windows would need about 128
partitions plus 118 unpublishable seconds, and those seconds hold the key PoshC2 records of steps 12–17 and 20.
Per-group unfiltered/filtered counts and bytes are in `<data>/apt29/day1-window-stats.json` and
`day2-window-stats.json`. All answer keys are agent consensus, not human-attested.

The invented sample `sample/sample-compound-README.md` with `sample/sample_compound_lab_2026-01-02.json` (three
fictitious hosts, records outside the window, out-of-profile records, a blank line) drives
`CompoundImportTest` in `test_benchmark_import_otrf.py`; the test zips it at run time.

# Splunk attack_data importer: Linux auditd and AWS CloudTrail (development split only)

`benchmark_import_attackdata.py` turns one published log file from
[Splunk attack_data](https://github.com/splunk/attack_data) into a benchmark case with the OTRF importer's safety
model and output layout (above). It adds Linux and AWS control-plane telemetry to the Windows-only OTRF corpus.
Every case is `split: development`, `provenance: public_replay`. attack_data labels a **whole dataset** with
techniques (YAML `mitre_technique`), never single events, so truth comes only from a human-written curation; without
one the importer writes a draft that scoring refuses (`truth.DRAFT.json`, `DRAFT_NOT_VALID_FOR_SCORING`, no
`scenario.json`; `benchmark_import_otrf.refuse_draft` applies unchanged).

## License and attribution

Checked at commit `3a25034e7446cbdd108b87e848d5296530545c80`: the `LICENSE` file is the **Apache License 2.0**
(GitHub also reports Apache-2.0). The README states "Copyright 2025 Splunk Inc."; the LICENSE appendix boilerplate
still reads "Copyright [2023] [Splunk Inc]". There is no NOTICE file. Imported cases are **modified** derivatives
(filtered, pseudonymized, re-encoded): redistribution must include a copy of the license, keep the attribution
notices and state that the files were changed. Each `evaluator/import-report.json` carries that notice. Keep
`LICENSE.splunk-attack_data.txt` beside downloaded data and **never commit downloaded data into this source tree**.
The same contamination caveat as OTRF applies: public data, likely in training sets, development only.

## Verified data format (inspected, not assumed)

Inspected on 2026-11-03 in the files listed in `bot-framework-data/attack_data/provenance.json`.

- **Dataset YAML:** `author`, `id` (UUID), `date`, `description`, `environment`, `directory`, `mitre_technique`
  (list), `datasets` (`name`, `path`, `sourcetype`, `source`). One YAML can declare several files of different
  sourcetypes. Some files indent sequence items as `-   name:`; the importer rewrites that one-level form to
  `- name:` before the shared OTRF subset parser runs and refuses nested over-indented items. Only `id`, `date`,
  `environment`, `directory`, `mitre_technique` and `datasets` are interpreted; unknown keys, anchors, aliases, tags,
  flow collections and tabs are refused.
- **Binding:** the supplied file name must equal exactly one declared `datasets[].path` basename. Its `sourcetype`
  selects the format: `auditd` → Linux auditd, `aws:cloudtrail` → CloudTrail. Anything else is
  `unsupported_sourcetype`; content that does not match the selected format is refused. Data files are Git LFS
  objects: download the object (not the pointer) and check it against the pointer's `oid sha256` and `size`.
- **auditd** files are author-selected extracts, often a single record type, newest first, with occasional
  byte-identical duplicate lines (kept as separate events). No inspected file carries `node=`. Two shapes, never
  mixed in one file (`mixed_record_shapes`):

| Shape | Header | Values |
| --- | --- | --- |
| `auditd-raw-epoch` | `msg=audit(<epoch>.<ms>:<serial>): ` | numeric IDs; untrusted strings (`comm`, `exe`, `name`, `cwd`) quoted or hex-encoded (decoded strictly, counted); optional enriched names after `0x1d` |
| `auditd-interpreted-local` | `msg=audit(MM/DD/YYYY HH:MM:SS.mmm:<serial>) : ` | `ausearch -i` output: names resolved, `exit=EACCES(Permission denied)` is the only value with a space in a SYSCALL/PATH/CWD record |

- **auditd argv records** (re-inspected 2026-11-07 in attack_data files outside the 32-case corpus; the corpus's four
  Linux files hold only SYSCALL and PATH records):
  - raw `EXECVE`: `argc=N a0="ls" a1=2D6C61 …`, each argument kernel-quoted or hex (any byte, including spaces and
    newlines); a long argument is `aN_len=… aN[0]=… aN[1]=…`, and a long argv continues in further EXECVE records
    of the same serial;
  - interpreted `EXECVE`: `argc=3 a0=grep a1=-Ev a2=.Xauthority|.bashrc|… ` — decoded, unquoted, and an argument
    may contain spaces or quotes;
  - raw `PROCTITLE`: `proctitle=<hex argv joined by NUL>` (or a quoted single word), cut at 128 bytes by the
    kernel; interpreted: `proctitle=sudo systemctl status auditd.service ` (NULs shown as spaces, to end of line);
  - one published PROCTITLE extract carries an EXECVE-shaped body (`argc=5 a0="sudo" …`); it is imported without
    `proctitle` and counted as `proctitle_unparsed`.
- **CloudTrail** files are one event object per line (not the S3 `{"Records": [...]}` envelope, which is refused).
  Each line needs `eventTime`, `eventID`, `eventName`, `eventSource`, `eventType` and a 12-digit
  `recipientAccountId`. Some files replace `recipientAccountId` with `111111111111` while `userIdentity.accountId`
  keeps another value. Failed console logins for unknown users carry `userName` `HIDDEN_DUE_TO_SECURITY_REASONS`.
- Not supported: Linux Sysmon XML, Security Lake OCSF, `kern.log`/`auth.log` syslog files and archives.

## Clock

| Shape | Offset / uncertainty |
| --- | --- |
| `auditd-raw-epoch` | 0 s / 0.001 s: kernel epoch time is UTC by definition. |
| `auditd-interpreted-local` | Operator-declared: the zone is not recorded. A draft needs `--clock-offset-seconds` (local − UTC) and `--clock-uncertainty-seconds`; without them `no_clock_reference`. The declaration goes into the curation template's `clock_declaration`; a curated import takes it only from the curation. |
| `cloudtrail-jsonl` | 0 s / 1 s: AWS documents `eventTime` as UTC, whole seconds. |

A declaration for any other shape is refused (`conflicting_arguments`). The date order `MM/DD/YYYY` is the inspected
`ausearch -i` (en_US) form; a month above 12 fails. Each event keeps its original value as
`fields.timestamp_original`.

## Assets and gaps

An auditd file comes from one kernel: without `node=` its one asset is named `audit-host` in curations (a
placeholder, pseudonymized in public output); with `node=` on every record each node is an asset; a mix is refused.
A CloudTrail asset is its `recipientAccountId`, OS `not-applicable`: a control plane is never Windows or Linux
evidence. Every source is `completeness: unknown` with a known gap that the published file is an extract chosen by the
dataset author. A missing record is therefore never a clean negative, and measured difficulty has gaps ≥ 1. A source
whose content values were truncated also gets a `content_truncated: N content values exceeded 16384 UTF-8 bytes …`
gap.

## Time-window partitions

A recording whose public bundle is too large for the prompt cap (`max_prompt_bytes`, at most 1 MiB) can be imported
as explicit partitions: `--window-start UTC --window-end UTC` (start inclusive, end exclusive, compared with the
**normalized** UTC time, after any clock declaration). Rules:

- Every record outside the window is excluded and stated: a `known_gaps` entry with reason
  `outside_partition_window: N records … (original lines a-b, c-d …)`, a stub with that reason at each excluded
  line of `records.jsonl`, and `partition` (`window_utc`, `excluded_records`, `excluded_line_ranges`) in
  `import-report.json`. Nothing inside the window is ever sampled or truncated.
- The partition window is the case's `window_utc` (and the default assessment window). Locators keep the original
  line numbers; a support record outside the window fails with `support_record_not_imported`.
- A curated import must declare the same window as `partition_window`; a missing, extra or different window fails
  with `partition_mismatch`. The draft's curation template already contains it.
- Partitions of one dataset keep its `family_id`, so they form one bootstrap cluster and never count as independent
  attacks. The `case_id` and `scenario_id` (suffix `-p<12 hex>`) differ per window, and the scenario's
  `sophistication.emulation_limitations` states the partition and the number of excluded records
  (`provenance` stays `public_replay`).
- Choose windows from the evidence (for example a pause in the activity), get the partition approved by the reviewer
  for every compared team, and use the same window for every team. `--window-start` without `--window-end` (or the
  reverse) fails with `conflicting_arguments`; an empty or inverted window with `invalid_window`; a window without a
  supported record with `no_supported_records`.

## Field allowlist and pseudonyms

`attackdata-fields.json` (`attackdata-fields-2`) maps format → record type → `{field: transform}`, plus one
`metadata_only` map per format. Unlisted fields are dropped and counted (`dropped_fields`).

**Generic fallback.** A record type without an entry is a **metadata-only event**, not a stub: `type`,
`audit_serial` and `timestamp_original` (auditd; its body is never tokenized, its keys are only counted), or the
CloudTrail `metadata_only` fields `eventName`, `eventSource`, `eventCategory`, `awsRegion`, `recipientAccountId`
(for example an `AwsServiceEvent`). The event type, record identity (locator), timestamp and asset come with every
event. They are counted in `metadata_only_by_type`; no gap is written for them. `records.jsonl` stubs remain only for
blank lines and records outside a partition window.

- **auditd** `SYSCALL`: `arch`, `syscall`, `success`, `exit`, `pid`, `ppid`, `auid`/`uid`/`euid`, `gid`/`egid`,
  `tty`, `ses`, `comm`, `exe`, the enriched `ARCH`, `SYSCALL`, `AUID`, `UID`, `EUID`, `GID`, `EGID`, and the content
  fields `command_line` and `proctitle` of its audit event. `EXECVE`: `argc` and `command_line`. `PROCTITLE`:
  `proctitle`. `PATH`: `item`, `name`, `nametype`, `mode`, `ouid`/`ogid` (+ enriched). `CWD`: `cwd`. The importer
  adds `type` and `audit_serial`. Dropped: syscall arguments `a0`–`a3`, the LSM label `subj`, saved/filesystem IDs,
  capability fields and the audit rule `key`, which is a detector label (for example `T1059_shell`).
- **argv reassembly.** Records with the same asset, serial and original timestamp are one audit event. Its EXECVE
  arguments (raw: quoted or hex, chunks `aN[k]` joined bytewise before decoding; interpreted: markers accepted only in
  argv order, so a value with spaces or a stray `aN=` stays one argument), across continuation records and with
  byte-identical duplicate lines used once, are joined with spaces; an argument that is empty or contains
  whitespace, quotes or backslashes is POSIX-single-quoted. Undecodable bytes and control characters other than tab
  and newline become `\xNN`. The result is `command_line` on the first EXECVE record and on the event's SYSCALL
  record. PROCTITLE (raw hex argv with NULs shown as spaces) is `proctitle` on its own record and on the SYSCALL.
  `import-report.json` `record_format.argv` counts `execve_records`, `execve_unparsed`, `execve_duplicate_records`,
  `execve_missing_args` (argc above the arguments present), `command_lines`, `command_lines_attached`,
  `proctitle_records` and `proctitle_unparsed`.
- **CloudTrail** `AwsApiCall` and `AwsConsoleSignIn`: `eventName`, `eventSource`, `eventCategory`, `awsRegion`,
  `errorCode`, `readOnly`, `managementEvent`, `recipientAccountId`, `sourceIPAddress`, `userIdentity.type`/`arn`/
  `principalId`/`accountId`/`userName`/`accessKeyId`/`invokedBy`, the session issuer's `type`/`arn`/`principalId`/
  `accountId`/`userName`, `sessionContext.attributes.mfaAuthenticated`, `responseElements.ConsoleLogin`,
  `additionalEventData.MFAUsed`, request names (`userName`, `roleName`, `groupName`, `policyArn`, `name`,
  `trailName`, `bucketName`, `s3BucketName`), the trail-scope booleans, and the content fields `userAgent`,
  `errorMessage`, `requestParameters`, `responseElements` and `additionalEventData`. Dropped: `tlsDetails`,
  `requestID`, `eventID` (kept only as the evaluator locator), `resources`, `sessionContext.attributes.creationDate`
  and `webIdFederationData`. Field names are dotted paths; a non-content path that holds an object or array is
  refused.
- **CloudTrail objects as content.** Before serialization, keys named `password`, `newPassword`, `oldPassword`,
  `masterUserPassword`, `secretAccessKey`, `sessionToken`, `privateKey`, `certificateBody`, `certificateChain`,
  `secretString`, `secretBinary` or `clientSecret` (any depth, case-insensitive) are dropped and counted (as
  `dropped_fields` paths such as `requestParameters.password`, and `secret_fields_dropped`). Policy documents stay.
  Identity keys at any depth (`userName`, `roleName`, `groupName`, `bucketName`, `s3BucketName`, `trailName`,
  `policyName`, `instanceProfileName`, `accountId`, `principalId`, `accessKeyId`; top-level `name`) get the matching
  structured transform. The object becomes canonical JSON (sorted keys, compact) in one string field; `null` stays
  `null`.

| Transform | Effect |
| --- | --- |
| `keep` | Value unchanged (strings ≤ 4096 characters). |
| `linux-path` | Path with the `/home/<user>` segment and ATT&CK-labelled segments pseudonymized. |
| `linux-comm` | Process name; ATT&CK-labelled names pseudonymized. |
| `linux-user`, `linux-group` | Numeric IDs, `unset` and well-known system accounts/groups kept; other names pseudonymized. |
| `aws-account` | 12-digit account ID. |
| `aws-arn` | Account and resource names pseudonymized, partition/service/region/resource type and `*` wildcards kept; IAM user and role names, STS assumed-role sessions and S3 bucket/key segments use the same pseudonyms as the matching name fields. |
| `aws-principal` | Unique ID; `ROLEID:session` keeps the separator. |
| `aws-user`, `aws-role`, `aws-resource`, `aws-key` | IAM user / role / other resource names, access key IDs. |
| `aws-source` | IPs pseudonymized like OTRF; AWS service principals (`*.amazonaws.com`, `AWS Internal`) kept. |
| `content` | Evidence text through `benchmark_sanitize.sanitize_text` (16384-byte bound). CloudTrail first: objects as above; ARNs and 12-digit account IDs inside the text get the `aws-arn`/`aws-account` pseudonyms. Then secrets are redacted (`[REDACTED:<kind>]`), identities pseudonymized, ATT&CK tokens masked (`T####`), and an oversized value is cut with an explicit marker. auditd: only `command_line` and `proctitle`, which must be `content`. |

Content runs after every structured field, in two passes: the first registers pseudonyms that only content names (an
ARN in an `errorMessage`, a `/home/<user>` in a command line, an IP); the second also replaces every known original
(users, groups, roles, resources, accounts, principals, keys, DNS names, IPs, `node=` hosts) as a whole token. A name
first seen in a later record is therefore never published raw in an earlier one. The detector `user` of
`/home/<name>` uses `linux-user`, so command-line users match `AUID`/`exe` users, and an IP matches
`sourceIPAddress`. `import-report.json` `counts.content` lists, per content field, `values`, `original_bytes`,
`redactions` by kind, `pseudonymized`, `attack_masked`, `truncated` and `secret_fields_dropped`.

Pseudonyms are the OTRF HMAC pseudonyms with the per-import salt, so an IAM user name, the user segment of its ARN and
a `requestParameters.userName` naming it correlate, as do a trail name and the trail ARN, and a Linux user name and
its `/home` path. Public output fails with `pseudonymization_leak` if a pseudonymized original (four characters or
more) remains, with `forbidden_public_metadata` if it contains the dataset ID, directory, a declared dataset name or
file stem (six characters or more), and with `attack_token_in_field` if a kept value carries an ATT&CK ID.

Input limits: 64 MiB file, 1 MiB line, 500,000 records, 256 KiB metadata, 4 MiB curation.

## Workflow

```powershell
# Draft (add --clock-offset-seconds/--clock-uncertainty-seconds only for an interpreted auditd export)
py -3 benchmark_import_attackdata.py --dataset $data/linux_auditd_at_execution.log --metadata $data/linux_auditd_at.yml --draft --output $work/draft-at
# Curated, reusing the draft's salt
py -3 benchmark_import_attackdata.py --dataset $data/linux_auditd_at_execution.log --metadata $data/linux_auditd_at.yml --curation $work/curation-at.json --salt-file $work/draft-at/<case_id>/evaluator/salt.json --output $cases
```

Then validate inside a development experiment exactly as in OTRF step 5. Proposals import as in OTRF step 4a and
agent-consensus curations as in step 4b.
Exit codes and the output layout are the
OTRF ones; `evaluator/locators.json` maps each event to its original line, line SHA-256, `record_id` (CloudTrail
`eventID` or the auditd serial), `record_type` and asset name.

## Curation schema differences

The curation follows the OTRF schema (strict, `schema_version: 1`, same label derivation, `matched_control`,
`lookalike_event_ids`, optional `assessment_windows`), with these differences:

| Field | Meaning |
| --- | --- |
| `assets`, `steps[].asset`, `controls[].asset` | Keyed by `asset_name` (`audit-host`, a `node=` name, or the account ID). `os_family` must be `linux` (auditd) or `not-applicable` (CloudTrail): `asset_format_mismatch`. |
| `clock_declaration` | Required. `{"offset_seconds", "uncertainty_seconds"}` for an interpreted auditd export, `null` otherwise. |
| `coverage` | auditd: `os` exactly `["linux"]`, `telemetry` exactly `["linux-audit"]`. CloudTrail: `os` exactly `["not-applicable"]`, `telemetry` exactly `["cloud-audit"]`, `execution_platform` includes `cloud-control-plane`, `identity_domain` includes `cloud-iam`. Otherwise `coverage_format_mismatch`. The template pre-fills these. |
| Locators | `{"line": N}`, `{"record_id": "ID"}` (unique in the file) or `{"record_id": "ID", "record_type": "PATH"}`. |
| `family_id` | Derived `attackdata-<sorted technique tokens>`. An override may also use the `otrf-` prefix to join an OTRF bootstrap cluster deliberately. |
| `partition_window` | Optional `{start_inclusive, end_exclusive}`; required exactly when the import uses `--window-start/--window-end`, and must equal them. |

`scenario_id` is `attackdata-<metadata id>-<declared dataset name>`, plus `-p<12 hex>` for a partition.

## Invented sample

`sample/attackdata-sample-linux.yml` (with `-   name:` items) declares `attackdata_sample_auditd.log` (raw shape:
enriched names, PATH and CWD records, a hex-encoded `comm`, an EXECVE whose quoted and hex-encoded argv carries an
`sshpass -p` password, an IP, a `/home` path and an ATT&CK token, a NUL-separated hex PROCTITLE, a `USER_CMD` record
for the metadata-only fallback, a blank line) and `attackdata_sample_auditd_interpreted.log` (an `ausearch -i` EXECVE
argument with a space, a PROCTITLE); `attackdata-sample-cloudtrail.yml` declares
`attackdata_sample_cloudtrail.json` (assumed-role and IAM-user callers, a trail created and stopped, an
AccessDenied `errorMessage` with a raw ARN, `CreateLoginProfile` with a password, `CreateAccessKey` with a secret key,
a bucket policy, and a metadata-only `AwsServiceEvent`). `curation-attackdata-auditd.json` and
`curation-attackdata-cloudtrail.json` are their
invented curations. They exist for `test_benchmark_import_attackdata.py` only; every account, user, address, key
and record is fictitious (documentation address ranges, `.test` names, example account `123456789012`).

# Splunk BOTS importer: Boss of the SOC v1, v2, v3 (development split only)

`benchmark_import_bots.py` turns explicit UTC windows of the public [Splunk Boss of the SOC](https://github.com/splunk/botsv3)
datasets (v1 2016, v2 2017, v3 2018) into partition cases: multi-host Windows, Linux, network-sensor, firewall, AWS
and SaaS telemetry of SOC exercises. It reuses the OTRF compound machinery (partition windows, `plan`, the OTRF
curation schema, `_curated`, `write_outputs`, consensus merge) and the attack_data pseudonyms, auditd parsing and
CloudTrail allowlist; it does not fork them. Every case is `split: development`, `provenance: public_replay`.

**License and contamination.** CC0-1.0 (`official/LICENSE` beside the data); no attribution requirement, the import
report records the notice anyway. Contamination is very high: questions, answers and IOCs are in many public
write-ups and training sets. Never use a BOTS case as a holdout or as evidence of hunting skill on unseen activity.
The importer refuses public output containing `botsv1`/`botsv2`/`botsv3` or `boss of the soc`
(`forbidden_public_metadata`) and never names the SIEM product in importer text, because `splunk` is also a lab host
label.

## Verified data format (inspected 2026-11-08)

| | v1 | v2 / v3 |
| --- | --- | --- |
| Files | `json/botsv1.<sourcetype>.json.gz`, one sourcetype per file | `botsv<N>-export/db_<latest>_<earliest>_<id>.csv.gz` (`splunk cmd exporttool -csv` buckets, mixed sourcetypes) |
| Record | `{"preview","offset","result":{…,"_raw","_time","host","source","sourcetype"}}` per line; optional final `{"preview":false,"lastrow":true}` | CSV `_time` (UTC epoch), `source::…`, `host::…`, `sourcetype::…`, `_raw`, `_meta` |
| `_time` | rendered `YYYY-MM-DD HH:MM:SS.mmm MDT` (UTC−6) | integer epoch seconds |
| Order | every file non-increasing in `_time` (all 31.9 M records checked) | unordered inside a bucket |

Measured over every row of all 16 v3 and 49 v2 buckets: no row precedes the `earliest` of its file name; rows of the
31 v2 daily noise buckets run up to 3599 s past `latest` (other buckets: none). The importer opens a bucket only when
`[earliest, latest + 3600 s]` overlaps the window and refuses a read row outside that range
(`bucket_range_violation`). v1 files are read newest first until the window start (`unsorted_export` if a file is not
ordered) and a v1 file whose sourcetype the profile excludes is not read. Undecodable bytes in `_raw` become `\xNN`
text and NUL characters in parsed values (Stream payloads decode `\u0000`) become the text `\x00`. A v1 search-time
multivalue `host`/`sourcetype` (JSON list) keeps its first value; the rest are counted per file
(`dataset.files_read[].multivalue_host_or_sourcetype_values_dropped`). Typical scan times on this workstation:
v3 ≈ 10 s, v1 ≈ 75 s for 2016-08-24, v2 ≈ 2 min (daily 263 MB buckets).

**Event time** is the Splunk-assigned `_time` (clock offset 0, uncertainty 1 s; `fields.timestamp_original` keeps the
exported value); timestamps inside `_raw` are not re-derived (v2 Windows renders host-local UTC−7, v1 hosts UTC−6/−7).
**Assets** are the Splunk `host` values with at least one imported record in the partition (sensors such as
`splunk-02`, `jupiter`, `FROTHLY-FW1` or `splunk.froth.ly` are assets too: each event sits on the host that logged
it). The draft template's default OS per host is derived from its sourcetypes' declared hints and is unverified.

## Selection: incident, window, collection profile

- `--incident <slug>` names the incident group; family `bots-<version>-<incident>` (one bootstrap cluster per
  incident, no `family_id` override). `scenario_id` adds `-p<12 hex>` of the window and profile.
- `--window-start/--window-end`: UTC with offset, start inclusive, end exclusive. The case window is the partition.
- Collection profile: `--host` (repeatable) and either `--sourcetype` or `--exclude-sourcetype` (repeatable),
  case-insensitive. Records of other hosts or sourcetypes inside the window are excluded and stated as
  `collection_profile_filter` known gaps (per asset with counts by sourcetype; one asset-less gap for other hosts;
  v1 files not read are named). Every asset also gets an `outside_partition_window` gap.
- `dataset_sha256` is the SHA-256 of the selection descriptor (dataset, version, incident, every export file name and
  byte count, profile); `metadata_sha256` is the data folder's `provenance.json`. A curation therefore binds to its
  incident and profile (`curation_dataset_mismatch`), and to its window through `partition_window`
  (`partition_mismatch`).
- **Locators.** Each record's global line is `file_number × 100,000,000 + ordinal` (`file_number` = 1-based position
  in the sorted file list, `ordinal` = CSV row or JSON line). `records.jsonl` is an index `{event_id, line}`;
  `locators.json` adds `record_id` (Windows `RecordNumber`/`EventRecordID`, CloudTrail `eventID`, O365/AAD `Id`,
  Stream/Suricata `flow_id`), `channel` (the sourcetype), `hostname`, `file` and `ordinal`. Curations cite
  `{"line": N}` or `{"record_id": "ID", "channel": "<sourcetype>", "hostname": "<host>"}` (bare `record_id` only
  when unique). A cited line of the export outside the partition fails with `support_record_not_imported`.

```powershell
py -3 benchmark_import_bots.py plan --version v3 --data $bots\v3 --incident aws-key --window-start 2018-08-20T09:16:00+00:00 --window-end 2018-08-20T09:28:00+00:00 --sourcetype aws:cloudtrail --output $work\v3\plans\aws-key.json
py -3 benchmark_import_bots.py case --version v3 --data $bots\v3 --incident aws-key --window-start 2018-08-20T09:21:40+00:00 --window-end 2018-08-20T09:28:00+00:00 --sourcetype aws:cloudtrail --draft --output $work\v3\drafts\aws-key-p02
py -3 benchmark_import_bots.py case --version v3 --data $bots\v3 --incident aws-key --window-start 2018-08-20T09:21:40+00:00 --window-end 2018-08-20T09:28:00+00:00 --sourcetype aws:cloudtrail --curation $work\v3\consensus\aws-key-p02.json --salt-file $draft\evaluator\salt.json --output $work\v3\cases-aws-key-p02
```

`plan` measures the prompt projection of every candidate partition with the real builder (greedy, binary search on
whole seconds) and lists seconds that alone exceed the cap as `unpublishable`; nothing is sampled. Profile exclusion
counts are kept per record time, so a partition built by `case` has exactly the size `plan` measured. Curations use
the OTRF schema (assets by `hostname`; proposal, `agent_consensus` and signed attestations as in OTRF steps 4a/4b) and
must keep the template's `partition_window` and omit `collection_profile` and `family_id`. The scenario's
limitations state the partition, the profile and, for v1/v2, that the background is generated noise (v1: ~1,757
synthetic Windows hosts; v2: 31 daily template buckets attributed to the real host names), not real-user activity.
In Git Bash set `MSYS_NO_PATHCONV=1`.

## Parsers and allowlist (`bots-fields.json`, `bots-fields-1`)

`bots-fields.json` maps each sourcetype to a parser, a source name, a coverage telemetry value (or null), a draft OS
hint and `events: {type key | "*": {field path: transform}}` (`"prefix.*"` covers every leaf under a prefix, `"*"`
every other leaf) plus non-content `metadata_only` fields for a parsed record whose type has no entry.
`events_from` reuses an existing allowlist: `otrf:<channel>` (OTRF EventData allowlists for Security, System,
Sysmon, PowerShell/Operational) or `attackdata:<format>` (CloudTrail record types and auditd); listed events override
it. Transforms are the OTRF and attack_data ones; `sid` additionally maps a classic `DOMAIN\name` rendering through
`account`, keeps Windows constants (`BUILTIN\…`, `NT AUTHORITY\…`, `Mandatory Label\…`) and pseudonymizes Entra ID
`S-1-12-1-…` SIDs whole. Unlisted fields are dropped and counted (`counts.dropped_fields`).

| Parser | Sourcetypes (parsed) |
| --- | --- |
| `winevent-classic` | `WinEventLog:Security`, `:System`, `:Application`, `:Microsoft-Windows-PowerShell/Operational` (4104 script blocks, 4103 via the OTRF parser), AppLocker, Directory-Service. Message labels map to EventData names (`Creator Subject/Security ID` → `SubjectUserSid`, `Process Command Line` → `CommandLine`, `New Account` → `Target*`, `Member` → `Member*`, …); System/Application/AppLocker publish `Message` as content. |
| `winevent-xml` | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` (EventData, `<!` DTD/entities refused → unparsed); `RuleName` stays dropped. |
| `json` | `stream:*` (tcp, udp, ip, icmp, igmp, arp, dhcp, dns, http, smtp, ftp, smb, ldap, mysql, mapi, sip, snmp, irc), `suricata` (type `event_type`), `osquery:results`/`osquery_results`, `aws:cloudtrail` (attack_data allowlist), `aws:description`, `aws:cloudwatch:guardduty`, `o365:management:activity`, `ms:o365:management` (type `Operation`), `ms:o365:reporting:messagetrace`, `ms:aad:signin`, `ms:aad:audit`, `code42:security`, `code42:user`, `csp-violation`, `nessus:scan`. Stream's non-JSON `\xNN` byte escapes are read as text; a record holding several JSON objects (Splunk line merging) publishes the first (`merged_json_objects_dropped`). |
| `kv` | `WinRegistry`, `WinHostMon` (type `Type`), `fgt_traffic`/`fgt_utm`/`fgt_event` (type `subtype`), `Script:ListeningPorts`, `Script:GetEndpointInfo`, `Unix:*`, `Linux:SELinuxConfig`, `mysql:transaction:details`, `mysql:user` |
| `syslog` | `syslog` (Cisco NVM `key="value"` flows or `program[pid]: message`), `linux_secure` |
| `cisco-asa` | `cisco:asa` (type = message ID, message as content) |
| `columns` | `pan:traffic`/`pan:threat`/`pan:system` (PAN-OS CSV after the syslog header), `access_combined`, `iis` (W3C default fields), `WebLogic_Access_Combined`, `aws:cloudwatchlogs:vpcflow`, `aws:elb:accesslogs`, `aws:s3:accesslogs`, `aws:rds:audit` |
| `auditd` | `linux_audit`, `auditd` (attack_data parsing, argv reassembly and allowlist; raw and `ausearch -i` shapes) |
| `text` | the whole line as sanitized `message` content: `symantec:ep:*`, `ps`, `top`, `lsof`, `netstat`, `who`, `lastlog`, `openPorts`, `package`, `bash_history`, `osquery:info`/`:warning`, apt/dpkg/cloud-init/dmesg/cron/maillog/yum, SSM agent, Tomcat/Apache/WebLogic/MySQL error logs, `aws:cloudwatchlogs`, `aws:rds:error`, `Script:InstalledApps` |
| `metadata` (declared metadata-only) | `Perfmon:*`, `PerfmonMk:Process`, `MSAD:NT6:*`, `collectd`, `mysql:*` statistics, `df`, `vmstat`, `iostat`, `cpu`, `bandwidth`, `interfaces`, `protocol`, `hardware`, `time`, `web_ping`, `aws:cloudwatch`, `aws:config:rule`, `code42:api`/`org`/`computer`, `ess_content_importer`, `WindowsUpdateLog`, `Powershell:ScriptExecutionSummary` |

Any other sourcetype is a **metadata-only** event (`st-<slug>` source, telemetry null; counted in
`counts.unknown_sourcetypes`); a record its parser refuses is metadata-only too and stated as an `unparsed_records`
known gap (`counts.unparsed_by_sourcetype`). Deliberately dropped: MAC addresses, HTTP response bodies
(`dest_content`), cookies, Stream binary payloads, `aws:description` Lambda environment variables (they hold a
collector token), osquery `decorations.host_uuid`, and Sysmon `RuleName`. Text records above 16384 bytes (`ps`,
`lsof`) are cut with the explicit marker and a `content_truncated` gap. Event types are `<source>:<type key>`; type
keys are printable, at most 64 characters, with ATT&CK-looking tokens masked.

**Decoding before sanitizing.** osquery `process_events` writes argv like the kernel's EXECVE record: quoted words,
and upper-case hex for words holding spaces (`"bash" "-c" 2F62696E2F7368…`). For the `hex_argv` paths
(`columns.cmdline` of both osquery sourcetypes) such a quoted command line is rewritten as shell words with the
attack_data argv rules, hex words decoded, so redaction and pseudonymization see ordinary command text
(`"useradd" "-p" "<pass>"` → `useradd -p [REDACTED:password]`; counted as `argv_rewritten` and `hex_argv_decoded` in
`counts.dropped_fields`). Well-known Linux/macOS service accounts (`root`, `ec2-user`, `mysql`,
`apache`, `postfix`, `games`, `streamfwd`, …; `SYSTEM_ACCOUNTS`) stay literal like Windows built-in principals, and
only multi-label host suffixes are DNS domains (`kutekitten.local` does not make `local` an identity). The lab's
domains come from the case's hosts, every host the scan saw in the window (including profile-excluded ones) and
Windows `Computer` names, so `froth.ly` is pseudonymized in DNS queries even when `splunk.froth.ly` is outside the
host profile. Names glued into other text stay as written: a pipe suffix `…\<user>48_` or a OneDrive personal-site
path `<user>_<domain>_<tld>` are not whole tokens of a known identity.

**Content and pseudonyms.** Content values pass `benchmark_sanitize.sanitize_text` (above), re-run until no new
pseudonym appears; lists are sanitized element-wise; objects (CloudTrail parameters, O365 `Parameters`) go through
attack_data `_aws_scrub` (secret-named keys dropped, identity keys pseudonymized) first, and ARNs/account IDs get the
AWS pseudonyms in sourcetypes flagged `aws`. Kept, path and SID values are rewritten with every identity the import
pseudonymized; ATT&CK tokens in kept values are masked (`sanitizer.attack_masked_kept_values`). AWS service principals
(`<service>.amazonaws.com`) stay literal. The leak check refuses a bundle whose event or asset values still contain
any pseudonymized original of four characters or more (alphanumeric boundaries; field names, the source half of
event types such as `stream-http`, the fixed question and gap texts are importer vocabulary and are not scanned; user
names `http`, `https`, `www`, `admin` and `administrator` stay literal with the service accounts; form/query user
keys such as `quick_username=`, `login=` or percent-encoded `%26username%3D<name>` get their value replaced in place by
its user (or `user@dns`) pseudonym, so every copy is pseudonymized alike) or any BOTS name anywhere. Other
percent-encoded identities (an encoded `email%3D<name>%40<domain>`) are not decoded. An original glued to other
characters (for example an attempted user `null<name>` in a CloudTrail message) is not a token and stays as written.

## Secrets found in the data (inspected 2026-11-08)

v3 holds `net1 user /add <name> <password>` in Sysmon and Security command lines (redacted, including the quoted
`"…\net.exe"` form), the leaked IAM access key ID in CloudTrail `userIdentity.accessKeyId` (pseudonymized `key-…`)
and in mail text (redacted `aws_access_key`); its secret key does not occur in the export. CloudTrail
`responseElements.credentials.sessionToken` and `requestParameters.password` are dropped. v1/v2 brute-force
passwords in HTTP `form_data` (`passwd=`) are redacted. Not detected: a password written as prose (the v2 phishing
mail gives its attachment password in the body); review mail `content_body` evidence before any wider use.

## Invented sample

`sample/bots-v3-sample.csv` (exporttool CSV: classic Security 4688/4720/4732/4689 with a `net user /add` password,
Sysmon XML with an `-enc` payload, an AWS key and a `technique_id` RuleName, Stream HTTP with `passwd=` and a cookie,
Stream DNS, CloudTrail `CreateLoginProfile` with a password, two merged osquery objects, `linux_secure`, Cisco ASA,
auditd EXECVE+SYSCALL with a detector `key`, O365 `Set-Mailbox` forwarding, PowerShell 4104, WinRegistry, an unknown
sourcetype, an unparsable Stream record, a second host and a record outside the window), `sample/bots-v1-sample.jsonl`
(search-export lines newest first with a `rar -hp` password and the `lastrow` marker), `sample/bots-provenance.json`
and `sample/curation-bots.json` exist for `test_benchmark_import_bots.py` only; the tests gzip them into bucket and
file names at run time. Every host, user, address, key and record is fictitious (`.example.test`, documentation
addresses, account `123456789012`).

# Agent consensus answer keys (both importers)

`benchmark_consensus.py` replaces human answer-key review with an automatic, honestly labelled mechanism:
**two independently written agent drafts plus deterministic agreement**. The result has truth attestation
`agent_consensus`. That means exactly one thing: two AI drafts agreed mechanically. It is stronger than a single
unreviewed proposal (`unreviewed_proposal`) and weaker than a human attestation (`human_attested`). It is always
its own cohort: every score from it carries `truth_attestation: "agent_consensus"` and is never compared or ranked
with scores from the other two. Like `unreviewed_proposal`, it is allowed for development and holdout cases. Two
drafts can share a mistake (same model family, same prompt, the same public write-up of the dataset), so agreement
is not correctness. No human reviews a consensus key, and nothing records one as reviewing it.

```powershell
py -3 benchmark_consensus.py merge --draft-a $p/curation.A.PROPOSED.json --draft-b $p/curation.B.PROPOSED.json --locators $work/draft-<ID>/<case_id>/evaluator/locators.json --template $work/draft-<ID>/<case_id>/evaluator/curation-template.json --output $work/curation-<ID>.consensus.json --report $work/consensus-<ID>.json
```

Then import `$work/curation-<ID>.consensus.json` with `--curation` and the draft's salt (OTRF step 4b).

## Inputs

- **Two proposals for the same dataset.** Each must be a `curation.PROPOSED.json` (status
  `PROPOSED_UNREVIEWED_NOT_FOR_SCORING`, null curator). Both use the same format: OTRF, or attack_data (detected
  by its required `clock_declaration`). Each is loaded through its own importer's loader. Both must carry the same
  `dataset_sha256` and `metadata_sha256` (`draft_dataset_mismatch`).
- **The draft import's side files** for that dataset (`locators_dataset_mismatch`, `template_dataset_mismatch`):
  - `--locators`: `evaluator/locators.json`. Every locator in both drafts is resolved through it to its original
    line, whichever form the draft used: `{"line": N}`, `{"record_id", "channel", "hostname"}` (channel and
    hostname case-insensitive), `{"record_id", "record_type"}` or a bare `{"record_id"}`. A locator that names no
    imported record fails with `unresolved_locator`; a bare record ID that occurs more than once fails with
    `ambiguous_locator`. Merged locators are written as `{"line": N}`.
  - `--template`: `evaluator/curation-template.json`. It supplies each asset's default `os_family` and the draft's
    default `assessment_windows` and `clock_declaration`.
- **Independence.** Write the drafts in separate sessions from the same curation template, without either seeing
  the other, ideally with different models. The tool cannot verify independence. It only refuses byte-identical
  drafts (`identical_drafts`). Independence is the operator's claim; the note and report record both draft
  SHA-256s.

## Agreement rules

| Item | Kept when / merged value |
| --- | --- |
| Step | Both drafts propose the same technique on the same asset (case-insensitive) with overlapping windows. Technique IDs are compared and written in canonical form for the pinned ATT&CK release (`benchmark_attack.canonical_technique`; revoked IDs follow their replacement). An ID unknown to that release fails with `unknown_technique`. Steps are paired one-to-one by maximum matching with sorted IDs, and get new IDs `step-N`. A paired step survives whatever support each draft cites. |
| Support sets | The minimal sets among `a ∪ b` for every support set `a` of draft A and `b` of draft B. A set is complete for a draft when it contains one of that draft's sets, so each union is complete for both drafts. Supersets of another union are dropped; at most 16 remain, smallest first, then by line. Example: `[95,239,380]` and `[239]` give `[[95,239,380]]`; `{[1],[68]}` and `{[1]}` give `[[1]]`. If either draft cites nothing (a non-sufficient step), the merged step has no support set. Jaccard values are reported as agreement measures only; they never drop a step. |
| Window | The hull of the two step windows, which must overlap. |
| Observability | The more conservative value: sufficient > insufficient > absent > unknown, the lower one wins. |
| Execution outcome | The shared value when both are equal, otherwise `unknown`. |
| Edges | Both drafts have the edge between the paired steps. |
| Controls | Same asset, same window and same expected disposition. |
| Lookalike groups | Identical groups (as resolved lines) in both drafts. |
| Coverage | Per axis: the shared tags. An axis with no shared tag gets the union of both drafts' tags and is reported as disputed. Differing tags never refuse a merge. |
| Assets | Same asset set (`assets_mismatch`). `os_family` (required): the shared value; if the drafts differ, the value that differs from the template default (a deliberate correction beats an untouched default); if neither is the default, draft A's. `os_version`, `architecture`, `vendor`: the shared value, otherwise null (unknown). Every disagreement is reported as disputed. |
| `attack_release` | The shared value; if the drafts differ, the newer version (compared numerically), reported as disputed. If a merged step's ID was renamed by canonicalisation, the merged release is at least the pinned release (`v20`). |
| Sophistication | A phase is kept when equal, otherwise `initial`. Two steps share a boundary when either draft puts them in one. When the drafts give a boundary different kinds within one rubric class ({identity, privilege}, {segment, domain}, {on-prem, cloud}, {it, ot}), the band-qualifying kind survives as draft A's value; kinds from different classes become `host`. Both cases are reported as disputed (`sophistication.conflicts`). The band is the drafts' band if they agree and the surviving steps satisfy the `hunt-rubric-1` rules. Otherwise it is the highest band the surviving steps satisfy, never S5: S5 survives only when both drafts claim it, and the importer re-checks its sparse/ambiguous-trace condition against measured difficulty. No valid band: `sophistication_unsupported`. Preconditions and group IDs: intersection. Emulation limitations and source references: union. |
| `matched_control` | Required exactly when no merged step is `sufficient`, dropped otherwise. When required: the shared value; if the drafts differ, draft A's if present, else draft B's, reported as disputed. If neither draft has one, the merge fails with `matched_control_unavailable`: measuring it needs the evidence bundle, which the merge never reads. |
| `assessment_windows`, `clock_declaration` | The shared value (windows compared as instants); if the drafts differ, the template's default, reported as disputed. A template without `assessment_windows` leaves them unset, which the importer reads as one whole-bundle window. |
| `partition_window` | Must be equal (`draft_conflict`): two different partitions are two different cases. With the dataset and metadata digests, it is the only field whose plain disagreement refuses a merge. A different asset set, a missing `matched_control` or no valid band still refuse (see their rows). |
| `family_id` | Kept only when both drafts carry the same override. |
| `revision`, `truth_revision` | The higher value. |

## Disputed evidence

A step that only one draft proposes is dropped. The report lists it under `disputed_steps` with a reason:
`no_counterpart`, or `counterpart_matched_elsewhere` when its candidate partner was paired with another step. A
dropped step's records are not truth, so a finding on them would otherwise score as a false positive. Instead, every
record that either draft cited as support, and that no merged support set contains, goes into the curation's
`excluded_locators`. That includes a dropped step's records and records only one draft used in a kept step. The
importer resolves them into truth `disputed_event_ids` and an `evaluator/import-report.json`
`curation.disputed_evidence` note. Scoring ignores a finding whose citations all fall within them (neither TP nor
FP) and counts it as `detection.disputed_ignored`; an edge with an ignored endpoint counts as
`chain_edges.disputed_ignored`. A question that no agreed step or control covers is labelled `null` (not
decidable), because the drafts disagreed there. The import report counts these as `curation.disputed_questions`,
and difficulty does not count them as evidence gaps.

## Output and report

The output is a NEW curation file. Existing paths and paths inside the source tree are refused. In it:

- `status` is removed;
- `curated_by` is `"agent-consensus"` and `curated_utc` is the merge time;
- `note` names both draft digests, the agreement counts and the disputed descriptive fields;
- `attestation_hint` is `"agent_consensus"`;
- `excluded_locators` holds the disputed evidence.

The command validates the file through its importer's loader before it succeeds, and removes it if that check
fails. The importer maps the hint to truth `attestation: "agent_consensus"` and adds an `emulation_limitations` line
to the scenario. It refuses `curated_by: "agent-consensus"` without the hint (`consensus_hint_missing`), a changed
curator (`consensus_curator_mismatch`) and `excluded_locators` without the hint (`excluded_without_consensus`), so
editing the file can never produce a human attestation.

`--report` writes a NEW JSON file with:

- the digests of both drafts, the locator map, the template and the curation;
- per-step agreement: paired step IDs, the technique ID each draft wrote, support basis (`minimal_unions`,
  `one_empty`, `both_empty`), sets dropped by the cap, support-set and locator Jaccard, and each draft's and the
  merged observability and outcome;
- every candidate pair and every disputed step;
- Cohen's kappa over the step/no-step decision. The items are every technique either draft proposed, crossed with
  every curated asset. Kappa is null with `chance_agreement_is_one` (for example one asset, and both drafts say yes
  to everything) or `no_candidate_items`;
- the mean support-set and locator Jaccard over the paired steps;
- the sophistication decision and boundary/phase conflicts;
- `disputed_fields` (`attack_release`, `coverage`, `asset_facts`, `matched_control`, `assessment_windows`,
  `clock_declaration`), the field decisions and the limitations.

Exit codes: `0` success; `2` refusal (`error: <code>: <field>`). Other refusals: `draft_not_proposal` (a signed
curation or an earlier consensus), `format_mismatch`, `output_exists`, `output_in_source_tree`,
`invalid_directory`, `conflicting_arguments`. `test_benchmark_consensus.py` exercises the merge on invented
curations derived from the samples above.

# Label-derived real-IOC and Wave 2 SQLite query-track APT importers

Four additional importers share `benchmark_case_writer.py`, `benchmark_sanitize.py`, `benchmark_ioc.py` (`ioc-feed-1`
in `public/intel.jsonl`) and `benchmark_query.py` (`events.sqlite3` FTS5 query store) to produce mechanical
`attestation: "publisher_labels"` cases without AI-drafted curations:

| Importer | Source dataset & license | Track & sophistication | Key sanitization & truth rules |
| --- | --- | --- | --- |
| `benchmark_import_goldensaml.py` | OTRF SimuLand `GoldenSAMLADFSMailAccess` (MIT) | Inline bundle; **S5** hybrid AD FS -> DC -> Entra ID -> Exchange Online | Joins Windows AD FS / DC Sysmon + Security logs (`WindowsEvents`) with Microsoft 365 Defender (`Microsoft365DefenderEvents`), Entra ID audit logs (`AADAuditEvents`) and Exchange Online (`OfficeActivityEvents`); maps steps from the published SimuLand sequence. |
| `benchmark_import_invictus.py` | Invictus AWS CloudTrail dataset | Inline bundle; **S0** benign controls and **S3/S4** multi-step AWS IAM/SecretsManager/CloudTrail evasion chains | Reads S3 `{"Records": [...]}` `.json` / `.json.gz` files, extracts Stratus Red Team invocation UUIDs from `userAgent` into mechanical `publisher_labels` ground truth, recursively redacts secret-bearing CloudTrail parameter/credential keys (`[REDACTED:secret]`), and strips all `stratus-red-team*` tokens from public `userAgent` before sealing. |
| `benchmark_import_camlds.py` | AIT / Austrian Institute of Technology CAM-LDS v1 (CC BY 4.0) | Inline bundle; **S0** Linux controls and **S2–S4** Linux multi-source SSH/VNC lateral-movement and persistence chains | Reads centralized Wazuh alerts (`wazuh/logs/alerts/alerts.json`) and host logs (`auth.log`, `cron.log`, `dpkg.log`, `apache2/access.log`, `audit/audit.log`, `suricata/eve.json`) and derives steps mechanically from `attacker/attackmate.json`; strictly refuses to copy `configs/` (private SSH/TLS keys) or `attacker/` logs into `public/`. |
| `benchmark_import_query_apt.py` | OTRF `APT29 Day 2` (MIT), `DEDALE` (CC BY 4.0, excluding DRL-1.1 rules), `FullAPT-2025` (CC BY 4.0) | Wave 2 SQLite `query_store` (`public/events.sqlite3`); **S4** whole-campaign multi-host / multi-OS APT chains (`24,000`–`28,000+` indexed events per case under `<20 KiB` prompt bytes) | Streams zip/bz2/CSV archives safely without loading multi-GB members into memory, strips publisher label columns (`Label`, `Technique`, `Tactic`, `Seed_Event` in `FullAPT-2025`; `malicious_events_class_1.jsonl` join in `DEDALE`) from public rows, indexes sanitized rows in FTS5 (`events`, `events_fts`, `iocs`, `meta`), and verifies citations against `events.sqlite3`. |

## Real threat-intelligence IOC feed (`benchmark_ioc.py`, `ioc-feed-1`)

Every case written through `benchmark_case_writer.py` seals `public/intel.jsonl` (`schema_version: 1` per line, specification `ioc-feed-1`):

1. Extracts technical indicators observed in sanitized events (SHA-256/MD5/IMPHASH hashes, named pipes, JA3 digests, User-Agents, SSH client banners, URL paths (`url_path`), process/script names, and pseudonymized C2/IPv4/domain indicators), emitting case-derived indicators with `source_feed: "scenario-ti-feed"`.
2. Merges real public CTI software/group tool indicators derived from the pinned MITRE ATT&CK v20 STIX bundle plus public MalwareBazaar/ThreatFox/Feodo-class tool and infrastructure artifacts, scrubbing all `Txxxx` technique strings so `intel.jsonl` never leaks ATT&CK answers.
3. Enforces two explicit evaluation regimes recorded in evaluator-only `scenario.json` (`ioc_regime`, cohort control, forbidden in public bundles) and `evaluator/import-report.json` (`ioc_feed.ioc_regime`):
   - `known_ioc_pivot`: requires at least one active entry-pivot indicator matching a truth event (`missing_known_ioc_pivot` if none can be extracted on a non-control case) alongside `known_false_positive` and `historical_rotated` benign decoy indicators.
   - `novel_apt_zero_ioc`: withholds all truth-step infrastructure/hash indicators (`active_truth_matches == 0`) while keeping benign decoy IOCs active in `intel.jsonl`, forcing teams to hunt via Pyramid-of-Pain behavioral chains rather than indicator memorization.

Unit tests (`test_benchmark_ioc.py`, `test_benchmark_query.py`, `test_benchmark_import_goldensaml.py`,
`test_benchmark_import_invictus.py`, `test_benchmark_import_camlds.py`, `test_benchmark_import_query_apt.py`, and
`test_benchmark_openai_http.py`) exercise all four importers, the IOC regimes, the SQLite query tools, and the
stdlib OpenAI/loopback subscription adapter on synthetic in-memory fixtures with zero external data dependencies.
