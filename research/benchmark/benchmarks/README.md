# Framework-managed threat-hunt benchmark

This benchmark compares **complete six-identity AI teams** doing threat hunting, not single prompts. It is separate from native Hermes delegation. Runs are fully automatic: every validated stage output, including the final handoff, advances unreviewed via the ledger's distinct `auto_advance` transition (actor `benchmark-auto-advance`) and the store event `stage_auto_advanced`; it is never recorded as a human approval. It is not a sandbox, authentication system, distributed lock, or evidence declassification mechanism.

## Offline validation

From `research/benchmark/`, with Python 3.9+ and no optional packages. The benchmark imports `bot`, `workflows` and `langchain_adapter` from `../../framework/` through `benchmark_paths.py`:

```powershell
py -3 -B benchmark.py validate --experiment benchmarks/examples/experiment.json --bundle-root benchmarks
py -3 -B benchmark.py validate --experiment benchmarks/examples/experiment-graduated.json --bundle-root benchmarks
py -3 -B ../../framework/bot.py workflow show benchmarks/team-workflow.json
py -3 -B ../../framework/bot.py workflow show benchmarks/team-workflow-novel-apt.json
```

Pass `--workflow benchmarks/team-workflow-novel-apt.json` to `corpus-experiment`, `validate`, `init` or `baselines` to select the Novel-APT Behavioral Hunting Playbook (Pyramid-of-Pain behavioral decomposition, mandatory `lookup_ioc` cross-checking, sub-technique specificity, and full asset/window calibration) instead of the default `benchmarks/team-workflow.json`. The frozen `workflow_sha256` binds every trial to its exact workflow template.

Use `python3` instead of `py -3` on macOS/Linux. `--bundle-root` explicitly declares the portable bundle containing the manifest and all its relative references; absent it, the manifest's parent is the bundle root. No `..`, aliases, hardlinks, symlinks, reparse paths or absolute manifest references are accepted. Validation creates no state and makes no network requests.

The example has five repetitions, seed 1729, one local team and a deliberately non-serving loopback discard port. It is not a configured model route. Select a versioned model and endpoint deliberately; nothing starts a server, downloads weights, obtains credentials or chooses a paid model. A configuration change creates a different comparison cohort. Model credentials are named by environment variable only and must match `BENCH_MODEL_*`; lab, AWS, Stratus and Terraform variables are refused so a manifest cannot route a lab secret to a model endpoint.

## Graduated invented corpus

`experiment-graduated.json` selects nine development cases, five repetitions each, seed 1729, and the same non-serving local model configuration. Its 1 MiB prompt cap accommodates the complete high-noise evidence; no records are sampled away. The original example remains a small single-case selection.

| Case | Exercise/control | D/S | Relevant / benign records | Required contexts | Correlation seconds |
| --- | --- | --- | ---: | ---: | ---: |
| `case-8b42` | Windows atomic discovery | D1/S1 | 2 / 8 | 1 | 130 |
| `case-5c21` | Linux linked host activity | D2/S2 | 2 / 14 | 1 | 600 |
| `case-7d33` | AD cross-host identity/privilege crossing | D3/S3 | 7 / 27 | 3 | 1,199 |
| `case-9e44` | Cross-domain persistence/re-entry | D4/S4 | 5 / 147 | 2 | 5,400 |
| `case-af55` | On-prem/cloud correlation with gaps | D5/S5 | 5 / 650 | 4 | 7,800 |
| `case-b060` | Benign-only control | D1/S0 | 0 / 10 | Inherited | Inherited |
| `case-c070` | Insufficient-evidence control | D5/S0 | 0 / 648 | Inherited | Inherited |
| `case-d080` | Blocked discovery attempt | D1/S1 | 1 / 6 | 1 | 0 |
| `case-e090` | Inert instruction inside a log | D4/S0 | 0 / 147 | Inherited | Inherited |

All fixtures are produced by `benchmarks/tools/generate_fixtures.py` from the authored cases in `benchmarks/tools/fixture_cases.py`. Each case has a committed salt; every public ID and in-field reference is an HMAC token (`kind-<12 hex>`), assets/sources/questions are ordered by opaque ID, and events by `(timestamp_utc, event_id)`. Rerunning the generator is byte-identical and refreshes the example digests. A leakage test rejects ID patterns, orderings or judgement words that separate support records from others. `source_receipt_sha256` is the SHA-256 of the canonical JSON array of a step's support rows sorted by `event_id`. Assets are attributed to the host where the acting process or session executed (stated in `prompt-contract.txt`).

Required contexts are source/asset joins needed by a complete support set, not merely installed sensors. `benchmark_difficulty.measure_case` recomputes every factor from records, per-support-set joins and time spans, curator-declared lookalike groups (`lookalike_event_ids` in truth) and undecidable questions; the fixture tests use it rather than private helpers. Zero-positive controls inherit matched-family difficulty; blocked attempts remain observable positives without implying successful compromise. The high-gap case has an unobservable step that does not enter positive recall, and `case-9e44` has a partial source whose re-entry step keeps two complete alternative support sets.

There are five authored attack families. Benign-only, insufficient, blocked-attempt and log-instruction controls share their matched family IDs; repetitions and controls do not add independent families. All data and evaluator keys are invented public development material, not secret holdouts. The instruction control verifies data/authority separation, not a real model's injection resistance.

Catalog `hunt-coverage-2` adds five explicitly `synthetic_verified` combinations after fixture/CLI validation. The original live targets remain planned/blocked. A snapshot earns coverage only for selected, hash-checked public evidence with matching provenance and categories. Unselected catalog evidence stays visible with `evidence_not_in_snapshot` and zero credit; arbitrary artifacts, scenario OS tags alone, and synthetic evidence labeled live cannot earn credit. Frozen catalog hashes prevent silently changing an old denominator.


## Running a team

Supply an unused absolute state path, an experiment bundle and the directory of answer keys (`<case_id>/evaluator/truth.json`):

```powershell
py -3 benchmark.py --state-root $state init --experiment $manifest --bundle-root $bundle --truth $truthDirectory
py -3 benchmark.py --state-root $state status --experiment $experiment
py -3 benchmark.py --state-root $state advance --experiment $experiment
```

`init` validates every case's answer key and freezes it automatically (`benchmark-auto-freeze`, `freeze_policy: automatic_at_init`) before any trial exists; a missing or invalid key creates no state. The truth's own `attestation` field says whether a human attested it (`human_attested`), it is one agent-drafted proposal (`unreviewed_proposal`), it is a mechanical consensus of two independent agent drafts (`agent_consensus`), or it was derived mechanically from dataset-publisher step/event labels (`publisher_labels`). The last command above is a **dry run**. To execute:

```powershell
py -3 benchmark.py --state-root $state advance --experiment $experiment --allow-model-execution
py -3 benchmark.py --state-root $state score --experiment $experiment --truth $truthDirectory
py -3 benchmark.py --state-root $state diagnose --experiment $experiment --truth $truthDirectory --output $newReport.json
py -3 benchmark.py --state-root $state export --experiment $experiment --output $newExportDirectory
```

Live LangChain execution requires the existing optional Python 3.10+ runtime and selected provider package; use that runtime for the whole command. Alternatively, `adapter: "openai_http"` (`benchmark_openai_http.py`) uses Python standard-library HTTP only (`urllib.request`) over an OpenAI-compatible `/v1/chat/completions` endpoint, including `benchmark_subscription_proxy.py` (loopback `http://127.0.0.1:<port>/v1`, routing to local OAuth subscription CLIs `claude` and `codex` with direct provider API keys stripped). `--allow-model-execution` runs every trial until it is finished, terminated for budget, or blocked. Up to `budgets.max_concurrent_calls` calls (default 4, max 16) run at once, across trials and independent branches; dependent stages stay ordered and each role keeps a separate context. Reports flag `timing_contended: true` above 1. A failed or unknown dispatch blocks only its own trial and makes the command exit 1. Without a truth freeze, execution is refused (`truth_not_frozen`). A manual `bot.py approve`/`reject` on a benchmark ledger is `unsupported_ledger_transition`.

**Route preflight.** Before any dispatch, `advance --allow-model-execution` checks every team route: the model adapter's SDK/Python prerequisite (as the model child sees it) and that each `credential_env` variable is present; the value is never read or logged. `status` and dry runs check only credential presence and launch no subprocess. A team that fails makes no call; its unfinished trials end `unrecoverable_stage` with the reason (`prerequisite_missing` or `credential_unavailable`) in `terminal_note`, and `advance` exits 1.

**Uncertain model calls recover automatically.** A narrative or checker call has no effect beyond local compute and cost. When one ends `unknown` (its own timeout, `dispatch_interrupted`, or a child crash after reservation), `advance --allow-model-execution` resolves it without a human, but only when the trial ledger proves the owning child ended (bot.py's own `run-failed` for the run that made the reservation). It records `reconciliation_recorded` by `benchmark-auto-reconcile` with `policy: automatic_model_call` and outcome `failed`; the receipt keeps the original failure reason, the discarded observation is `observed_elapsed_ms`, and the worst-case reserved time and cost stay charged. The task resumes through the distinct `bot.py auto-resume` (ledger event `auto_resume`; actors must start with `benchmark-auto`) and the stage retries as the next attempt within `max_attempts_per_stage` and the other budgets, or the trial is terminated `budget_exhausted`. A late response for a resolved call is never accepted. An unproven process stop is `process_stop_unconfirmed` and blocks. Campaign (lab) steps are never reconciled automatically.

**Known model failures retry automatically.** A call that ended `failed` for a model-attributable or transient reason (`invalid_response`, `empty_response`, `tool_response`, `output_limit`, `model_identity_mismatch`, `transport_failed`, `upstream_http_error`, `dispatch_interrupted`, `timeout`) is retried as the next attempt within budget after the same proven-process-end check, recorded as `trial_status_changed` by `benchmark-auto-retry` with `policy: automatic_retry`. Failed receipts and their charges are kept, and format-error rates count every attempt. Configuration failures (`credential_unavailable`, `authentication_failed`, `configuration_invalid`, `unsupported_parameter`, `prerequisite_missing`, `budget_exceeded`) are never retried; their trial ends `unrecoverable_stage` and the others continue. Any other reason still needs an operator `reconcile --experiment ID --call ID --by NAME --note TEXT --outcome failed|completed --evidence FILE` (strict evidence object; `--by` may not start with `benchmark-auto`; recorded as `policy: human_operator`) and `advance --allow-model-execution --retry-call $call`. Exports count automatic and operator reconciliations and retries separately.

**Reasoning models.** A leading inline `<think>…</think>` block (as emitted by local DeepSeek-R1-style models over an OpenAI-compatible endpoint) is discarded before validation and never stored or scored; an unclosed block is `output_limit`.

**Structured output.** Set a narrative role's `parameters.structured_output: true` to request schema-constrained decoding on OpenAI-compatible routes (Anthropic and the Jev checker refuse it with `unsupported_parameter`). Each call sends `response_format: {type: json_schema, json_schema: {name: stage_output, strict: true, schema}}` via LangChain `extra_body` (the `model_kwargs` path raises on `finish_reason: length` and loses the response). The schema from `benchmark_contracts.stage_output_schema(stage, evidence)` closes every object, requires every field and enumerates the case's real event, asset and question IDs up to 200 each; `validate_stage_output` still decides every response. Because the schema prevents some errors (for example citing nonexistent records), the setting is part of the model spec and fingerprint and is reported as the treatment attribute `structured_output_roles`; compare a team with and without it rather than pooling them. Whether a server enforces the schema is that server's behaviour.

**Rejected-output diagnostics.** A narrative call that fails `invalid_response` or `output_limit` after an answer arrived keeps an evaluator-only `rejected_response` record (`error_code`, `error_field`, `byte_count`, `truncated`, and an artifact holding the first `max_response_bytes` bytes with any reasoning block removed). Rejected answers never reach a prompt, checker or score. `status` shows `format_error`, `report.json` adds `format_failures`, and `diagnose` adds `aggregate.format_failures_by_reason`. In the first fully automatic local run (DeepSeek-R1-0528-Qwen3-8B Q4_K_S, three agent-consensus cases, no structured output) every scope attempt failed `invalid_response` and all three trials ended `budget_exhausted`: the benchmark then measured format compliance, not hunting.

**Timeouts and stable source.** `status` and `advance` list each stage's calls with `elapsed_ms`, `timeout_seconds`, `timeout_margin_ms` and the budget charge; `report.json` adds `timeouts`, `reconciliations` and `automatic_retries`. Choose each role's `timeout_seconds` from these margins: a slow local 8B reasoning model needed 446 s for a 10.6k-token scope stage and exceeded 600 s on the next. For long runs, `py -3 benchmark.py snapshot-source --output NEW_DIR` copies the fingerprinted sources, every module they import (the benchmark's own and `bot.py`, `workflows.py` and `langchain_adapter.py` from `framework/`) and the declared data files (`benchmarks/` data, and `hermes-bots/catalog.json` and `roles/*.txt` from `framework/`) into one folder, `NEW_DIR/framework/`, with `SOURCE-MANIFEST.json`; run `py -3 NEW_DIR/framework/benchmark.py --state-root $state …` so concurrent edits never change the adapter fingerprint mid-run. State roots must lie outside `NEW_DIR`; a test performs a real dispatch from a snapshot to keep the declared file list complete.

Exit codes: validation/preflight failure `2`; execution failure/unknown `1`; successful commands, including honest blocker status and dry runs, `0`. `campaign run` exits 1 on blocked/failed/unknown and `campaign cleanup` exits 1 when cleanup is failed/unknown.

A trial that can never finish does not stall the experiment. When a stage's attempts, calls, active time, API cost or prompt bytes are exhausted, `advance --allow-model-execution` records `budget_exhausted` for that trial (never while a dispatch outcome is unknown) and moves on. An operator may abandon a trial with `terminate --experiment ID --trial ID --by NAME --note TEXT`. Terminated trials are scored as completion failures with every eligible positive missed. Overall status becomes `finished` when every trial is completed or terminated.

## Data boundaries

- `coverage.json` is a frozen target catalog, not a list of working live adapters. Rows have owners, prerequisites and explicit status/evidence. Evidence references are authored bundle-relative public paths, resolved through immutable trial artifacts and canonical frozen manifests, never through current source files. Marginal category coverage and registered-combination coverage have separate denominators; exports include verified digests and unresolved-reference/provenance/category blockers. A cloud-control-plane asset with OS `not-applicable` is not Windows or Linux evidence.
- `fixtures/` contains invented, public development data. Public records and evaluator truth are separate. They prove software behavior, not model quality, live coverage or secrecy of a holdout. No existing example has been relabeled as hidden truth.
- The public bundle carries pseudonymous assets, sources and clock facts, original and normalized timestamps, immutable file digests, stable event locators and a complete predeclared asset/window question set. Missing records are never silently sampled or invented.
- Scenario difficulty, sophistication, technique/group truth, campaign recipes, attack outcomes and answer keys are evaluator-only. Hunter prompts contain the public bundle and the automatically advanced direct-predecessor outputs, not evaluator metadata, absolute paths, runtime/team labels or scoring results.
- State requires an explicitly supplied absolute directory outside source trees, Git worktrees, profiles and private downloads. System temporary directories are allowed for disposable synthetic checks. Existing experiment IDs and ledgers are never reused.
- JSON is strict: integer schema version 1, duplicate and unknown keys rejected, finite numeric values, offset-bearing UTC timestamps and SHA-256 digests. Workflow/catalog/evidence JSON digests use sorted-key compact UTF-8 canonical JSON; prompt contracts and file artifacts use exact bytes. Hashes detect changes, not authenticity or secret content.

## Campaign evidence and explicit release

The separate [range-kit guide](../../../hunt-range/benchmark/README.md) documents enrollment, per-phase authority, independent collectors and cleanup. Its executor scripts were never part of the portable framework, and the benchmark itself no longer is either. Campaign collection never grants model permission. A release is needed only when private (non-`synthetic`/`public_replay`) evidence would reach a non-loopback route; a literal-loopback route keeps the bytes on this machine.

Cleanup runs a fixed read-only leftover check (Windows `session_check`, Linux `close_sessions`). Any remaining process or session of the guest or dedicated account fails cleanup and quarantines those targets. Until that cleanup succeeds, `preflight` and `run` refuse with `target_quarantined` for any campaign in the same state directory that shares an enrolled VM, machine or AWS account ID. AWS campaigns also require a known worst-case `cloud_cost_bound` from the pinned range kit that is no greater than `limits.max_cloud_cost_usd`. It is checked at preflight and at every dispatch, and recorded with each authorization and step receipt. It is a local pre-check, not billing enforcement. The shipped kit's bound is unknown, so AWS preflight is blocked until a reviewed kit revision cites every rate and a ceiling for every quantity.

After complete independent collection and verified cleanup, materialize a new public directory beneath `$state/campaigns/$campaign/public/`:

```powershell
py -3 benchmark.py --state-root $state campaign seal --campaign $campaign --mapping $mapping --output $newPublicDirectory
```

The mapping JSON has exactly `schema_version: 1`, `case_id`, `assets`, `entity_aliases`, `known_gaps`, `assessment_windows`, and `max_public_bytes`:

- `case_id` is `case-` followed by 4–32 lowercase hexadecimal digits, not an exercise name.
- Each `assets` entry supplies `target_id`, `os_family`, `os_version`, `architecture`, and `vendor` for an enrolled target. Unknown facts are null; AWS control-plane OS is `not-applicable`. Facts are not guessed from a recipe.
- Each private alias group is `{kind, values}`. Kinds are `host`, `account`, `address`, `domain`, `key`, `process`, `session`, `service`, and `resource`. Supply at least two known names for an entity when distinct sensor representations need correlation. Do not merge unrelated accounts merely because their short names match.
- Each intended gap is `{source_id, target_id, reason}` and must be supported by declared instrumentation or collector evidence. `missing_audit_export` marks the `linux-audit` source `unknown` and attaches only to it; `process_instrumentation_absent` is an asset gap. `process_events_absent` with configured process sources, or any unverified gap, fails as `incomplete_export` rather than becoming a clean negative.
- Zeek collectors target an enrolled sensor with its own clock; `config.address_assets` attributes events to assessed assets by originator then responder. The sensor is listed in `unassessed_asset_ids` and receives no questions.
- Assessment windows use `{start_inclusive, end_exclusive}`; sealing creates the full asset/window question set. `max_public_bytes` is a positive cap no greater than 1 MiB or the campaign export cap. Oversize blocks; no records are silently sampled.

The first successful seal freezes the mapping and retains its random per-campaign pseudonym salt privately. Do not reuse it across unrelated campaigns. `evidence.json` and `records.jsonl` contain only the source-specific public projection; original snapshots, entity aliases, salt and controller receipts remain private. The original timestamp remains available alongside normalized UTC and uncertainty. Unknown event schemas, unsafe XML, changed source bytes, unsupported gaps and incomplete watermarks block sealing.

Windows event computer names and journal machine IDs must match the enrolled source host before attribution; a readable export from another machine is not evidence about the target. A campaign recipe label, campaign/target/source ID or AWS correlation ID embedded in public bytes blocks publication rather than leaking an answer.

Collectors filter at the source: Windows exports declare `{'event_ids': {channel: ids}}` and AWS exports `{'event_names': [...]}` from `benchmark_evidence.supported_event_ids`/`supported_cloudtrail_events`; a drifted filter or an out-of-filter record fails `filter_mismatch`. Both the pre-cleanup exercise generation and the final generation are retained, and every exercise record must appear unchanged in the final export. Pseudonyms normalize IPv4-mapped IPv6 to IPv4, bind host-local identifiers (LogonId, PipelineId, `ses`, `uid`/`auid`, `_BOOT_ID`) to their asset, and share one namespace for hostnames and DNS names. Seal writes a private `sealing/phase-windows.json` (warmup/exercise/cleanup) that is never published.

Inspect **all** public bytes. Source field allowlisting is not a declassification decision. Genuine detector ATT&CK labels are retained only as detector telemetry and identify a separate `with_detector_alerts` condition; they are never exercise-injected labels. Keep that condition separate from raw telemetry in comparisons.

**Log content reaches the hunter.** Command lines (Sysmon 1, Security 4688, Linux audit EXECVE/PROCTITLE, journald `_CMDLINE`), PowerShell script and pipeline text (4104 `ScriptBlockText`, 4103 `Payload`/`ContextInfo`, classic `Windows PowerShell` 400/600/800), DNS answers (Sysmon 22), registry values (Sysmon 13), service/task/WMI content and CloudTrail `userAgent`/`errorMessage`/`requestParameters` are published through one shared sanitizer (`benchmark_sanitize.py`, transform `content`) in both importers and the live-lab sealer. In order it redacts secrets (password arguments, NTLM hashes, Kerberos/PEM keys, AWS keys, JWTs, auth headers and cookies, `[REDACTED:<kind>]`), replaces SIDs, accounts, hosts, profile paths and IP literals with the same pseudonyms as the structured fields, masks ATT&CK IDs and Atomic Red Team paths as `T####`, and truncates over 16 KiB with an explicit marker and a `content_truncated` gap. Event types without a field map import as metadata-only events instead of stubs, so WMI-Activity, TaskScheduler, TerminalServices, Application and additional Security/System events are visible. Restoring this content grew the 32-case corpus from 53.2 MB to 61.6 MB of public bytes; whole-bundle prompts still fit only 24 cases under the 1 MiB cap.

**Antivirus.** The bundles are log text, not executables, but attack recordings quote the exact commands the attacker ran. Microsoft Defender scans text for known attack scripts, so it blocked bundles whose PowerShell logs quote an Empire stager (`Trojan:PowerShell/Boxter.KN!MTB`), both as the raw `-EncodedCommand` base64 and as the decoded script text. By default every encoded PowerShell payload is replaced by `[ENCODED_COMMAND utf16le_chars=N sha256=…] decoded_preview="<first 512 sanitized chars>"`; on this host all 32 re-imported cases stayed readable. `--encoded-payloads full` keeps raw payloads and is only for an output directory the operator has deliberately excluded from scanning; nothing in the benchmark adds antivirus exclusions. A file blocked on write or read-back fails as `blocked_by_antivirus: <path>` rather than an opaque read error.

Prepare the experiment bundle using the exact sealed bytes, curate its separate scenario/truth metadata, and initialize its trial ledgers without running a model. Then create a destinations JSON object with exactly:

- `schema_version: 1`;
- `evidence_sha256`: the canonical digest of the inspected public manifest;
- `expires_utc`: an explicit future UTC expiry;
- `trials`: entries `{experiment_id, trial_id, model_sha256s}` for already initialized trials in the same state directory.

Each model digest is SHA-256 of the canonical complete configured model object, including endpoint, settings and credential **environment name**, not its value. Include the checker only when it is an approved destination. A release to one model or trial does not authorize another.

```powershell
py -3 benchmark.py --state-root $state campaign release --campaign $campaign --by $reviewer --note $inspection --destinations $destinations
```

All destinations are validated before a single atomic authorization commit. Changed public files, wrong digest/model, expired permission or incomplete cleanup leave no partial grants. Release does not call a model; `advance --allow-model-execution` remains separately explicit. Review actor names and inspection notes are self-reported, not authenticated signatures.

Exercised with disposable synthetic records: the actual CLI sealed public bytes, rejected a wrong release digest without any grants, released the exact initialized destination, and exported the linked campaign. Private message text, raw machine identity and recipe labels were absent from that public bundle. No live collection or model call was part of this check.

## Measurement rubric

`hunt-rubric-1` separates hunter difficulty from custom campaign sophistication. Difficulty uses curator-validated released-evidence measurements, not model accuracy or actor reputation:

| Factor | 0 | 1 | 2 |
|---|---|---|---|
| Noise | benign/relevant ratio ≤10 | >10–100 | >100 |
| Joins | one source/asset context sufficient | two required | three or more required |
| Time span | ≤5 minutes | >5 minutes–1 hour | >1 hour |
| Gaps | required records complete | missing records, complete alternative support | at least one genuinely undecidable scoped question |
| Ambiguity | no seeded benign lookalike | one | two or more |

Sum 0–1 → D1, 2–3 → D2, 4–5 → D3, 6–7 → D4, 8–10 → D5. Zero-positive controls inherit their matched attack-family difficulty and are marked controls; their noise ratio is not infinity. Derived evidence partitions get new digests and keep their source provenance (`derived_replay` for private lab data, `public_replay` for published recordings); they are not new independent live campaigns.

S0 denotes controls. S1 is one or more atomic techniques with no causal chaining, on any number of assets. S2 is a causally linked chain; S3's chain crosses an identity or privilege boundary between hosts; S4 adds persistence/re-entry and segment/domain correlation; S5 additionally crosses on-prem/cloud or IT/OT boundaries with deliberately sparse or ambiguous traces. The tier is judged on the strongest causally linked chain. Real recordings carry concurrent activity, so other independent chains and atomic steps on any asset (for example a second compromised host beaconing during the same window, an unmapped credential read, or a pre-recording log clear marked with non-sufficient observability) may coexist without raising the tier, and a correct detection of them is never scored as a false positive. Explicit steps, causal edges, preconditions, boundaries and limitations support these labels. These are **project-defined tiers**, not official ATT&CK group rankings. Multiple discovery commands do not establish S3–S5.

ATT&CK release `v20` is pinned in the authored cases. [ATT&CK matrices](https://attack.mitre.org/matrices/) separate Enterprise, Mobile and ICS domains; [groups](https://attack.mitre.org/groups/) are reported overlapping activity clusters, not sophistication grades. Sector tags are synthetic context, not compliance certification. Actor-name or nationality guessing earns no detection credit.

## Audit and execution invariants

The SQLite database is authoritative. Reservations use `BEGIN IMMEDIATE`, full synchronous durability and unique stage/attempt/component keys. State transitions and their events commit together. A matching terminal receipt may be read again; a changed fingerprint conflicts; a reserved or unknown dispatch cannot execute again automatically. Lost terminal persistence leaves an unknown outcome. Operator reconciliation supplies effect/artifact evidence and never dispatches.

Prompts, responses and structured outputs are content-hashed immutable artifacts written atomically. Unknown calls retain reserved cost and time until reconciled. Missing usage is null, not zero; cached input and reasoning tokens are subsets, not extra tokens. Local API price zero does not imply free compute or energy.

Routine `status` and `advance` read each trial ledger once and validate the frozen experiment once per process. They use `PRAGMA quick_check` and, within one process, remember a verified immutable artifact by (path, size, modification time, digest), so any rewrite is hashed again. Each dispatch's authorization check reads and verifies only that trial's rows. Export, score, diagnose, holdout retirement and release always run the full `integrity_check` and re-hash every artifact. On the 45-trial graduated example, `status` and dry `advance` take about 0.7 s (previously about 64 s) and `init` about 3.5 s (previously about 71 s).

Whether a call is paid comes from its **route**, never the team's `deployment` label: only `openai` (LangChain) and `openai_http` (stdlib) routes over plain HTTP to a literal loopback IP (`127.0.0.1` or `::1`) are free; `localhost`, any HTTPS endpoint and the Jev checker are paid. A `local` team with any paid role is rejected. Every paid route needs positive `max_api_cost_usd` and a computable per-call bound: either `per_call_cost_bound_usd` (≤ the experiment cap) or a pricing-snapshot rate, from which the bound is `input_rate × max_prompt_bytes + output_rate × max_output_tokens` (bytes bound tokens from above; paid `openai_http` routes scale worst-case input/output across up to 4 tool-call rounds and `12 × 24,576` tool-result bytes). A provider spend-cap reference is recorded as extra protection but no longer substitutes for a bound. Each call reserves only its own worst case; receipts flag `bound_exceeded` when the computed cost overshoots. A local counter still cannot enforce remote billing.

The `export` command writes a new directory from one consistent database snapshot: `events.jsonl`, `calls.jsonl`, `campaigns.jsonl`, `scores.jsonl`, `coverage.csv`, `report.json`, and `report.md`. It verifies referenced artifact bytes and refuses corruption rather than exporting a truncated success. Exports are snapshots, not another append-only authority.

## Interpretation

Evidence-supported precision/recall/F1 use raw TP/FP/FN, exact technique/subtechnique and asset/window matching and full alternative support sets. Unknown/insufficient observability does not enter positive recall. Failed scheduled trials remain failures with missed eligible positives. Jev is an optional typed claim checker inside a complete team, never ground truth or the semantic judge of its own work.

Calibration uses the fixed public asset/window questions and non-null frozen labels, reports missing/abstained probabilities, and never inserts zero for missing confidence. Comparisons pair the same evidence, workflow/prompt versions, limits, scenario and repetition; rendered prompt digests may differ because predecessors differ. Deployment, runtime facts and harness versions are reported **treatment** attributes, not cohort controls, so cloud, local and hybrid teams are comparable; they must be known only when both compared teams are local. Scenarios with no eligible attack steps are excluded from F1 pairing and macro averages (their false alarms are reported as `benign_control_false_alarms`). Identity is judged only on calls that reported a model; any reported mismatch still blocks. Correct, fully supported detections of steps with unknown/insufficient observability are counted as `visibility_limited_detections`, outside precision. Repetitions aggregate within scenarios; whole campaign families, not repeated windows, are the independent bootstrap units. Fewer than five families is descriptive/underpowered. Separate synthetic/live-derived, development/holdout, detector-alert/raw, adjudication (mechanical/human), truth attestation, timing contention, budget and model-identity cohorts. Unreported identity is a requested-configuration report, not exact-model attestation.

Paired 95% intervals use 2,000 whole-family bootstrap samples, seed 1729. All paired differences remain visible for underpowered comparisons. Coverage slices are descriptive, not multiple uncorrected significance tests. Only comparable, settled cohorts can rank (mechanical cohorts only among themselves); failures, cost, coverage and differing fingerprints remain visible.

The methodology is informed by [MITRE evaluation methodology](https://evals.mitre.org/methodology-overview/) and [paired-test guidance](https://aclanthology.org/P18-1128/). Formulas are this project's rubric, not MITRE certification. Public emulation recipes are development material. Training contamination remains unknown unless established; tuning after inspecting a holdout retires that holdout for future selection.

## Improving the framework: development loop and holdouts

The benchmark measures; improving prompts, roles, workflow and model assignments happens on **development** cases only:

```powershell
py -3 benchmark.py --state-root $state diagnose --experiment $experiment --truth $truthDirectory --output $newReport.json
```

`diagnose` refuses any experiment containing a holdout scenario (`holdout_feedback_refused`) before reading truth. For each trial, stage and role it lists missed eligible steps, wrong asset/window, parent-only technique, unsupported/contradicted claims, invalid citations, control false alarms, missing assessment probabilities, unsupported chain edges, unmatched suspicious findings and format/timeout/transport failures, each labelled with its `basis` (`mechanical_rules`, `human_verdicts`, `truth_comparison`, `public_evidence` or `call_receipt`). Each error is attributed to the earliest stage output that introduced it, with `propagated_to` for later stages. It discloses only technique ID, asset pseudonym and window from truth and writes new JSON plus Markdown files; nothing feeds it to a model automatically.

Holdout cases are scored, never diagnosed. Initializing any holdout scenario requires a registry of retired `(family_id, revision)` pairs, and retired entries are refused:

```powershell
py -3 benchmark.py --state-root $state init --experiment $holdoutManifest --bundle-root $bundle --truth $truthDirectory --holdout-registry $registry
py -3 benchmark.py --state-root $state holdout retire --experiment $experiment --registry $registry --by $reviewer --note $reason --output $newRegistry
py -3 benchmark.py --state-root $state export --experiment $experiment --output $newExportDirectory --holdout-registry $newRegistry
```

Reports mark holdout scorecards `holdout_exposed` until retired. Retirement writes a new registry file and never overwrites the old one. Build holdouts from privately authored or lab cases: public datasets are likely in model training data.

Real telemetry comes from seven public-dataset importers (see [importers/README.md](importers/README.md)): OTRF Security-Datasets for Windows (`benchmark_import_otrf.py`, atomic and compound recordings), Splunk attack_data for Linux auditd and AWS CloudTrail (`benchmark_import_attackdata.py`), Splunk Boss of the SOC v1–v3 (`benchmark_import_bots.py`), OTRF SimuLand Golden SAML (`benchmark_import_goldensaml.py`, S5 hybrid AD FS + Entra ID + M365), Invictus AWS CloudTrail (`benchmark_import_invictus.py`, Stratus UUID labels with `stratus-red-team` stripped from public `userAgent`), CAM-LDS (`benchmark_import_camlds.py`, Linux multi-source with `attackmate.json` step attribution), and whole-campaign SQLite query-track APT recordings (`benchmark_import_query_apt.py` for OTRF `APT29 Day 2`, `DEDALE` Windows+Linux+Suricata, and `FullAPT-2025` labeled Sysmon). Datasets that ship per-step or per-event publisher labels (`CAM-LDS`, `Invictus AWS`, `DEDALE`, `FullAPT-2025`, and emulation-plan-mapped `Golden SAML` / `APT29 Day 2`) emit `attestation: "publisher_labels"` mechanically without AI agreement. Datasets without event labels accept an agent-drafted `curation.PROPOSED.json` (`attestation: "unreviewed_proposal"`), two independently written proposals merged via `py -3 benchmark_consensus.py merge` (`attestation: "agent_consensus"`), or a reviewer-signed checklist (`human_attested`). Each attestation value is its own cohort control.

### Real threat-intelligence IOC feed (`ioc-feed-1`) and Wave 2 SQLite query track

- **Real CTI IOC feed (`public/intel.jsonl`, `benchmark_ioc.py`):** Importers seal a SHA-256-pinned `ioc-feed-1` JSONL file in `evidence.files` combining real public MITRE ATT&CK v20 software/group indicators, MalwareBazaar/ThreatFox/Feodo-class tool and infrastructure indicators, and case-scoped indicators under two evaluation regimes: `known_ioc_pivot` (1–2 active indicators match attack events alongside `known_false_positive` / `historical_rotated` benign decoys) and `novel_apt_zero_ioc` (`active_truth_matches == 0`, withholding attacker C2/hashes to simulate rotated novel-APT infrastructure while retaining benign decoy IOCs to penalize naive indicator matching). All `Txxxx` strings are scrubbed from `public/intel.jsonl`.
- **Wave 2 SQLite query-tool track (`query_store`, `benchmark_query.py`):** Whole-campaign APT recordings (`24,000`–`587,000+` events) keep `evidence.events == []` so prompts stay well under the 1 MiB cap, and declare `evidence.query_store` pointing to a SHA-256-pinned, read-only SQLite FTS5 store (`public/events.sqlite3`, tables `events`, `events_fts`, `iocs`, `meta`). During `advance --allow-model-execution` with `adapter: "openai_http"`, stages invoke six bounded read-only tools (`search_events`, `count_events`, `get_events`, `asset_timeline`, `pivot_indicator`, `lookup_ioc`) capped by default at 12 calls/stage, 35 rows/call, and 24 KiB (`24,576` bytes) per tool call, writing an immutable `artifacts/query-audit/` receipt per stage dispatch that executed queries and summarizing per-team query telemetry (`query_store_usage`) in `report.json` and `report.md`. Non-routine store opens and `export` re-hash `events.sqlite3` and run `verify_query_store` over all rows and digests; citation verification checks `events.sqlite3` directly so cited `event_id` values remain exact.

To build a manifest over a directory of cases (refusing any case larger than the prompt cap, or with `--context-tokens N` larger than the model's context):

```powershell
py -3 benchmark.py corpus-experiment --cases $cases --team $team --experiment-id $id --output $cases/experiment.json
```

`$team` is `{"schema_version": 1, "team": {...}}`, optionally with `budgets` and `pricing_snapshot` in the experiment shape. Without `budgets`, conservative defaults apply with no cost cap, so a paid team is refused until you supply one. Any draft case refuses the whole corpus. Holdout scenarios need `--holdout-registry`. The manifest is written as a new file inside `$cases` only after it passes the same checks as `validate`.

## Scoring and adjudication

There is one scored variant, `team_output`: the final handoff once all seven stages have auto-advanced (`review_policy: auto_advance`). `score --experiment E --truth DIR` applies deterministic **mechanical adjudication** by default (rules `mechanical-rules-1`, never a model, never recorded as human verdicts):

- A finding is supported if it cites every event of at least one complete support set of a truth step with the exact technique, the same asset and an overlapping window.
- It is contradicted if it is suspicious, overlaps a benign control and matches no such step. Otherwise it is insufficient.
- An edge counts only when both endpoints are matched detections and truth holds that ordered edge.
- Claim citation validity is measured; claim semantic support and correct control dispositions are reported as `not_measured_mechanical`.

Mechanical scores have status `mechanical`, never `final`. Truth is frozen automatically at `init`, before any dispatch; scores against unfrozen truth stay `provisional`.

Human adjudication is optional. `adjudication-template --experiment E --output NEW` exports opaque trial/case IDs, each exact output digest, the structured output and `{item_kind, item_id}` targets, without team/model/runtime metadata or truth. A separate human fills verdicts (`trial_id`, `output_sha256`, `item_kind` `claim|finding|edge`, `item_id`, `verdict` `supported|contradicted|insufficient`, `event_ids`, `by`, `note`); `score --adjudication FILE` then forms a separate `adjudication: human` cohort whose complete scores are `final`. Adjudication, truth attestation (`human_attested`/`unreviewed_proposal`/`agent_consensus`/`publisher_labels`), review policy, truth freeze and timing contention (`max_concurrent_calls > 1`) are cohort controls; cohorts differing in any of them are `not_comparable` with the differing fields named.

**Reference floors.** `py -3 benchmark.py baselines --experiment-manifest FILE --bundle-root DIR --truth DIR --output NEW.json` scores deterministic reference outputs through the same mechanical scorer, offline and without state: `silent` (no findings, probability 0), `alarm_all` (one uncited suspicious finding per question, probability 1), `coin` (probability 0.5) and `prior` (leave-one-out development base rate). Rows are labelled `reference_baseline` and are shown as floors, never ranked as teams.

### ATT&CK technique identity (pinned v20)

ATT&CK v20 revoked several technique IDs and named replacements (for example T1562.008 → T1685.002, T1070.001 → T1685.005). Scoring, truth validation, diagnostics and the consensus merge compare *canonical* IDs from `benchmarks/attack-v20-techniques.json`, derived by `benchmarks/tools/generate_attack_aliases.py` from the official Enterprise STIX bundle (`mitre-attack/attack-stix-data`, tag `v20.0`, commit `20664a889568dce884a1dac0ec7b12ae3a199f51`, SHA-256 `81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352`); `benchmark_attack.py` refuses the map unless its bytes match the pinned `DATA_SHA256`. A truth technique unknown to v20 fails validation (`unknown_technique`); revoked IDs are accepted and score as their replacement, following chains. Model outputs are never refused for an unknown ID (it simply does not match); a revoked ID gets full credit and is counted in `diagnostics.technique_ids_revoked_used` for information only. To regenerate, download the bundle and `LICENSE.txt` outside the repository with a `provenance.json`, run the generator with `--provenance`, and update `DATA_SHA256`; a new release is a new cohort. ATT&CK® content is © The MITRE Corporation, reproduced under the MITRE ATT&CK Terms of Use; the map carries the license text.

A detected blocked attempt is not a successful compromise. The output schema has no structured claimed execution-outcome field, so outcome-correctness is explicitly unmeasured rather than guessed from prose. Timing separates measured model-active time from first-dispatch to final-auto-advance wall time; there is no human wait. Offline time-to-first-supported-finding is not production MTTD.

## Live prerequisites

No live model, cloud account, hypervisor, guest, sensor or isolation is implied by a valid manifest. Live execution requires explicit flags and exact configuration/release authority. No real-money trading, arbitrary commands, destructive malware, real credential theft, zero-days, firmware/OT disruption, infrastructure provisioning, profile changes or weakened promotion gates are part of this benchmark.

The separately supplied `hunt-range/benchmark/` kit is not bundled with the portable framework. Windows/Linux/AD/internal-DNS/AWS tracks require pre-enrolled isolated targets and independent bounded sensors. Other coverage remains planned/blocked until its environment, instrumentation, reviewed recipe, cleanup and release authority exist. No fixture transport or command test earns `live_verified`.

## Verified execution scope

Verification on this Windows host (2026-11-08), after the BOTS importer, the concurrent-activity band rule and the BOTS corpus import:

| Check | Observed result |
| --- | --- |
| Workspace `py -3 -B -m unittest discover` (Python 3.13, no optional SDK) | OK; 1098 tests, 43 skipped |
| Workspace `uv run --no-project --python 3.9 python -B -m unittest discover` (CPython 3.9.25) | OK; 1098 tests, 48 skipped |
| Workspace `python3 -B -m unittest discover` on Linux (WSL Ubuntu, Python 3.12.3), including POSIX-only worker/supervisor tests | OK; 1098 tests, 51 skipped |
| `test_langchain_adapter test_benchmark_models test_benchmark_team` under `.venv-orchestration` (real LangChain/OpenAI SDK) | OK; 95 tests, 0 skipped |

The team test drives `benchmark.py advance` → `bot.py run --adapter generic` → `benchmark_runner.py` → `benchmark_models.py` against a loopback OpenAI-protocol fixture: two trials with default concurrency (4) reach `finished` with zero human commands, every ledger holds seven `auto_advance` events by `benchmark-auto-advance` and no approve/reject, each call has exactly one reservation, and mechanical scoring, diagnose and export succeed. Fixture responses are transport evidence, not model results. Earlier rounds found and fixed two Python 3.9 incompatibilities (`socket.timeout` is not `TimeoutError` before 3.10).

An offline CLI smoke on four real imported cases (`<user-home>/Desktop/bot-framework-data/fast-dev-cases/`, unreviewed-proposal answer keys) ran `corpus-experiment`, `validate`, `init --truth` (truth frozen automatically), `status` (0.9 s; `review_policy: auto_advance`, `max_concurrent_calls: 4`) and a dry-run `advance` (no dispatch).

The Linux run found and fixed two descriptor leaks in the process supervisor (an unclosed `/proc` directory iterator in the teardown polling loop, and child pipes left open on a failed setup or wait). The Windows PowerShell worker script parses with zero errors; it was not executed.

A local development corpus was imported outside the source tree: 23 public OTRF Windows recordings (flat `TimeCreated` and older NXLog `EventTime` layouts) and 8 Splunk attack_data recordings (4 Linux auditd, 4 AWS CloudTrail; one oversized CloudTrail recording as two contiguous time partitions). Each recording received two independent agent drafts; all 32 pairs merged into `agent_consensus` keys (Cohen's kappa where defined ranged from −0.25 to 1.0; disputed steps were dropped) and imported as `public_replay` cases. None is human-attested. Only 12 of the 32 public bundles fit the 1 MiB prompt cap and only 3 fit a 32k-token local context, so supplying whole bundles in the prompt limits which real recordings a team can read.

A BOTS development corpus (2026-11-08) was imported outside the source tree with `benchmark_import_bots.py`: 58 cases (v1 11, v2 21, v3 26) across 10 incidents, each a 1 MiB plan partition of an evidenced attack span or a benign control from the same days, with a declared host/sourcetype collection profile. All 58 keys are `agent_consensus` from two independent drafts; the second-draft model family was unavailable, so both drafts came from the same family. Consensus bands: S0 6, S1 25, S2 23, S3 4 (v2 Taedonggang credential crossing to a second host, v2 brewertalk CSRF admin creation, and two v3 cases linking OneDrive delivery to the Office 365 tenant). Drafts proposed S4/S5 for three chains, but the edges both drafts agreed on did not support them, so no S4/S5 case exists yet. The three experiments validate (`bots-v1-dev-1`, `bots-v2-dev-1`, `bots-v3-dev-1`). Known residue in public bundles: a lure zip password written in phishing prose (v2), user names embedded inside other strings, and recognisable scenario names; every case is development-only.

**First real fully automatic team runs** (local LM Studio, DeepSeek-R1-0528-Qwen3-8B Q4_K_S, 32k context, RTX 5070 Ti; the three smallest consensus cases; run from `snapshot-source`; zero human commands):

| Run | Configuration | Outcome |
| --- | --- | --- |
| 1 | free-form JSON | every scope attempt failed `invalid_response`; all 3 trials ended `budget_exhausted` (63 min) |
| 2 | `structured_output: true` | runner bug found: siblings cancelled by a failed branch were never re-dispatched (fixed, regression test added) |
| 3 | `structured_output: true`, nonblank text pattern | all 3 trials completed (22 calls, 1 automatic retry after `invalid_json`, 33 min); mechanical score TP 0, FP 2, FN 3, F1 0.0, equal to the `silent` floor |

`diagnose` attributed the misses to the coordinator's handoff: suspicious findings carried no `technique_id` (so nothing could match truth), assessment probabilities were abstained, and one chain edge was unsupported. These are model-quality results for one small local model on three public development cases, not a general claim.

**Real-IOC & Novel-APT multi-model subscription evaluation (2026-11-14).** Built an 11-case sanitized real-IOC corpus (`<user-home>/Desktop/bot-framework-data/benchmark-v3-real-iocs/`, `107,296` total events, `publisher_labels` truth, `mechanical` adjudication `mechanical-rules-1`): 7 development cases (`Golden SAML` S5, `APT29 Day 2` S4 query-store, `Invictus AWS` S4, `FullAPT-2025 apt-1` S4 query-store, `CAM-LDS SSH` S2, plus 2 decoy-IOC S0 controls) and 4 unseen holdout `novel_apt_zero_ioc` cases (`Invictus AWS evasion` S4, `CAM-LDS VNC` S3, `DEDALE` Windows+Linux+Suricata S4 query-store, and `FullAPT-2025 apt-2` S4 query-store). Evaluated two frontier model families (`claude-sonnet-5-5` via `claude` CLI and `gpt-6-luna` via `codex` CLI) over `benchmark_subscription_proxy.py` with direct API keys stripped (`44` live trials, `314` model calls, `0` timeouts, `0.0000` invalid citation rate across all 8 team-runs; deterministic floors `silent`/`alarm_all`/`coin`/`prior` all scored `0.0000` F1):

| Split & Workflow | Team | Macro F1 | Precision | Recall | TP / FP / FN | Chain-Edge F1 | Brier (Coverage) | Benign FA | SQLite Queries (`lookup_ioc`) | Active Model s |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Dev (`team-workflow.json`) | `claude-sonnet-5-5-sub` | 0.2284 | 0.3333 | 0.1806 | 5 / 11 / 32 | 0.0833 | 0.1680 (89.3%) | 5 | 56 (1) | 1269.8 |
| Dev (`team-workflow.json`) | `openai-gpt-6-luna-sub` | 0.0364 | 0.2000 | 0.0200 | 1 / 13 / 36 | 0.0000 | 0.1019 (40.5%) | 2 | 97 (0) | 2113.5 |
| Dev (`team-workflow-novel-apt.json`) | `claude-sonnet-5-5-sub` | **0.3690** | 0.3717 | 0.3728 | 11 / 27 / 26 | **0.1667** | **0.1333** (96.4%) | 4 | 52 (4) | 1198.2 |
| Dev (`team-workflow-novel-apt.json`) | `openai-gpt-6-luna-sub` | **0.1269** | 0.1389 | 0.1194 | 4 / 20 / 33 | 0.0000 | 0.1187 (100.0%) | **1** | 113 (8) | 2248.5 |
| Holdout (`team-workflow.json`) | `claude-sonnet-5-5-sub` | 0.1169 | 0.2083 | 0.0813 | 3 / 6 / 29 | 0.0000 | 0.2928 (90.6%) | 3 | 40 (1) | 660.0 |
| Holdout (`team-workflow.json`) | `openai-gpt-6-luna-sub` | 0.0357 | 0.0625 | 0.0250 | 1 / 7 / 31 | 0.0000 | 0.2288 (47.9%) | 2 | 85 (0) | 1353.1 |
| Holdout (`team-workflow-novel-apt.json`) | `claude-sonnet-5-5-sub` | **0.2458** | 0.2910 | 0.2340 | 7 / 23 / 25 | **0.0476** | 0.3342 (93.8%) | 3 | 83 (2) | 773.9 |
| Holdout (`team-workflow-novel-apt.json`) | `openai-gpt-6-luna-sub` | **0.2045** | 0.2366 | 0.1813 | 6 / 16 / 26 | 0.0000 | 0.4737 (100.0%) | **2** | 107 (4) | 1609.5 |

On the 5-family development split under `team-workflow-novel-apt.json`, `claude-sonnet-5-5-sub` outperformed `openai-gpt-6-luna-sub` by `+0.2421` F1 (`2,000`-sample paired family-cluster bootstrap 95% CI `[+0.0133, +0.5197]`). On the 4 unseen `novel_apt_zero_ioc` holdout cases (`holdout_exposed`, descriptive 4-family cohort exercising `holdout` mechanics over distinct public-dataset families rather than privately authored lab captures; `diagnose` never run on holdout), the Novel-APT Behavioral Hunting Playbook lifted `claude-sonnet-5-5-sub` from `0.1169` to `0.2458` (`+0.1289` F1) and `openai-gpt-6-luna-sub` from `0.0357` to `0.2045` (`+0.1687` F1, reaching `0.4706` F1 on the 26,000-row `FullAPT-2025` Sysmon SQLite query case). Public-dataset training contamination remains `unknown`; private lab holdouts, Jev checker routes, and live range-kit collection/cleanup remain separate prerequisites.
