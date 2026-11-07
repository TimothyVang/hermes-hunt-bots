# Optional LangGraph and LangChain runtime

The standard-library ledger in `bot.py` still supports Python 3.9+ without installing anything here. These two optional entrypoints need **Python 3.10+**:

- `orchestrate.py`: a real LangGraph `StateGraph` with one ledger gate node per workflow task, a durable SQLite checkpointer, and explicit interrupt/resume. It observes the existing ledger; it never runs a bot, creates task events, generates prompts, invokes a model, or approves work.
- `langchain_adapter.py`: an explicitly invoked, text-only model CLI using LangChain's `init_chat_model`. It works through the existing `bot.py run --adapter generic` subprocess path. It is not a Hermes profile, tool-using agent, or automatic graph dispatcher.

Human ledger approval remains authoritative **for this workflow's decisions**, but `--by` is self-reported and not authentication or a security boundary. Approval does not prove evidence correct or authorize publication, trades, messaging, deployment, or other external effects.

## Install in a project-local virtual environment

From the copied `framework` directory, select an installed Python 3.10+ executable. These commands do not install globally or activate a shell-wide environment.

**Windows PowerShell (example: installed Python 3.13)**

```powershell
py -3.13 -m venv .venv-orchestration
$python = (Resolve-Path '.\.venv-orchestration\Scripts\python.exe').Path
& $python -m pip install -r .\requirements-orchestration.txt
```

**macOS / Linux**

```sh
python3 -m venv .venv-orchestration
python="$PWD/.venv-orchestration/bin/python"
"$python" -m pip install -r requirements-orchestration.txt
```

The requirements pin published releases `langgraph==1.2.19`, `langgraph-checkpoint-sqlite==3.1.3`, and `langchain==1.4.7`. They have compatible declared dependency ranges and require Python 3.10+. This is a direct-dependency pin set, not an all-transitive, hash-locked environment. Installation resolves their transitive dependencies separately. Package metadata compatibility is not evidence of a local test run or of provider/model access.

The graph does **not** require a model provider SDK. For explicit model use, install only the selected supported integration into that same environment:

| `--provider` | Separate install, using the environment's Python | Configuration supplied separately through the approved environment |
| --- | --- | --- |
| `openai` | `-m pip install langchain-openai==1.7.3` | SDK-supported OpenAI configuration, normally `OPENAI_API_KEY` |
| `anthropic` | `-m pip install langchain-anthropic==1.7.7` | SDK-supported Anthropic configuration, normally `ANTHROPIC_API_KEY` |

For example, `& $python -m pip install langchain-openai==1.7.3` in PowerShell or `"$python" -m pip install langchain-openai==1.7.3` in a POSIX shell. The adapter deliberately supports these two provider integrations, which expose the timeout and zero-retry controls it uses. It does not claim all `init_chat_model` providers work with identical settings.

Never put real credentials in arguments, task records, prompts, output, chat, or this distribution. The adapter neither accepts credential arguments nor reads `.env`; the SDK obtains its approved configuration from the inherited environment. Configure that environment privately using the destination's approved mechanism. Existing Hermes configuration and the private Envision `.env` example in `hermes-setup.md` do **not** automatically configure this adapter. Do not inspect or copy them into a portable release.

## Create a ledger workflow, then start a progress cursor

The graph needs a **workflow group** created by `bot.py workflow create`, not an arbitrary task ID or the JSON template path. It derives the graph from the group's actual ledger members and dependency edges, not from a mutable template file on disk. Older initialized workspaces remain usable: `workflow create` adds group tables through the ledger's existing transaction; do not reinitialize them.

For a new disposable workspace in PowerShell:

```powershell
$ws = '.\graph-example'
& $python .\bot.py -w $ws init
& $python .\bot.py -w $ws workflow create research-review --title 'Review supplied notes' --scope 'Use only supplied examples/meeting-notes.txt; no browsing or external effects.' --acceptance 'Identify the decision, action owner and deadline, and uncertainty with source evidence.'
# Use the actual printed workflow ID and task mapping. These illustrate this fresh workspace only.
$workflowId = 1
$researchId = 1
& $python .\orchestrate.py -w $ws status $workflowId
& $python .\orchestrate.py -w $ws run $workflowId
```

For the same new-workspace sequence in a POSIX shell:

```sh
ws=./graph-example
"$python" bot.py -w "$ws" init
"$python" bot.py -w "$ws" workflow create research-review --title 'Review supplied notes' --scope 'Use only supplied examples/meeting-notes.txt; no browsing or external effects.' --acceptance 'Identify the decision, action owner and deadline, and uncertainty with source evidence.'
workflow_id=1
research_id=1
"$python" orchestrate.py -w "$ws" status "$workflow_id"
"$python" orchestrate.py -w "$ws" run "$workflow_id"
```

Set `-w` before the subcommand. `run WORKFLOW_ID` starts or resumes the same durable thread, `workflow:WORKFLOW_ID`. It returns JSON with `checkpoint` (`not_started`, `waiting`, `paused`, or `complete`), checkpoint ID, fingerprint, reconciled `completed_tasks`, `next_nodes`, and current ledger task/dependency statuses. A successful exit with `waiting` is expected, not an error. `paused` means a saved, unfinished traversal exists without an outstanding interrupt; another explicit `run` can continue its local ledger reads.

`status WORKFLOW_ID` never invokes the graph and never advances or creates durable checkpoints. When a checkpoint exists it inspects a consistent in-memory SQLite backup, so the checkpointer's automatic schema setup cannot modify the original. Status is an observation, not a reservation; the ledger can change after it is read. Missing groups, malformed/cyclic/out-of-group dependencies, unavailable optional packages, and uninitialized workspaces produce a clean error, not automatic initialization or a fallback executor.

### Human review drives every node

The graph traverses a deterministic topological order **sequentially**. Independent branches are not executed automatically or in parallel. A task gate checks its actual ledger state and prerequisites; only `done` advances. All other states (`pending`, `active`, `running`, `blocked`, and `review`) interrupt and wait.

The same generic workflow-ID interface applies to a created `threat-hunt` group; use the printed group ID (not a task ID) with `status` or `run`. Its `evidence` and `hypotheses` tasks are independently available in the ledger after scope approval, although this optional cursor observes gates sequentially. The cursor does not perform either branch, supply evidence, or make decisions. See the [offline hunt procedure](hermes-setup.md#offline-defensive-threat-hunt) for its six tasks and safeguards. A disposable synthetic-fixture smoke exercised this hunt's cursor waiting and resuming through completion and confirmed that a repeated complete run reused its checkpoint. Ledger approvals were labeled smoke simulations, not human sign-off; no agent adapter or live model was run.

Continue using the existing manual ledger commands:

```powershell
& $python .\bot.py -w $ws start $researchId
& $python .\bot.py -w $ws prompt $researchId
# Do the authorized work outside the graph, manually or via an explicitly approved CLI.
& $python .\bot.py -w $ws submit $researchId --by 'researcher' --note '<replace with actual sourced findings, coverage, evidence paths, and uncertainties>'
& $python .\orchestrate.py -w $ws run $workflowId
# It still waits: review is not done.
```

After a human actually reviews the handoff and evidence, choose exactly one decision, replacing the instructional notes with observed findings:

```powershell
& $python .\bot.py -w $ws reject $researchId --by 'human reviewer' --note '<actual deficiencies and requested corrections>'
# OR, only when acceptance is supported:
& $python .\bot.py -w $ws approve $researchId --by 'human reviewer' --note '<actual evidence checked and acceptance decision>'
& $python .\orchestrate.py -w $ws run $workflowId
```

Rejection returns the task to `active` and the graph keeps waiting on that same task. Revise and submit it again before later approval. Approval lets the next explicit graph `run` reconcile the completed task and wait on the next incomplete node. Repeat the normal start/work/submit/human-decision process for **every** remaining task. In a POSIX shell use `"$python" bot.py -w "$ws" ...` and `"$python" orchestrate.py -w "$ws" run "$workflow_id"` with the printed task IDs.

Graph resume payloads are internal wake-up signals, never approvals. Nodes can re-enter after interrupts or crashes, but their only work is reading the ledger and updating their own cursor. They do not call `start`, `prompt`, `run`, `submit`, or `approve`, and do not create duplicate ledger events. Already reconciled nodes are not dispatched again. Repeating `run` on a completed workflow does not create another checkpoint or perform completed work. Completion means the ledger tasks were approved; it does not mean any external operation occurred.

### Persistence, concurrent commands, and recovery

Runtime state is local plaintext in the workspace:

- `workflow.sqlite3`: existing authoritative tasks, decisions, events, artifacts, and workflow groups; the orchestrator opens it read-only.
- `langgraph.sqlite3`: independent LangGraph SQLite checkpoints, plus SQLite-managed WAL/SHM sidecars when present. Checkpoints contain task IDs, a definition fingerprint, cursor state, and interrupt metadata, not model prompts or credentials.
- `orchestration-lock.sqlite3`: separate SQLite transaction lock, serializing all graph `run` commands for this workspace. It is deliberately not the ledger or the checkpoint database.

An overlapping graph writer fails cleanly as busy rather than racing a checkpoint. The OS releases the SQLite lock when its process exits, including abrupt termination. Wait for the other invocation to finish, or deliberately terminate only the known stuck orchestration process after checking it; then invoke `run` again. **Never delete or replace a lock database while a process might hold it.** There is no PID guessing, stale lock expiry, automatic retry loop, or parallel dispatcher. `status` uses a consistent SQLite snapshot and can inspect while another process holds the writer lock. Keep workspaces on a local filesystem with reliable SQLite locking; this is not a distributed or multi-host worker system.

A stable SHA-256 fingerprint covers runtime format, workflow identity and definition, task identities/roles/scopes/acceptance, and dependency topology. A different graph cannot silently reuse the old cursor. The runtime also rechecks that previously reconciled tasks are still `done`. A mismatched definition or regression fails closed. Restore a matching ledger/checkpoint backup after investigation, or create a separately scoped new workflow group; there is no silent reset or checkpoint-as-approval shortcut. A crash before the initial state is established may require restoring the matching backup or using a new group, rather than accepting an unidentifiable partial checkpoint. There is no supported ledger edit/reopen path for approved tasks.

For backups, stop graph and ledger writers and use an approved SQLite backup procedure for the corresponding databases, including active WAL data. Do not copy a live database file by itself. Never import untrusted checkpoint files; strict LangGraph message-pack deserialization is enabled, but neither file permissions nor human approval are a sandbox. Do not ship workspaces, virtual environments, caches, or private data with portable source files.

## Explicit LangChain invocation through the existing reservation path

First authorize the data destination, provider, model, and cost; inspect `bot.py prompt TASK_ID`. The entire generated prompt is sent to the configured endpoint, including role instructions, task/history/artifact paths and immediate predecessor handoffs. Artifact file contents are **not** automatically included. Source text and model output are untrusted. The adapter has no tools bound and cannot itself browse, read artifacts, edit files, run code, or access a Hermes profile. A model's claim of performing such actions is not evidence.

The task must already be `active`. Use the virtual environment's **absolute Python executable path** and the adapter's **absolute script path**, because `bot.py` executes it from a new per-run working directory:

**PowerShell**

```powershell
$adapter = (Resolve-Path '.\langchain_adapter.py').Path
$model = '<replace with an explicitly authorized model identifier>'
& $python .\bot.py -w $ws run --adapter generic --timeout 120 $researchId -- $python $adapter --provider openai --model $model --request-timeout 60
& $python .\bot.py -w $ws show $researchId
```

**macOS / Linux**

```sh
adapter="$PWD/langchain_adapter.py"
model='<replace with an explicitly authorized model identifier>'
"$python" bot.py -w "$ws" run --adapter generic --timeout 120 "$research_id" -- "$python" "$adapter" --provider openai --model "$model" --request-timeout 60
"$python" bot.py -w "$ws" show "$research_id"
```

For Anthropic, install its integration and select `--provider anthropic` with an explicitly authorized Anthropic model. There is no provider/model inference or default credential. `--request-timeout` is a finite positive SDK timeout (default 60 seconds); the existing ledger's `--timeout` is the outer subprocess deadline. SDK timeouts may apply per network operation; the ledger deadline bounds the direct child process overall.

The adapter reads the **entire** UTF-8 stdin prompt up to **1 MiB**. Empty, invalid UTF-8, or oversized input fails without silently truncating it or invoking a model. Reduce context deliberately instead. It emits only authentic nonempty model text to stdout, preserving Unicode and text whitespace. Empty, reasoning-only, tool-only, or mixed text/tool-call responses fail rather than becoming false successful handoffs. No tools are executed. The adapter sets `max_retries=0`, has no framework retries or fallback provider, disables LangSmith/LangChain tracing for the invocation, and suppresses SDK debug output and raw errors. Errors are generic and non-sensitive; no provider traceback or rejected argument value is emitted. This is not content redaction: authorized prompts and authentic responses must themselves be free of secrets.

The unchanged `bot.py run` transaction reserves `active -> running` before launch. A zero exit records authentic output artifacts and moves to `review`, **never** `done`; a human must inspect the actual output and explicitly approve/reject. Launch failure, nonzero exit, or timeout follows existing `run-failed -> blocked` handling. Resolve the cause before explicit `resume`. If a crash leaves `running`, inspect surviving processes and real outputs, then use the existing `recover-run` procedure before any new explicit model run. The graph never retries these operations. See [README failure/recovery rules](README.md#optional-explicit-cli-execution).

### OpenAI-compatible endpoint opt-in

`--base-url` is supported **only** for `--provider openai`, through the official `ChatOpenAI` `base_url` option. The adapter forces the ordinary Chat Completions API (`use_responses_api=False`) and does not enable hosted tools or server-side conversational state. Use an authorized implementation of that API; nonstandard extensions and any particular proxy/provider are not assumed compatible.

An explicit URL must be HTTPS, or HTTP on literal loopback/`localhost` for an intentionally local endpoint. Credentials/userinfo, query parameters, fragments, whitespace/control characters, and invalid ports are rejected without echoing the URL. These checks do not authorize a destination or protect against a malicious server, DNS/proxy configuration, or inherited SDK settings. Audit the separately supplied environment privately. Never place tokens in any URL path either.

For an already-running, explicitly authorized **throwaway local** OpenAI-compatible server, the same command may add:

```text
--base-url http://127.0.0.1:8000/v1
```

Use the server's actual local port and model identifier. The OpenAI SDK still expects its usual environment key; if a local test server ignores authentication, configure a non-secret placeholder only in that isolated smoke-test process environment. The production adapter never creates a placeholder or substitutes fallback credentials. Do not point real credentials or controlled data at a test server. No local test server is included or automatically started by this project.

## Local checks and evidence boundaries

The existing base checks remain available with ordinary Python 3.9+. The new tests skip optional-package-dependent cases when those dependencies are absent. After installation, a maintainer can run the full suite once from this directory:

```powershell
& $python -m unittest discover
```

```sh
"$python" -m unittest discover
```

`test_orchestration.py` uses real temporary ledger databases, genuine LangGraph/SQLite checkpoints, separate subprocess resumes, review/rejection/block gates, completion, graph fingerprint checks, and a real cross-process SQLite lock. Its non-replay failure case runs the standard-library JSON parser against a non-JSON prompt; it is not a mock model or a success handoff. `test_langchain_adapter.py` checks bounded UTF-8 input, safe arguments/URLs, missing optional packages, and genuine LangChain message text extraction without contacting a provider. No permanent mock provider, echo handoff, or forwarding adapter is supplied. These tests do not establish real provider access; a separately authorized local OpenAI-compatible smoke test can exercise the actual LangChain/SDK request path without a paid provider.

Windows verification used Python 3.13 in `.venv-orchestration` with the three pinned core packages and `langchain-openai==1.7.3`: all **29 tests passed**. A disposable copied-source smoke run exercised real LangGraph/SQLite interrupt/resume through rejection, blocking, approval and completion, with no duplicate ledger events or automatic execution. The existing `bot.py workflow list` also ran under Python `-S`, without site packages.

The same smoke used the real LangChain/OpenAI SDK against a throwaway loopback HTTP fixture. Nonempty Unicode text reached ledger review; an HTTP 429 failed once without retry or exposing its raw error marker; a tool-only response failed rather than producing a handoff. Three requests were observed for the three explicit attempts, with none replayed by graph resume. The fixture returned synthetic protocol responses, not model-generated research. Its server and temporary records were removed afterward. No paid provider call or real credential was used. Anthropic live transport, external OpenAI/proxy endpoints, Envision model routing, model quality, and macOS/Linux remain unverified.

## Official references

- [LangGraph interrupts and resume semantics](https://docs.langchain.com/oss/python/langgraph/interrupts)
- [LangGraph persistence](https://docs.langchain.com/oss/python/langgraph/persistence)
- [LangGraph SQLite checkpointer](https://pypi.org/project/langgraph-checkpoint-sqlite/3.1.3/)
- [Pinned LangGraph release](https://pypi.org/project/langgraph/1.2.19/) and [LangChain release](https://pypi.org/project/langchain/1.4.7/)
- [LangChain `init_chat_model`](https://reference.langchain.com/python/langchain/chat_models/base/init_chat_model)
- [ChatOpenAI integration and custom base URL](https://docs.langchain.com/oss/python/integrations/chat/openai)
- [ChatAnthropic integration](https://docs.langchain.com/oss/python/integrations/chat/anthropic)
- [Disabling tracing with `tracing_context`](https://docs.langchain.com/langsmith/trace-without-env-vars)
