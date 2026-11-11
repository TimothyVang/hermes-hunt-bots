# Portable Hermes Bot Framework

This directory is the portable source project for approved Windows, macOS, or Linux machines: a human-operated task ledger, workflow templates, six Hermes bot identities, native defensive threat-hunt skills, a guarded profile/component installer, a source-only ZIP exporter, optional LangGraph/LangChain integration, and a built-in Windows Elastic + Arkime hunting lab. It excludes Hermes itself, live profiles, credentials, model providers, and the surrounding research and GitLab downloads.

The threat-hunt experience runs in **native Hermes**: the coordinator uses Hermes `delegate_task` and its native per-task delegation strategy. OMP is a development tool, not a product runtime dependency. The skill and ledger do not provide isolation or authenticated approvals. Start with [portable installation and native delegation](hermes-setup.md#native-hermes-threat-hunting), the [bot pack](hermes-bots/README.md), and [optional LangGraph/LangChain execution](optional-runtime.md). Opening this folder does not install bots, execute workflows, or call providers.

The native roster uses six cybersecurity roles: **Incident Response Lead**, **Threat Hunter**, **Detection Engineer**, **Purple Team Analyst**, **Threat Intelligence Analyst**, and **Network Analyst**. The Network Analyst analyzes approved, human-prepared sanitized Arkime/Wireshark summaries that exclude SSIDs, headers, credentials, cookies, authentication payloads, and authentication/session data, or the loaded lab case through its owned tools: Arkime session metadata and `packet_fields`, decoded allowlisted fields of the case's saved capture with secrets removed (accepted decision ADR 0003 in the planning notes). It must not capture live traffic, open raw captures, packet bytes or tool views other than through those tools, operate Wireshark, or connect to an Arkime endpoint. Existing `framework-*` profile IDs and ledger role identifiers are retained. Installing the role does not authorize connection, capture or collection.

The separate [optional Envision job bridge](#optional-envision-job-bridge) uses only the standard library and does not change the ledger or require Hermes. It is not automatically installed, started, or included in the fixed Hermes ZIP export.

The [optional Temporal integration](hermes_temporal/README.md) adds durable, separately human-gated native Hermes turns, local dispatch receipts, and explicit unknown-outcome reconciliation. Its `hermes_temporal.cli hunt WORKFLOW_ID --input JSON` entrypoint builds a bounded, serial, six-profile supplied-evidence hunt from explicitly supplied inline synthetic evidence; it does not fetch locators or begin paid execution. Optional ontology/context selections and the strict handoff contract are documented in the guide; without an ontology, existing free-text behavior remains. The Temporal stage sequence is serial even though native Hermes `delegate_task` can support parallel-ready branch work; neither implies automatic approval. Every stage still requires human execute and review decisions. Unknown results require reconciliation and do not supply reviewed predecessor output. Temporal is only the outer durability layer: it does not prove model identity or enforce per-role child tools through `delegate_task`, authenticate approval, sanitize evidence, or make hunting autonomous. The integration is included as source in the portable ZIP; the SDK and server are separate opt-in installations. It does not move agent delegation into OMP or require LangGraph. The [native threat-hunt skill](hermes-skills/threat-hunt/SKILL.md) describes native collaboration guidance; authored source guidance does not itself update existing installed profiles. The constructor/API smoke used synthetic handoffs and no provider calls; it is not proof of live model collaboration. 

The [Bot Mode compatibility matrix](desktop/BOT-MODE-COMPATIBILITY.md) covers every section of the official guide, native offline checks, known guide/source discrepancies, and remaining Desktop/guest/provider acceptance checks. Source support does not mean a working live deployment.

The opt-in [native security-audit skill](hermes-skills/security-audit/SKILL.md) incorporates Cloudflare's public vulnerability-audit workflow: scoped reconnaissance, coverage-led hunting, adversarial validation, structured verdicts and fresh record verification. [Provenance and verification](hermes-skills/security-audit/PROVENANCE.md) preserve its MIT license and pinned source. All 65 validator tests passed on Linux; the native Windows CLIs intentionally refuse input because required OS file-opening protections are unavailable. This is not Cloudflare's private fleet harness, an audit result, or permission to run target code.

The separate [framework-managed threat-hunt benchmark](benchmarks/README.md) runs all six cybersecurity identities as a fully automatic seven-stage AI team: stages advance without human gates (recorded as unreviewed `auto_advance`, never as human approval), calls run concurrently, truth is frozen at `init`, and scoring is mechanical by default with optional human adjudication as a separate cohort. Its coverage catalog is a target matrix, not live-support evidence. Model execution still needs `--allow-model-execution` and a configured team; the separately supplied range kit needs explicit lab authority. It does not replace native Hermes routing or repair Desktop group execution. `benchmark.py diagnose` reports per-stage/role errors on development cases only, holdouts are guarded by a retirement registry, and the [OTRF and attack_data importers](benchmarks/importers/README.md) turn public recordings into cases.

On Windows, run `py -3 .\setup_hermes.py check`, then deliberately run `py -3 .\setup_hermes.py install`. This preserves existing exact authored profiles, uses Hermes's normal confirmation for new profiles, and installs/enables the built-in lab backend and Desktop components. On macOS/Linux use `python3`; the ledger remains cross-platform, but automatic lab provisioning currently requires Windows x64. Install Hermes separately and sign in locally only when model execution is wanted. Copying the source kit does not transfer an account or establish a working Bot Chat.

## Built-in local hunting lab

Normal framework setup includes the lab; there is **no separate QEMU, Docker, Ubuntu, pycdlib, or ISO installation for the user**. In a compatible native Hermes Desktop, open **Cybersecurity workspace → Open hunting lab**, or the **Hunting Lab** sidebar entry. Find the local framework profiles, select `framework-network-analyst`, then click **Start lab VM**.

The first explicit Start downloads hash-pinned public prerequisites, extracts QEMU without executing its installer, prepares the guest, and boots it. Docker and the digest-pinned Elasticsearch 8.19.23 / Arkime 6.9.1 images are installed inside the guest. **Prepare lab assets** is optional and does not boot. Opening/importing the framework, setup, help, check, and status do not download or start the VM; a valid existing deployment is reused unchanged.

Requirements: Windows x64, Windows Hypervisor Platform already enabled, at least **5 GiB available RAM** and **37 GiB free disk** for first preparation. The guest uses 4 GiB RAM, two vCPUs, and a 32 GiB virtual disk. Initial setup requires Internet and large public downloads; the framework does not request elevation, enable Windows features, or silently fall back to software emulation. Compatible native SDK profile CLI requests and `SandboxedFrame` are required; the installer does not patch Hermes itself.

The bundled `dns-lab-001` case contains 40 invented events and a 32-packet DNS capture, producing 16 Arkime sessions. Human-only Arkime inspection is separate; choose **All (careful)** or April 15, 2025, 09:00–09:10 UTC because the recent default window excludes this historical fixture.

**Per-bot lab tools.** Each specialist owns read-only tools in toolset **`hunt_lab`**: Threat Hunter `elastic_search`, `elastic_aggregate`, `lab_browser`, `packet_fields`; Network Analyst `arkime_sessions`, `arkime_unique`, `hunt_lab_query`, `lab_browser`, `packet_fields`; Threat Intelligence Analyst `intel_lookup`, `elastic_aggregate`; Detection Engineer `detection_test`, `elastic_aggregate`; Purple Team Analyst `elastic_search`, `arkime_sessions`, `detection_test`. The Incident Response Lead has no lab tools and sends follow-up questions to the owning specialist through `delegate_task`. The ownership map is `TOOL_OWNERSHIP` in `hunt_lab/query_adapter.py`; `native_team.py` writes the same lists as `agent.allowed_tool_names`. **Ownership is enforced at runtime by registration:** the plugin registers only the profile's owned tools (none for the Incident Response Lead or any unknown profile), so a call to another bot's tool never reaches the model's tool list and Hermes's existing unknown-tool check refuses it before anything runs (`test_hunt_lab_tools.RegistrationTests`). Stock Hermes still ignores `agent.allowed_tool_names` itself; core tools such as `terminal` are kept out by the `platform_toolsets.cli` and `agent.disabled_toolsets` values that `native_team.py apply` writes. No live refusal run is recorded yet; in the recorded live hunts, made before this change, no bot called another bot's tool. Every query tool goes through the guest lab service on the forwarded lab port, which scopes each query to the loaded case (Elastic `event.dataset`; Arkime tag `case:<id>` and the case window; packet fields the case's own saved capture), bounds sizes, allows only Arkime's session and unique-value read routes (never delete, tag, hunt, pcap or user routes), and records each call in a read-only `/activity` log. `lab_browser` is the exception: it opens Arkime's own pages, so it enforces the same limits inside its browser (next paragraph). No tool can control the VM, capture traffic, reach other indices or endpoints, or read an answer key.

**Packet fields.** `packet_fields` (guest route `/packets`) runs `tshark -r` on the loaded case's `evidence/traffic.pcap`, the file next to `case.json`, as an argument list without a shell, with a 20-second deadline and the 8 MiB output cap of the other backends; it never passes `-i` and writes no files. Each row is one matching frame with `frame.number`, `frame.time_epoch` and the requested fields from a fixed allowlist of 38 (IP addresses and ports, DNS names, types, rcodes and answers, HTTP host, method, URI, status, user agent, content type and length, TLS handshake type, SNI, JA3/JA3S/JA4 and record version, SMB2 command, file and tree names, Kerberos and NTLM user names and domain). Anything else is refused with `field_not_allowed`, so cookies, authorization headers, bodies, file data, raw bytes, passwords, hashes, tickets and challenges never leave the guest; `http.request.uri` is reduced to its path (a query string or fragment becomes `?[redacted]`) and URL userinfo is dropped. An optional display filter (at most 300 characters) is tokenized against a closed grammar: allowlisted fields except `http.request.uri` and `_ws.col.Protocol`, the protocols `ip ipv6 tcp udp dns http tls smb2 kerberos ntlmssp arp icmp` as bare tests, `== != > < >= <=` and `eq ne gt lt ge le` between a field and a number, IP address or double-quoted string without backslashes, `and or not && || !` and parentheses. `contains`, `matches`, `~`, slices, functions, `${}` references, `@`, membership sets and anything else are refused with `invalid_filter`, because a filter on a denied or redacted field would leak it one guess at a time. On first use the guest asks `tshark -G fields` once which allowlisted fields its tshark knows; a field it lacks is refused with `field_unavailable`. tshark failures are `packet_tool_error`, an overrun deadline is `packet_tool_timeout`, and tshark's own text is never relayed. A case with `"network_capture": "none"` answers `no_network_capture`. These guest checks are enforced and covered by `test_lab_server.PacketFieldsTests` with a faked tshark; no live tshark run is recorded yet. The guest installs Ubuntu 22.04's `tshark` package (3.6.x): `tls.handshake.ja4` exists only from Wireshark 4.2 and reports `field_unavailable` there, while JA3/JA3S exist from 3.6.0. The tool description tells bots to cite a frame as `frame-<frame.number>` next to the matching `evt-` events; the scorer credits such a frame when the case's key lists it (see Loading a larger case).

**Lab browser.** `lab_browser` drives a dedicated, real Chromium-family browser on the lab's own web tools: Arkime's Sessions and SPI View pages and the lab console. A bot opens a page, gets a snapshot of its interactive elements with refs (`e1`, `e2`, ...) from the accessibility tree, then clicks, types into or reads an element by ref, presses an allowlisted key, or scrolls. Before a click the element must be visible, enabled, inside the viewport and not covered (an `elementFromPoint` hit test adapted from the MIT omp browser tool). The pointer travels an eased, slightly bent Bezier path with small jitter and occasional overshoot, and keys arrive with a varied rhythm (`hunt_lab/humanize.py`), all as CDP `Input` events. Enforced at runtime, with tests: every request pauses in CDP `Fetch` and fails unless its origin is exactly the lab or Arkime URL from the runtime status; every Arkime search request (query and body, GET and POST) leaves the browser as `(<expression>) && tags == "case:<id>"` with its time range clamped to the case window; Arkime write, export, packet, file and admin routes fail; downloads are denied and popups closed. Launch flags add a second fence that holds even with no CDP client attached: all traffic goes to a dead proxy except the two lab ports (observed against the live lab; a test pins the flags). The browser uses its own profile under the analyst profile's `hunt-lab-browser/<bot>/`, runs headless unless demo mode (below) or `HUNT_LAB_BROWSER_HEADED=1` asks for a window, and is `HUNT_LAB_BROWSER` or Microsoft Edge on Windows (chromium elsewhere). It needs the `websockets` package that Hermes ships. One browser per bot persists across that bot's calls and closes after 10 idle minutes or when the bot's process exits. Each action is appended to `hunt-lab-browser/<bot>/audit.jsonl` (time, action, page, ref, typed text, final URL, blocked-request count, and each lab request with its case-scoped expression); these calls bypass the guest service, so they do not appear in `/activity`. Arkime's own UI writes, such as saving field history, fail by design.

**Kibana Discover.** The guest also runs Kibana 8.19.23 (`guest/compose.yaml`, pinned in `guest/image-lock.json` by manifest and config digest) on the same Elasticsearch, and the runtime forwards it to a loopback port reported as `kibana_url`. `guest/kibana.yml` fixes a read-only analyst surface: Lucene as the query language with the same `query_string` options as `elastic_search` (fields, AND, no leading wildcards, lenient), so a query typed into Discover finds the same events; UTC dates; Discover as the default route; telemetry, newsfeed, the welcome screen, announcements, ES|QL and the Console UI off; value suggestions by aggregation. On every boot `guest/kibana_setup.py` points the filtered alias `hunt-lab-case-events` at the loaded case's `event.dataset`, makes it the default data view with `@timestamp` as its time field, and sets the time defaults and the one quick range to the case window; a failure prints a `stage=failed_kibana_*` line, and `/health` is ready only once the data view names the loaded case (`kibana_ready`). `lab_browser` page `kibana_discover` opens Discover on that data view and window with only the given `q`; in demo mode the query is typed into Kibana's query bar. In the browser the Kibana origin admits Discover's page, static bundles and the reads Discover 8.19 was observed to need. Each batch search must use the `ese` or `es` strategy, target the case alias and an allowlisted set of body keys, and is rewritten to also filter on the case window whatever the time picker says. Field lists must name the case alias, value suggestions are forced to `terms_agg`, and data view reads are allowed only for `index-pattern`. Every other route fails, among them saved-object and content writes, settings writes, `/api/console/proxy`, index management, alert creation and other apps; a page that leaves `/app/discover` is replaced by `about:blank` (`navigation_refused`). Expanding a document, adding a filter (Add filter) and adding a column (a field's preview) all work through the existing click, type and press by ref.

**Lab browser demo mode.** To film the bots, the operator writes `hunt-lab-browser/demo.json` under the analyst profile, beside the bots' browser profiles, for example `{"headed": true, "window": [0, 0, 1600, 1000], "cursor": true}`. Each key is optional: `headed` and `cursor` default to true, `window` (x, y, width, height) to `[0, 0, 1600, 1000]`, and `scale` is absent. A bot's browser reads the marker when it starts, and a running browser is reused only while the marker still asks for the window, cursor and scale it started with; otherwise it is closed and relaunched, because the gateway that hosts the tools keeps its browser between calls. `headed` opens a visible window at that position and size. `scale` (a number from 1 to 2) makes pages render larger for the camera: the browser starts with `--force-device-scale-factor=<scale>` and its window flags divided by `scale`, so the window keeps the marker's size in screen pixels while pages lay out in `scale` times fewer CSS pixels, with text `scale` times larger. Without `scale` the browser keeps the system's scale factor, and `window` is then in the system's device-independent pixels: on this workstation Edge reported a device pixel ratio of 1.22, so a 1280x1080 window was 1562x1318 screen pixels and its screencast frames 1538 pixels wide. With `"window": [200, 100, 1280, 1080]` the window measured 1280x1080 screen pixels at scales 1.5 and 2, with screencast frames 1247 and 1238 pixels wide (observed in a throwaway local Edge window, not yet in a filmed hunt). Pointer paths, clicks, typing, the actionability check and the cursor overlay all work in CSS pixels, which the scale factor leaves alone: in the same window a dispatched click at CSS (140, 215) reached the page at (140, 215) at every scale, and a test pins identical actionability and input traffic at scale 1.5. `cursor` draws the CDP pointer, which the browser never paints, as an arrow that follows each mouse move and ripples on each press. It is a script in its own isolated world that adds a `pointer-events:none` element in a closed shadow root on the top layer, so page scripts and CSS cannot reach it and hit tests (`elementFromPoint`, the actionability check, real clicks) pass through it. A test pins identical actionability and input traffic with the overlay on; the hit-test pass-through and the hostile-CSS case were observed by hand in headless Edge 157 on a local test page. In demo mode a search given to `open` (`expression` or `q`) is entered through the page's own search box: the tool loads the page without it, clicks the text field named "Search" in the page snapshot, types the search with the same pointer path and typing cadence as `type`, presses Enter, waits for the page to settle and returns the usual `open` result. The search then leaves the page as an ordinary request, so the same case tag and window rewriting applies. When the page has no such field or the entry fails, the tool opens the search URL as it does outside demo mode. Each audit line records `"entered"`: `"typed"`, `"url"`, or `"fallback:<reason>"` such as `"fallback:no_search_box"` (null for actions without a search). Tests pin the typed sequence, the unchanged URL path without the marker, and the fallback against a fake browser; the field names come from the lab console's markup and Arkime's search field and were not yet observed in a live demo run. A marker with an unknown key, a wrong type, an out-of-range window or a scale outside 1 to 2 is ignored whole: the browser stays headless with no cursor and no forced scale, and every audit line records `"demo":"invalid_marker"` (`"on"` when the marker applies). The tool only reads the marker and never writes it. `HUNT_LAB_BROWSER_HEADED=1` still opens a window, without the cursor, for manual runs, but the Temporal worker starts Hermes with a fixed environment (`_environment` in `hermes_temporal/execution.py`) that drops it, so a filmed hunt needs the marker.

Each tool's description lists the exact fields it accepts. For Elastic that is every field the scenario generator writes, including `winlog.event_data.*` such as the lsass-access `TargetImage` and `GrantedAccess`. A refused call returns a fixed code the bot can act on: `field_not_allowed` or `invalid_field_list` (a field outside the list), `leading_wildcard_not_supported`, or `invalid_query` (the backend rejected the syntax). The host relays only these codes, never free text. A test keeps the host's advertised lists equal to the guest allowlists.

The lab console (`/` and `/view` on the guest) and the `hunt_lab_query` `events` dataset search events with the same builder as `elastic_search`: a Lucene `query_string` over the same fields, scoped to the case, with the same leading-wildcard check and the same refusal codes. Both return every top-level object the scenario generator writes, including `user`, `group`, `file`, `service`, `url`, `http`, `tls`, `user_agent` and `observer`. The console prefills its Search (`q`) and Host boxes with the submitted values, shows `N of M events`, and on a refused query shows only the fixed code with HTTP 400. The `network` dataset keeps its simple query string over `dns.host` and `network.protocol`.

**Loading a larger case.** `python -m hunt_lab.scenario generate --size medium|large [--story a|b]` writes an invented case (events, pcap, intel feed, case metadata) and a separate operator-only key. Story `a` (the default) is an Office-macro intrusion; story `b` is a different organisation and a web-server-exploit intrusion with its own decoys, for testing that improvements generalise. With the VM stopped, `hunt_lab/prepare_guest.py reseed --update-deployment` builds a new setup disc with a new cloud-init instance ID. cloud-init runs setup once per instance ID, so loading the same case again (for example, switching back to it) writes a fresh `-load<N>` disc; earlier discs are never overwritten. On the next start the guest loads the case once, keeps earlier cases, and serves the new one. The key never enters the guest. Besides the event IDs of each evidence group, the key lists the frames of that group's network events in the written capture (`frame-<n>`, the same numbering as tshark's `frame.number`) and the intel record IDs (`ioc-NNNNN`, which `intel_lookup` returns as `id`) of the fact's domains and IPs those sessions carry; `python -m hunt_lab.scenario score --truth KEY REPORT` accepts any of them for the group. An intel ID is listed only in the first group of a fact whose sessions carry it, so a lookup alone never satisfies more than one group. Keys without these lists score on event IDs alone, exactly as before. A large story `a` key is about 2.4 MB because the fleet-wide decoys list tens of thousands of frames.

The same plugin adds a **Hunt Board** sidebar page for watching a running hunt. It embeds the read-only board served by `python -m hermes_temporal.board` on `http://127.0.0.1:8790/`, which must be started separately (see the [Temporal guide](hermes_temporal/README.md)). Nothing is fetched until you click **Show board**; the frame uses the Desktop's opaque-origin sandbox. The board shows only the workflow's real status, the bots' recorded outputs and, for tool-driven hunts, every lab tool call from `/activity`. Updating the page reuses the unchanged noVNC console bundle in `hunt_lab/desktop/plugin.js` and replaces only the trailing `plugin.entry.js` code, which is what `build_console.py` would produce from the same inputs.

Optional CLI controls use the same native owner, without creating a ledger:

```powershell
py -3 .\bot.py lab status
py -3 .\bot.py lab start
py -3 .\bot.py lab query --case-id dns-lab-001 --dataset events --q powershell.exe --limit 20
py -3 .\bot.py lab stop
```

Add `--home <approved-general-Hermes-home>` and `--hermes <executable>` after the lab action when using an isolated installation. State and downloads stay under the native analyst home's `hunt-lab-vm`, outside the source kit. Services bind host loopback only; there are no host shares or exposed Elasticsearch port. Outbound NAT remains enabled: this is **not air-gapped, authenticated multiuser hosting, or malware/CUI containment**. No AWS service, model call, live attack, or benchmark campaign starts automatically.

To export the bounded `dns-lab-001` responses for Temporal practice, first start and inspect the lab explicitly through the human-operated controls above. From `framework/`, write to a new file:

```powershell
py -3 -m hermes_temporal.cli lab-input --state-dir <approved-lab-state> --output .\synthetic-lab-hunt.json
```

The export reads the existing case/events/network responses; it neither starts/stops the lab nor connects to Temporal or calls Hermes/providers, and it refuses to overwrite the output file. It includes no scoring truth. Keep the operator-only truth and rubric out of the exported input and workflow; source-kit access is not blind-test isolation.

For finite practice, use the optional Temporal integration and its already-running local backend. The parent defaults to three rounds (1–10 allowed), reuses the same fixture rather than a holdout, and is not evidence of improvement. Each child hunt retains separate human execute and review gates at every stage; decisions target the exact child workflow ID shown by this form:

```sh
python -m hermes_temporal.cli practice synthetic-practice-001 --input ./synthetic-lab-hunt.json --rounds 3
python -m hermes_temporal.cli practice-status synthetic-practice-001
python -m hermes_temporal.cli decision synthetic-practice-001:round:001 --step-id scope --phase execute --choice approve --decision-id practice-001-r001-exec-scope
python -m hermes_temporal.cli practice-stop synthetic-practice-001
```

The parent advances only after a completed round and stops on every non-completed outcome; uncertainty never triggers replay. Stopping the parent does not prove that a child Hermes process or delegated descendant stopped. Inspect child status and approved runtime evidence. Native execution stays disabled by default; running practice with native execution requires an actually ready backend and bounded provider authorization, with no global spend cap. The new export and practice functionality is not live-verified.

The parent timeout is the requested round count multiplied by the per-round sum, over every hunt step, of `3 × approval_timeout_seconds + step.timeout_seconds + 140 seconds` (execute/review/reconciliation gate allowances plus activity schedule-to-close allowance). A structured step adds one more execute allowance and activity allowance for its one handoff-correction retry. This bounds the configured workflow wait, not provider spend or downstream Hermes execution.

The scripted synthetic verification reached the existing prepared Elastic/Arkime range (`/health` ready, 40 events, 16 sessions); `lab-input` exported 35,725 bytes with six evidence items. A real local Temporal/SQLite smoke completed 3 × 9 scripted activities with 54 simulated approvals, including same-store restart/recovery and separate stop/failure/abort cases. No Hermes/provider calls or human approvals occurred, no VM lifecycle action was taken, and this does not verify live native execution or an active hunt. Evidence and detailed caveats: [Temporal practice verification](hermes_temporal/README.md#current-synthetic-practice-and-lab-input-verification).

[`hunt_lab/case.py`](hunt_lab/case.py) supplies operator-side deterministic generation/scoring; it and generated grading keys are excluded from the installed bot package and guest. The source kit includes the grader, so same-account host tools are not blind-test isolation. [Setup details](hermes-setup.md#built-in-hunting-lab) describe the native component layout and version boundary.

### Operator scoring

From this framework directory, generate into **new, separate external directories**, never a live profile or source fixture:

```powershell
py -3 .\hunt_lab\case.py generate --evidence-dir C:/HuntRange/new-case/evidence --truth-dir C:/HuntRange/new-case/operator-only
py -3 .\hunt_lab\case.py score --truth C:/HuntRange/new-case/operator-only/truth.json --findings C:/HuntRange/new-case/operator-only/reviewed-findings.json
```

The deterministic generator reproduces the bundled invented case; it does not replace deployed evidence or implement arbitrary-log import. Findings contain `schema_version: 1`, `case_id`, and a `findings` array of `{fact_id,event_ids}` mapped by the operator after reviewing actual cited observations. Keep the key and fact-ID rubric from the bot. The scorer reports precision/recall over seven rubric facts, not semantic grading of free-form text or evidence of model accuracy. It is separate from `benchmark.py` campaigns and the unimplemented live Elastic source adapter.



## Native cybersecurity workspace companion

The original [Desktop SDK companion](desktop/REVIEW.md) adds a native workspace page, sidebar/palette/status entry, the six-role roster, explicit human-gate guidance, and an optional visible-pet reminder. Human clicks navigate to native Kanban, profiles, browser, Bot Screen, or the separate Hunting Lab page. The companion does not execute lab commands, read conversations, call models, execute tasks, write memory or record approvals. Its advisory gate graph is **not** native memory. Native HUD and memory graph controls remain native; no unsupported SDK bridge is used.

Normal `setup_hermes.py install` includes the companion and lab. The narrower `install_desktop.py check` / `install_desktop.py install --home <approved-home>` remain available for an explicit companion-only installation. Hash-owned packages can be updated; unknown destinations, user-modified managed files and aliases are refused. Review [provenance, licensing, permissions and prerequisites](desktop/REVIEW.md). No specialist SOUL edits, profile resets, cloning, provider setup or automatic task advancement occur.

[Timestamped video inventory](desktop/VIDEO-INVENTORY.md) covers the complete returned public transcript, not complete audiovisual coverage. [Verification and unresolved blockers](desktop/VERIFICATION.md) distinguish real native UI mounting, source-level group-routing fixes and tests from **unverified live runtime repair and the still-undemonstrated two-bot exchange**. The bundled runtime patch is review-only against its documented Hermes source base; the installer never applies it. Existing Astra/Luna/Terra requirements remain unchanged, with no fallback/substitution. Preserve the known completion-role-label inconsistency and the limits of child-reported identity.

## Setup and safety

The ledger needs Python 3.9 or newer and its standard library; it has no third-party Python dependencies. Copy the folder to the destination and open a terminal in it. Check Python and the CLI:

**Windows PowerShell**

```powershell
py -3 --version
py -3 .\bot.py --help
$ws = '.\bot-workspace'
py -3 .\bot.py -w $ws init
py -3 .\bot.py -w $ws list
```

**macOS / Linux**

```sh
python3 --version
python3 bot.py --help
ws=./bot-workspace
python3 bot.py -w "$ws" init
python3 bot.py -w "$ws" list
```

Run `init` once per new workspace; it refuses to replace an existing database. The remaining worked example uses PowerShell; on macOS/Linux use `python3 bot.py`, `"$ws"` for the workspace argument, and `/` for path separators. To create a workspace with a different name, pass its path with `-w` before the subcommand.

`-w` must precede the subcommand and can point anywhere you have permission to write. Without it, the workspace is `./bot-workspace` relative to the current directory. Initialization creates the directory if needed and creates `workflow.sqlite3` exclusively; if that file exists, initialization fails rather than overwrite it. The SQLite file contains all task text, notes, decisions and artifact paths in plaintext. Restrict filesystem access and back it up appropriately; avoid secrets, credentials, cookies, personal information, or account/session data in the ledger, prompts, or artifacts. The tool does not scan or redact content. Do not give an agent access to a workspace containing information it should not see. Close running commands before copying the database for a backup.

This is a coordination aid, not a sandbox or permission enforcement system. Role boundaries and human review are instructions and procedures, not access controls; actors supplied via `--by` are self-reported, not authenticated. Use your agent's own permissions and isolation. Do not execute real trades; even demo trading requires explicit user intent. External CLIs can take actions or contact services under your account; approval here does not override applicable policies or grant access to external systems.

## Worked example: summarize meeting notes

The included `examples/meeting-notes.txt` is a small real input. First create a researcher task and then a dependent reviewer task; IDs below assume a freshly initialized workspace. `--depends-on` can be repeated. Dependencies must already exist, so the creation order is a directed acyclic graph.

```powershell
py -3 .\bot.py -w $ws add --title 'Summarize the reading group meeting' --role researcher --scope 'Use only examples/meeting-notes.txt; do not alter the source.' --acceptance 'Identify the decision, owner and deadline of the action, and the open question, with the source path.'
py -3 .\bot.py -w $ws add --title 'Review the meeting summary' --role reviewer --scope 'Compare the researcher handoff to the original meeting notes.' --acceptance 'Identify inaccuracies or explicitly confirm each decision, action, deadline and open question against the source.' --depends-on 1
py -3 .\bot.py -w $ws start 1
py -3 .\bot.py -w $ws prompt 1
```

Give the printed prompt and the source file to a human or agent that is authorized to read them. Review all content before sharing it externally. Ask for a concise sourced summary, then record the **actual** handoff and evidence using `submit`. For this specific file, an accurate example handoff is:

```powershell
py -3 .\bot.py -w $ws artifact 1 --path .\examples\meeting-notes.txt --description 'Original meeting notes used for verification'
py -3 .\bot.py -w $ws submit 1 --by 'researcher' --note 'Source: examples/meeting-notes.txt. Decision: meet at the library on the first Saturday monthly. Action: Maya asks the library about room availability by October 15. Open question: provide books or ask participants to bring their own.'
py -3 .\bot.py -w $ws show 1
```

A human checks the source and handoff, then explicitly approves it. Do not issue the following approval until that review actually occurs. The second task cannot start until its prerequisite is approved. The reviewer should inspect both the source and the predecessor's `show` output; `prompt 2` includes the immediate predecessor's stored task, handoff history and artifact paths, but not artifact file contents.

```powershell
py -3 .\bot.py -w $ws approve 1 --by 'human reviewer' --note 'Checked the handoff against examples/meeting-notes.txt; all three requested items match.'
py -3 .\bot.py -w $ws start 2
py -3 .\bot.py -w $ws show 1
py -3 .\bot.py -w $ws prompt 2
```

Have an independent reviewer compare the handoff and file, record their actual result with `submit 2 --by reviewer --note '...'`, then a human reviews and records the actual decision with `approve 2 --by 'human reviewer' --note '...'`, or returns it for revision with `reject 2 --by 'human reviewer' --note '...'`. Replace the example ellipses with substantive observed findings; the CLI requires a nonempty note but cannot judge its truth. Nothing automatically verifies an assertion or reads an artifact into the prompt. Don't reuse the illustrative approval unless you performed that check.

## State and handoffs

- `pending -> active` with `start`; all prerequisites must be `done`.
- `active -> blocked` with `block ID --by NAME --note 'blocker and needed decision'`; after addressing the blocker, `resume ID` returns to `active`.
- `active -> review` with `submit ID --by NAME --note 'results and evidence'`; this is the handoff to a human, not completion.
- `review -> done` with `approve ID --by NAME --note 'review and evidence checked'`, or `review -> active` with `reject ID --by NAME --note 'findings and requested revision'`. Submit again after revision.

`list` displays the board and `show ID` displays the full task, dependency statuses, linked artifacts and chronological event history. Every state change is recorded. `prompt ID` prints the appropriate role text, task and history, followed by each immediate predecessor's stored task, history and artifact references, explicitly labeled untrusted. It does not recursively expand ancestors or read artifact files; inspect and supply approved source/output files separately when needed. Notes should state what was actually done, where evidence is located, what remains uncertain, and what decision is needed. `artifact ID --path FILE --description TEXT` records the absolute path of an existing file; it does not copy, snapshot, hash, open, verify, or protect the file, which may later change or disappear. Workspace database writes are transactional, but multiple operators should coordinate responsibilities and avoid editing the database directly. The CLI has no claim/lock ownership, editing, deletion, scheduling, notifications, model routing, or automated retry; create another task if scope changes.

## Reusable human-operated workflows

Workflow templates describe task records and dependencies, not executable commands. They reuse the same manual `start`, `prompt`, `submit`, `approve` and `reject` steps as individual tasks. Creating a workflow never runs an agent, invokes a model, installs a profile, starts a task, approves work, or publishes anything.

| Bundled template | Required handoff sequence |
| --- | --- |
| `research-review` | `research` (researcher) → `review` (independent reviewer) → `synthesis` (coordinator) |
| `build-review` | `requirements` (researcher) → `build` (builder) → `review` (independent reviewer) → `handoff` (coordinator) |
| `threat-hunt` | `scope` (coordinator) → `evidence` + `hypotheses` (researchers, parallel after scope approval) → `analysis` (researcher) → `review` (reviewer) → `handoff` (coordinator) |
| `evidence-acquisition` | `scope` (coordinator) → `acquire` (human operator runs imager) → `verify` (independent reviewer runs `imager verify`) → `handoff` (coordinator) |

`threat-hunt` is a defensive, supplied-evidence workflow: approve the source/time/authority boundary first; evidence and hypothesis work can then proceed independently. Analysis joins both handoffs, and review and final handoff remain gated by human approval. The hunt is not autonomous collection, a security boundary, or incident response.

Research uses only the operator-approved supplied sources. Keep original source facts separate from AI-generated notes, inference and unknowns; include source locators and disclose coverage limits. The builder implements only agreed changes. The reviewer checks actual sources or changes independently and records findings, not an automatic approval. The coordinator reconciles evidence and unresolved issues into a decision handoff, not a publication or deployment. Later steps also depend directly on earlier evidence-producing steps so their stored handoffs appear in the generated prompt.

### Create and inspect

From the portable folder, use the initialized `$ws` from setup (or an existing workspace you intend to extend):

```powershell
py -3 .\bot.py workflow list
py -3 .\bot.py workflow show research-review
py -3 .\bot.py -w $ws workflow create research-review --title 'Review the reading-group decision' --scope 'Use only examples/meeting-notes.txt, supplied separately; no browsing, downloads, or source edits.' --acceptance 'Trace the decision, action owner and deadline, and open question to the supplied source; report uncertainties.'
```

`workflow list` and `workflow show TEMPLATE` need no workspace and do not create one. `show` prints the validated JSON in dependency order. `create` prints `Created workflow N: TITLE`, followed by `KEY: TASK_ID` lines. Record that mapping: workflow IDs and task IDs are separate identifiers and need not match. Every task is created as `pending`, with the workflow title and labeled operator scope/acceptance in addition to its step scope/acceptance.

Creation adds the workflow group, all member tasks, dependencies and creation events in one transaction. Existing manual tasks and history are preserved; existing ledgers receive the additive workflow tables on their first successful workflow creation, without reinitialization. An invalid template or a failed write does not leave a partial group. Close other writers and back up an important existing ledger before changes.

Assign these variables from the actual printed IDs; the following values illustrate a fresh workspace's first `research-review` workflow only:

```powershell
$workflowId = 1
$researchId = 1
$reviewId = 2
$synthesisId = 3
py -3 .\bot.py -w $ws workflow status $workflowId
py -3 .\bot.py -w $ws ready
py -3 .\bot.py -w $ws start $researchId
py -3 .\bot.py -w $ws prompt $researchId
```

`workflow status ID` shows member keys, task IDs, roles, statuses, and ready/blocker information. `ready` is a read-only list of **all** pending tasks in the workspace whose prerequisites are `done`, including manual tasks and other workflows. It neither claims nor starts tasks and is not a scheduler. Active, blocked, running, review, and done tasks are not ready.

### Perform, review, and finish each handoff

A person can do the entire workflow without a model. Alternatively, after separately authorizing the destination and tools, pass a reviewed prompt and approved source files to any suitable agent or an existing Hermes bot. A prompt contains immediate predecessor notes and paths, not the contents of evidence files; inspect those files separately. Treat both source material and agent output as untrusted.

After real research, record its evidence. The quoted angle-bracket text below is an instruction to replace it with actual findings, **not** an example result or approval to reuse:

```powershell
py -3 .\bot.py -w $ws submit $researchId --by 'researcher' --note '<actual sourced findings, coverage, uncertainties and evidence paths>'
py -3 .\bot.py -w $ws show $researchId
```

A human compares each criterion with the source and handoff. Only after that check, choose **one** decision:

```powershell
py -3 .\bot.py -w $ws reject $researchId --by 'human reviewer' --note '<actual issues and required corrections>'
# OR, only when the evidence supports acceptance:
py -3 .\bot.py -w $ws approve $researchId --by 'human reviewer' --note '<actual evidence checked and acceptance decision>'
```

Rejection returns the task to `active`; revise and `submit` it again before any later approval. A submission in `review` is not enough to unlock its dependents. After actual research approval, `ready` will include the reviewer:

```powershell
py -3 .\bot.py -w $ws ready
py -3 .\bot.py -w $ws start $reviewId
py -3 .\bot.py -w $ws prompt $reviewId
```

Use an independent reviewer where possible and disclose any independence limitation. The reviewer submits actual checks and findings using `submit $reviewId`; a human inspects the evidence and explicitly approves or rejects that reviewer task using the same decision procedure. Approval of research does not prove it correct, and approval of a review does not silently fix issues it identified. If a prior approved task needs correction, stop and create a separately scoped correction task or a revised workflow, then carry the actual reviewed disposition into the handoff; there is no reopen/edit command or automatic revision loop.

Only after reviewer approval, explicitly `start $synthesisId`, inspect `prompt $synthesisId`, and prepare the final synthesis. Record it using `submit $synthesisId --by coordinator --note '<actual synthesis, evidence, review disposition and requested decision>'`. A human must review and explicitly `approve` or `reject` this coordinator task too. Finish with `workflow status $workflowId` to inspect all member states. All `done` means the ledger handoffs were approved, not that publication, deployment, messaging, or other external action occurred or was authorized.

For `build-review`, use the same procedure with its printed `requirements`, `build`, `review`, and `handoff` task IDs; the builder does only the human-approved change, and every role must pass normal submission and human approval. `block`/`resume` remain available for active work that needs a decision. The [optional CLI adapters](#optional-explicit-cli-execution) also work on explicitly started workflow tasks; they do not bypass review or automatically run the next step.

### Use the defensive threat-hunt template

The bundled `framework/workflows/threat-hunt.json` records the exact scope, evidence, hypotheses, analysis, review, and handoff task graph. From `framework/`, list/show it and create a workflow in an initialized workspace:

```powershell
py -3 .\bot.py workflow list
py -3 .\bot.py workflow show threat-hunt
py -3 .\bot.py -w $ws workflow create threat-hunt --title 'Bounded synthetic supplied-evidence hunt' --scope 'Use only examples/synthetic-hunt-events.json supplied separately; it is invented offline data. Record approved source, time range, authority and exclusions; no browsing or collection.' --acceptance 'Provide cited observations, evidence sufficiency, alternatives, bounded conclusions, coverage and unresolved-finding disposition.'
```

On macOS/Linux use:

```sh
python3 bot.py workflow list
python3 bot.py workflow show threat-hunt
python3 bot.py -w "$ws" workflow create threat-hunt --title 'Bounded synthetic supplied-evidence hunt' --scope 'Use only examples/synthetic-hunt-events.json supplied separately; it is invented offline data. Record approved source, time range, authority and exclusions; no browsing or collection.' --acceptance 'Provide cited observations, evidence sufficiency, alternatives, bounded conclusions, coverage and unresolved-finding disposition.'
```

Use the printed task-ID mapping with `workflow status ID`, `ready`, `start TASK_ID`, `prompt TASK_ID`, `submit`, and a human's explicit `approve` or `reject` for every task. Approving `scope` unlocks `evidence` and `hypotheses`; `analysis` requires both. Reviewer rejection prevents the final handoff from starting until the review is revised, resubmitted and approved. Prompts contain immediate predecessor histories and artifact paths, never artifact contents; manually supply only approved evidence to an authorized person or agent. No browsing, live telemetry, network scans, tool execution, remediation or production mutation is part of the workflow; separately authorize any such activity. Private archives, `.env`, credentials, profiles, logs, and account data are out of scope. Findings and role instructions are procedural, not enforced access controls; missing telemetry cannot prove absence, and the workflow does not assert compromise or its absence automatically. Workflow creation does not create or configure Hermes bots; see [Hermes setup](hermes-setup.md) for optional manual use and its limitations.

`examples/synthetic-hunt-events.json` is a fictional, offline fixture, not observed activity or a hidden-truth/parity benchmark. Inspect and supply it separately; artifact paths in prompts are references only.

### Acquire evidence with imager (`evidence-acquisition`)

`evidence-acquisition` connects the separate [imager](../imager/README.md) forensic tool to the ledger. The framework never launches, schedules or wraps acquisition: a human operator runs `imager` from an elevated prompt, and `imager_import.py` only reads the JSON record imager wrote. Do **not** use `bot.py run --adapter generic` for imager; that adapter hands a prompt to an agent CLI and would let an agent start raw-disk reads.

`imager_import.py [-w WS] TASK_ID RECORD [--kind image|collect|verify] [--base-dir DIR] [--by NAME] [--no-submit]` accepts the `image` record `BASE.json`, saved `collect --json` output, or saved `verify --json` output (UTF-8 or the UTF-16 that PowerShell 5 `>` writes). It:

- refuses a missing `schema_version` or a major version other than 1;
- refuses if any referenced file is missing (relative paths resolve against the record's directory unless `--base-dir` is given);
- re-hashes every file with SHA-256 and refuses with exit code 3, recording nothing, on any mismatch: raw segments against the record's image SHA-256 and byte count, `BASE.json` against the `Record SHA256` line in `BASE.txt`, a collect container against `container_sha256`, a raw image against `verify`'s computed SHA-256, and any imager verification that did not match;
- registers each file through `bot.py artifact` with description `imager <role>: sha256=<hex> bytes=<n>` (image: `BASE.json`, `BASE.txt`, every segment; collect: the record, `CopyLog.csv`, `SkipLog.csv`, VSS logs, or the container; verify: the record, the image, the sidecar);
- if the task is `active` (and `--no-submit` is absent), records a factual `submit` note with the record SHA-256, image hashes, bytes, bad-sector count, verification result and every artifact hash. Otherwise it registers artifacts only.

It never approves; a human still runs `approve` or `reject`. E01 segment contents are checked by `imager verify` (embedded and sidecar hashes), not by the helper. Assign the task IDs from the printed `workflow create` mapping; the values below illustrate a fresh workspace.

Windows (PowerShell; run imager in an **Administrator** window, the ledger commands in any window):

```powershell
cd framework
$ws = "$env:TEMP\case-0001-ledger"
py -3 .\bot.py -w $ws init
py -3 .\bot.py -w $ws workflow create evidence-acquisition --title 'Case 0001 USB image' --scope 'Image only \\.\PhysicalDrive2 (serial recorded in scope) to E:\cases\0001; authority ref AUTH-0001.' --acceptance 'E01 acquired, independently verified, every artifact hash recorded.'
# scope: 1, acquire: 2, verify: 3, handoff: 4
py -3 .\bot.py -w $ws start 1
py -3 .\bot.py -w $ws submit 1 --by coordinator --note 'Authority AUTH-0001; source \\.\PhysicalDrive2 SanDisk 32GB serial ...; E01 to E:\cases\0001; case file E:\cases\0001\case.json'
py -3 .\bot.py -w $ws approve 1 --by 'Jane Examiner' --note 'Scope approved'
py -3 .\bot.py -w $ws start 2
# Administrator prompt, operator only:
imager image --source \\.\PhysicalDrive2 --out E:\cases\0001\usb --case-file E:\cases\0001\case.json
py -3 .\imager_import.py -w $ws 2 E:\cases\0001\usb.json --by operator
py -3 .\bot.py -w $ws approve 2 --by 'Jane Examiner' --note 'Acquisition record reviewed'
py -3 .\bot.py -w $ws start 3
# Reviewer (independent of the operator):
imager verify E:\cases\0001\usb.E01 --json | Set-Content -Encoding utf8 E:\cases\0001\usb.verify.json
py -3 .\imager_import.py -w $ws 3 E:\cases\0001\usb.verify.json --by reviewer
py -3 .\bot.py -w $ws approve 3 --by 'Jane Examiner' --note 'Independent verify matched'
py -3 .\bot.py -w $ws show 2
certutil -hashfile E:\cases\0001\usb.E01 SHA256
```

For triage, the operator instead runs `imager collect --target KapeTriage --source C: --dest E:\cases\0001\triage --case-file E:\cases\0001\case.json --json | Set-Content -Encoding utf8 E:\cases\0001\collect.json` and imports `collect.json`.

macOS/Linux (`sudo` for imager only; never run the ledger as root):

```sh
cd framework
ws="$(mktemp -d)/case-0001-ledger"
python3 bot.py -w "$ws" init
python3 bot.py -w "$ws" workflow create evidence-acquisition --title 'Case 0001 USB image' --scope 'Image only /dev/sdb (serial recorded in scope) to /cases/0001; authority ref AUTH-0001.' --acceptance 'E01 acquired, independently verified, every artifact hash recorded.'
python3 bot.py -w "$ws" start 1
python3 bot.py -w "$ws" submit 1 --by coordinator --note 'Authority AUTH-0001; source /dev/sdb; E01 to /cases/0001; case file /cases/0001/case.json'
python3 bot.py -w "$ws" approve 1 --by 'Jane Examiner' --note 'Scope approved'
python3 bot.py -w "$ws" start 2
sudo imager image --source /dev/sdb --out /cases/0001/usb --case-file /cases/0001/case.json   # macOS: /dev/rdiskN
python3 imager_import.py -w "$ws" 2 /cases/0001/usb.json --by operator
python3 bot.py -w "$ws" approve 2 --by 'Jane Examiner' --note 'Acquisition record reviewed'
python3 bot.py -w "$ws" start 3
imager verify /cases/0001/usb.E01 --json > /cases/0001/usb.verify.json
python3 imager_import.py -w "$ws" 3 /cases/0001/usb.verify.json --by reviewer
python3 bot.py -w "$ws" approve 3 --by 'Jane Examiner' --note 'Independent verify matched'
python3 bot.py -w "$ws" show 2
shasum -a 256 /cases/0001/usb.E01    # Linux: sha256sum
```

Finish with `start 4`, a coordinator `submit 4` listing the artifact paths and SHA-256 values, and a human `approve 4`. Files imager writes as root may need `sudo chown` before the unprivileged import can read them.

**Using acquired evidence in `threat-hunt`.** The hunt's `evidence` step may cite artifacts from an `evidence-acquisition` workflow whose `handoff` is `done` instead of hand-supplied files. Record in the hunt's `scope` submission the acquisition workflow ID (`workflow status ID` shows every member `done`), the artifact paths and SHA-256 values from `show ACQUIRE_TASK_ID`, and the authority reference; the hunt scope approver confirms they match. Before analysis, the researcher re-hashes the files they use (`certutil -hashfile FILE SHA256` / `shasum -a 256 FILE`) and cites the ledger artifact hash in each locator. Optionally re-register those exact paths on the hunt task with `bot.py artifact`. Mount or open images read-only; the hunt workflow still authorizes no new collection.

### Supply a custom template

`TEMPLATE` is a bundled name or an explicit JSON file path resolved from your current directory, not the workspace. For example, after writing and reviewing your own file:

```powershell
py -3 .\bot.py workflow show .\my-workflow.json
py -3 .\bot.py -w $ws workflow create .\my-workflow.json --title 'Approved goal' --scope 'Approved source and change boundary' --acceptance 'Observable human-reviewed outcome'
```

A template has exactly `version`, `name`, `description`, and `tasks`; `version` must be integer `1`. `tasks` is a nonempty array; each task has exactly `key`, `title`, `role`, `scope`, `acceptance`, and `depends_on`. Text fields must be nonempty, roles must be `coordinator`, `researcher`, `builder`, or `reviewer`, and task keys must be unique. `depends_on` is an array of unique existing task keys. Forward references are allowed; cycles and self-dependencies are rejected. Missing/unknown fields, duplicate JSON object properties, duplicate task keys/dependencies, invalid roles and unsupported versions are rejected before database mutation. There are no executable fields, shell interpolation, expression evaluation or variable substitution: supplied text remains literal task context. Review its meaning and data boundary yourself; structural validation is not a security approval.

On macOS/Linux substitute `python3 bot.py -w "$ws"` and your shell's variables for PowerShell commands, with `/` path separators. Bundled templates and role files live entirely in the copied folder and require no surrounding research tree.

## Optional explicit CLI execution

Only run a CLI you trust and are authorized to use. Review `prompt ID` before sending it: the full task, event history, artifact paths, role instructions, and immediate predecessor task histories and references are sent on stdin, potentially to an external provider. The subprocess inherits your environment and account permissions, including any configured credentials; this framework does not read or configure them. Its working directory is a fresh directory under the workspace's `runs` directory, **not a security sandbox**: the executable may access other files, networks, or external systems. Restrict the workspace's filesystem permissions (on Windows, inspect inherited ACLs); output and stderr are stored there unredacted. Do not put secrets in arguments or task data.

Start a ready task as usual, then explicitly invoke the installed Hermes CLI. In profile-free safe mode supply a model supported by your authorized provider:

```powershell
py -3 .\bot.py -w $ws run --adapter hermes --model '<model-id>' --provider '<provider-id>' --timeout 300 1
py -3 .\bot.py -w $ws show 1
```

Replace the example values with a valid model and provider for your installation; `--provider` is optional when Hermes can select it. The adapter sends the prompt on stdin to `hermes chat --query-file - --oneshot --safe-mode --model <model-id>`, with the optional provider and `-Q`, in a fresh working directory. `--model` is required for this mode and is checked before reserving the task. An installed compatible Hermes version, provider access, and authorization are prerequisites; use `--executable 'C:\path\to\hermes.exe'` before the task ID if it is not on PATH. This unqualified invocation may still select Hermes' sticky default profile, but safe mode discards profile configuration and identity; it is not a way to invoke a specific bot. Safe mode is not a sandbox; the framework never adds `--yolo`. A real model call can send data and incur costs. No model call happens until the operator runs this command.

To address an **existing** profile, explicitly opt in to its configuration instead of safe mode:

```powershell
py -3 .\bot.py -w $ws run --adapter hermes --profile 'researcher-bot' --allow-profile-config --timeout 300 1
```

On macOS/Linux use `python3 bot.py -w "$ws"` in place of the PowerShell prefix. Substitute the exact existing Hermes profile name, not its Desktop display title or a path; `hermes profile list` is Hermes' way to inspect available names. This runs `hermes --profile researcher-bot chat --query-file - --oneshot -Q`. Both profile options are required together, only with the Hermes adapter, and must precede the task ID. They do not create a profile or change Hermes' sticky default; missing profiles should fail according to the installed Hermes version, with errors recorded and the task blocked. Hermes versions and executables differ: verify their CLI support independently. The framework cannot independently prove which identity a third-party executable actually used.

The opt-in removes `--safe-mode` because safe mode suppresses config, `SOUL.md`, memory and other identity customizations. Profile model/provider, tools, plugins, hooks, MCP servers, memory and other configuration may now apply. Review them through authorized means before running; inherited environment and Hermes configuration may independently change behavior, including approvals. The framework does not request `--yolo` or disable approvals, but noninteractive execution cannot guarantee an approval prompt can be answered and may fail or time out. Hermes itself may write session history, memory, logs or other profile state and may refresh shared authentication; this framework does not directly edit profiles or credentials, but cannot guarantee a profile stays unchanged during a real Hermes run. Do not use this mode if such writes are not authorized. Avoid concurrent agents on the same profile. This is a separate CLI session, not necessarily the Desktop bot's canonical Bot Chat, and is not a sandbox.

For another executable, provide its complete argument vector after `--`; options for `run` must precede the task ID. The executable must accept the prompt on standard input and produce its handoff on standard output; supply its own noninteractive and safety options. Use an absolute executable path if it is not on PATH. Arguments are passed directly, without a shell, interpolation, or pipeline. Windows batch files (`.bat` and `.cmd`) are rejected because the operating system may invoke a shell for them:

```powershell
py -3 .\bot.py -w $ws run --adapter generic --timeout 300 1 -- 'C:\path\to\agent.exe' 'agent-option'
```

Each run reserves the task as `running` transactionally before starting the executable, preventing another invocation for that task. A zero exit status records the actual stdout and stderr as artifacts and moves the task to `review`, **not** `done`; exit status alone does not establish that output is correct or complete. Inspect both files, verify the work and any side effects, then explicitly `approve` or `reject`. Nonzero exit, launch failure, or timeout records available output and moves the task to `blocked`; inspect and resolve the cause before `resume`. Timeout terminates the direct child, but its descendants may survive. A crash or interruption can leave `running` with an unknown outcome; do not blindly retry. First check for and stop any surviving process and inspect the recorded run directory, then explicitly reconcile with `recover-run ID --by NAME --note 'what was checked'` to move to `blocked`. Resume only when safe. If output recording or database finalization fails, the task likewise remains `running`; files may exist without artifact entries. A run cannot be made exactly-once across process or machine failure.

## Roles and optional Hermes mapping

`roles/coordinator.txt`, `researcher.txt`, `builder.txt`, and `reviewer.txt` are ordinary UTF-8 instructions. Copy a suitable role and the generated task context into any agent's instructions or chat, or give them to a person. Use separate conversations/identities and a different reviewer from the implementer where possible; role names do not create agent processes or isolation. Keep tasks bounded, minimize shared context, and stop for a human decision on missing authority, risky actions, or uncertain results.

The [authored Hermes pack](hermes-bots/README.md) supplies coordinator, researcher, builder, reviewer, and librarian identities in the documented profile distribution format. Installing one is an explicit external state change, separate from copying this folder. For manual Bot Mode use, select the intended existing profile in the installed interface, inspect its capabilities and provider route, supply only the approved prompt/evidence, then record the actual handoff with `submit` and review it in the ledger. CLI profile installation alone does not prove a canonical Desktop Bot Chat exists. The librarian is a separate bot identity, not an added ledger role; use the pack's documented coordinator-task mapping.

## Local regression checks

From this folder, use `py -3 -m unittest discover` on Windows or `python3 -m unittest discover` on macOS/Linux. Core tests require no third-party packages; optional runtime tests skip when their dependencies are absent. Run discovery with the optional environment's Python to exercise LangGraph persistence and the LangChain adapter's behavioral boundaries too; see [optional-runtime.md](optional-runtime.md). Tests use temporary workspaces, not real paid models. A documented command is not evidence it was executed; record actual results separately.

## Research basis and limitations

The role and handoff design draws on research about Hermes bots and agent workflows; the research collection is separate and is not required to copy or run this folder. This package deliberately uses manual coordination and does not establish that multi-agent setups improve quality, cost, privacy, or security.

Hermes support depends on the destination's OS and architecture; consult the [official platform matrix](https://hermes-agent.nousresearch.com/docs/getting-started/platform-support). The Python 3.9+ standard-library ledger is designed for Windows, macOS and Linux, but only Windows has been exercised in this project's local development context; macOS/Linux behavior is not verified here. Hermes, Python, model providers, and their operating-system permissions are installed and configured separately on each machine. This portability intent is not evidence of a particular Hermes/provider version's compatibility or of a test run for these changes.

## Optional Envision job bridge

`envision_bridge.py` is an explicitly operated, single-operator bridge: a local client submits bounded jobs to an HTTPS queue; an authorized worker polls that queue and calls its configured Foundry deployment. It is **not** a VPN, general HTTP proxy, remote shell, or multi-tenant service. The ledger and Hermes integrations are unchanged.

### Approval and persistence prerequisites

Before deployment, establish the approved relay hostname, certificates, hosting environment, identities, and permitted prompt/result data flow. Public HTTPS connectivity alone does not establish any of these approvals. Do not send CUI/NSS, private GitLab material, credentials, or other unapproved data through the relay.

The worker needs an approved runtime with network access to both Foundry and the relay. A Windows App connection does not give local programs EITaaS routing. A worker started in an interactive developer desktop may survive a lock or disconnect, but can terminate on session logoff, administrative timeout, or VM shutdown. Do not disable CAC-removal or session policies or simulate activity to keep it running. Unattended operation needs an approved persistent service/job host and service identity independent of the personal desktop session.

This component does not install services, register schedules, open firewall rules, provision a relay, or renew OAuth credentials. Its default worker credential is a Foundry bearer access token provisioned privately through the environment. For production, use an approved OAuth application/service identity with externally managed token renewal; personal development tokens are not production credentials. Restart a worker through approved operations when its environment credential changes, after checking in-flight job state.

### Source and private configuration

Python 3.9+ and the standard library are sufficient. The fixed portable ZIP allowlist includes the shared `envision_protocol.py` and its tests because the framework-managed benchmark reuses its bounded transport; it does not include the Envision bridge or queue applications. The ZIP also includes the benchmark sources/tests, documentation, offline example manifests, nine explicitly authored synthetic cases with their invented evaluator keys and their deterministic generator, and the OTRF importer with its field allowlist and an invented sample. It excludes actual experiment configurations, runtime databases/receipts, raw exports, downloaded datasets, import salts, real evaluator truth, credentials, and the separate range-kit scripts/binaries. To deploy this optional Envision application, transfer the reviewed `envision_bridge.py`, `envision_queue.py`, `envision_protocol.py`, and `langchain_adapter.py` together to an approved destination; transfer the three `test_envision_*.py` files too if testing there. Never transfer runtime databases or this workstation's `.env`.

Provision these variables privately; there are no credential CLI arguments or `.env`/token-file readers:

| Variable | Processes that need it |
|---|---|
| `ENVISION_BRIDGE_CLIENT_TOKEN` | Relay and local client |
| `ENVISION_BRIDGE_WORKER_TOKEN` | Relay and worker |
| `ENVISION_API_KEY` | Worker only; never supplied to the relay or local client |

The two relay tokens must be distinct, 32–8192 visible ASCII characters without whitespace; use strong independently generated secrets. They define one operator boundary: all clients with the client token can inspect that operator's jobs. They are not per-user authorization or data-loss prevention. Do not put secrets in commands, task prompts, artifacts, transcripts, or logs.

The SQLite queue stores submitted prompts and permitted results in plaintext until explicitly deleted. Restrict directory access and backups. Use a separate database, not the ledger/checkpointer DB. Existing non-bridge databases are refused. The default capacity is 1,000 retained jobs (maximum configurable capacity 10,000); completed jobs still occupy capacity until `forget`. `envision-bridge-runtime/` is ignored by Git, but ignore rules do not protect manual copying or already tracked files.

### Explicit launch and use

The following commands are deployment templates, not a provisioned service. Replace the example relay hostname, certificate paths, and full model RID with approved values. Do not use the model RID merely because it appeared in a public example; both relay and worker require their own explicit allowlist.

**Relay host, after approval and private environment provisioning:**

```powershell
New-Item -ItemType Directory -Force .\envision-bridge-runtime | Out-Null
py -3 .\envision_bridge.py serve `
  --database .\envision-bridge-runtime\queue.sqlite3 `
  --host 0.0.0.0 --port 8765 `
  --tls-cert C:\approved-certs\relay-chain.pem `
  --tls-key C:\approved-certs\relay-key.pem `
  --model ri.language-model-service..language-model.approved-model
```

The listener emits a JSON readiness record with the actual port and TLS status. It requires TLS 1.2+; expose it only behind the organization's approved access controls and operational protections. This small standard-library listener is not a replacement for a managed internet-facing gateway. Without TLS, the CLI permits only an explicitly requested literal-loopback bind via `--allow-loopback-http`. That flag is for disposable fixtures, not a workaround for certificates or a way to use nonlocal HTTP. Clients verify certificates and never follow redirects.

**Worker in the approved Foundry-accessible runtime:**

```powershell
py -3 .\envision_bridge.py worker `
  --queue-url https://relay.approved.example:8765 `
  --foundry-url https://envision.af.mil `
  --model ri.language-model-service..language-model.approved-model
```

This explicitly started process polls until interrupted. Add `--once` to claim at most one job and exit; an empty queue produces a successful exit without calling Foundry. Worker output contains only job IDs/states and fixed error codes, not model text, tokens, headers, or upstream error bodies. An authentication, permission, or connection failure stops the worker instead of repeatedly using bad configuration.

**Local client:**

```powershell
$queue = 'https://relay.approved.example:8765'
$job = py -3 .\envision_bridge.py submit --queue-url $queue `
  --operation auth-check | ConvertFrom-Json
py -3 .\envision_bridge.py result --queue-url $queue $job.id
```

`auth-check` calls only `GET /api/v2/ontologies` and returns a status, never ontology contents. A successful job proves access to that endpoint, not model-inference permission. A `401` records `authentication_failed`; `403` records `permission_denied` and is not proof of an invalid token.

For chat, send a reviewed UTF-8 prompt on stdin:

```powershell
$job = 'Reply with a short greeting.' | py -3 .\envision_bridge.py submit `
  --queue-url $queue --operation chat `
  --model ri.language-model-service..language-model.approved-model `
  --max-output-tokens 256 | ConvertFrom-Json
py -3 .\envision_bridge.py result --queue-url $queue $job.id
```

`submit` returns a queued job ID, not a model result. Invoke `result` again when the worker has processed it. Chat is limited to one user message, a 64 KiB UTF-8 prompt, 1–4,096 output tokens, and a 256 KiB text result. The worker calls only the documented OpenAI-compatible chat-completions path with streaming disabled. Tools, arbitrary messages/roles, file access, URLs, headers, shell commands, and user-supplied provider options are not job fields. Tool calls, refusal, truncation, malformed responses, and empty/nontext outputs are not successful handoffs.

After inspecting an approved result, explicitly remove the terminal job:

```powershell
py -3 .\envision_bridge.py forget --queue-url $queue $job.id
```

`forget` refuses queued/running jobs. On macOS/Linux use `python3` and the shell's corresponding stdin/variable syntax; no platform-specific package is required.

### Failure and recovery contract

Claims are atomic and durable across relay restart. A job progresses from `queued` to `running`, then `succeeded`, `failed`, or `unknown`. The default claim lease is 120 seconds (`--lease-seconds`, range 10–3,600). The worker caps its upstream timeout to the remaining lease minus a reporting margin. Keep relay and worker clocks synchronized.

Expired running jobs become `unknown` on the next queue operation; they are **never automatically requeued**. Transport failure, malformed output, or lost completion delivery can follow a billable upstream execution. Inspect `unknown` jobs before any explicit resubmission. A client that loses its submit response must likewise not assume no job was created. There is no inference retry, lease renewal, replay, or fallback provider.

### Exercised verification and limits

Windows verification ran `py -3 -m unittest discover`: 93 tests ran, with 86 passing and seven optional-dependency tests skipped. New regression coverage includes concurrent claims, restart persistence, lease expiry, wrong-role rejection, request limits, model allowlists, unsafe output rejection, and refusal to forward credentials through redirects.

A throwaway smoke used real relay/client/worker CLI subprocesses, a disposable SQLite database, synthetic credentials, and a temporary trusted test CA without changing system trust. Verified TLS worked; an untrusted relay certificate failed. A synthetic loopback upstream exercised status-only authentication checks, a text result, a denied request, rejected tool output, restart persistence, role/model restrictions, and explicit deletion. Exactly four upstream fixture requests occurred, without automatic retries. Its servers, certificate files, database, and harness were removed afterward. The bridge itself has no cryptography-package dependency.

These checks do **not** establish real token validity, live model inference, cross-boundary deployment, CAC-removal survival, an approved queue endpoint, or macOS/Linux runtime verification.
