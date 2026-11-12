# Portable Hermes Bot Framework

This directory is the portable source project for approved Windows, macOS, or Linux machines: a human-operated task ledger, workflow templates, six Hermes bot identities, native defensive threat-hunt skills, a guarded profile/component installer, a source-only ZIP exporter, optional LangGraph/LangChain integration, and a built-in Windows Elastic + Arkime hunting lab. It excludes Hermes itself, live profiles, credentials, model providers, and the surrounding research and GitLab downloads.

The threat-hunt experience runs in **native Hermes**: the coordinator uses Hermes `delegate_task` and its native per-task delegation strategy. OMP is a development tool, not a product runtime dependency. The skill and ledger do not provide isolation or authenticated approvals. Start with [portable installation and native delegation](hermes-setup.md#native-hermes-threat-hunting), the [bot pack](hermes-bots/README.md), and [optional LangGraph/LangChain execution](optional-runtime.md). Opening this folder does not install bots, execute workflows, or call providers.

The native roster uses six cybersecurity roles: **Incident Response Lead**, **Threat Hunter**, **Detection Engineer**, **Purple Team Analyst**, **Threat Intelligence Analyst**, and **Network Analyst**. The Network Analyst analyzes approved, human-prepared sanitized Arkime/Wireshark summaries that exclude SSIDs, headers, credentials, cookies, authentication payloads, and authentication/session data, or the loaded lab case through its owned tools: Arkime session metadata and `packet_fields`, decoded allowlisted fields of the case's saved capture with secrets removed (accepted decision ADR 0003 in the planning notes). It must not capture live traffic, open raw captures, packet bytes or tool views other than through those tools, operate Wireshark, or connect to an Arkime endpoint. Existing `framework-*` profile IDs and ledger role identifiers are retained. Installing the role does not authorize connection, capture or collection.

The [optional Temporal integration](hermes_temporal/README.md) adds durable, separately human-gated native Hermes turns, local dispatch receipts, and explicit unknown-outcome reconciliation. Its `hermes_temporal.cli hunt WORKFLOW_ID --input JSON` entrypoint builds a bounded, serial, six-profile supplied-evidence hunt from explicitly supplied inline synthetic evidence; it does not fetch locators or begin paid execution. Optional ontology/context selections and the strict handoff contract are documented in the guide; without an ontology, existing free-text behavior remains. The Temporal stage sequence is serial even though native Hermes `delegate_task` can support parallel-ready branch work; neither implies automatic approval. Every stage still requires human execute and review decisions. Unknown results require reconciliation and do not supply reviewed predecessor output. Temporal is only the outer durability layer: it does not prove model identity or enforce per-role child tools through `delegate_task`, authenticate approval, sanitize evidence, or make hunting autonomous. The integration is included as source in the portable ZIP; the SDK and server are separate opt-in installations. It does not move agent delegation into OMP or require LangGraph. The [native threat-hunt skill](hermes-skills/threat-hunt/SKILL.md) describes native collaboration guidance; authored source guidance does not itself update existing installed profiles. The constructor/API smoke used synthetic handoffs and no provider calls; it is not proof of live model collaboration. 

The [Bot Mode compatibility matrix](desktop/BOT-MODE-COMPATIBILITY.md) covers every section of the official guide, native offline checks, known guide/source discrepancies, and remaining Desktop/guest/provider acceptance checks. Source support does not mean a working live deployment.

The opt-in [native security-audit skill](hermes-skills/security-audit/SKILL.md) incorporates Cloudflare's public vulnerability-audit workflow: scoped reconnaissance, coverage-led hunting, adversarial validation, structured verdicts and fresh record verification. [Provenance and verification](hermes-skills/security-audit/PROVENANCE.md) preserve its MIT license and pinned source. All 65 validator tests passed on Linux; the native Windows CLIs intentionally refuse input because required OS file-opening protections are unavailable. This is not Cloudflare's private fleet harness, an audit result, or permission to run target code.

The framework-managed threat-hunt benchmark is parked outside the product, in the repository's `research/benchmark/` folder (see its README there): it is not in the portable ZIP and the default gate does not run its tests (`python scripts/hunt_bots_check.py --benchmark` does). It runs all six cybersecurity identities as a fully automatic seven-stage AI team: stages advance without human gates (recorded as unreviewed `auto_advance`, never as human approval), calls run concurrently, truth is frozen at `init`, and scoring is mechanical by default with optional human adjudication as a separate cohort. Its coverage catalog is a target matrix, not live-support evidence. Model execution still needs `--allow-model-execution` and a configured team; the separately supplied range kit needs explicit lab authority. It does not replace native Hermes routing or repair Desktop group execution. `benchmark.py diagnose` reports per-stage/role errors on development cases only, holdouts are guarded by a retirement registry, and its OTRF and attack_data importers (`research/benchmark/benchmarks/importers/README.md`) turn public recordings into cases.

On Windows, run `py -3 .\setup_hermes.py check`, then deliberately run `py -3 .\setup_hermes.py install`. This preserves existing exact authored profiles, uses Hermes's normal confirmation for new profiles, and installs/enables the built-in lab backend and Desktop components. On macOS/Linux use `python3`; the ledger remains cross-platform, but automatic lab provisioning currently requires Windows x64. Install Hermes separately and sign in locally only when model execution is wanted. Copying the source kit does not transfer an account or establish a working Bot Chat.

## Built-in local hunting lab

Normal framework setup includes the lab; there is **no separate QEMU, Docker, Ubuntu, pycdlib, or ISO installation for the user**. In a compatible native Hermes Desktop, open **Cybersecurity workspace → Open hunting lab**, or the **Hunting Lab** sidebar entry. Click **Find profiles** beside **Route**, select `framework-network-analyst` as the VM owner, click **Refresh status**, then click **Start lab**. The **Status** box shows the selected VM's last validated state (running, starting, stopped, error, or unknown before any status) with the VM name, reason, preparation, memory, acceleration and the last command with its exit code; the observation time sits beside **Refresh status**. **Stop lab** sits with the running facts while the VM runs and beside Start otherwise (hidden only when the VM is reported stopped); while the last validated status is running, **Start lab** and **Prepare again** are disabled ("VM is running"), so Stop is the only lifecycle action offered. The **Running state** column (PID, lab, Arkime and console endpoints, the QEMU console window, **Stop lab**, **Open Arkime**, **Open lab**) appears only from a validated running reply, and the full requirements and limits sit in the collapsed **Requirements and limits** row.

The first explicit Start downloads hash-pinned public prerequisites, extracts QEMU without executing its installer, prepares the guest, and boots it. Docker and the digest-pinned Elasticsearch 8.19.23 / Arkime 6.9.1 images are installed inside the guest. **Prepare lab** (shown as **Prepare again** once the reply says the lab is prepared) is optional and does not boot. Opening/importing the framework, setup, help, check, and status do not download or start the VM; a valid existing deployment is reused unchanged.

Requirements: Windows x64, Windows Hypervisor Platform already enabled, at least **5 GiB available RAM** and **37 GiB free disk** for first preparation. The guest uses 4 GiB RAM, two vCPUs, and a 32 GiB virtual disk. Initial setup requires Internet and large public downloads; the framework does not request elevation, enable Windows features, or silently fall back to software emulation. Compatible native SDK profile CLI requests and `SandboxedFrame` are required; the installer does not patch Hermes itself.

The bundled `dns-lab-001` case contains 40 invented events and a 32-packet DNS capture, producing 16 Arkime sessions. Human-only Arkime inspection is separate; choose **All (careful)** or April 15, 2025, 09:00–09:10 UTC because the recent default window excludes this historical fixture.

**Per-bot lab tools.** Each specialist owns read-only tools in toolset **`hunt_lab`**: Threat Hunter `elastic_search`, `elastic_aggregate`, `lab_browser`, `packet_fields`; Network Analyst `arkime_sessions`, `arkime_unique`, `hunt_lab_query`, `lab_browser`, `packet_fields`; Threat Intelligence Analyst `intel_lookup`, `elastic_aggregate`; Detection Engineer `detection_test`, `elastic_aggregate`; Purple Team Analyst `elastic_search`, `arkime_sessions`, `detection_test`. The Incident Response Lead has no lab tools and sends follow-up questions to the owning specialist through `delegate_task`. The ownership map is `TOOL_OWNERSHIP` in `hunt_lab/query_adapter.py`; `native_team.py` writes the same lists as `agent.allowed_tool_names`. **Ownership is enforced at runtime by registration:** the plugin registers only the profile's owned tools (none for the Incident Response Lead or any unknown profile), so a call to another bot's tool never reaches the model's tool list and Hermes's existing unknown-tool check refuses it before anything runs (`test_hunt_lab_tools.RegistrationTests`). Stock Hermes still ignores `agent.allowed_tool_names` itself; core tools such as `terminal` are kept out by the `platform_toolsets.cli` and `agent.disabled_toolsets` values that `native_team.py apply` writes. No live refusal run is recorded yet; in the recorded live hunts, made before this change, no bot called another bot's tool. Every query tool goes through the guest lab service on the forwarded lab port (or, for a connected case, the host-side connected service; see [Serving a work Elastic directly](#serving-a-work-elastic-directly-connected-mode)), which scopes each query to the loaded case (Elastic `event.dataset`; Arkime tag `case:<id>` and the case window; packet fields the case's own saved capture), bounds sizes, allows only Arkime's session and unique-value read routes (never delete, tag, hunt, pcap or user routes), and records each call in a read-only `/activity` log. `lab_browser` is the exception: it opens Arkime's own pages, so it enforces the same limits inside its browser (next paragraph). No tool can control the VM, capture traffic, reach other indices or endpoints, or read an answer key.

**Packet fields.** `packet_fields` (guest route `/packets`) runs `tshark -r` on the loaded case's `evidence/traffic.pcap`, the file next to `case.json`, as an argument list without a shell, with a 20-second deadline and the 8 MiB output cap of the other backends; it never passes `-i` and writes no files. There is no packet-count limit: tshark reads the whole capture, so a filter that matches only late frames still finds them. A scan the output cap cuts short returns `"truncated": true` and one the deadline stops is `packet_tool_timeout`, so a page with `more` and `truncated` both false covers the whole capture. Each row is one matching frame with `frame.number`, `frame.time_epoch` and the requested fields from a fixed allowlist of 38 (IP addresses and ports, DNS names, types, rcodes and answers, HTTP host, method, URI, status, user agent, content type and length, TLS handshake type, SNI, JA3/JA3S/JA4 and record version, SMB2 command, file and tree names, Kerberos and NTLM user names and domain). Anything else is refused with `field_not_allowed`, so cookies, authorization headers, bodies, file data, raw bytes, passwords, hashes, tickets and challenges never leave the guest; `http.request.uri` is reduced to its path (a query string or fragment becomes `?[redacted]`) and URL userinfo is dropped. An optional display filter (at most 300 characters) is tokenized against a closed grammar: allowlisted fields except `http.request.uri` and `_ws.col.Protocol`, the protocols `ip ipv6 tcp udp dns http tls smb2 kerberos ntlmssp arp icmp` as bare tests, `== != > < >= <=` and `eq ne gt lt ge le` between a field and a number, IP address or double-quoted string without backslashes, `and or not && || !` and parentheses. `contains`, `matches`, `~`, slices, functions, `${}` references, `@`, membership sets and anything else are refused with `invalid_filter`, because a filter on a denied or redacted field would leak it one guess at a time. On first use the guest asks `tshark -G fields` once which allowlisted fields its tshark knows; a field it lacks is refused with `field_unavailable`. tshark failures are `packet_tool_error`, an overrun deadline is `packet_tool_timeout`, and tshark's own text is never relayed. A case with `"network_capture": "none"` answers `no_network_capture`. These guest checks are enforced and covered by `test_lab_server.PacketFieldsTests` with a faked tshark; live runs against the guest's tshark are recorded from 2026-11-10 (see HUNT-BOTS.md). The guest installs Ubuntu 22.04's `tshark` package (3.6.x): `tls.handshake.ja4` exists only from Wireshark 4.2 and reports `field_unavailable` there, while JA3/JA3S exist from 3.6.0. The tool description tells bots to cite a frame as `frame-<frame.number>` next to the matching `evt-` events; the scorer credits such a frame when the case's key lists it (see Loading a larger case).

**Lab browser.** `lab_browser` drives a dedicated, real Chromium-family browser on the lab's own web tools: Arkime's Sessions and SPI View pages and the lab console. A bot opens a page, gets a snapshot of its interactive elements with refs (`e1`, `e2`, ...) from the accessibility tree, then clicks, types into or reads an element by ref, presses an allowlisted key, or scrolls. Before a click the element must be visible, enabled, inside the viewport and not covered (an `elementFromPoint` hit test adapted from the MIT omp browser tool). The pointer travels an eased, slightly bent Bezier path with small jitter and occasional overshoot, and keys arrive with a varied rhythm (`hunt_lab/humanize.py`), all as CDP `Input` events. Enforced at runtime, with tests: every request pauses in CDP `Fetch` and fails unless its origin is exactly the lab or Arkime URL from the runtime status; every Arkime search request (query and body, GET and POST) leaves the browser as `(<expression>) && tags == "case:<id>"` with its time range clamped to the case window; Arkime write, export, packet, file and admin routes fail; downloads are denied and popups closed. Launch flags add a second fence that holds even with no CDP client attached: all traffic goes to a dead proxy except the two lab ports (observed against the live lab; a test pins the flags). The browser uses its own profile under the analyst profile's `hunt-lab-browser/<bot>/`, runs headless unless demo mode (below) or `HUNT_LAB_BROWSER_HEADED=1` asks for a window, and is `HUNT_LAB_BROWSER` or Microsoft Edge on Windows (chromium elsewhere). It needs the `websockets` package that Hermes ships. One browser per bot persists across that bot's calls and closes after 10 idle minutes or when the bot's process exits. Each action is appended to `hunt-lab-browser/<bot>/audit.jsonl` (time, action, page, ref, typed text, final URL, blocked-request count, and each lab request with its case-scoped expression); these calls bypass the guest service, so they do not appear in `/activity`. Arkime's own UI writes, such as saving field history, fail by design.

**Kibana Discover.** The guest also runs Kibana 8.19.23 (`guest/compose.yaml`, pinned in `guest/image-lock.json` by manifest and config digest) on the same Elasticsearch, and the runtime forwards it to a loopback port reported as `kibana_url`. `guest/kibana.yml` fixes a read-only analyst surface: Lucene as the query language with the same `query_string` options as `elastic_search` (fields, AND, no leading wildcards, lenient), so a query typed into Discover finds the same events; UTC dates; Discover as the default route; telemetry, newsfeed, the welcome screen, announcements, ES|QL and the Console UI off; value suggestions by aggregation. On every boot `guest/kibana_setup.py` points the filtered alias `hunt-lab-case-events` at the loaded case's `event.dataset`, makes it the default data view with `@timestamp` as its time field, and sets the time defaults and the one quick range to the case window; a failure prints a `stage=failed_kibana_*` line, and `/health` is ready only once the data view names the loaded case (`kibana_ready`). `lab_browser` page `kibana_discover` opens Discover on that data view and window with only the given `q`; in demo mode the query is typed into Kibana's query bar. In the browser the Kibana origin admits Discover's page, static bundles and the reads Discover 8.19 was observed to need. Each batch search must use the `ese` or `es` strategy, target the case alias and an allowlisted set of body keys, and is rewritten to also filter on the case window whatever the time picker says. Field lists must name the case alias, value suggestions are forced to `terms_agg`, and data view reads are allowed only for `index-pattern`. Every other route fails, among them saved-object and content writes, settings writes, `/api/console/proxy`, index management, alert creation and other apps; a page that leaves `/app/discover` is replaced by `about:blank` (`navigation_refused`). Expanding a document, adding a filter (Add filter) and adding a column (a field's preview) all work through the existing click, type and press by ref.

**Lab browser demo mode.** To film the bots, the operator writes `hunt-lab-browser/demo.json` under the analyst profile, beside the bots' browser profiles, for example `{"headed": true, "window": [0, 0, 1600, 1000], "cursor": true}`. Each key is optional: `headed` and `cursor` default to true, `window` (x, y, width, height) to `[0, 0, 1600, 1000]`, and `scale` is absent. A bot's browser reads the marker when it starts, and a running browser is reused only while the marker still asks for the window, cursor and scale it started with; otherwise it is closed and relaunched, because the gateway that hosts the tools keeps its browser between calls. `headed` opens a visible window at that position and size. `scale` (a number from 1 to 2) makes pages render larger for the camera: the browser starts with `--force-device-scale-factor=<scale>` and its window flags divided by `scale`, so the window keeps the marker's size in screen pixels while pages lay out in `scale` times fewer CSS pixels, with text `scale` times larger. Without `scale` the browser keeps the system's scale factor, and `window` is then in the system's device-independent pixels: on this workstation Edge reported a device pixel ratio of 1.22, so a 1280x1080 window was 1562x1318 screen pixels and its screencast frames 1538 pixels wide. With `"window": [200, 100, 1280, 1080]` the window measured 1280x1080 screen pixels at scales 1.5 and 2, with screencast frames 1247 and 1238 pixels wide (observed in a throwaway local Edge window, not yet in a filmed hunt). Pointer paths, clicks, typing, the actionability check and the cursor overlay all work in CSS pixels, which the scale factor leaves alone: in the same window a dispatched click at CSS (140, 215) reached the page at (140, 215) at every scale, and a test pins identical actionability and input traffic at scale 1.5. `cursor` draws the CDP pointer, which the browser never paints, as an arrow that follows each mouse move and ripples on each press. It is a script in its own isolated world that adds a `pointer-events:none` element in a closed shadow root on the top layer, so page scripts and CSS cannot reach it and hit tests (`elementFromPoint`, the actionability check, real clicks) pass through it. A test pins identical actionability and input traffic with the overlay on; the hit-test pass-through and the hostile-CSS case were observed by hand in headless Edge 157 on a local test page. In demo mode a search given to `open` (`expression` or `q`) is entered through the page's own search box: the tool loads the page without it, clicks the text field named "Search" in the page snapshot, types the search with the same pointer path and typing cadence as `type`, presses Enter, waits for the page to settle and returns the usual `open` result. The search then leaves the page as an ordinary request, so the same case tag and window rewriting applies. When the page has no such field or the entry fails, the tool opens the search URL as it does outside demo mode. Each audit line records `"entered"`: `"typed"`, `"url"`, or `"fallback:<reason>"` such as `"fallback:no_search_box"` (null for actions without a search). Tests pin the typed sequence, the unchanged URL path without the marker, and the fallback against a fake browser; the field names come from the lab console's markup and Arkime's search field and were not yet observed in a live demo run. A marker with an unknown key, a wrong type, an out-of-range window or a scale outside 1 to 2 is ignored whole: the browser stays headless with no cursor and no forced scale, and every audit line records `"demo":"invalid_marker"` (`"on"` when the marker applies). The tool only reads the marker and never writes it. `HUNT_LAB_BROWSER_HEADED=1` still opens a window, without the cursor, for manual runs, but the Temporal worker starts Hermes with a fixed environment (`_environment` in `hermes_temporal/execution.py`) that drops it, so a filmed hunt needs the marker.

Each tool's description lists the exact fields it accepts. For Elastic that is every field the scenario generator writes, including `winlog.event_data.*` such as the lsass-access `TargetImage` and `GrantedAccess`. A refused call returns a fixed code the bot can act on: `field_not_allowed` or `invalid_field_list` (a field outside the list), `leading_wildcard_not_supported`, or `invalid_query` (the backend rejected the syntax). The host relays only these codes, never free text. A test keeps the host's advertised lists equal to the guest allowlists.

The lab console (`/` and `/view` on the guest) and the `hunt_lab_query` `events` dataset search events with the same builder as `elastic_search`: a Lucene `query_string` over the same fields, scoped to the case, with the same leading-wildcard check and the same refusal codes. Both return every top-level object the scenario generator writes, including `user`, `group`, `file`, `service`, `url`, `http`, `tls`, `user_agent` and `observer`. The console prefills its Search (`q`) and Host boxes with the submitted values, shows `N of M events`, and on a refused query shows only the fixed code with HTTP 400. The `network` dataset keeps its simple query string over `dns.host` and `network.protocol`.

**Lab service caller secret.** The guest lab service and the connected service answer only their own caller. A request whose `Host` is not `127.0.0.1:<port>` gets `403 {"error": "host_not_allowed"}` (so a DNS-rebinding web page gets nothing), and one without the instance's secret in `X-Hunt-Lab-Secret` gets `401 {"error": "caller_not_authorized"}`; every answer, a refusal too, names the instance in `X-Hunt-Lab-Instance`. The secret sits in a file only the owning user and SYSTEM can open: for the VM, `<seed>.secret.json` beside the seed ISO `deployment.json` boots (each `prepare_guest.py reseed` makes a new one, carried into the guest as a systemd credential); for a connected service, its `state.json`. The bot tools, `lab-input`, the board, `lab_browser` (on requests to the lab service's own origin only, never Arkime or Kibana) and the operator tools read it and send it; it is never returned to a bot. A seed written before this check has no secret file, so its lab answers `lab_secret_unavailable` until it is reseeded. The console pages alone (`GET /` and `/view`) also take the secret as `?key=`, because a browser tab cannot send a header: the running `hunt-lab status` reports `lab_console_url` with it, the desktop's **Open lab** opens that URL, and the page's search form carries the key on. The JSON routes never accept `?key=`.

**Loading a larger case.** `python -m hunt_lab.scenario generate --size medium|large [--story a|b]` writes an invented case (events, pcap, intel feed, case metadata) and a separate operator-only key. Story `a` (the default) is an Office-macro intrusion; story `b` is a different organisation and a web-server-exploit intrusion with its own decoys, for testing that improvements generalise. With the VM stopped, `hunt_lab/prepare_guest.py reseed --update-deployment` builds a new setup disc with a new cloud-init instance ID. cloud-init runs setup once per instance ID, so loading the same case again (for example, switching back to it) writes a fresh `-load<N>` disc; earlier discs are never overwritten. On the next start the guest loads the case once, keeps earlier cases, and serves the new one. The key never enters the guest. Besides the event IDs of each evidence group, the key lists the frames of that group's network events in the written capture (`frame-<n>`, the same numbering as tshark's `frame.number`) and the intel record IDs (`ioc-NNNNN`, which `intel_lookup` returns as `id`) of the fact's domains and IPs those sessions carry; `python -m hunt_lab.scenario score --truth KEY REPORT` accepts any of them for the group. An intel ID is listed only in the first group of a fact whose sessions carry it, so a lookup alone never satisfies more than one group. Keys without these lists score on event IDs alone, exactly as before. A large story `a` key is about 2.4 MB because the fleet-wide decoys list tens of thousands of frames.

Keys also list `evidence_sibling_groups`: per evidence group of an attack fact, the other events of the same process (`process.entity_id`) with the same `event.category` as one of the group's events, which a report may cite to prove the same step. The generator lists only events of processes whose start an attack group accepts, never an event any fact's groups accept (decoys included), and never one that would sit beside two groups; decoy, benign and coverage facts get none. `hunt_lab.import_dedale` lists the unlabelled events its process rule assigns to that one process, except an event whose own `process.entity_id` names another process, plus the Sysmon file deletions winlogbeat 7.10 failed to parse (no `process` or `event.category` fields), matched by `winlog.event_data.ProcessGuid` as category `file`. The scorer keeps `found`, `by_kind` and `decoys_cleared` strict and adds a separate `with_siblings` score in which those events cite their group too; keys without the list get no `with_siblings` and score exactly as before. In practice the generator's groups already hold nearly every event of an attack process (50 medium cases, seeds 1-25 of both stories, list none), while the three DEDALE keys list 5, 1,171 and 428 file deletions.

The same plugin adds a **Hunt Board** sidebar page for watching a running hunt. It embeds the read-only board served by `python -m hermes_temporal.board` on `http://127.0.0.1:8790/`, which must be started separately (see the [Temporal guide](hermes_temporal/README.md)); the page bar shows that address, **Show board** and **Open in browser**, and while the board is hidden the page shows the start command with a copy button. Nothing is fetched until you click **Show board** (then **Reload** and **Hide**); the frame uses the Desktop's opaque-origin sandbox and fills the page below the bar. The board shows only the workflow's real status, the bots' recorded outputs and, for tool-driven hunts, every lab tool call from `/activity`. Updating the page reuses the unchanged noVNC console bundle in `hunt_lab/desktop/plugin.js` and replaces only the trailing `plugin.entry.js` code, which is what `build_console.py` would produce from the same inputs.

The plugin's pages, the `lab_browser` chat card and the cybersecurity workspace follow the approved Hunt Command design canvas (frames 08 to 11; the design sources live outside this repository): a 44 px page bar, sentence-case section headings, one raised box per section with 0.5 px hairlines, pill buttons, and status as a 12 px shape beside a word (working arc, done check, idle ring, blocked dot). Surfaces use the Desktop's `--ui-bg-*` variables and ink and hairlines are its `--ui-base` colour at the canvas alphas, so they follow whichever theme is active; colour means state only (working amber, done teal, blocked red, idle grey) plus one blue accent for focus. Icons are Lucide 0.577.0 paths inlined at 16 px and stroke 1.5, because the SDK's own set is Tabler and lacks several of them; the sidebar entries use the host's codicons (`list-unordered`, `beaker`, `shield`). The `lab_browser` card shows a header (globe, status shape, `lab_browser`, the action, and running/done/failed with the elapsed time this card observed), then the call's arguments, page result fields (title, URL, element count, blocked requests, image path) or error, and a small live or final frame when one loads. The plugin also contributes a dark **Hunt Command** theme (the canvas surfaces: rail `#0e0e0e`, chrome `#121212`, pane `#161616`, raised `#1c1c1c`, white ink, neutral lines, blue focus ring, no web fonts) to the Desktop theme picker through `THEMES_AREA`; it changes nothing until the user picks it, and a Desktop without that area simply does not list it. With Windows glass translucency on, the host paints the sidebar translucent whatever the theme; set **Settings → Appearance → Window & layout → Tint** to 0 for the opaque canvas rail.

Optional CLI controls use the same native owner, without creating a ledger:

```powershell
py -3 .\bot.py lab status
py -3 .\bot.py lab start
py -3 .\bot.py lab query --case-id dns-lab-001 --dataset events --q powershell.exe --limit 20
py -3 .\bot.py lab stop
```

Add `--home <approved-general-Hermes-home>` and `--hermes <executable>` after the lab action when using an isolated installation. Without `--hermes`, the lab commands (and `setup_hermes.py install`, which installs the profiles and the lab) run `LAB_HERMES_EXE` when it is set, and only otherwise the `hermes` on PATH; a `LAB_HERMES_EXE` that does not exist is an error, not a fallback, because the `hermes` on PATH may be a self-updating launcher that drains the lab's gateway. They refuse to run while the home holds `.hermes-update-in-progress`, the marker a Hermes update writes, and name that file in the error; when neither the process named on its first line nor a `delegate:<pid>` it names is still running, the error calls the marker stale and says to delete it if no update is running (nothing here deletes it). The operator tools that run the lab's Hermes (`operator/lab_paths.py`) refuse the same way. `lab status` only asks the VM for its status; it never installs or re-enables plugins. State and downloads stay under the native analyst home's `hunt-lab-vm`, outside the source kit. Services bind host loopback only; there are no host shares or exposed Elasticsearch port. Only the first boot of a prepared disk has outbound NAT, because its bootstrap installs the guest packages and pulls the locked images. Every later boot, including each reseeded case, starts QEMU user networking with `restrict=on`: the guest cannot reach the host or the Internet, and the loopback port forwards still work. The start and status results report the boot's `network` as `provisioning` or `restricted`, and `state.json` under `hunt-lab-vm\framework-network-analyst` records it. A VM launched by older code has no recorded mode and reports `unrestricted_legacy`, because it still has outbound NAT; its next start is restricted. The runtime treats any earlier launch in that folder whose guest ran as proof the disk was provisioned. So if the first boot stopped before the lab became ready, or a new disk was prepared into a folder that kept its `state.json`, stop the VM and delete that `state.json` so the next start provisions. This is still **not air-gapped, authenticated multiuser hosting, or malware/CUI containment**. No AWS service, model call, live attack, or benchmark campaign starts automatically.

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

### Loading a work export

Real work hunts take one time window of the operator's own **unclassified** work logs from the work Elastic and hunt it in the lab unchanged (HUNT-BOTS.md rule 1; planning tickets 01 and 06). CUI/NSS data never goes this way without a named, approved boundary for it. Exports and the cases built from them stay under the repository's Git-ignored `runtime/` folder (or another folder outside the repository), never in tracked files. `hunt_lab/import_elastic.py` does both steps with the standard library only.

1. **Export** the window, read-only. Point-in-time search needs Elasticsearch 7.12 or later (8.x recommended); older versions and OpenSearch are refused. Use an API key that can only read: the `read` index privilege on the index pattern, plus the `monitor` cluster privilege that the version check (`GET /`) needs. Put the key (the base64 `id:api_key` value Elasticsearch shows as `encoded`) in an environment variable for this one shell, never in a file or on the command line; the exporter reads it only from the variable named by `--api-key-env` (default `HUNT_ELASTIC_API_KEY`), sends it only as `Authorization: ApiKey ...`, and never prints, logs or writes it. Errors from Elasticsearch are reported as their HTTP status and error type only. TLS is always verified, against the system trust store or, with `--ca-file`, your internal CA bundle alone; redirects are refused. With `--ca-file` the chain and host name are verified but OpenSSL's strict RFC 5280 extension checks are off, because Elasticsearch 8's auto-generated `http_ca.crt` has no keyUsage extension and would otherwise be refused. Live run (2026-11-11, Elasticsearch 8.15.3 in a throwaway container with security on, synthetic events): an API key with only `read` and `view_index_metadata` on the index pattern and cluster `monitor` exported all 20,845 documents of the window; a wrong key was reported as `HTTP 401 (security_exception)`, a window over `--max-events` was refused before any download, and the key appeared in no output.

   ```powershell
   $env:HUNT_ELASTIC_API_KEY = Read-Host -MaskInput 'Elastic API key'   # PowerShell 7
   py -3 -m hunt_lab.import_elastic export --url https://elastic.example.internal:9243 --index 'logs-*' `
       --start 2026-11-03T08:00:00Z --end 2026-11-03T12:00:00Z --hosts WS-0142,WS-0177 `
       --output ..\runtime\work-exports\2026-11-03-am.ndjson
   Remove-Item Env:HUNT_ELASTIC_API_KEY
   ```

   The window is `[start, end)` on `@timestamp`; `--hosts` keeps only those exact `host.name` values (default: every host). The exporter opens one point in time, pages it 5,000 documents at a time sorted on `@timestamp` and `_shard_doc` with `search_after`, and closes it, also when the export fails. A window holding more than `--max-events` documents (default 200,000) is refused before any document is downloaded and nothing is written: narrow the window or hosts, or raise the cap. The output holds one `{"_index", "_id", "_source"}` object per line; `<output>.meta.json` beside it records the cluster host (no credentials), index pattern, window, hosts, count, Elasticsearch version and the NDJSON's SHA-256. Neither file may exist yet.

2. **Import** it as a lab case. The input may also be NDJSON of raw `_source` documents or one saved `_search` response with `hits.hits`, for example from Kibana's Inspect panel.

   ```powershell
   py -3 -m hunt_lab.import_elastic import --input ..\runtime\work-exports\2026-11-03-am.ndjson `
       --case-id work-2026-11-03-am --start 2026-11-03T08:00:00Z --end 2026-11-03T12:00:00Z `
       --evidence-dir ..\runtime\cases\work-2026-11-03-am\evidence
   ```

   Records with `@timestamp` in the window are sorted by (`@timestamp`, `host.name`, `_index`, `_id`) and numbered `event.id` `evt-000001` onwards in that order; a source `event.id` moves to `event.original_id`, and `event.dataset` becomes the case ID, as the lab requires. Dotted field names are nested as Elasticsearch reads them; `_index`, `_id` and other search metadata are dropped. The evidence directory, which must not exist yet, gets `events.jsonl` and a `case.json` with `"data_origin": "work-export"` and the same question as the other real-data cases. There is no answer key, so the scorer does not apply: the operator's review of the report is the evaluation. The output is byte-identical for the same input and arguments, and the printed summary's input SHA-256 matches the export's `.meta.json`.

3. **Load and hunt** it like any other case. With the VM stopped (`py -3 .\bot.py lab stop`), `py -3 .\hunt_lab\prepare_guest.py reseed --evidence-dir ..\runtime\cases\work-2026-11-03-am\evidence --state-dir <analyst-home>\hunt-lab-vm --profile framework-network-analyst --update-deployment` switches the lab to the case, and `py -3 .\bot.py lab start` serves it. Export the hunt input with the operator's approval of that origin; without `--data-origin work-export`, or with another origin, `lab-input` refuses the case:

   ```powershell
   py -3 -m hermes_temporal.cli lab-input --tool-driven --data-origin work-export --state-dir <analyst-home>\hunt-lab-vm --output ..\runtime\work-hunt.json
   ```

   Every step prompt, the hunt scope and the lab console call the case a work log export (real telemetry from the operator's environment; unclassified work data), never synthetic. The profiles' static `SOUL.md` files and the `intel_lookup` tool description still describe the lab case as synthetic; each prompt states that its origin governs where they differ. Use the Slack bridge's minimal cards for these hunts (HUNT-BOTS.md rule 4).

**In one command.** From the repository root, `operator/work_hunt.py` runs all three steps and the hunt, using the operator tools' `runtime/` folder next to the clone (`HUNT_BOTS_RUNTIME`, see [operator/README.md](../operator/README.md)). It prints a reminder that only unclassified, non-CUI work data may be exported and refuses a case ID whose case, export or work folder already exists. It then exports to `runtime/work-exports/<case>.ndjson` (an empty window stops here and removes the empty export), imports into `runtime/cases/<case>/evidence`, loads the case with an `operator/switch_case.py --hold` holder in its own process group, exports the hunt input with `--data-origin work-export`, and starts one parallel hunt with six follow-up hunters (`--follow-ups`). It reads the API key only from `HUNT_ELASTIC_API_KEY`, removes it from its own environment and gives it to the export alone, so the lab, the workflow and the gate driver never see it. An export or import that runs past 60 minutes or is interrupted with Ctrl+C is killed, waited for, and its partial copy of work data removed; a path it cannot remove is named so you can delete it. It runs `operator/drive_gates.py` in the foreground: with `--operator "<name>"` in two-decision mode, so you approve the scope and accept or reject the final report with the command it prints, or on Slack (minimal cards), and every other gate is recorded as automated; with `--delegated-by` and `--reason` it approves every gate, those two included, on that person's behalf, recorded as delegated. The run's record, with who decides the gates, the export and import summaries, the lab's READY line, the workflow, its outcome, tokens and the final report path, is `runtime/practice/work-hunts/<case>/hunt.json`; a run that ends early once the lab is loading (a failed step, Ctrl+C) still writes it, marked `ended_early`, and prints the gate driver's resume command once the workflow exists. The lab stays loaded afterwards; the command prints how to stop the holder and the VM (`hunt-lab stop`: the VM runs detached from the holder). It needs `LAB_HERMES_EXE`, `HUNT_BOTS_PYTHON` with the Temporal dependencies, a running worker on `HUNT_BOTS_TASK_QUEUE`, and a Python with `pycdlib` for the reseed (`--reseed-python`):

```powershell
$env:HUNT_ELASTIC_API_KEY = Read-Host -MaskInput 'Elastic API key'   # PowerShell 7
py -3 operator\work_hunt.py --url https://elastic.example.internal:9243 --index 'logs-*' `
    --start 2026-11-03T08:00:00Z --end 2026-11-03T12:00:00Z --hosts WS-0142,WS-0177 `
    --case-id work-2026-11-03-am --operator "Ada Lovelace"
Remove-Item Env:HUNT_ELASTIC_API_KEY
```

Live run (2026-11-11, Elasticsearch 8.15.3 in a throwaway container with security on, the 20,845 synthetic events of `team-med-021` without their `event.id` and `event.dataset`, a 1-day API key with `read` and `view_index_metadata` on `huntproof-*` and cluster `monitor`, delegated gate approvals): case `work-proof-003` exported and imported all 20,845 events from 25 hosts, the lab reported READY, and the parallel hunt with six follow-ups completed all 16 steps with no step dropped and no handoff rejected, in about 20 minutes and 2,919,953 tokens. All 16 step prompts said work log export and none said synthetic; six of the 16 step outputs still mention synthetic data, for example guessing from `.test` domains and documentation IP ranges that the data may be synthetic. The key appeared in no output, log or record. An earlier run (`work-proof-002`) lost its required `incident` step when a Hermes self-update drained the lab's gateway; that step failed in 0 seconds with zero tokens, after 3,375,749 tokens.

### Serving a work Elastic directly (connected mode)

`hunt_lab/connected.py` is the connected mode of ADR 0005 (planning notes): instead of an export, a lab service on this PC holds a read-only API key to the work Elastic and answers the bots' existing Elasticsearch tools on `127.0.0.1`. The VM is not involved. The bots never see the key or the cluster address. Its cases say `"data_origin": "work-connected"` (HUNT-BOTS.md rules 1 and 2); `prepare_guest` refuses to seed one into the VM.

- `connect.json` (operator-only, never served) names the cluster: `{"url": "https://elastic.example.internal:9243", "index": "logs-*", "ca_file": "C:\\path\\http_ca.crt"}`. `ca_file` and `api_key_env` (default `HUNT_ELASTIC_API_KEY`) are optional. Cross-cluster patterns (`remote:index`) are refused.
- `case.json` is what the bots see, the same shape as every lab case: `case_id`, `question`, `"schema_version": 1`, `sources` (`{"artifact", "coverage"}` texts saying what the window holds, such as `{"artifact": "work Elastic", "coverage": "Sysmon process events"}`), `time_range_utc` (exactly `start_inclusive` and `end_exclusive`, with a UTC offset such as `Z`), `"data_origin": "work-connected"`, `"network_capture": "none"` and optional `hosts` (exact `host.name` values, at most 50), and nothing else. It names no cluster or index: `check` and `serve` refuse a case whose `case_id`, `question`, `hosts` or `sources` texts hold the cluster host or any comma-separated member of the index pattern as a whole word (case-insensitive; letters, digits and `-` on either side make it part of another word). The window must have ended at least 15 minutes ago.
- The API key needs `read` and `view_index_metadata` on the pattern, the `monitor` cluster privilege for the version check (`GET /`; without it the check fails with `HTTP 403`), and nothing that can write, delete or manage. Create it with role descriptors limited to the hunted pattern.
- Before serving, the service reads the key's own role descriptors (`GET /_security/_authenticate` for its id, then `GET /_security/api_key?id=…`) and allows only `monitor` on the cluster and `read` / `view_index_metadata` on indices. It refuses (`key_not_read_only`) a key without role descriptors (it would have its owner's rights), any `run_as`, application, global, remote or restricted-index entry, and any other privilege or action. As a second layer it asks `_has_privileges` about the pattern and every index, alias, data stream, backing index, index behind an alias and alias of a resolved index (200 names per request), for the named write and manage privileges, a list of write and admin actions, and the privilege names added after 7.12 that the cluster knows; anything granted or missing is refused. A data stream's aliases outside the pattern are not visible to `_resolve/index`; the allow-list covers them. Privileges outside the pattern are not inspected otherwise.
- `serve` also refuses a key whose text is in the Hermes home's or any profile's `.env` or `config.yaml`. It reads each of those files in full, and refuses to start (`profile_unreadable`) when one exists but cannot be read.
- As with the exporter, the key is read only from the environment variable. The service then removes it from its own environment and never prints, logs or writes it. TLS, `ca_file` and redirect handling match the exporter.

```powershell
$env:HUNT_ELASTIC_API_KEY = Read-Host -MaskInput 'Elastic API key'   # this terminal only
py -3 -m hunt_lab.connected check --config ..\runtime\connect.json --case ..\runtime\cases\work-conn-001\case.json
py -3 -m hunt_lab.connected serve --config ..\runtime\connect.json --case ..\runtime\cases\work-conn-001\case.json `
    --state-dir <hermes home>\profiles\framework-network-analyst
```

`check` prints the Elasticsearch version, the number of events in scope, which allowlisted aggregation fields the cluster does not index as aggregatable (`unavailable_fields`), and which default query fields it lacks (`unsearched_query_fields`); it serves nothing. `serve` binds a free loopback port, prints the `lab_url`, and writes `<state-dir>\hunt-lab-connected\state.json` (port, case, instance token, the caller secret and the key variable's name, never the key) in an owner-only folder. The file is removed when that service stops. A second `serve` is refused while the file exists; if a service crashed, delete the stale file.

While serving:
- Every query is filtered to the case window and hosts, and all of them read one point-in-time snapshot sorted on `@timestamp` and `_shard_doc`.
- A record's `event.id` is its citation: `evt-` plus 16 digits derived from its `_id`. `event.id:evt-…`, bare `evt-…` terms (a term of its own, so `srv-evt-01` is plain text) and `event.id:("evt-…" OR …)` find the cited documents again. Quoted phrases are searched as written, and plain terms never match the cluster's own `event.id`: any other use of the `event.id` field, also escaped (`event\.id`) or matched by a field wildcard (`event.\*`, `\*`), is refused as `invalid_query`.
- Citations are kept in `hunt-lab-connected\<case_id>\citations.jsonl` (document IDs only) across restarts. An unknown citation is refused as `unknown_citation`, never answered with zero hits.
- A page token from an expired or lost snapshot, or from an earlier run of the service, is refused as `cursor_expired`.
- Lucene `/regex/` terms are refused as `regex_not_supported` (the cluster is shared production), also inside a range (`[a TO /z/]`). A `"` inside a range and an unclosed phrase are refused as `invalid_query`, so neither can hide a regex. Searches do not allow partial results, so a query error on some shards is `invalid_query`, never a partial answer.
- Aggregating a field the cluster does not index is refused as `field_unavailable`, and so is aggregating `event.id` (its buckets would be the cluster's own values, not citations). A search on a field the cluster lacks matches nothing, as in the lab; `check` lists the aggregation and default query fields the cluster lacks.
- Intel (`no_intel_source`), Arkime, `/network` and packets (`no_network_capture`) are off. The console page (`/`, `/view`) names the case's origin, as in the lab. `/health` waits only for events.
- Every response carries the instance token in `X-Hunt-Lab-Instance`, and every request needs the secret named in `state.json` (`X-Hunt-Lab-Secret`, above); a `Host` other than the service's exact `127.0.0.1:<port>` is refused.

Live run (2026-11-11, Elasticsearch 8.15.3 in a throwaway container with security and TLS on, synthetic Sysmon-shaped events; the bot tools run through `query_adapter` against `serve` running as its own process with the key only in its environment):
- `check` reported 8.15.3 and 31 events in scope. A key without `monitor` failed with `HTTP 403`. These keys were refused as `key_not_read_only`: an unrestricted key, a key that could write only to the data stream inside the pattern, and a key holding `manage_slm`. The read-only key placed in a researcher profile's `.env` was refused as `key_in_bot_profile`.
- `elastic_search` paged all 31 in-scope events in 5 pages, with 31 unique 16-digit citations, in both sort orders.
- The out-of-window and other-host events never appeared.
- Follow-up (`event.id:evt-…`), board-style (`event.id:("…" OR …)`) and `NOT evt-…` queries returned exactly the cited events.
- `elastic_aggregate`, `detection_test` and `hunt_lab_query` (events) answered.
- Every refusal above came back as its fixed code.
- On shutdown the point in time was closed and `state.json` removed.
- Neither the key nor the elastic password appeared in any tool result, the service's output, or its state or citation files.

How the bots find it (`hunt_lab/endpoints.py`, the one lab resolver behind every bot tool, `lab-input` and the board's `--lab-state-dir`): a case is served by the VM when its runtime `status` says running and its `/case` names the case, or by the connected service whose `hunt-lab-connected\state.json` sits beside the analyst's `hunt-lab-vm` state dir and whose `/case` names it. Refusals are fixed codes:
- `ambiguous_lab` when both serve the case (for `lab-input` without `--case-id`, when both are up), `case_mismatch` when a lab answers for another case, `owned_vm_not_running` when neither is up. A connected service whose `state.json` names another case is not asked, so a VM case with the VM stopped is `owned_vm_not_running` even while a connected service runs.
- `lab_secret_unavailable` when the running VM's deployed seed has no valid caller file (a seed written before the caller secret existed: reseed it); `lab_http_401` with detail `caller_not_authorized` when a lab refuses the secret sent. A VM answer must also name the deployed seed's instance, else `lab_instance_mismatch`.
- `lab_instance_mismatch` when any answer from the connected port lacks the state file's instance token (another process holds the port), and `connected_state_invalid` for a malformed state file. A state file left by a crashed service is skipped while the VM serves the case, is never asked about another case, and is `lab_unreachable` otherwise.
- `key_in_bot_environment`: a bot's tool refuses a connected case while the bot's own process environment holds the variable named in `state.json` (`api_key_env`), so start the worker and gateways from a terminal without the key.
- `no_lab_browser`: `lab_browser` has no Kibana or Arkime to show for a connected case.

Live run of the resolver (2026-11-11, Elasticsearch 8.19.23, the guest's pinned version, in a throwaway container with security and TLS on; `serve` as its own process with the key only in its environment; the bot tools through `query_adapter` with a stopped VM, so they found the service only through its `state.json`):
- `elastic_search` paged all 31 in-scope events in 5 pages with 31 unique citations; the out-of-window and other-host events never appeared. Follow-up and board-style citation lookups returned exactly the cited events.
- `unknown_citation`, `no_intel_source`, `no_network_capture` (Arkime), `regex_not_supported` and `no_lab_browser` came back as fixed codes.
- With a stand-in VM serving another case, each case went to its own lab, a third case got `case_mismatch`, and the VM serving the connected case too got `ambiguous_lab`. The key variable set in the bot's process got `key_in_bot_environment`.
- The board's lab observer (`--lab-state-dir`) found the service, read the bots' 14 tool calls from `/activity`, and resolved three cited events; a citation the service never served was listed as missing.
- After the service was killed without cleanup its stale `state.json` gave `lab_unreachable`; another process listening on its port gave `lab_instance_mismatch`.
- The key and the elastic password appeared 0 times in any tool result, output or file.

Hunt it with the operator's approval of the origin. Start the Temporal worker and the bots' gateways from a terminal that does not hold the key variable, or every tool call answers `key_in_bot_environment`. `--case-id` picks the connected case even while the VM serves another one:

```powershell
py -3 -m hermes_temporal.cli lab-input --tool-driven --data-origin work-connected --case-id work-conn-001 `
    --state-dir <hermes home>\profiles\framework-network-analyst\hunt-lab-vm --output ..\runtime\work-conn-001-hunt.json
py -3 -m hermes_temporal.board --workflow-id <practice id> --input ..\runtime\work-conn-001-hunt.json `
    --lab-state-dir <hermes home>\profiles\framework-network-analyst\hunt-lab-vm
```

The bots are told the case is a work log connection (live read-only queries of the operator's work Elastic; unclassified work data), never synthetic. Connected hunts are unscored: work data has no answer key. Use the Slack bridge's minimal cards (HUNT-BOTS.md rule 4).

### Operator scoring

From this framework directory, generate into **new, separate external directories**, never a live profile or source fixture:

```powershell
py -3 .\hunt_lab\case.py generate --evidence-dir C:/HuntRange/new-case/evidence --truth-dir C:/HuntRange/new-case/operator-only
py -3 .\hunt_lab\case.py score --truth C:/HuntRange/new-case/operator-only/truth.json --findings C:/HuntRange/new-case/operator-only/reviewed-findings.json
```

The deterministic generator reproduces the bundled invented case; it does not replace deployed evidence or implement arbitrary-log import. Findings contain `schema_version: 1`, `case_id`, and a `findings` array of `{fact_id,event_ids}` mapped by the operator after reviewing actual cited observations. Keep the key and fact-ID rubric from the bot. The scorer reports precision/recall over seven rubric facts, not semantic grading of free-form text or evidence of model accuracy. It is separate from `benchmark.py` campaigns and the unimplemented live Elastic source adapter.



## Native cybersecurity workspace companion

The original [Desktop SDK companion](desktop/REVIEW.md) adds a native workspace page, sidebar/palette/status entry, the six-role roster (role monogram, profile id and remit per row), the human gates as a five-step guide (scope → evidence + hypotheses → analysis → independent review → handoff), a **Bot screen** route picker, and **Quick links**: hunting lab, hunt board, native Kanban, profile manager, in-app browser and an optional visible-pet gate reminder. Human clicks navigate to those native surfaces, Bot Screen, or the separate Hunting Lab page. The companion does not execute lab commands, read conversations, call models, execute tasks, write memory or record approvals. Its advisory gate guide is **not** native memory. Native HUD and memory graph controls remain native; no unsupported SDK bridge is used. Usage notes, model routes and boundaries are in the collapsed **Notes and limits** row at the bottom of the page.

Normal `setup_hermes.py install` includes the companion and lab. The narrower `install_desktop.py check` / `install_desktop.py install --home <approved-home>` remain available for an explicit companion-only installation. Hash-owned packages can be updated; unknown destinations, user-modified managed files and aliases are refused. Review [provenance, licensing, permissions and prerequisites](desktop/REVIEW.md). No specialist SOUL edits, profile resets, cloning, provider setup or automatic task advancement occur.

[Timestamped video inventory](desktop/VIDEO-INVENTORY.md) covers the complete returned public transcript, not complete audiovisual coverage. [Verification and unresolved blockers](desktop/VERIFICATION.md) distinguish real native UI mounting, source-level group-routing fixes and tests from **unverified live runtime repair and the still-undemonstrated two-bot exchange**. The runtime patch that earlier releases bundled has been removed; nothing in this folder applies native source changes. Existing Astra/Luna/Terra requirements remain unchanged, with no fallback/substitution. Preserve the known completion-role-label inconsistency and the limits of child-reported identity.

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

Replace the example values with a valid model and provider for your installation; `--provider` is optional when Hermes can select it. The adapter sends the prompt on stdin to `hermes chat --query-file - --oneshot --safe-mode --model <model-id>`, with the optional provider and `-Q`, in a fresh working directory. `--model` is required for this mode and is checked before reserving the task. An installed compatible Hermes version, provider access, and authorization are prerequisites. The adapter runs `--executable 'C:\path\to\hermes.exe'` (before the task ID) when given, else `LAB_HERMES_EXE`, else `hermes` on PATH; an executable that cannot be found is refused before the task is reserved, and a `LAB_HERMES_EXE` that does not exist is an error, not a fallback. This unqualified invocation may still select Hermes' sticky default profile, but safe mode discards profile configuration and identity; it is not a way to invoke a specific bot. Safe mode is not a sandbox; the framework never adds `--yolo`. A real model call can send data and incur costs. No model call happens until the operator runs this command.

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
