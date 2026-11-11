# Build this project with Hermes

This folder is the portable source project. Copy authored source and the `hermes-bots/` pack to an approved destination, excluding `.venv*`, workspace databases, run output, and surrounding downloads/research. It contains a Python ledger, reusable workflows and bot identity definitions, **not** the Hermes application, configured provider, live Bot Mode state, chat history, or credentials. Optional LangGraph/LangChain dependencies are installed separately on each machine; see [optional runtime](optional-runtime.md).

## Portable kit quick start

The clean ZIP is a setup kit, not a bundled Hermes runtime or an export of a working account. It contains the native profile distributions, defensive skills, ledger/workflow code, the built-in Elastic + Arkime lab controller and public synthetic fixture, pinned public-download manifests, setup/export helpers, and regression tests. VM disks, QEMU binaries, downloaded caches, live profiles, credentials and generated grading keys are not exported. Hermes, provider sign-in for model use, native delegation, and optional orchestration dependencies remain destination prerequisites; the lab manages its own guest stack.

### Install on another machine

1. Transfer the generated ZIP and compare its SHA-256 with the sender's recorded digest. Extract it; open the `hermes-bot-framework` directory. Hashes detect transfer changes, not whether the source is trustworthy.
2. Install Python 3.9+ and a supported Hermes release using the [official installation guide](https://hermes-agent.nousresearch.com/docs/getting-started/installation). Check the [OS/architecture matrix](https://hermes-agent.nousresearch.com/docs/getting-started/platform-support); this kit does not make unsupported platforms supported.
3. Inspect the authored identities and run the local check:

   **Windows PowerShell**
   ```powershell
   py -3 .\setup_hermes.py check
   py -3 .\setup_hermes.py install
   ```

   **macOS / Linux**
   ```sh
   python3 setup_hermes.py check
   python3 setup_hermes.py install
   ```

   `check` validates the catalog/manifests and locates an executable; it does not test provider authentication, model access, gateway health, or Desktop SDK support. If Hermes is not on PATH, put `--hermes "/absolute/path/to/hermes"` before `check` or `install`. Use `--home <approved-general-Hermes-home>` before `install` to select an isolated root; otherwise the helper uses `HERMES_HOME` or the standard platform home.
4. Review each native Hermes preview and confirm only intended new profile installations. Existing exact authored identities are preserved; the helper checks public metadata/file types rather than opening SOUL or private configuration. Native `plugins enable` manages its own enablement settings without resetting providers or the identity. `install --profile framework-coordinator` selects a subset; the analyst is also included as the lab owner. Paths resolve relative to the script. Setup stages/enables components but does not prepare media, download assets, or boot a VM. A running gateway imports a plugin only once, and `plugins enable` does not notify it about an already-enabled plugin. Every `chat --oneshot` hunt step runs inside that gateway, including the default-profile multiplexer that serves all profiles. Install therefore asks the gateway serving each profile to re-import its plugins, so the next session gets the new per-profile tool set. If the gateway refuses or cannot reload, install fails. Restart it with `hermes gateway restart` from the default profile when no hunt is running, then rerun install.
5. Use the destination's existing authorized Hermes sign-in; complete native sign-in only if that connection actually lacks it. Open `hermes desktop --cwd .` where Desktop is supported, then inspect the installed identities in **Bots**. Review model, tools, and permissions before sending a prompt. Do not create the same profile again with New Agent. A CLI registration alone does not prove a canonical Bot Chat exists or that its gateway works.

Installation never supplies force/overwrite, alias, clone, or skip-confirmation flags. It validates all authored distributions before native installation and rejects linked distribution paths and unsupported manifest changes. Existing profile identity is checked through public native distribution metadata and file types only. Native cancellation, failure, or an unrecognized success response stops the sequence with a nonzero exit; earlier installations remain. Unknown plugin destinations and user-modified hash-owned components are refused, not adopted. Never bypass these refusals with overwrite flags.

Check the selected connection/home before diagnosing OAuth. Named profiles can borrow provider credentials from their own root through native credential-pool fallback; a separate custom development home is not automatically the normal Desktop home. A Codex-only status failure is not proof of account-wide logout or Claude OAuth failure. Do not copy refresh tokens or require a new sign-in for every role merely because the role has no local credential entry.

The helpers do not download Hermes, handle credentials, configure providers, start models, initialize a ledger, or enable schedules, messaging, or native delegation. Normal setup **does enable the lab's native plugin** and stages its standalone Desktop entry and the workspace companion. Native CLI startup may initialize its own runtime; the installer is not a sandbox.

## Built-in hunting lab

After normal framework setup, open **Cybersecurity workspace → Open hunting lab** in the desktop app built from this repository, select the exact local `framework-network-analyst` owner and click **Start lab VM**. That one action automatically acquires verified public host prerequisites, prepares a standalone Ubuntu guest, boots it, and installs the pinned Elastic + Arkime stack inside it. Users do not separately install QEMU, host Docker, pycdlib, or media. Existing valid deployments are reused unchanged. Initial Internet access, Windows x64/WHPX, 5 GiB available RAM and 37 GiB free disk are prerequisites; Windows features are never enabled through elevation or an emulation fallback.

The source and portable kit include `hunt_lab/`. Framework setup installs only its tool backend into each registered framework profile; that backend has no `desktop/` tree, so Hermes never materializes a unified package with a separate opt-in Desktop posture. The Hunting Lab page itself ships bundled in the desktop app built from this repository (`apps/desktop/src/plugins/hunt-lab/`); framework setup no longer writes `desktop-plugins/hunt-lab`, and a copy left there by an older setup is shown in **Capabilities → Plugins** as a stale disk copy the bundled page shadows. The workspace companion is still installed under `desktop-plugins/` with ownership hashes; disabled native user preferences remain authoritative. Loading either page is inert until a human action.

Human Start/Prepare observes read-only setup status for at most ten minutes; the setup worker has its own one-hour deadline. No lifecycle retry is issued. If observation ends first, refresh status explicitly. A running QEMU process is not service readiness: use the returned loopback `/health`, which requires ingested events, Arkime sessions, and its viewer. The real console is available before HTTP readiness. Closing Hermes does not stop the VM; use **Shut down lab VM**.

See [requirements, native CLI and evidence boundaries](README.md#built-in-local-hunting-lab). The current local development deployment uses `C:\HuntRange\native-hermes-home` and the separately prepared source-mode Desktop. It does not repair or replace the live PM-managed Hermes installation. On another machine a compatible native release is still required; the framework does not install a new Hermes application or silently apply `runtime-fixes.diff`.

## Native Desktop workspace

Normal framework setup includes `desktop/cybersecurity-workspace/plugin.js`. For a deliberately narrower companion-only installation, run `python install_desktop.py check` and `python install_desktop.py install --home <approved-general-Hermes-home>`. Use `py -3` on Windows or `python3` on macOS/Linux. Hash-owned components can be updated; unknown directories, altered managed files and aliases are refused without overwriting them. No profiles are reset or broadened. Review [permissions and prerequisites](desktop/REVIEW.md), [video coverage](desktop/VIDEO-INVENTORY.md), and [actual verification](desktop/VERIFICATION.md).

The companion displays human gates and six roles, with human-clicked native navigation, explicit registered-route selection for native Bot Screen, and an optional fixed reminder through an already visible native pet. Screen discovery reads route metadata only after its button is clicked; opening a selected running screen observes live frames. A framework-named alias is not sufficient: its actual target must be an approved framework profile. Starting or controlling the screen remains a separate native action. This is not a VM boot/install console. The companion does not install pet assets or an image backend. Its gate diagram is advisory, not a live memory graph or approval record. Use the native HUD titlebar control and native Memory graph palette entry only under an approved data boundary. HUD is deliberately absent from the SDK action allowlist; do not inject shortcuts or import internals to bypass that boundary. Native Kanban completion is not ledger approval; no existing research card is advanced.

### Native source patch and separate Desktop build

`desktop/runtime-fixes.diff` targets exact Hermes base `bf0203a794a07aac3ff764972ab9087baa4e4f4e`, retaining `desktop/HERMES-LICENSE.txt`. Its 32 files include group-turn/gateway refusal repairs, the native `host.openScreen` SDK and provider lifecycle, embedded QEMU control and validation, early desktop-data isolation, and associated regression tests including native delegation success coverage. It is **not auto-applied**. Installing the companion alone does not add the required native APIs or update an existing Desktop binary.

In a separately prepared development clone at that exact base, review both patches. Their recorded hashes cover raw LF bytes, not Windows checkout-normalized bytes. Apply `runtime-fixes.diff` first; then verify the prerequisite digest and every role-policy manifest preimage before applying `native-role-policy.diff`. A null preimage requires the path to be absent, including aliases. Stop on any mismatch; do not normalize a changed file to make its hash pass.

```sh
git -c core.autocrlf=false -c core.eol=lf apply --check /absolute/path/to/source-kit/desktop/runtime-fixes.diff
git -c core.autocrlf=false -c core.eol=lf apply /absolute/path/to/source-kit/desktop/runtime-fixes.diff
# Verify desktop/native-role-policy.json preconditions before the next two commands.
git -c core.autocrlf=false -c core.eol=lf apply --check /absolute/path/to/source-kit/desktop/native-role-policy.diff
git -c core.autocrlf=false -c core.eol=lf apply /absolute/path/to/source-kit/desktop/native-role-policy.diff
npm ci
npm run build --workspace apps/desktop
```

Use the source's supported Node/npm versions and build prerequisites. The patch was applied to pristine files from the pinned public archive and all 32 resulting files matched the exercised development source byte-for-byte. The latest focused native run passed 83 tests with one platform-specific skip across 11 files; both renderer and Electron TypeScript checks passed. Native delegation checks separately passed 71 tests and 31 related backend/route tests with scripted conversations, not provider calls. See `desktop/VERIFICATION.md` for actual UI evidence and its limits. Follow the destination's supported packaging/publication process and authorized lifecycle controls after building. Never hand-edit an immutable installed generation, suppress runtime errors or restart a shared messaging gateway as a shortcut. A running isolated source build is not proof that an active PM generation or the original parked goal was repaired.

## Native Hermes threat hunting

This is a native Hermes chat workflow, not a separate dashboard. OMP is used to develop the framework and is **not** required to run the hunt. The coordinator's `SOUL.md` and `hermes-skills/threat-hunt/SKILL.md` define a supplied-evidence workflow with human gates. `framework/native_team.py` is an explicit policy helper; `initialize PROFILE` can exclusively create reviewed nonsecret `config.yaml` settings for one exact registered profile that has no config. It does not create profiles, install or activate the separate native-policy patch or plugins, start providers, handle credentials, or read existing config contents.

Process guidance borrows bounded-task and handoff ideas from [OpenRig Workshop](https://github.com/mvschwarz/openrig-world/blob/582084a72d025103fd81d5fdc22ea6d9a8cb982e/rigs/workshop/README.md), not its daemon, permission bypass, tmux setup, or standing seats. OpenRig supplies workflow patterns only; it does not supply this cybersecurity ontology, persistent shared memory, measured savings, or an installed daemon. This remains behavioral guidance: it adds no enforced security/runtime capability, tool permission, automatic execution, or test evidence, and installation does not promise working delegation. Keep the existing six roles, exact model routing/no-fallback rules, direct-child limit, and operator gates. Bounded turns or summary size are not spend caps; actual token savings are unmeasured. Do not overwrite live installed SOULs or profiles.
The [optional supplied-evidence ontology guide](hermes_temporal/README.md#start-a-supplied-evidence-hunt) documents `ontology`, `context_by_step`, and each step's `HermesStep.hunt_context` for a bounded synthetic hunt. See the [native threat-hunt skill](hermes-skills/threat-hunt/SKILL.md) for collaboration guidance and the pure standard-library [`ontology.py` validator](hermes_temporal/ontology.py) for its implementation. Its stable, evidence-cited IDs and strict handoff objects are coordination guidance and validation—not a shared database, evidence retrieval mechanism, truth verifier, native-chat schema enforcement, automatic redaction, or approval. Native Hermes can delegate independent branches in parallel when configured; the optional Temporal hunt retains its fixed nine-stage serial execution and human execute/review gates. Source-kit skill/guidance edits are not silently installed into or applied to existing profiles. This documentation change makes no provider calls and does not configure credentials, install a runtime, or start an ontology service.


Inspect the static policy before any native work:

```powershell
py -3 .\native_team.py plan
py -3 .\native_team.py check
```

Use `python3 native_team.py plan` and `python3 native_team.py check` on macOS/Linux. `plan` is local and read-only. By default, `check` verifies each exact authored `distribution.yaml` identity, then requests only allowlisted leaves through native Hermes `-p <profile> config get <key> --json`: `model.default` (never the potentially sensitive whole `model` mapping), `fallback_providers`, legacy `fallback_model`, `agent.max_turns`, `agent.allowed_tool_names`, `platform_toolsets.cli`, `agent.disabled_toolsets`, and coordinator delegation limits/routes. The helper binds `HERMES_HOME` to `--home <approved-home>` (or the standard root resolved by `lab.resolve_home`) and applies a finite timeout. Native leaf errors are suppressed; only the exact pinned-source `Config key not set: <key>` response means an unset non-model leaf. Other failures, malformed values, and a missing `model.default` (including a legacy scalar) are refused. Existing differing values remain conflicts. Matching persisted values are not evidence of enforcement or effective provider/model readiness.

**Ordinary native startup is not zero-write or secret-free.** Even `config get` can load `.env`/external secret sources, create logs/scratch directories or config backups, repair launchers/dependency state, and run startup recovery before reaching the getter. Neither `check` nor `apply` is permitted as a live diagnostic in the current model-shape investigation. The only permitted live diagnostic surface for that loop, after separate source/interpreter review, is the standalone projection below; implementing it does not authorize invoking it against live state.

The earlier 42-leaf check verified approved nonsecret **output only**; it did not prove ordinary CLI startup was side-effect-free. No authentication mutation was observed, and that check does not establish whether ordinary startup internals read authentication stores. The new projection's synthetic evidence covers importing the native package and executing the module under import/write/network/process denials with unchanged fixture snapshots; the exact installed `-I -B -m` entrypoint was also exercised on an owned synthetic profile. This is not evidence of a live projection or permission to run one. `hermes_cli.__init__` repairs process stdio; the projection never accesses its lazy version attribute (which would import additional installation/PM code).

The reviewed native-policy patch adds a separate startup-isolated module. Use an explicitly selected native Python with that patched package and its YAML parser already installed (no automatic interpreter discovery, installation, bootstrap, or recovery):

```text
<reviewed-native-python> -I -B -m hermes_cli.config_model_projection --root <absolute-approved-native-root> --profile framework-researcher --expected-model claude-sonnet-5
```

Its entire success response is `{"shape":"scalar","expected_model_match":true}` (shape is exactly `missing`, `scalar`, `mapping`, or `other`; the second field is a JSON boolean). Only exact persisted string equality, either `model: MODEL` or `model: {default: MODEL}`, matches. Mapping `name`/`model` aliases and nested defaults do not certify a match; YAML anchors use the native safe parser's normal semantics. Missing files/keys, mismatches and unsupported values return false. Unreadable/malformed YAML, non-mapping roots (including empty/null documents), duplicate keys, invalid arguments, missing profile directories, tombstones, and symlink/reparse paths fail with a fixed nonrevealing error. Root and profile are explicit, without sticky-profile selection or path-variable expansion. It does not merge defaults/managed overlays, expand environment values, resolve providers/auth, mutate/migrate config, or expose raw model/provider values or parse-error contents. The projection is about persisted configuration only, not effective session routing or readiness.

For a separately authorized full helper operation, opt in with `native_team.py --model-projection-python <reviewed-native-python> --home <approved-root> check` (or `apply`). The projection runs before ordinary getters for each profile, replaces only the `model.default` read, and accepts only a strict two-field scalar/mapping true response. An exact legacy scalar remains unchanged; missing/mismatching/invalid results refuse before that profile's ordinary getters and before any explicit policy writes. The other getters still have the ordinary startup effects above. Without this explicit option, existing helper behavior is unchanged.

To configure one newly installed exact profile without signing in or making provider calls, first review `plan`, then run an explicit `initialize` for only that profile, for example `py -3 .\native_team.py --home <approved-home> initialize framework-researcher` (macOS/Linux: `python3 native_team.py --home <approved-home> initialize framework-researcher`). This exclusively creates `profiles/<PROFILE>/config.yaml` as a YAML-compatible JSON mapping with reviewed model/fallback/turn settings, `agent.allowed_tool_names` (the per-profile hunt tool ownership listed under `apply` below), direct toolset and disabled-toolset settings, `tools.tool_search.enabled: off` for the five tool-owning specialists, and the coordinator's pinned-plugin `profile_routes` backend, route list and default route. It also retains the current finite delegation limits. The config directory must be an ordinary path and `distribution.yaml` identity must exactly match the requested profile. Any existing config entry, including a dangling symlink or reparse point, is refused without being opened or overwritten; exclusive creation refuses a concurrent creation race. It stages under the profile directory and publishes with an exclusive hard link: same-filesystem hard-link support is required, and filesystems without that support fail safely without replacing an existing path. Initialization does not install/activate the separate reviewed native-policy patch or plugin and does not prove that Hermes enforces these fields, provider access, final tools, routes, or runtime readiness. `check` makes no explicit policy writes but retains ordinary startup effects; `apply` remains conservative for existing or legacy configs and never initializes missing files as a side effect.

After reviewing the plan and selected profile state, `py -3 .\native_team.py --home <approved-home> apply` (or `python3 native_team.py --home <approved-home> apply`) explicitly applies only non-conflicting native config leaves: `model.default` route IDs, empty modern `fallback_providers` and legacy `fallback_model` chains, finite per-profile `agent.max_turns`, and exact `agent.allowed_tool_names`, which record hunt tool ownership: coordinator `delegate_task`; researcher (Threat Hunter) `elastic_search`, `elastic_aggregate`, `lab_browser`, `packet_fields`; Network Analyst `arkime_sessions`, `arkime_unique`, `hunt_lab_query`, `lab_browser`, `packet_fields`; librarian (Threat Intel) `intel_lookup`, `elastic_aggregate`; builder (Detection Engineer) `detection_test`, `elastic_aggregate`; reviewer (Purple Team) `elastic_search`, `arkime_sessions`, `detection_test`. These lists come from `TOOL_OWNERSHIP` in `hunt_lab/query_adapter.py`, and the `hunt-lab` plugin uses the same map to register only the profile's owned `hunt_lab` tools (none for the coordinator or an unknown profile), so Hermes refuses any other hunt tool as unknown even though stock Hermes ignores `agent.allowed_tool_names`. Coordinator controls remain `delegation.max_spawn_depth=1`, `max_iterations=8`, `max_summary_chars=4000`, and `delegation.fallback_providers=[]`; it also configures `delegation.backend=profile_routes`, the five `delegation.backends.profile_routes.profiles` entries, and `delegation.backends.profile_routes.default=framework-researcher`, so a task that names no profile runs as the Threat Hunter rather than as the coordinator. The CLI toolset selections are coordinator `[no_mcp, delegation, hunt_lab]` and `[no_mcp, hunt_lab]` for the other five: Hermes 0.23.0 builds a delegated child's toolsets as a subset of its parent's, so the coordinator enables `hunt_lab` for the specialists it delegates to, while registering no hunt tool for itself. Those five also get `tools.tool_search.enabled: off`, because native Tool Search defers plugin tools behind bridge tools that an exact allowlist strips. It additively disables `desktop_ui`, `project`, `catalog`, `x_search`, `context_engine`, and `memory` through `agent.disabled_toolsets`, plus `delegation` for the five specialists, preserving all other existing entries; for every profile it removes a `hunt_lab` entry left by the earlier policy. Persisting these settings does not prove native enforcement or runtime readiness.

`apply` verifies all six exact registered identities and preflights every reviewed safe leaf before its first explicit policy write. Missing non-model values are explicitly applied, and values that exactly equal the earlier reviewed policy (empty specialist allowlists, Network Analyst `[hunt_lab_query]`, the Threat Hunter and Network Analyst allowlists from before `lab_browser` and from before `packet_fields`, specialist CLI toolsets `[no_mcp]`) are upgraded; any other custom conflict is preserved and causes refusal. It refuses malformed/unknown inspection and conflicting allowlists, caps, or routes. Without the explicit projection interpreter it also refuses an ambiguous missing model leaf; with the projection, only exact supported persisted matches are admitted and never rewritten. Native output is suppressed. If a write fails, earlier settings may remain; no rollback is attempted. Ordinary native startup may have its own effects before policy preflight. `agent.max_turns` caps model/tool iterations; `delegation.max_summary_chars` caps child summaries, not provider output tokens. They are not aggregate spending caps.

Pinned upstream's credential-free `--list-tools` catalog is built before final tool assembly and does not prove the effective tool boundary. The review-only [native role-policy patch](desktop/native-role-policy.diff) targets Hermes `bf0203a794a07aac3ff764972ab9087baa4e4f4e` **after** [runtime-fixes.diff](desktop/runtime-fixes.diff); [its manifest](desktop/native-role-policy.json) records the prerequisite patch hash and exact file preimages/postimages. It enforces `agent.allowed_tool_names` against final tools and invocation, validates `delegation.allowed_profiles` and every batch's submitted/backend-returned profile choices before credential resolution, and gives admitted named-profile children their own explicit CLI allowlists, disabled toolsets, and exact cap. Preserve the Hermes MIT notice. Check every manifest precondition in a separate source tree before applying; do not apply to an unmatched or running installation. The patch is not installed, activated, or verified by `native_team.py`. See [executed verification and limits](desktop/VERIFICATION.md); config persistence is not deployment evidence. The patch provides neither OS isolation nor an aggregate spending cap.

Exact caps also survive stored-session reconstruction, compression, branch/reset publication, gateway cache rebuilds, background/preview agents, and API/one-shot/in-process ACP consumers. Pending or unreadable authority remains deny-all until a finalized row is available; a provisional watch cap does not permanently erase a finalized nonempty cap. One-shot calls restore their caller's mode flags, logging level and task-local delivery context on return or exception. These are native source changes, not capabilities supplied by the Python policy helper alone.

The official advanced-delegation plugin was reviewed at commit `b3825d097195b5748585b0491fab48c95d105c19`; source is not bundled. On Hermes 0.22.5 or newer, its exact native pinned-source install form is:

```powershell
hermes -p framework-coordinator plugins install https://github.com/NousResearch/hermes-official-plugins/tree/b3825d097195b5748585b0491fab48c95d105c19/advanced-delegation --ref b3825d097195b5748585b0491fab48c95d105c19
```

Use normal native confirmation and dependency consent. Do not add `--enable` (skips enable confirmation), `--yes-deps`, `--force`, or a floating branch. Verify installed revision independently; this helper never downloads/installs plugins.

The reviewed plugin's supported config API is `hermes -p framework-coordinator delegation config`; `--show` reports routes. Configure its exact `profile_routes` backend with `delegation.backends.profile_routes.profiles` as the five `{name, description}` entries shown by `native_team.py plan`, `delegation.backend: profile_routes`, and `delegation.backends.profile_routes.default: framework-researcher`. The plugin's task schema uses `profile` (not `option`). Hermes 0.23.0 turns the route list into the `profile` enum and refuses any other value before the plugin runs; a task that names no profile runs as the default route instead of as the coordinator. `delegation.allowed_profiles` is not read by Hermes 0.23.0 and is no longer written. A delegated child's toolsets are a subset of the coordinator's (`no_mcp`, `delegation`, `hunt_lab`), so children get no core tools, and within `hunt_lab` each child registers only its own profile's tools (checked live on 2026-11-10: a child delegated as `framework-researcher` called `elastic_aggregate` through the lab). Never infer runtime readiness from config output.

This strict path uses explicit `task.profile` selections and has no model-map `option` configuration or instructions. Profile identity is not OS isolation, and direct Bot Mode profiles/groups are distinct from internal delegation. Provider sign-in, entitlement, model access, and live route execution are not checked.

Managed-worker sessions with frozen configuration cannot switch to another profile: pinned Hermes explicitly refuses that route before reading target credentials. This kit does not add cross-profile worker routing. Verify that the selected native execution path supports the required profile handoffs before inference; do not remove the required profile, disable a safety guard, or fall back to the coordinator's model to bypass the refusal.

Human decisions remain required for every stage. Use only approved sanitized evidence; never pass credentials, account/session data, raw PCAP or controlled material to an unapproved service. Model calls may transmit submitted text and incur costs.

### Optional authorized source-code vulnerability audit

The portable kit also contains `hermes-skills/security-audit/`, adapted from the pinned MIT-licensed [Cloudflare skill](https://github.com/cloudflare/security-audit-skill) and its [harness article](https://blog.cloudflare.com/build-your-own-vulnerability-harness). Review its `SKILL.md`, supporting guides, validators and `PROVENANCE.md` before use. Install the **entire directory**, not only `SKILL.md`, into the explicitly approved coordinator home's `skills/security/security-audit/`, refusing an existing destination. This is a separate opt-in skill, not an expansion of the supplied-evidence threat-hunt scope.

Keep delegation inside Hermes. Full audit requires explicit repository/path authorization, exclusions, an approved new output directory, and a finite total-agent cap. Use a fresh verifier rather than self-grading. The pinned validators require Linux file-opening protections; their Windows refusal must not be bypassed. Target-controlled execution additionally requires a separately approved OS-enforced sandbox; a portable VM or profile alone is insufficient. Missing prerequisites remain `needs_validation`, not confirmed findings. No scans, external ingestion, schedules, source modifications or merges occur merely by installing the skill.


## Build a clean transferable ZIP

From the source directory, choose a new output filename:

**Windows PowerShell**
```powershell
New-Item -ItemType Directory -Force .\dist | Out-Null
py -3 .\package_portable.py --output .\dist\hermes-bot-framework.zip
```

**macOS / Linux**
```sh
mkdir -p dist
python3 package_portable.py --output dist/hermes-bot-framework.zip
```

The exporter refuses an existing destination and packages only a fixed allowlist. It excludes `.env`, live profiles, auth/session stores, logs, workspaces, virtual environments, local context files, and surrounding downloads/research. Symlinks and Windows reparse points at the kit root or inside it, and hard-linked source files, are refused; aliases in parent directories outside the kit are supported. File identity and link count are checked again on the opened file before reading. It includes `SHA256SUMS` for the authored members and prints the ZIP digest. This boundary is not a content sanitizer or protection against every concurrent filesystem change: review edits to allowlisted source before sharing. The archive has one top-level `hermes-bot-framework/` directory and no dependency on the original checkout.

Windows verification exercised ZIP extraction, all five original native profile installs and the added Network Analyst install in disposable Hermes homes, native cancellation, existing-profile refusal with the installed SOUL unchanged, and creation of the six-stage hunt ledger. Run the packaged regression suite with `python -m unittest discover` (or `py -3 -m unittest discover` on Windows). macOS/Linux installation is designed for but not exercised here; no provider call or native Bot Chat success is claimed by these setup checks.


## 1. Prepare the destination

1. Install Python 3.9+ with SQLite support for the ledger. Install Hermes separately using its [official installation guide](https://hermes-agent.nousresearch.com/docs/getting-started/installation), and check the [platform support matrix](https://hermes-agent.nousresearch.com/docs/getting-started/platform-support). Hermes Desktop packaging varies by OS and architecture; it is not available as the same prebuilt package on every platform.
2. Configure any desired model provider **on that machine** through Hermes. Follow the provider's rules and use only data authorized for that provider. Do not copy this machine's credentials, cookies, or profile data into this project folder.
3. Open a terminal in the copied `framework` folder and check `hermes --version`. Where the installed Hermes supports its Desktop command, run `hermes desktop --cwd .` to request this project as the initial working directory. Alternatively choose this folder in your installed Hermes interface. Do not assume that choosing a directory restricts filesystem or network access.
4. For a development session, open the copied folder itself and explicitly provide the packaged instructions below. Local `AGENTS.md`/`CLAUDE.md` files from this workstation are not exported. Review any destination context files, since choosing a directory is not an isolation boundary.

For a new development task you can ask Hermes:

> Read `README.md`, `hermes-setup.md`, and the selected authored `hermes-bots/<profile-name>/SOUL.md`. Inspect the existing code before changing it. Propose and implement the requested task using a disposable workspace and benign data; preserve cross-platform behavior, human review, and provider neutrality. Do not access credentials, run trades, or send controlled data to an external service.

Replace the final sentence of your request with the actual task. Review changes and command approvals before accepting them.

### Optional: Envision language models

Envision's **Applications → Models → Model Catalog → Palantir-provided models** lists models and their resource identifiers. For example, the catalog showed `ri.language-model-service..language-model.gpt-5-6-terra`. Availability and permissions are account-dependent.

Palantir documents an [OpenAI-compatible chat completions API](https://www.palantir.com/docs/foundry/api/v2/llm-apis/models/openai-chat-completions-proxy/) at `https://envision.af.mil/api/v2/llm/proxy/openai/v1/chat/completions`. Use a model resource identifier as `model` and a Foundry bearer token for authentication; the token is tied to the account, not a separate key per model. OAuth applications need the `api:use-language-models-execute` scope. The endpoint and credentials have not been tested from this framework.

Use only an organization-approved device, network, credential store, and data boundary. Direct connectivity from the original workstation timed out; Envision was accessible inside the EITaaS desktop/VM. In-VM browser access does **not** establish local API connectivity, and a local timeout is not evidence of an invalid token. The documented proxy endpoint remains unverified for this deployment. Personal Foundry tokens carry account privileges, are shown only once, and are for development/testing, not production; see [Palantir's token guidance](https://www.palantir.com/docs/foundry/platform-security-third-party/user-generated-tokens/). For production, use an approved OAuth application.

#### Approved local configuration exception

For this user's explicitly approved PC, the user has requested a private repository-root `.env` as a narrow exception to the project's usual no-secrets-in-project convention. This is user-specific local configuration, **not** part of the portable `framework/` folder. Do not copy it when moving the framework. Keep it excluded from Git commits, source releases, archives, and shared backups; Git ignore rules do not protect manual copies or already tracked files. Restrict filesystem access to authorized users. This exception does not authorize sharing credentials in chat, task prompts, ledger records, artifacts, logs, or command-line arguments, nor transferring them to other machines.

The intended root `.env` variables are:

| Variable | Purpose |
| --- | --- |
| `ENVISION_API_KEY` | Private Foundry account bearer token; not a per-model key. |
| `ENVISION_BASE_URL` | Documented OpenAI client base URL: `https://envision.af.mil/api/v2/llm/proxy/openai/v1` (without `/chat/completions`). |
| `ENVISION_MODEL` | Authorized model resource identifier, such as `ri.language-model-service..language-model.gpt-5-6-terra`. |
| `ENVISION_TOKEN_EXPIRES_AT` | Expiry recorded from the token UI, including timezone when available; informational metadata, not automatic renewal or enforcement. |

These instructions do not assert that the file has been created, that its values are valid, or that an API call has succeeded. Replace or revoke tokens through approved account controls before expiry or after suspected exposure; do not paste token values into commands.

For a separately approved local-to-EITaaS integration, see the [optional Envision job bridge](README.md#optional-envision-job-bridge). Its worker uses an explicitly provisioned environment credential, not this `.env` file. It requires an approved relay and execution environment; Windows App is not a VPN, and an interactive CAC session is not an always-on service.

#### Optional Python OpenAI client

The ledger `bot.py` uses the standard library, does **not** load `.env`, and does not call model APIs directly. The following is a separate, opt-in client example, not a ledger or Hermes integration. Install these optional dependencies into an approved Python environment, using a virtual environment if required by local policy:

```powershell
py -3 -m pip install openai python-dotenv
```

On macOS/Linux use `python3 -m pip install openai python-dotenv`. This installation is not needed for the ledger itself.

Save the following example as a private local Python script and run it **from the repository root containing the approved `.env`**, not from `framework/`. It explicitly loads only that root file into the process environment; existing environment variables take precedence. Do not display the file, dump the environment, enable HTTP/debug logging, or include the token in shell arguments. In a portable copy without the root file, configure these environment variables through the destination's approved credential mechanism instead.

```python
import os
from pathlib import Path

from dotenv import load_dotenv
from openai import APIError, OpenAI

load_dotenv(dotenv_path=Path.cwd() / ".env", override=False)
required = ("ENVISION_API_KEY", "ENVISION_BASE_URL", "ENVISION_MODEL")
if any(not os.environ.get(name) for name in required):
    raise SystemExit("Configure the required Envision environment variables privately.")

client = OpenAI(
    api_key=os.environ["ENVISION_API_KEY"],
    base_url=os.environ["ENVISION_BASE_URL"],
    timeout=30.0,
    max_retries=0,
)
try:
    response = client.chat.completions.create(
        model=os.environ["ENVISION_MODEL"],
        messages=[{"role": "user", "content": "Reply with a short greeting."}],
    )
except APIError:
    # Do not dump request objects, headers, or raw error payloads.
    raise SystemExit(
        "Envision request failed. Check approved network access, endpoint, "
        "token expiry/permissions, and model access without exposing credentials."
    ) from None
print(response.choices[0].message.content)
```

Run the saved script with `py -3 .\envision_example.py` on Windows or `python3 ./envision_example.py` on macOS/Linux if that is the filename you chose. This makes a real external request using only the benign greeting; use it only within the approved data boundary. `ENVISION_TOKEN_EXPIRES_AT` is not consumed by the OpenAI SDK; check expiry separately. The example has not been executed or verified against Envision.

To use an external agent with Envision, configure a compatible client separately in an approved environment and run it through the explicit generic CLI adapter described in `README.md`. Loading `.env` in this standalone script does not configure a different process or Hermes. Verify the client's support for a custom OpenAI-compatible base URL and Foundry model identifiers; compatibility has not been established for Hermes. Never place credentials in the ledger, task prompts, or CLI arguments.

## 2. Use the role instructions in Desktop Bot Mode

Hermes Desktop's [Bot Mode](https://hermes-agent.nousresearch.com/docs/user-guide/bot-mode) presents Hermes profiles as bots. Each profile is managed by Hermes outside this folder; copying this project does not create bots or migrate their state.

Use the [authored bot pack](hermes-bots/README.md) rather than improvising identities: incident response lead, threat hunter, detection engineer, purple team analyst, threat intelligence analyst, and network analyst. The pack includes source-traceable SOUL files and supported local distribution manifests. Fresh Desktop creation and CLI distribution installation are alternative setup routes; do not create the same profile twice. Copying the source alone performs neither operation.

1. Open **Bots** and choose **New Agent**. Create a fresh profile rather than cloning an existing profile when you do not intend to copy its configuration or data. Review the API-key-copy setting and turn it off if credential copying is not intended.
2. Give the bot the selected catalog entry's name, title, and description. Under **Advanced**, use its complete `hermes-bots/<profile-name>/SOUL.md`. The four `roles/*.txt` files remain provider-neutral ledger instructions; the authored SOUL files add persistent identity and handoff boundaries, including intelligence and network-analysis specializations. Review tools, skills, MCP servers, and permissions before saving. Repeat only for intended, unused names.
3. Give each bot a bounded task and review its work. The role text is guidance, not an access-control mechanism. Bot creation can modify local Hermes profiles; do it deliberately, not as a side effect of opening this folder.

No bot profiles, recurring routines, model routes, or messaging integrations are created by this project automatically. Use the installed Hermes version's documentation for UI and version-specific behavior. Hermes profiles do not sandbox filesystem access.

## 3. Optional task ledger

See `README.md` for Windows and macOS/Linux setup. Create a new workspace, add a bounded task or create a reusable workflow, explicitly start a ready task, and use `prompt ID` to print the appropriate role and task context. A human may paste that context into a bot chat and record the actual response with `submit`; approval remains an explicit human decision. Prompts include immediate predecessor task histories and artifact paths as untrusted context, but do not open artifact files or recursively include all ancestor tasks. Review all included context before sharing it and supply only separately approved source files.

Alternatively `run --adapter hermes --model MODEL ID` invokes an installed compatible Hermes CLI for an active task in safe mode, optionally with `--provider PROVIDER`. Use a real model and provider authorized for the destination; safe mode suppresses profile identity and configuration. To select an existing profile instead, use `run --adapter hermes --profile NAME --allow-profile-config ID`; it uses Hermes' global profile selector without safe mode and does not accept the safe-mode model/provider overrides. NAME must be an existing profile's actual name, which need not equal its Desktop display title. This starts a CLI session, not necessarily the bot's canonical Desktop Bot Chat; it does not create profiles or coordinate bots.

Both paths are opt-in, inherit the account's permissions, may transmit prompt data and incur costs, and record output for review—not automatic approval. Profile mode additionally permits profile config, SOUL, memory, tools, plugins, hooks and integrations. Hermes may write its own session history, memory, logs or authentication state even though this project does not directly modify profiles or credentials. Review the complete prompt, destination and profile configuration before use; do not run without authorization for those effects. Neither a profile nor safe mode is a sandbox. See `README.md` for exact commands, failure recovery and limitations.

### Reusable workflows without automatic bots

The bundled `research-review` workflow creates researcher → independent reviewer → coordinator synthesis tasks. `build-review` creates requirements researcher → builder → independent reviewer → coordinator release-handoff tasks. Both restrict research to approved supplied sources, distinguish source facts from AI-generated notes, and stop for missing authority or evidence. The builder makes only agreed changes; the coordinator prepares a human decision, not automatic publication or deployment.

For example, from PowerShell in this folder, using a new workspace path:

```powershell
$ws = '.\workflow-example'
py -3 .\bot.py -w $ws init
py -3 .\bot.py workflow list
py -3 .\bot.py workflow show research-review
py -3 .\bot.py -w $ws workflow create research-review --title 'Review supplied meeting notes' --scope 'Use only examples/meeting-notes.txt supplied separately; no browsing or source edits.' --acceptance 'Identify decision, action owner and deadline, and open question with source evidence.'
# IDs below illustrate only this fresh workspace; use the printed mapping.
py -3 .\bot.py -w $ws workflow status 1
py -3 .\bot.py -w $ws ready
py -3 .\bot.py -w $ws start 1
py -3 .\bot.py -w $ws prompt 1
```

Use `python3 bot.py -w "$ws"` with your shell's variables on macOS/Linux. An existing initialized workspace can be extended directly with `workflow create`; do not reinitialize it. Creation atomically records the group and all pending tasks, dependencies and events, preserving existing manual work. It prints a workflow ID and key-to-task-ID mapping; these ID spaces are separate. Every task carries the workflow goal and labeled operator scope/acceptance as well as its step instructions. `workflow status ID` reports member keys, IDs, roles, statuses and readiness/blockers. `ready` lists only pending tasks whose prerequisites are all approved (`done`), across the whole workspace; it does not start them.

Do the research manually, or give the reviewed prompt and approved source to an authorized existing bot. Record actual findings with `submit TASK_ID --by researcher --note '<actual sourced findings and uncertainties>'`, then inspect `show TASK_ID`. A human checks the evidence and chooses `approve TASK_ID --by 'human reviewer' --note '<actual evidence checked and decision>'` or `reject TASK_ID --by 'human reviewer' --note '<actual issues and corrections>'`. Replace all placeholder notes with observed work; never copy them as evidence. Rejection returns work to active for revision and resubmission. `review` does not unlock dependent tasks; only human approval does.

After approval, use `ready`, explicitly start the reviewer task from the mapping, and inspect its prompt. Have an independent reviewer check sources and report actual evidence/issues; submit that result and have a human approve or reject it too. Then start the coordinator task, prepare and submit the synthesis or release decision handoff, and obtain explicit human approval for that final task as well. Inspect `workflow status ID` after each decision. No role, including reviewer or coordinator, self-approves. Unresolved earlier findings require a human decision and separately scoped correction work, not an invented claim that they were fixed; see the [complete workflow procedure](README.md#reusable-human-operated-workflows).

Custom templates use `workflow show .\my-workflow.json` and the same `workflow create` options. File paths resolve from the current directory. The strict version-1 JSON schema rejects missing/unknown fields, duplicate object properties or task keys/dependencies, unsupported versions, invalid roles, missing dependencies and cycles before database mutation. Forward references are supported. Templates contain data, not executable commands, interpolation or expressions; see `README.md` for all fields.

Workflow creation does not call Hermes or any model, select profiles, install tools, approve tasks, configure services or provide bot-to-bot transport. To use the explicit CLI adapter, first authorize its effects, inspect the full prompt and `start` the ready task; the existing `run` options above then apply unchanged. CLI success produces a review handoff, never an automatic next step. The manual path needs no Hermes installation or provider.

### Offline defensive threat hunt

The bundled `threat-hunt` template uses the existing ledger roles and, if desired, existing Hermes profiles; it installs nothing and requires no new profile. The included [synthetic event fixture](examples/synthetic-hunt-events.json) is invented, offline, not operational telemetry or a scored evaluation. It supplies stable event IDs, bounded source coverage, a suspicious sequence, a benign comparison, a possible alternative explanation and an explicit telemetry gap; it supplies no hidden truth.

From this folder in PowerShell, use an existing initialized workspace or initialize a new one as above. First inspect the template and deliberately approve the fixture as the only supplied source for this exercise:

```powershell
py -3 .\bot.py workflow show threat-hunt
py -3 .\bot.py -w $ws workflow create threat-hunt --title 'Review invented offline events' --scope 'Use only examples/synthetic-hunt-events.json, supplied separately, for the 2025-04-15 09:00-10:00 UTC exercise; authority is limited to this invented fixture. Exclude all other data and actions.' --acceptance 'Cite event IDs, distinguish observations from hypotheses and inference, consider alternatives and contradictory evidence, and report coverage and uncertainty for human decision.'
```

Record the printed workflow ID and the six key-to-task-ID mappings; they are separate ID spaces and depend on the workspace. Substitute the actual IDs in the following commands, not the angle-bracket labels:

```powershell
py -3 .\bot.py -w $ws workflow status <workflow-id>
py -3 .\bot.py -w $ws ready
py -3 .\bot.py -w $ws start <scope-task-id>
py -3 .\bot.py -w $ws prompt <scope-task-id>
py -3 .\bot.py -w $ws artifact <scope-task-id> --path .\examples\synthetic-hunt-events.json --description 'Invented offline event fixture supplied for the scoped exercise'
```

The artifact command records an existing path, not its contents or a snapshot. Prompts contain artifact paths and immediate predecessor histories as untrusted context; they never automatically read the file. Review and separately supply only approved evidence to the worker. Use `python3 bot.py -w "$ws"` and shell-appropriate ID variables on macOS/Linux.

| Task key | Ledger role and optional existing bot | Required handoff |
| --- | --- | --- |
| `scope` | coordinator / `framework-coordinator` | Record the human-approved supplied sources, time range, authority and exclusions. Submit and obtain a human decision before proceeding. |
| `evidence` | researcher / `framework-researcher` | Inventory approved evidence and locators, with coverage and gaps. |
| `hypotheses` | researcher / `framework-researcher` | Develop testable alternatives from the approved scope; do not treat them as findings. |
| `analysis` | researcher / `framework-researcher` | After both branches are approved, cite evidence locators, distinguish observation, hypothesis and inference, address alternatives and contradictory evidence, and report coverage and uncertainty without asserting compromise or absence automatically. |
| `review` | reviewer / `framework-reviewer` | Independently inspect the supplied evidence and prior handoffs, including limitations and contradictions; disclose any independence limitation. |
| `handoff` | coordinator / `framework-coordinator` | Reconcile findings, review disposition and unresolved uncertainty for a human decision, not remediation. |

After actual work on each task, record the real handoff with `submit TASK_ID --by ROLE --note '<actual work and evidence>'`; inspect `show TASK_ID`, then a human separately chooses `approve TASK_ID --by 'human reviewer' --note '<actual review and decision>'` or `reject TASK_ID --by 'human reviewer' --note '<actual issues and corrections>'`. Replace instructional placeholders with actual work, never fabricated findings or approvals. A rejected task returns to active for revision and resubmission. After scope approval, `evidence` and `hypotheses` can proceed independently; `analysis` waits for both approvals. Each later step likewise requires its listed predecessors to be approved. `ready` is advisory across the workspace, not a scheduler; explicitly start and inspect each task's prompt.

No browsing, live telemetry, network scans, tool execution, remediation or production mutation is authorized by this exercise; request separate authorization for any such action. Private archives, `.env`, credentials, profiles, logs and account data are forbidden as sources. These boundaries are procedural instructions, not enforcement or isolation; inspect runtime capabilities and use appropriate external controls. A ledger approval does not authorize external action. OMP worker routing used to build this project is separate from Hermes runtime/provider configuration: the portable project requires no OMP dependency or model pin.

If the separately installed optional runtime is already available, `orchestrate.py -w $ws status <workflow-id>` and `orchestrate.py -w $ws run <workflow-id>` accept the actual workflow group ID for this template as for other groups; invoke with the optional environment's Python as documented in [optional runtime](optional-runtime.md). Its cursor observes ledger approvals sequentially and does not execute either branch, dispatch bots, or approve tasks. This describes the interface, not a claim of an execution or compatibility check.

### Local checks and portability

Use `py -3 -m unittest discover` on Windows or `python3 -m unittest discover` on macOS/Linux from this folder to include both CLI and workflow regression tests. Tests use temporary local workspaces and benign local processes, not real model calls. These are commands to run and record, not claims of completed checks. Python 3.9+ standard-library portability is a design goal; only Windows has been exercised in this project's local development context, and macOS/Linux execution is not verified here. Hermes/provider compatibility must be checked separately on each approved destination.

## Moving to another computer

Copy the source folder only after excluding runtime workspaces, `__pycache__/`, and any locally added private data. The included `.gitignore` helps with Git, but copying files manually requires your own review. Do not copy Hermes profile directories, credentials, cookies, or controlled source archives as part of this portable project. Set up and authorize Hermes separately on the new machine.

A ledger database can contain sensitive task text and absolute artifact/output paths. If you deliberately migrate runtime data, use an approved process, stop writers before backup, and expect machine-specific artifact paths to need separate handling; this folder does not rewrite them. Hermes profiles and conversations have their own [export/import mechanisms](https://hermes-agent.nousresearch.com/docs/user-guide/profiles), separate from copying project files; check their security implications before use.

## References

- [Hermes Agent source](https://github.com/NousResearch/hermes-agent)
- [Hermes Desktop guide](https://hermes-agent.nousresearch.com/docs/user-guide/desktop)
- [Hermes profiles](https://hermes-agent.nousresearch.com/docs/user-guide/profiles)
- [Bot Mode](https://hermes-agent.nousresearch.com/docs/user-guide/bot-mode)
- [Context files](https://hermes-agent.nousresearch.com/docs/user-guide/features/context-files)
