# Portable Hermes bot identities

This is an authored distribution pack, not an export of anyone's live profiles. It contains six self-contained identities for deliberate human-operated use. Adding these files alone does not install profiles or establish a Bot Chat, provider connection, tool restrictions, or model behavior. Installation and Desktop creation are separate, human-authorized operations.

## Catalog and contents

[catalog.json](catalog.json) is a JSON array for setup consumers. Every entry has `name`, `title`, `description`, `soul_path`, `distribution_path`, and `role`. Paths resolve relative to this `hermes-bots/` directory, not the process working directory; `distribution_path` names the directory passed to Hermes installation. Names are profile identifiers; titles are display labels.

| Bot title | Existing profile ID | Responsibility | Ledger mapping |
| --- | --- | --- | --- |
| Incident Response Lead | `framework-coordinator` | Human-led incident coordination and bounded native delegation | `coordinator` |
| Threat Hunter | `framework-researcher` | Supplied-evidence investigation and hypotheses | `researcher` |
| Detection Engineer | `framework-builder` | Authorized detection-content proposals; no deployment | `builder` |
| Purple Team Analyst | `framework-reviewer` | Independent review of evidence and detection proposals; no live emulation | `reviewer` |
| Threat Intelligence Analyst | `framework-librarian` | Provenance-rich intelligence drafts for human review | Separately scoped `coordinator` task or manual work |
| Network Analyst | `framework-network-analyst` | Analyze authorized, sanitized Arkime/Wireshark summaries, case session metadata and redacted packet fields of the case's saved capture, and disclose evidence limitations | `researcher` |

Each directory contains `distribution.yaml`, `SOUL.md`, and a credential/runtime `.gitignore`. The manifests use the official fields `name`, `version`, `description`, and `distribution_owned`. The official specification makes only `name` required; the explicit ownership list limits distribution-managed content to `SOUL.md`. No unsupported custom manifest fields, provider requirements, invented compatibility floor, or license attribution are added. The JSON catalog is this project's setup metadata, not an additional Hermes manifest schema.

There is intentionally **no `config.yaml` in the identity pack**. The optional `../native_team.py plan`, `check`, explicit `initialize PROFILE`, and `apply` commands do not install profiles or the native-policy source patch. `initialize PROFILE` is the explicit no-sign-in/no-provider-call path for one exact authored registered profile with no config: it creates the reviewed nonsecret YAML-compatible model, fallback, cap, tool-name allowlist, route, and toolset policy and refuses any existing config path without reading or replacing it. `check` makes no explicit policy writes, but ordinary native CLI startup can read secrets, write logs/backups, and perform installation/runtime recovery; it is not a zero-write diagnostic. `apply` remains conservative for existing configs. The helper requests individual config leaves, never the whole `model` mapping. See the [native setup guide](../hermes-setup.md#native-hermes-threat-hunting) for `--hermes`, `--home`, preserved-conflict behavior, and safety limits. Atomic initialization requires same-filesystem hard-link support and refuses safely if unavailable. The native policy fields need a separately reviewed and deployed native patch plus the pinned official delegation plugin; Hermes upstream may ignore unsupported fields. Persisted config and profiles alone do **not** prove final tools, route enforcement, or runtime readiness. SOUL files are behavioral instructions, not access controls or a sandbox.

No credentials, runtime data, existing profile metadata, memory, sessions, schedules, hooks, plugins, MCP connections, or bundled skills are shipped. `.gitignore` is defense in depth, not a sanitizer for manual copies, existing tracked files, or arbitrary secrets. Distribute only the authored files, never a live profile directory.

## Desktop: Fresh / New Agent (preferred explicit Bot Mode creation)

Use the destination's authorized Hermes Desktop installation and [official Bot Mode instructions](https://hermes-agent.nousresearch.com/docs/user-guide/bot-mode). UI labels can vary by version. Review the identity before creating it: creation may generate an introductory model turn and write profile/session state; do not proceed without authorization for that provider and data boundary.

For each catalog entry you intend to create:

1. Open **Bots -> New Agent**. Confirm the intended local backend; if **Create on** appears, do not accidentally create on a remote connection. Check that the exact profile name is unused. Do not overwrite, duplicate, delete, or rename an unrelated existing profile.
2. Enter the catalog's exact **Name**, **Title**, and **Description**.
3. Open **Advanced**. Select **Fresh profile**, not **Clone from default** or another existing profile. Choose **Create empty** where available to omit bundled skills.
4. Explicitly turn **Copy API keys from the main profile OFF**. Official documentation says it is on by default; Fresh selection alone is not evidence that copying is off. If the installed dialog cannot expose this control, stop rather than assume credentials will not be copied.
5. Paste the entire matching `SOUL.md` into **Custom SOUL.md**, replacing any generated persona. Do not paste a source transcript or just a link to this file.
6. Leave model/provider pins unset in this pack. Hermes documents that an unset selection can inherit the launch profile's route; that inheritance is not proof the destination is approved. Configure an authorized route separately on the destination, without putting secrets into these source files or chat. If no authorized route exists, defer creation that would invoke a model.
7. Review per-skill, per-toolset, and per-MCP-server capabilities. Keep unnecessary capabilities off, especially messaging, web/network access, memory writes, schedulers, and external integrations. Native threat-hunt delegation is a separate explicit opt-in described in the [Hermes setup](../hermes-setup.md#native-hermes-threat-hunting); upstream children may inherit parent tools, so do not delegate unless the separate reviewed native-policy patch and pinned plugin are verified. The detection engineer only drafts within an expressly authorized boundary. A capability toggle is not proof of OS isolation; use appropriate filesystem/network controls for actual enforcement.
8. Save deliberately. Do not add routines, goal loops, groups, messaging gateways, remote peers, shared memory services, or automated team dispatch. Verify the displayed identity and exact profile name through the UI before assigning any task. Repeat only for intended identities. The operator's opt-in Slack bridge (`operator/slack_gates.py`, ADR 0004) is not a bot messaging gateway: it runs on the operator's side with the operator's own tokens, relays only the operator's two hunt decisions to the workflow, and gives no bot a messaging tool.

Bot Mode's canonical persistent Bot Chat is a Desktop feature with metadata/session requirements. The official docs describe a session titled exactly `Bot Chat` and a Bot-Mode-managed profile metadata marker. Do not hand-edit live metadata to manufacture these markers. Creating or installing a CLI profile alone does **not guarantee** the canonical Desktop Bot Chat exists. An ordinary CLI chat is not proof of canonical-chat creation or bot-to-bot messaging readiness. This pack does not require messaging at all.

## Alternative: install an authored local directory

[Official profile distributions](https://hermes-agent.nousresearch.com/docs/user-guide/profile-distributions) explicitly support a local directory. Use this route **instead of creating the same name first**. Review the destination's installed CLI help and profile list, then inspect each authored manifest and SOUL. Install only names that are absent. Preserve the no-overwrite default: do not add force/overwrite options, bypass confirmation, or install over an existing profile. If a name collides, stop and resolve the choice with the human; do not silently replace it. Do not use `profile update` as a workaround for a collision.

The portable [`setup_hermes.py`](../setup_hermes.py) helper validates all authored distributions before invoking these same native commands, with ordinary confirmation and no overwrite options. See the [portable quick start](../hermes-setup.md#portable-kit-quick-start) for selected-profile installation and clean ZIP export. A collision or cancelled/unconfirmed install stops the helper; it does not delete earlier successful installations.


From the copied `framework/` directory, these are the optional commands to run after review, not commands executed by this project:

```sh
hermes profile install ./hermes-bots/framework-coordinator/
hermes profile install ./hermes-bots/framework-researcher/
hermes profile install ./hermes-bots/framework-builder/
hermes profile install ./hermes-bots/framework-reviewer/
hermes profile install ./hermes-bots/framework-librarian/
hermes profile install ./hermes-bots/framework-network-analyst/
```

These relative paths also work in PowerShell. Run one at a time and inspect the manifest/confirmation. No `--yes`, `--alias`, cloning from another profile, automatic update, or automatic chat is requested. Installation writes outside this portable source tree into Hermes-managed profile storage and may generate an `.env.EXAMPLE`; never copy generated files back into the distribution. No environment variables are declared because provider setup belongs to the authorized destination, not the portable identity.

After authorized installation, `hermes profile list` and `hermes profile info framework-researcher` (substitute the relevant name) can inspect profile registration without claiming a model run. Refresh Desktop and inspect the existing profile using its supported UI. If it is not a canonical Bot Chat, do not re-create the same name or patch profile metadata; follow the installed Desktop's documented management flow, or use the Fresh route with a deliberately unused identity. Titles and descriptions in the catalog are inputs for Desktop setup, not a claim that the distribution installer populates Desktop display metadata.

Do not run installation from this README automatically. The parent/operator owns actual Desktop setup and verification. Future distribution updates may replace SOUL; review changes first. Keep personal overrides and all runtime state outside this authored tree.

## Connect to the existing human ledger workflows

See the [framework workflow procedure](../README.md#reusable-human-operated-workflows) and [Hermes setup](../hermes-setup.md). The existing workflow files remain authoritative:

- [research-review](../workflows/research-review.json): `research` -> independent `review` -> `synthesis`. The Threat Hunter, Purple Team Analyst, and Incident Response Lead map to those existing roles for compatible supplied-evidence work.
- [build-review](../workflows/build-review.json): `requirements` -> `build` -> independent `review` -> `handoff`. The Detection Engineer's builder mapping covers authorized detection proposals, not unrestricted software implementation or deployment.
- [threat-hunt](../workflows/threat-hunt.json): `scope` (coordinator) -> independent `evidence` and `hypotheses` branches (researcher) -> `analysis` (researcher) -> independent `review` (reviewer) -> `handoff` (coordinator). The underlying profile and ledger role identifiers remain unchanged. Both branches require human approval before analysis; the reviewer independently checks supplied evidence and handoffs.

The Network Analyst is an additional `researcher` specialization, not a new ledger role or an automatic collection stage. The human can assign a separately scoped research task and supply approved, human-prepared sanitized Arkime/Wireshark summaries. Neither tool is a bundled integration, and outside its owned lab tools this role must not connect to an Arkime endpoint, operate either tool, or open raw captures or tool views. In a tool-driven lab hunt its `packet_fields` reads decoded, allowlisted fields of the case's saved capture with cookies, authorization headers, credentials, bodies and payload bytes removed; it never captures live traffic. Never read, print, store, or transmit SSIDs, headers beyond those allowlisted fields, credentials, cookies, authentication payloads, or authentication/session data. If the supplied summary is insufficient, request another safely prepared summary rather than accessing underlying evidence. Never send controlled material to an unapproved model or service.

The manual route needs Python's standard library only and works without Hermes, LangGraph, LangChain, or any provider. From `framework/`, inspect a template with `python bot.py workflow show research-review` (use `py -3` on Windows or `python3` where appropriate). Create a workflow with the existing documented goal, scope, and acceptance options and retain its printed task mapping. Do not assume task IDs.

For each ready task, the human explicitly starts it, inspects `prompt TASK_ID`, and provides that reviewed prompt plus separately approved evidence to the matching bot or a human worker. The prompt contains immediate predecessor notes and artifact paths, not artifact file contents or all ancestors. No bot is assumed to possess another chat's context. Supply only the bounded context needed.

The worker returns actual findings; the operator records them with `submit`, inspects `show`, and personally chooses `approve` or `reject` with real evidence. Every step, including reviewer and coordinator, needs a human decision. Only approved (`done`) predecessors unlock dependent work. `ready` is advisory, never a dispatcher. Approval labels are self-reported and do not provide authentication or prevent unsafe tools. Bot messages, if any exist elsewhere, do not advance this ledger.

For the offline hunt, follow the [creation and per-stage procedure](../hermes-setup.md#offline-defensive-threat-hunt), retaining the printed workflow and task IDs. The human approves the scope, including supplied sources, time range, authority and exclusions, before either evidence or hypotheses work begins. Those branches may be performed independently, but each must be submitted and separately approved before analysis; every subsequent task also requires submission and an explicit human decision. Evidence is manually supplied: the prompt references artifact paths but never reads their contents. Cite locators, separate observation, hypothesis and inference, consider alternatives and contradictory evidence, and report coverage and uncertainty; neither compromise nor its absence is automatic. The coordinator's final handoff supports a human decision, not remediation.

The [invented fixture](../examples/synthetic-hunt-events.json) is offline, non-operational, and not scored. Do not browse, collect live telemetry, scan networks, execute tools, remediate, or mutate production as part of this exercise; request separate authorization for those actions. Do not use private archives, `.env`, credentials, profiles, logs, or account data as sources. These are procedural instructions, not enforced tool restrictions. OMP worker routing during project development is distinct from destination Hermes profile/provider configuration; this portable pack requires neither OMP nor model pins.
Strict native profile-routed `delegate_task` children require the separate reviewed native-policy patch and pinned official plugin. Every task must explicitly set an admitted `task.profile`; omitted or unadmitted routes must be rejected before credentials, and backend-returned profiles are also checked. With that patch, named-profile children receive their own explicit toolsets and caps instead of the coordinator's direct toolset. The coordinator allows only `delegate_task`; each specialist allows only the read-only `hunt_lab` tools it owns: researcher `elastic_search`, `elastic_aggregate`, `lab_browser`, `packet_fields`; Network Analyst `arkime_sessions`, `arkime_unique`, `hunt_lab_query`, `lab_browser`, `packet_fields`; librarian `intel_lookup`, `elastic_aggregate`; builder `detection_test`, `elastic_aggregate`; reviewer `elastic_search`, `arkime_sessions`, `detection_test`. Each SOUL states its owned tools, how to drive a hunt with them while citing event IDs, and that other bots' tools are not its own; the coordinator routes follow-up questions to the owning specialist. Without the verified patch, do not assume upstream honors these settings, that profile identities enforce least privilege, or that the route works. Do not use model-map `option` guidance for this strict profile route path. Direct Bot Mode profiles/groups are distinct from internal subagent routes. See the [native setup guide](../hermes-setup.md#native-hermes-threat-hunting).

For library curation, first finish the relevant research/review handoffs. Then create a separately scoped **coordinator** task naming librarian curation in the scope, or work manually outside the ledger. The catalog value `role: librarian` identifies the bot; it is **not** a valid `bot.py --role librarian` value. This pack does not modify `ROLES`. A librarian produces a staging draft with provenance, contradictions, proposed destination, and unresolved questions. Independent review and human judgment precede any separate promotion; no bot silently writes trusted wiki pages or memory. A completed ledger curation task means its handoff was accepted, not that publication was authorized or occurred.

Optional CLI invocation remains governed by the existing profile opt-in contract: exact existing name plus `--allow-profile-config`; safe mode suppresses SOUL/profile identity. Do not substitute a profile name for authorization. Existing reservation, timeout, failure, and `recover-run` behavior remains unchanged. No bot retries or recovers a run automatically. No code in this pack launches workflows, LangGraph, models, or bots.

## Research provenance and deliberate adaptations

Authored from selected primary transcript excerpts in the saved research, with official documentation controlling installation/UI details. The adjacent NotebookLM guides were read only as AI-generated secondary summaries, not independent evidence. The pack does not include the research itself and does not require sibling research files when copied.

| Source | Primary transcript locator (no timecodes) | Adopted boundary |
| --- | --- | --- |
| [Is Hermes Bot Mode Worth It?](https://www.youtube.com/watch?v=3RoK0rrOHCA) | `research/wanderloots/videos/3RoK0rrOHCA/transcript.txt`; phrases “each bot as a specialist with its own workstation”, “remove unnecessary capabilities”, and “the librarian organizes the approved knowledge” | Specialist identities, minimum capabilities, human-reviewed knowledge. The video's clone-from-default demonstration is deliberately **not** adopted. |
| [What Is An Agentic Librarian?](https://www.youtube.com/watch?v=_bieksxg6oY) | `research/wanderloots/videos/_bieksxg6oY/transcript.txt`; phrases “human judgment is what allows it into the library”, “human in the loop review layer”, and “maintains consistency not trust” | Raw sources -> staged draft/review -> separate human-controlled trusted knowledge. Preserve contradictions and claim-level provenance; no automatic ingestion or promotion. |
| [Subagents vs Agent Teams?](https://www.youtube.com/watch?v=GlW4N7p5KS8) | `research/wanderloots/videos/GlW4N7p5KS8/transcript.txt`; phrases “one powerful agent with sub agents can often be enough”, “zero knowledge of the parents conversation history”, and “every handoff is a row in a database” | Avoid unnecessary team complexity; provide explicit task context; keep durable manual handoffs. Do not claim the existing ledger is Hermes Kanban or enable autonomous goal loops. |

The saved inventory `research/wanderloots/RECENT-BOTS.md` records that transcripts have **no timestamps**, guides are AI secondary notes, and regular-video frame coverage is partial. These are excerpt-based design inputs, not claims of complete video/diagram review. Transcript transcription errors and evolving Hermes versions limit certainty. Exact phrases are textual locators, not invented video timestamps. The videos do not uniquely prescribe the roster. The conservative no-messaging, no-clone, draft-only defaults are project safety decisions, not assertions that Hermes lacks those features.

Official references checked while authoring:

- [Profile distributions: manifest fields, local directory installation, ownership and credential/runtime exclusions](https://hermes-agent.nousresearch.com/docs/user-guide/profile-distributions).
- [Bot Mode: New Agent, Fresh profile, copy-key default, capabilities, and canonical Bot Chat conditions](https://hermes-agent.nousresearch.com/docs/user-guide/bot-mode).

## Release note and verification boundary

The original `framework-*` profile IDs and ledger roles remain unchanged. The existing development profiles were retitled in Hermes and their role instructions updated; this preserves the coordinator's native delegation setup without creating duplicate profiles. Changes to SOUL instructions take effect when Hermes loads them for a new session. The names and procedural boundaries do not establish tool isolation or authorize live purple-team activity.

An earlier Windows native smoke demonstrated an Astra coordinator dispatching a synthetic evidence/hypotheses batch. Its child reported Luna/Terra route metadata, but the parent completion displayed an inconsistent role label; do not treat that label or the bot title as independent proof of model identity. Human stage approvals remain required.
