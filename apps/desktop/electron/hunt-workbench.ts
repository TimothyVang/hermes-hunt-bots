import { type ChildProcess, spawn } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import http from 'node:http'
import net from 'node:net'
import path from 'node:path'

import type { IpcMain } from 'electron'

import { hiddenWindowsChildOptions } from './windows-child-options'

export type HuntDataOrigin = 'public-dataset' | 'synthetic' | 'unknown' | 'work-connected' | 'work-export'

export interface HuntBoardDescriptor {
  address: string
  caseId: string
  childWorkflowId: null | string
  liveEnabled: boolean
  liveProfiles: string[]
  managed: boolean
  mode: 'inline' | 'tool_driven'
  port: number
  url: string
  workflowId: string
}

export interface HuntBoardDiscoveryResult {
  boards: HuntBoardDescriptor[]
  error?: string
  ok: boolean
}

export interface HuntBoardStartRequest {
  address?: string
  caseId?: string
  dataOrigin?: string
  inputPath?: string
  port?: number
  workflowId: string
}

export interface HuntBoardStartResult {
  board?: HuntBoardDescriptor
  error?: string
  ok: boolean
}

export interface HuntGateDecisionRecord {
  decidedBy: string
  decision: string
  decisionId: string
  phase: string
  slackUser: string
  stepId: string
  via: string
}

export interface HuntGateStepSummary {
  optional: boolean
  profile: string
  reason: string
  state: string
  stepId: string
  wave: number
}

export interface HuntOpenGate {
  choices: string[]
  gateKind: 'execute' | 'incident' | 'intermediate_review' | 'reconcile' | 'scope'
  label: string
  phase: 'execute' | 'reconcile' | 'review'
  stepId: string
  waitingSteps: string[]
  wave: null | number
}

export interface HuntGateStatus {
  address: string
  caseId: null | string
  childWorkflowId: null | string
  completedRounds: null | number
  currentRound: null | number
  dataOrigin: HuntDataOrigin
  decisions: HuntGateDecisionRecord[]
  openGate: HuntOpenGate | null
  parentStage: null | string
  roundsRequested: null | number
  stage: string
  steps: HuntGateStepSummary[]
  syntheticOnly: boolean
  temporalStatus: null | string
  unverifiedBotSummary: null | string
  workflowId: string
}

export interface HuntGateStatusResult {
  error?: string
  ok: boolean
  status?: HuntGateStatus
}

export interface HuntGateDecisionRequest {
  address?: string
  checkNote: string
  childWorkflowId: string
  choice: 'abort' | 'accept' | 'approve' | 'deny'
  operatorName: string
  phase: 'execute' | 'reconcile' | 'review'
  stepId: string
}

export interface HuntGateDecisionResult {
  decidedAtUtc?: string
  decidedBy?: string
  decisionId?: string
  error?: string
  ok: boolean
  via?: 'cli'
  workflowId?: string
}

export interface HuntWorkbenchApi {
  decideGate: (request: HuntGateDecisionRequest) => Promise<HuntGateDecisionResult>
  discoverBoards: (options?: { port?: number }) => Promise<HuntBoardDiscoveryResult>
  gateStatus: (request: { address?: string; workflowId: string }) => Promise<HuntGateStatusResult>
  startBoard: (request: HuntBoardStartRequest) => Promise<HuntBoardStartResult>
  stopBoard: () => Promise<{ ok: boolean; stopped: boolean }>
}

export interface ResolvedHuntPython {
  frameworkRoot: string
  pythonExe: string
}

interface PreparedBoardStart {
  home: string
  inputPath: string
  isToolDriven: boolean
  labStateDir: string
  runtime: ResolvedHuntPython
  tempInputPath: null | string
}

export interface HuntWorkbenchDeps {
  activeHermesRoot?: string
  allocateFreePort?: () => Promise<number>
  env?: NodeJS.ProcessEnv
  execPath?: string
  hermesHome: () => string
  huntEnabled: boolean
  isPortBindable?: (port: number) => Promise<boolean>
  isWindows?: boolean
  log?: (message: string) => void
  nowUtc?: () => string
  probeBoardPort?: (port: number, managedPort: null | number) => Promise<HuntBoardDescriptor | null>
  resolvePython?: () => Promise<ResolvedHuntPython | null>
  runPythonCommand?: (
    runtime: ResolvedHuntPython,
    args: string[],
    options?: { stdin?: string; timeoutMs?: number }
  ) => Promise<{ code: number; stderr: string; stdout: string }>
  sourceRepoRoot?: string
  spawnBoardProcess?: (
    runtime: ResolvedHuntPython,
    args: string[]
  ) => ChildProcess
}

const DEFAULT_TEMPORAL_ADDRESS = '127.0.0.1:7233'
const DEFAULT_BOARD_PORT = 8790
const SAFE_WORKFLOW_ID = /^[A-Za-z0-9._:-]{1,128}$/
const SAFE_ROUND_WORKFLOW_ID = /^[A-Za-z0-9._:-]{1,160}$/
const SAFE_STEP_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/
const SAFE_CASE_ID = /^[a-z0-9-]{3,64}$/
const ALLOWED_DATA_ORIGINS = new Set(['public-dataset', 'work-export', 'work-connected'])
const MAX_STATE_BYTES = 512 * 1024
const MAX_EVIDENCE_NOTE_BYTES = 4096

const GATE_STATUS_SCRIPT = `
import asyncio, json, sys
from temporalio.client import Client
from hermes_temporal.board import parse_handoff
from hermes_temporal.contracts import DATA_ORIGINS, SYNTHETIC, validate_loopback_address
from hermes_temporal.practice import PracticeWorkflow
from hermes_temporal.workflows import HermesWorkflow

STAGE_PHASE = {
    "awaiting_execution_approval": ("execute", ["approve", "deny"]),
    "awaiting_review": ("review", ["approve", "deny"]),
    "needs_reconciliation": ("reconcile", ["accept", "abort"]),
}

def _printable_line(text, limit=240):
    clean = " ".join(str(text or "").split())
    return clean[:limit]

def _synthetic_summary(results_by_exec, step_meta, waiting_ids):
    lines = []
    for step_id in waiting_ids:
        meta = step_meta.get(step_id) or {}
        exec_id = meta.get("execution_id")
        raw_out = results_by_exec.get(exec_id, "")
        if not raw_out and step_id in results_by_exec:
            raw_out = results_by_exec[step_id]
        if not raw_out:
            continue
        parsed, err = parse_handoff(raw_out)
        if parsed:
            claims = parsed.get("claims") or []
            disp = _printable_line(parsed.get("disposition") or "review_ready", 64)
            lines.append(f"[{step_id}] disposition={disp}, claims={len(claims)}")
            for claim in claims[:4]:
                cid = _printable_line(claim.get("claim_id"), 48)
                stmt = _printable_line(claim.get("statement"), 220)
                lines.append(f"- {cid}: {stmt}")
            if len(claims) > 4:
                lines.append(f"- (+{len(claims) - 4} more claims)")
            for req in (parsed.get("requested_decisions") or [])[:2]:
                lines.append("Requested decision: " + _printable_line(req, 200))
        else:
            lines.append(f"[{step_id}] (untyped output: {_printable_line(err or 'raw', 80)}) " + _printable_line(raw_out, 300))
    joined = "\\n".join(lines).strip()
    return joined[:1200] if joined else None

async def _inspect(address, workflow_id):
    addr = validate_loopback_address(address)
    client = await asyncio.wait_for(Client.connect(addr), 8.0)
    handle = client.get_workflow_handle(workflow_id)
    desc = await asyncio.wait_for(handle.describe(), 8.0)
    wf_type = desc.workflow_type or ""
    parent_info = None
    child_id = workflow_id
    if wf_type == "PracticeWorkflow":
        p_state = await asyncio.wait_for(handle.query(PracticeWorkflow.status), 8.0)
        p_dict = vars(p_state)
        parent_info = {
            "stage": str(p_dict.get("stage") or ""),
            "round_index": p_dict.get("round_index") if isinstance(p_dict.get("round_index"), int) else None,
            "rounds": p_dict.get("rounds") if isinstance(p_dict.get("rounds"), int) else None,
            "completed_rounds": p_dict.get("completed_rounds") if isinstance(p_dict.get("completed_rounds"), int) else None,
        }
        cid = p_dict.get("child_workflow_id")
        child_id = cid if isinstance(cid, str) and cid else None
    if not child_id:
        return {
            "workflowId": workflow_id,
            "childWorkflowId": None,
            "address": addr,
            "parentStage": parent_info["stage"] if parent_info else None,
            "currentRound": parent_info["round_index"] if parent_info else None,
            "roundsRequested": parent_info["rounds"] if parent_info else None,
            "completedRounds": parent_info["completed_rounds"] if parent_info else None,
            "stage": parent_info["stage"] if parent_info else (desc.status.name if desc.status else "unknown"),
            "temporalStatus": desc.status.name if desc.status else None,
            "caseId": None,
            "dataOrigin": "unknown",
            "syntheticOnly": False,
            "openGate": None,
            "steps": [],
            "decisions": [],
            "unverifiedBotSummary": None,
        }
    c_handle = client.get_workflow_handle(child_id)
    c_state = await asyncio.wait_for(c_handle.query(HermesWorkflow.status), 8.0)
    c_desc = await asyncio.wait_for(c_handle.describe(), 8.0)
    history = await asyncio.wait_for(c_handle.fetch_history(skip_archival=True), 8.0)
    req_data = None
    for event in history.events:
        if event.WhichOneof("attributes") == "workflow_execution_started_event_attributes":
            payloads = event.workflow_execution_started_event_attributes.input.payloads
            if payloads:
                try:
                    req_data = json.loads(payloads[0].data)
                except Exception:
                    req_data = None
            break
    raw_origin = req_data.get("data_origin", SYNTHETIC) if isinstance(req_data, dict) else "unknown"
    raw_synth = req_data.get("synthetic_only") if isinstance(req_data, dict) else False
    if raw_origin == SYNTHETIC and raw_synth is True:
        data_origin = "synthetic"
        synthetic_only = True
    elif raw_origin in DATA_ORIGINS and raw_synth is False:
        data_origin = raw_origin
        synthetic_only = False
    else:
        data_origin = "unknown"
        synthetic_only = False
    case_id = None
    req_steps = req_data.get("steps") if isinstance(req_data, dict) and isinstance(req_data.get("steps"), list) else []
    step_profiles = {}
    step_optional = {}
    ordered_step_ids = []
    for item in req_steps:
        if isinstance(item, dict) and isinstance(item.get("step_id"), str):
            sid = item["step_id"]
            ordered_step_ids.append(sid)
            step_profiles[sid] = str(item.get("profile") or "")
            step_optional[sid] = bool(item.get("optional"))
            hc = item.get("hunt_context")
            if case_id is None and isinstance(hc, dict) and isinstance(hc.get("snapshot"), dict):
                cid_val = hc["snapshot"].get("case_id")
                if isinstance(cid_val, str):
                    case_id = cid_val
    c_plain = json.loads(json.dumps(vars(c_state), default=lambda v: v.__dict__, ensure_ascii=False))
    stage = str(c_plain.get("stage") or "")
    gate_step_id = c_plain.get("step_id") if isinstance(c_plain.get("step_id"), str) else None
    temporal_status = c_desc.status.name if c_desc.status else None
    wave_states = c_plain.get("steps") if isinstance(c_plain.get("steps"), list) else []
    steps_out = []
    step_meta = {}
    if wave_states:
        for st in wave_states:
            if not isinstance(st, dict):
                continue
            sid = str(st.get("step_id") or "")
            step_meta[sid] = st
            steps_out.append({
                "stepId": sid,
                "wave": st.get("wave") if isinstance(st.get("wave"), int) else 1,
                "state": str(st.get("state") or ""),
                "reason": str(st.get("reason") or ""),
                "profile": step_profiles.get(sid, ""),
                "optional": step_optional.get(sid, False),
            })
    else:
        for idx, sid in enumerate(ordered_step_ids):
            steps_out.append({
                "stepId": sid,
                "wave": idx + 1,
                "state": "awaiting_review" if (stage == "awaiting_review" and gate_step_id == sid) else (
                    "awaiting_approval" if (stage == "awaiting_execution_approval" and gate_step_id == sid) else ""
                ),
                "reason": "",
                "profile": step_profiles.get(sid, ""),
                "optional": step_optional.get(sid, False),
            })
    open_gate = None
    if temporal_status == "RUNNING" and stage in STAGE_PHASE and gate_step_id:
        phase, choices = STAGE_PHASE[stage]
        wave_num = None
        waiting_steps = []
        if wave_states:
            max_wave = max((s["wave"] for s in steps_out), default=1)
            if gate_step_id.startswith("wave-") and gate_step_id[5:].isdigit():
                wave_num = int(gate_step_id[5:])
            target_state = "awaiting_review" if phase == "review" else ("awaiting_approval" if phase == "execute" else "working")
            waiting_steps = [s["stepId"] for s in steps_out if (wave_num is None or s["wave"] == wave_num) and s["state"] == target_state]
            if not waiting_steps and gate_step_id in step_profiles:
                waiting_steps = [gate_step_id]
            if phase == "review":
                if wave_num == 1 or "scope" in waiting_steps:
                    gate_kind = "scope"
                elif wave_num is not None and wave_num == max_wave:
                    gate_kind = "incident"
                else:
                    gate_kind = "intermediate_review"
            elif phase == "reconcile":
                gate_kind = "reconcile"
            else:
                gate_kind = "execute"
        else:
            waiting_steps = [gate_step_id]
            last_sid = ordered_step_ids[-1] if ordered_step_ids else "incident"
            if phase == "review":
                if gate_step_id == "scope":
                    gate_kind = "scope"
                elif gate_step_id == last_sid or gate_step_id == "incident":
                    gate_kind = "incident"
                else:
                    gate_kind = "intermediate_review"
            elif phase == "reconcile":
                gate_kind = "reconcile"
            else:
                gate_kind = "execute"
        label_map = {
            "scope": "Human Gate 1 of 2: Scope & Framing Review",
            "incident": "Human Gate 2 of 2: Incident Report Review",
            "intermediate_review": f"Stage Review Gate ({gate_step_id})",
            "execute": f"Execution Gate ({gate_step_id})",
            "reconcile": f"Reconciliation Gate ({gate_step_id})",
        }
        open_gate = {
            "stepId": gate_step_id,
            "phase": phase,
            "choices": choices,
            "gateKind": gate_kind,
            "label": label_map[gate_kind],
            "wave": wave_num,
            "waitingSteps": waiting_steps,
        }
    decisions_out = []
    for dec in (c_plain.get("decisions") or []):
        if isinstance(dec, dict):
            decisions_out.append({
                "stepId": str(dec.get("gate") or dec.get("step_id") or ""),
                "phase": str(dec.get("phase") or ""),
                "decision": str(dec.get("decision") or ""),
                "decisionId": str(dec.get("decision_id") or ""),
                "decidedBy": str(dec.get("decided_by") or ""),
                "via": str(dec.get("via") or ""),
                "slackUser": str(dec.get("slack_user") or ""),
            })
    summary = None
    if synthetic_only and open_gate and open_gate["phase"] == "review":
        results_by_exec = {}
        raw_results = c_plain.get("results") or []
        for idx, res in enumerate(raw_results):
            if isinstance(res, dict) and isinstance(res.get("output"), str):
                eid = res.get("execution_id")
                if isinstance(eid, str):
                    results_by_exec[eid] = res["output"]
                if not wave_states and idx < len(ordered_step_ids):
                    results_by_exec[ordered_step_ids[idx]] = res["output"]
        summary = _synthetic_summary(results_by_exec, step_meta, open_gate["waitingSteps"])
    return {
        "workflowId": workflow_id,
        "childWorkflowId": child_id,
        "address": addr,
        "parentStage": parent_info["stage"] if parent_info else None,
        "currentRound": parent_info["round_index"] if parent_info else None,
        "roundsRequested": parent_info["rounds"] if parent_info else None,
        "completedRounds": parent_info["completed_rounds"] if parent_info else None,
        "stage": stage,
        "temporalStatus": temporal_status,
        "caseId": case_id,
        "dataOrigin": data_origin,
        "syntheticOnly": synthetic_only,
        "openGate": open_gate,
        "steps": steps_out,
        "decisions": decisions_out,
        "unverifiedBotSummary": summary,
    }

def main():
    req = json.loads(sys.stdin.read())
    try:
        out = asyncio.run(_inspect(req["address"], req["workflow_id"]))
        print(json.dumps({"ok": True, "status": out}, ensure_ascii=False))
    except ValueError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"Temporal query failed ({type(exc).__name__})"}, ensure_ascii=False))

if __name__ == "__main__":
    main()
`

export function validateLoopbackAddress(raw?: string): string | null {
  const value = String(raw || DEFAULT_TEMPORAL_ADDRESS).trim()
  const match = /^127\.0\.0\.1:([1-9]\d{0,4})$/.exec(value)

  if (!match) {
    return null
  }

  const port = Number(match[1])

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return null
  }

  return `127.0.0.1:${port}`
}

export function normalizeOperatorName(raw: unknown): string | null {
  if (typeof raw !== 'string') {
    return null
  }

  const trimmed = raw.trim()

  for (let i = 0; i < trimmed.length; i += 1) {
    const code = trimmed.charCodeAt(i)

    if (code < 0x20 || code === 0x7f) {
      return null
    }
  }

  const normalized = trimmed.replace(/ +/g, ' ')

  if (!normalized || normalized.length > 200) {
    return null
  }

  return normalized
}

export function normalizeCheckNote(raw: unknown): string | null {
  if (typeof raw !== 'string') {
    return null
  }

  const normalized = raw.trim().replace(/\r\n/g, '\n')

  if (!normalized || normalized.length > 1000) {
    return null
  }

  for (let i = 0; i < normalized.length; i += 1) {
    const code = normalized.charCodeAt(i)

    if ((code < 0x20 && code !== 0x09 && code !== 0x0a) || code === 0x7f) {
      return null
    }
  }

  return normalized
}

export function formatDesktopEvidenceNote(operatorName: string, isoUtc: string, checkNote: string): string {
  const prefix = `Decided by ${operatorName} via Hunt Command Desktop at ${isoUtc}. Checked: `
  const full = prefix + checkNote

  if (Buffer.byteLength(full, 'utf8') <= MAX_EVIDENCE_NOTE_BYTES) {
    return full
  }

  const available = MAX_EVIDENCE_NOTE_BYTES - Buffer.byteLength(prefix, 'utf8')
  let trimmed = checkNote

  while (trimmed.length > 0 && Buffer.byteLength(trimmed, 'utf8') > available) {
    trimmed = trimmed.slice(0, -1)
  }

  return prefix + trimmed
}

function defaultNowUtc(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')
}

function fileExists(candidate: string): boolean {
  try {
    return fs.statSync(candidate).isFile()
  } catch {
    return false
  }
}

function dirExists(candidate: string): boolean {
  try {
    return fs.statSync(candidate).isDirectory()
  } catch {
    return false
  }
}

function ancestorDirs(startPath: string, maxDepth = 5): string[] {
  const results: string[] = []
  let current = path.resolve(startPath)

  for (let i = 0; i < maxDepth; i += 1) {
    results.push(current)
    const parent = path.dirname(current)

    if (parent === current) {
      break
    }

    current = parent
  }

  return results
}

function discoverFrameworkRoots({
  activeHermesRoot,
  env = process.env,
  execPath = process.execPath,
  hermesHome,
  sourceRepoRoot
}: {
  activeHermesRoot?: string
  env?: NodeJS.ProcessEnv
  execPath?: string
  hermesHome: string
  sourceRepoRoot?: string
}): string[] {
  const candidates: string[] = []

  if (env.HERMES_HUNT_FRAMEWORK_ROOT) {
    candidates.push(path.resolve(env.HERMES_HUNT_FRAMEWORK_ROOT))
  }

  if (sourceRepoRoot) {
    candidates.push(path.join(path.resolve(sourceRepoRoot), 'framework'))
  }

  if (activeHermesRoot) {
    candidates.push(path.join(path.resolve(activeHermesRoot), 'framework'))
  }

  if (hermesHome) {
    candidates.push(path.join(path.resolve(hermesHome), 'hermes-agent', 'framework'))

    for (const ancestor of ancestorDirs(hermesHome, 5)) {
      candidates.push(path.join(ancestor, 'framework'))
      candidates.push(path.join(ancestor, 'repo', 'framework'))
    }
  }

  if (execPath) {
    for (const ancestor of ancestorDirs(path.dirname(execPath), 6)) {
      candidates.push(path.join(ancestor, 'framework'))
      candidates.push(path.join(ancestor, 'repo', 'framework'))
    }
  }

  const seen = new Set<string>()
  const valid: string[] = []

  for (const candidate of candidates) {
    const resolved = path.resolve(candidate)

    if (seen.has(resolved)) {
      continue
    }

    seen.add(resolved)

    if (
      fileExists(path.join(resolved, 'hermes_temporal', 'cli.py')) &&
      fileExists(path.join(resolved, 'hermes_temporal', 'board.py'))
    ) {
      valid.push(resolved)
    }
  }

  return valid
}

function pythonCandidatesForFramework(
  frameworkRoot: string,
  hermesHome: string,
  env: NodeJS.ProcessEnv,
  isWindows: boolean
): string[] {
  const relVenv = isWindows ? path.join('Scripts', 'python.exe') : path.join('bin', 'python')
  const candidates: string[] = []

  for (const override of [env.HERMES_HUNT_PYTHON, env.HERMES_TEMPORAL_PYTHON]) {
    if (override) {
      candidates.push(path.resolve(override))
    }
  }

  const repoRoot = path.dirname(frameworkRoot)

  for (const dir of [
    path.join(frameworkRoot, '.venv-temporal'),
    path.join(frameworkRoot, '.venv'),
    path.join(frameworkRoot, 'venv'),
    path.join(repoRoot, '.venv-temporal'),
    path.join(repoRoot, '.venv'),
    path.join(repoRoot, 'venv')
  ]) {
    candidates.push(path.join(dir, relVenv))
  }

  for (const base of [hermesHome, repoRoot]) {
    if (!base) {
      continue
    }

    for (const ancestor of ancestorDirs(base, 4)) {
      candidates.push(path.join(ancestor, 'practice', 'gate-venv', relVenv))
      candidates.push(path.join(ancestor, 'runtime', 'practice', 'gate-venv', relVenv))
    }
  }

  const seen = new Set<string>()

  return candidates.filter(candidate => {
    const key = isWindows ? candidate.toLowerCase() : candidate

    if (seen.has(key) || !fileExists(candidate)) {
      return false
    }

    seen.add(key)

    return true
  })
}

function defaultRunPythonCommand(
  runtime: ResolvedHuntPython,
  args: string[],
  options: { stdin?: string; timeoutMs?: number } = {}
): Promise<{ code: number; stderr: string; stdout: string }> {
  const timeoutMs = options.timeoutMs ?? 15_000

  return new Promise(resolve => {
    const env = {
      ...process.env,
      PYTHONPATH: runtime.frameworkRoot
    }

    const child = spawn(
      runtime.pythonExe,
      args,
      hiddenWindowsChildOptions({
        cwd: runtime.frameworkRoot,
        env,
        shell: false,
        stdio: ['pipe', 'pipe', 'pipe']
      })
    )

    let stdout = ''
    let stderr = ''
    let settled = false

    const finish = (code: number, extraErr = '') => {
      if (settled) {
        return
      }

      settled = true
      clearTimeout(timer)
      resolve({
        code,
        stderr: (stderr + (extraErr ? `\n${extraErr}` : '')).slice(0, 16_384),
        stdout: stdout.slice(0, 65_536)
      })
    }

    const timer = setTimeout(() => {
      try {
        child.kill('SIGKILL')
      } catch {
        void 0
      }

      finish(124, 'command timed out')
    }, timeoutMs)

    child.stdout?.setEncoding('utf8')
    child.stderr?.setEncoding('utf8')
    child.stdout?.on('data', chunk => {
      if (stdout.length < 65_536) {
        stdout += String(chunk)
      }
    })
    child.stderr?.on('data', chunk => {
      if (stderr.length < 16_384) {
        stderr += String(chunk)
      }
    })
    child.on('error', err => finish(127, err.message))
    child.on('close', code => finish(code ?? 1))

    if (options.stdin !== undefined) {
      child.stdin?.end(options.stdin, 'utf8')
    } else {
      child.stdin?.end()
    }
  })
}

function defaultAllocateFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer()
    server.unref()
    server.on('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      const port = typeof address === 'object' && address ? address.port : 0
      server.close(err => {
        if (err || !port) {
          reject(err || new Error('failed to allocate loopback port'))
        } else {
          resolve(port)
        }
      })
    })
  })
}

export function defaultIsPortBindable(port: number): Promise<boolean> {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return Promise.resolve(false)
  }

  return new Promise(resolve => {
    const server = net.createServer()
    server.unref()
    server.once('error', () => resolve(false))
    server.listen(port, '127.0.0.1', () => {
      server.close(() => resolve(true))
    })
  })
}

export function defaultProbeBoardPort(port: number, managedPort: null | number): Promise<HuntBoardDescriptor | null> {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return Promise.resolve(null)
  }

  return new Promise(resolve => {
    let done = false

    const finish = (result: HuntBoardDescriptor | null) => {
      if (!done) {
        done = true
        resolve(result)
      }
    }

    const req = http.request(
      {
        agent: false,
        headers: {
          Accept: 'application/json',
          Host: `127.0.0.1:${port}`
        },
        host: '127.0.0.1',
        method: 'GET',
        path: '/state.json',
        port,
        timeout: 4000
      },
      res => {
        const serverHeader = String(res.headers.server || '')

        if (res.statusCode !== 200 || !serverHeader.startsWith('HuntBoard')) {
          res.resume()
          finish(null)

          return
        }

        let raw = ''
        res.setEncoding('utf8')
        res.on('data', chunk => {
          raw += String(chunk)

          if (raw.length > MAX_STATE_BYTES) {
            req.destroy()
            finish(null)
          }
        })
        res.on('end', () => {
          try {
            const parsed = JSON.parse(raw) as Record<string, any>
            const caseId = typeof parsed?.case?.case_id === 'string' ? parsed.case.case_id : ''

            if (!caseId || !Array.isArray(parsed?.steps)) {
              finish(null)

              return
            }

            const parentWid =
              typeof parsed?.run?.parent?.workflow_id === 'string' ? parsed.run.parent.workflow_id : ''

            const childWid =
              typeof parsed?.run?.parent?.child_workflow_id === 'string'
                ? parsed.run.parent.child_workflow_id
                : typeof parsed?.run?.child?.workflow_id === 'string'
                  ? parsed.run.child.workflow_id
                  : null

            const liveOwners: unknown = parsed?.live?.owners

            const liveProfiles = Array.isArray(liveOwners)
              ? liveOwners.flatMap(entry =>
                  entry &&
                  typeof entry === 'object' &&
                  'profile' in entry &&
                  typeof (entry as { profile?: unknown }).profile === 'string' &&
                  (entry as { profile: string }).profile
                    ? [(entry as { profile: string }).profile]
                    : []
                )
              : liveOwners && typeof liveOwners === 'object'
                ? Object.keys(liveOwners as Record<string, unknown>)
                : []

            finish({
              address: DEFAULT_TEMPORAL_ADDRESS,
              caseId,
              childWorkflowId: childWid,
              liveEnabled: Boolean(parsed?.live),
              liveProfiles,
              managed: managedPort === port,
              mode: parsed?.mode === 'tool_driven' ? 'tool_driven' : 'inline',
              port,
              url: `http://127.0.0.1:${port}/`,
              workflowId: parentWid
            })
          } catch {
            finish(null)
          }
        })
      }
    )

    req.on('timeout', () => {
      req.destroy()
      finish(null)
    })
    req.on('error', () => finish(null))
    req.end()
  })
}

export function createHuntWorkbench(deps: HuntWorkbenchDeps): HuntWorkbenchApi & { dispose: () => void } {
  const env = deps.env ?? process.env
  const isWindows = deps.isWindows ?? process.platform === 'win32'
  const runPython = deps.runPythonCommand ?? defaultRunPythonCommand
  const allocatePort = deps.allocateFreePort ?? defaultAllocateFreePort
  const checkPortBindable = deps.isPortBindable ?? defaultIsPortBindable
  const probePort = deps.probeBoardPort ?? defaultProbeBoardPort
  const nowUtc = deps.nowUtc ?? defaultNowUtc
  const log = deps.log ?? (() => undefined)

  let cachedPython: ResolvedHuntPython | null = null
  let boardLifecycleEpoch = 0
  let boardStartSeq = 0

  let inflightBoard: {
    child: ChildProcess | null
    epoch: number
    tempInputPath: null | string
  } | null = null

  let managedBoard: {
    address: string
    child: ChildProcess
    port: number
    tempInputPath: null | string
    workflowId: string
  } | null = null

  const killChildQuietly = (child: ChildProcess | null) => {
    if (!child) {
      return
    }

    try {
      child.kill()
    } catch {
      void 0
    }
  }

  const unlinkQuietly = (filePath: null | string) => {
    if (!filePath) {
      return
    }

    try {
      fs.unlinkSync(filePath)
    } catch {
      void 0
    }
  }

  const resolveRuntime = async (): Promise<ResolvedHuntPython | null> => {
    if (deps.resolvePython) {
      return deps.resolvePython()
    }

    if (cachedPython && fileExists(cachedPython.pythonExe)) {
      return cachedPython
    }

    const home = deps.hermesHome()

    const roots = discoverFrameworkRoots({
      activeHermesRoot: deps.activeHermesRoot,
      env,
      execPath: deps.execPath,
      hermesHome: home,
      sourceRepoRoot: deps.sourceRepoRoot
    })

    for (const frameworkRoot of roots) {
      const pythons = pythonCandidatesForFramework(frameworkRoot, home, env, isWindows)

      for (const pythonExe of pythons) {
        const candidate: ResolvedHuntPython = { frameworkRoot, pythonExe }

        const check = await runPython(
          candidate,
          ['-c', 'import temporalio, websockets, hermes_temporal.cli, hermes_temporal.board'],
          { timeoutMs: 8000 }
        )

        if (check.code === 0) {
          cachedPython = candidate

          return candidate
        }
      }
    }

    return null
  }

  const cancelInflightBoard = () => {
    boardLifecycleEpoch += 1

    if (!inflightBoard) {
      return null
    }

    const pending = inflightBoard
    inflightBoard = null
    killChildQuietly(pending.child)
    unlinkQuietly(pending.tempInputPath)

    return pending.child
  }

  const retireManagedBoard = () => {
    if (!managedBoard) {
      return null
    }

    const active = managedBoard
    managedBoard = null
    killChildQuietly(active.child)
    unlinkQuietly(active.tempInputPath)

    return active.child
  }

  const cleanupManagedBoard = () => {
    const cancelledChild = cancelInflightBoard()
    const retiredChild = retireManagedBoard()

    return Boolean(cancelledChild || retiredChild)
  }

  const readRegistryEntries = (home: string): Map<number, { address?: string; filePath: string; workflowId?: string }> => {
    const entries = new Map<number, { address?: string; filePath: string; workflowId?: string }>()

    if (!home) {
      return entries
    }

    const dir = path.join(home, 'hunt-board')

    if (!dirExists(dir)) {
      return entries
    }

    try {
      for (const name of fs.readdirSync(dir)) {
        if (!/^board-\d+\.json$/.test(name)) {
          continue
        }

        const filePath = path.join(dir, name)

        try {
          const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8')) as Record<string, unknown>
          const port = Number(parsed.port)

          if (Number.isInteger(port) && port >= 1 && port <= 65535) {
            entries.set(port, {
              address: typeof parsed.address === 'string' ? parsed.address : undefined,
              filePath,
              workflowId: typeof parsed.workflow_id === 'string' ? parsed.workflow_id : undefined
            })
          }
        } catch {
          void 0
        }
      }
    } catch {
      void 0
    }

    return entries
  }

  const discoverBoards: HuntWorkbenchApi['discoverBoards'] = async options => {
    if (!deps.huntEnabled) {
      return { boards: [], error: 'hunt_variant_only', ok: false }
    }

    const home = deps.hermesHome()
    const registryEntries = readRegistryEntries(home)
    const candidatePorts = new Set<number>()

    if (managedBoard) {
      candidatePorts.add(managedBoard.port)
    }

    for (const port of registryEntries.keys()) {
      candidatePorts.add(port)
    }

    if (options?.port && Number.isInteger(options.port) && options.port >= 1 && options.port <= 65535) {
      candidatePorts.add(options.port)
    }

    candidatePorts.add(DEFAULT_BOARD_PORT)

    const managedPort = managedBoard?.port ?? null

    const probed = await Promise.all(
      [...candidatePorts].map(async port => {
        const descriptor = await probePort(port, managedPort)
        const reg = registryEntries.get(port)

        if (!descriptor && reg && (await checkPortBindable(port))) {
          unlinkQuietly(reg.filePath)
        }

        if (descriptor) {
          if (!descriptor.workflowId && reg?.workflowId) {
            descriptor.workflowId = reg.workflowId
          }

          if (!descriptor.workflowId && managedBoard?.port === port) {
            descriptor.workflowId = managedBoard.workflowId
          }

          if (reg?.address && validateLoopbackAddress(reg.address)) {
            descriptor.address = reg.address
          } else if (managedBoard?.port === port) {
            descriptor.address = managedBoard.address
          }
        }

        return descriptor
      })
    )

    const boards = probed
      .filter((item): item is HuntBoardDescriptor => item !== null)
      .sort((a, b) => Number(b.managed) - Number(a.managed) || a.port - b.port)

    return { boards, ok: true }
  }

  const validateStartRequest = (request?: HuntBoardStartRequest) => {
    const workflowId = String(request?.workflowId || '').trim()

    if (!SAFE_WORKFLOW_ID.test(workflowId)) {
      return { error: 'Enter a valid workflow ID (1-128 letters, digits, ., _, :, -).' }
    }

    const address = validateLoopbackAddress(request?.address)

    if (!address) {
      return { error: 'Temporal address must stay on loopback (127.0.0.1:<port>).' }
    }

    const rawOrigin = String(request?.dataOrigin || '').trim()

    if (rawOrigin && rawOrigin !== 'synthetic' && !ALLOWED_DATA_ORIGINS.has(rawOrigin)) {
      return { error: 'Unsupported data origin.' }
    }

    const caseId = String(request?.caseId || '').trim()

    if (caseId && !SAFE_CASE_ID.test(caseId)) {
      return { error: 'Invalid case ID.' }
    }

    if (request?.port !== undefined && (!Number.isInteger(request.port) || request.port < 0 || request.port > 65535)) {
      return { error: 'Port must be between 1 and 65535 (or 0 for automatic loopback port).' }
    }

    if (request?.port !== undefined && request.port !== 0 && managedBoard?.port === request.port) {
      return {
        error: `Port ${request.port} is already in use by the running Hunt Board; omit port (or pass 0) for zero-downtime replacement, or stop the current board first.`
      }
    }

    return { address, caseId, rawOrigin, workflowId }
  }

  const resolveBoardInputFile = async (
    runtime: ResolvedHuntPython,
    home: string,
    labStateDir: string,
    rawInputPath: string,
    rawOrigin: string,
    caseId: string,
    onTempPath?: (tempPath: string) => void
  ): Promise<{ error?: string; inputPath?: string; isToolDriven?: boolean; tempInputPath: null | string }> => {
    let inputPath = rawInputPath
    let tempInputPath: null | string = null

    if (inputPath) {
      inputPath = path.resolve(inputPath)

      if (!fileExists(inputPath)) {
        return { error: `Input JSON file does not exist: ${inputPath}`, tempInputPath: null }
      }
    } else {
      if (!home || !dirExists(path.dirname(labStateDir))) {
        return {
          error:
            'Analyst profile directory not found in HERMES_HOME; start the Hunting Lab or provide an exported --input JSON path.',
          tempInputPath: null
        }
      }

      const boardDir = path.join(home, 'hunt-board')
      fs.mkdirSync(boardDir, { mode: 0o700, recursive: true })
      tempInputPath = path.join(boardDir, `desktop-input-${Date.now()}-${crypto.randomBytes(4).toString('hex')}.json`)
      onTempPath?.(tempInputPath)

      const exportArgs = ['-m', 'hermes_temporal.cli', 'lab-input', '--tool-driven', '--state-dir', labStateDir, '--output', tempInputPath]

      if (rawOrigin && rawOrigin !== 'synthetic') {
        exportArgs.push('--data-origin', rawOrigin)
      }

      if (caseId) {
        exportArgs.push('--case-id', caseId)
      }

      const exported = await runPython(runtime, exportArgs, { timeoutMs: 20_000 })

      if (exported.code !== 0 || !fileExists(tempInputPath)) {
        unlinkQuietly(tempInputPath)
        const detail = exported.stderr.trim() || exported.stdout.trim() || 'lab-input export failed'

        return { error: detail, tempInputPath: null }
      }

      inputPath = tempInputPath
    }

    try {
      const parsedInput = JSON.parse(fs.readFileSync(inputPath, 'utf8')) as Record<string, unknown>

      return { inputPath, isToolDriven: parsedInput?.mode === 'tool_driven', tempInputPath }
    } catch {
      unlinkQuietly(tempInputPath)

      return { error: 'Input file is not valid UTF-8 JSON.', tempInputPath: null }
    }
  }

  const pickTargetBoardPort = async (requestedPort?: number): Promise<{ error?: string; port?: number }> => {
    if (requestedPort === undefined) {
      const defaultFree = managedBoard?.port !== DEFAULT_BOARD_PORT && (await checkPortBindable(DEFAULT_BOARD_PORT))

      return { port: defaultFree ? DEFAULT_BOARD_PORT : await allocatePort() }
    }

    if (!Number.isInteger(requestedPort) || requestedPort < 0 || requestedPort > 65535) {
      return { error: 'Port must be between 1 and 65535 (or 0 for automatic loopback port).' }
    }

    return { port: requestedPort === 0 ? await allocatePort() : requestedPort }
  }

  const awaitBoardStartup = (child: ChildProcess): Promise<{ error?: string; port?: number; url?: string }> =>
    new Promise(resolve => {
      let stdoutBuf = ''
      let stderrBuf = ''
      let settled = false

      const done = (value: { error?: string; port?: number; url?: string }) => {
        if (!settled) {
          settled = true
          clearTimeout(timer)
          resolve(value)
        }
      }

      const timer = setTimeout(() => {
        try {
          child.kill()
        } catch {
          void 0
        }

        done({ error: stderrBuf.trim() || 'Timed out waiting for Hunt Board to bind on 127.0.0.1.' })
      }, 10_000)

      child.stdout?.setEncoding('utf8')
      child.stderr?.setEncoding('utf8')
      child.stdout?.on('data', chunk => {
        stdoutBuf += String(chunk)
        const newline = stdoutBuf.indexOf('\n')

        if (newline < 0) {
          return
        }

        try {
          const msg = JSON.parse(stdoutBuf.slice(0, newline).trim()) as { status?: string; url?: string }
          const match = msg.status === 'serving' && typeof msg.url === 'string' ? /^http:\/\/127\.0\.0\.1:(\d+)\/$/.exec(msg.url) : null

          if (match && msg.url) {
            done({ port: Number(match[1]), url: msg.url })
          }
        } catch {
          void 0
        }
      })
      child.stderr?.on('data', chunk => {
        if (stderrBuf.length < 8192) {
          stderrBuf += String(chunk)
        }
      })
      child.on('error', err => done({ error: err.message }))
      child.on('close', code => done({ error: stderrBuf.trim() || `Hunt Board exited with code ${code ?? 1}.` }))
    })

  const defaultSpawnBoard = (rt: ResolvedHuntPython, argv: string[]) =>
    spawn(
      rt.pythonExe,
      argv,
      hiddenWindowsChildOptions({
        cwd: rt.frameworkRoot,
        env: { ...process.env, PYTHONPATH: rt.frameworkRoot },
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe']
      })
    )

  const buildBoardArgs = (
    workflowId: string,
    inputPath: string,
    address: string,
    port: number,
    isToolDriven: boolean,
    labStateDir: string,
    home: string
  ) => [
    '-u',
    '-m',
    'hermes_temporal.board',
    '--workflow-id',
    workflowId,
    '--input',
    inputPath,
    '--address',
    address,
    '--port',
    String(port),
    ...(isToolDriven ? ['--lab-state-dir', labStateDir] : []),
    ...(home && dirExists(home) ? ['--hermes-home', home] : [])
  ]

  const toStartedDescriptor = (
    probed: HuntBoardDescriptor | null,
    address: string,
    workflowId: string,
    caseId: string,
    home: string,
    isToolDriven: boolean,
    port: number,
    url: string
  ): HuntBoardDescriptor =>
    probed
      ? { ...probed, address, managed: true, workflowId: probed.workflowId || workflowId }
      : {
          address,
          caseId: caseId || 'unknown',
          childWorkflowId: null,
          liveEnabled: Boolean(home && dirExists(home)),
          liveProfiles: ['framework-researcher', 'framework-network-analyst'],
          managed: true,
          mode: isToolDriven ? 'tool_driven' : 'inline',
          port,
          url,
          workflowId
        }

  const spawnAndActivateBoard = async (
    tracker: { child: ChildProcess | null; epoch: number; tempInputPath: null | string },
    runtime: ResolvedHuntPython,
    boardArgs: string[],
    validated: { address: string; caseId: string; workflowId: string },
    home: string,
    isToolDriven: boolean
  ): Promise<HuntBoardStartResult> => {
    const child = (deps.spawnBoardProcess ?? defaultSpawnBoard)(runtime, boardArgs)
    tracker.child = child
    const started = await awaitBoardStartup(child)

    if (boardLifecycleEpoch !== tracker.epoch) {
      killChildQuietly(child)
      unlinkQuietly(tracker.tempInputPath)

      return { error: 'Board startup cancelled.', ok: false }
    }

    if (!started.port || !started.url) {
      if (inflightBoard === tracker) {
        inflightBoard = null
      }

      killChildQuietly(child)
      unlinkQuietly(tracker.tempInputPath)

      return { error: started.error ?? 'Failed to start Hunt Board.', ok: false }
    }

    if (inflightBoard === tracker) {
      inflightBoard = null
    }

    retireManagedBoard()

    managedBoard = {
      address: validated.address,
      child,
      port: started.port,
      tempInputPath: tracker.tempInputPath,
      workflowId: validated.workflowId
    }

    child.on('close', () => {
      if (managedBoard?.child === child) {
        unlinkQuietly(managedBoard.tempInputPath)
        managedBoard = null
      }
    })

    log(`[hunt-workbench] started Hunt Board for ${validated.workflowId} at ${started.url}`)
    const probed = await probePort(started.port, started.port)

    if (boardLifecycleEpoch !== tracker.epoch) {
      return { error: 'Board startup cancelled.', ok: false }
    }

    return {
      board: toStartedDescriptor(
        probed,
        validated.address,
        validated.workflowId,
        validated.caseId,
        home,
        isToolDriven,
        started.port,
        started.url
      ),
      ok: true
    }
  }

  const waitForChildExit = (child: ChildProcess, timeoutMs: number): Promise<void> =>
    new Promise(resolve => {
      if (typeof child.exitCode === 'number' || typeof child.signalCode === 'string') {
        resolve()

        return
      }

      const finish = () => {
        clearTimeout(timer)
        child.off('exit', finish)
        child.off('close', finish)
        resolve()
      }

      const timer = setTimeout(finish, timeoutMs)
      child.once('exit', finish)
      child.once('close', finish)
    })

  const prepareBoardStart = async (
    request: HuntBoardStartRequest | undefined,
    validated: { caseId: string; rawOrigin: string },
    myStart: number
  ): Promise<{ error: string } | PreparedBoardStart> => {
    let tempInputPath: null | string = null

    const fail = (error: string) => {
      unlinkQuietly(tempInputPath)

      return { error }
    }

    try {
      const runtime = await resolveRuntime()

      if (boardStartSeq !== myStart) {
        return fail('Board startup cancelled.')
      }

      if (!runtime) {
        return fail('Temporal Python environment not found (expected framework/.venv-temporal with temporalio and websockets).')
      }

      const home = deps.hermesHome()
      const labStateDir = home ? path.join(home, 'profiles', 'framework-network-analyst', 'hunt-lab-vm') : ''

      const resolvedInput = await resolveBoardInputFile(
        runtime,
        home,
        labStateDir,
        String(request?.inputPath || '').trim(),
        validated.rawOrigin,
        validated.caseId,
        tempPath => {
          tempInputPath = tempPath
        }
      )

      tempInputPath = resolvedInput.tempInputPath

      if (boardStartSeq !== myStart) {
        return fail('Board startup cancelled.')
      }

      if (!resolvedInput.inputPath) {
        return fail(resolvedInput.error ?? 'Failed to prepare input file.')
      }

      if (resolvedInput.isToolDriven && !labStateDir) {
        return fail('Tool-driven board requires HERMES_HOME with analyst lab state.')
      }

      return {
        home,
        inputPath: resolvedInput.inputPath,
        isToolDriven: Boolean(resolvedInput.isToolDriven),
        labStateDir,
        runtime,
        tempInputPath
      }
    } catch (err) {
      return fail(err instanceof Error ? err.message : 'Failed to prepare Hunt Board input.')
    }
  }

  const startBoard: HuntWorkbenchApi['startBoard'] = async request => {
    if (!deps.huntEnabled) {
      return { error: 'hunt_variant_only', ok: false }
    }

    const validated = validateStartRequest(request)

    if ('error' in validated) {
      return { error: validated.error, ok: false }
    }

    boardStartSeq += 1
    const myStart = boardStartSeq
    const cancelledInflight = cancelInflightBoard()
    const inflightExited = cancelledInflight ? waitForChildExit(cancelledInflight, 3000) : Promise.resolve()
    const prepared = await prepareBoardStart(request, validated, myStart)

    if ('error' in prepared) {
      return { error: prepared.error, ok: false }
    }

    const tracker = {
      child: null as ChildProcess | null,
      epoch: boardLifecycleEpoch,
      tempInputPath: prepared.tempInputPath
    }

    inflightBoard = tracker

    const abortTracker = (error: string): HuntBoardStartResult => {
      if (inflightBoard === tracker) {
        inflightBoard = null
      }

      killChildQuietly(tracker.child)
      unlinkQuietly(tracker.tempInputPath)

      return { error, ok: false }
    }

    try {
      await inflightExited

      if (boardLifecycleEpoch !== tracker.epoch) {
        return abortTracker('Board startup cancelled.')
      }

      const portChoice = await pickTargetBoardPort(request?.port)

      if (boardLifecycleEpoch !== tracker.epoch) {
        return abortTracker('Board startup cancelled.')
      }

      if (portChoice.port === undefined) {
        return abortTracker(portChoice.error ?? 'Invalid port.')
      }

      if (managedBoard?.port === portChoice.port) {
        return abortTracker(
          `Port ${portChoice.port} is already in use by the running Hunt Board; omit port (or pass 0) for zero-downtime replacement, or stop the current board first.`
        )
      }

      const boardArgs = buildBoardArgs(
        validated.workflowId,
        prepared.inputPath,
        validated.address,
        portChoice.port,
        prepared.isToolDriven,
        prepared.labStateDir,
        prepared.home
      )

      return await spawnAndActivateBoard(
        tracker,
        prepared.runtime,
        boardArgs,
        validated,
        prepared.home,
        prepared.isToolDriven
      )
    } catch (err) {
      return abortTracker(err instanceof Error ? err.message : 'Failed to start Hunt Board.')
    }
  }

  const stopBoard: HuntWorkbenchApi['stopBoard'] = async () => {
    if (!deps.huntEnabled) {
      return { ok: false, stopped: false }
    }

    boardStartSeq += 1

    return { ok: true, stopped: cleanupManagedBoard() }
  }

  const gateStatus: HuntWorkbenchApi['gateStatus'] = async request => {
    if (!deps.huntEnabled) {
      return { error: 'hunt_variant_only', ok: false }
    }

    const workflowId = String(request?.workflowId || '').trim()

    if (!SAFE_ROUND_WORKFLOW_ID.test(workflowId)) {
      return { error: 'Enter a valid workflow ID (1-160 letters, digits, ., _, :, -).', ok: false }
    }

    const address = validateLoopbackAddress(request?.address)

    if (!address) {
      return { error: 'Temporal address must stay on loopback (127.0.0.1:<port>).', ok: false }
    }

    const runtime = await resolveRuntime()

    if (!runtime) {
      return {
        error:
          'Temporal Python environment not found (expected framework/.venv-temporal with temporalio and websockets).',
        ok: false
      }
    }

    const result = await runPython(runtime, ['-c', GATE_STATUS_SCRIPT], {
      stdin: JSON.stringify({ address, workflow_id: workflowId }),
      timeoutMs: 15_000
    })

    if (result.code !== 0) {
      return {
        error: result.stderr.trim() || 'Temporal gate status query failed.',
        ok: false
      }
    }

    try {
      const parsed = JSON.parse(result.stdout.trim()) as HuntGateStatusResult

      if (!parsed.ok || !parsed.status) {
        return { error: parsed.error || 'Workflow status unavailable.', ok: false }
      }

      // Defense-in-depth: guarantee non-synthetic origins never pass bot-written text across IPC.
      if (!parsed.status.syntheticOnly || parsed.status.dataOrigin !== 'synthetic') {
        parsed.status.unverifiedBotSummary = null
      }

      return { ok: true, status: parsed.status }
    } catch {
      return { error: 'Malformed status response from Temporal helper.', ok: false }
    }
  }

  const decideGate: HuntWorkbenchApi['decideGate'] = async request => {
    if (!deps.huntEnabled) {
      return { error: 'hunt_variant_only', ok: false }
    }

    const childWorkflowId = String(request?.childWorkflowId || '').trim()

    if (!SAFE_ROUND_WORKFLOW_ID.test(childWorkflowId)) {
      return { error: 'Valid target round workflow ID is required.', ok: false }
    }

    const stepId = String(request?.stepId || '').trim()

    if (!SAFE_STEP_ID.test(stepId)) {
      return { error: 'Valid gated step ID is required.', ok: false }
    }

    const phase = request?.phase

    if (phase !== 'execute' && phase !== 'review' && phase !== 'reconcile') {
      return { error: 'Gate phase must be execute, review, or reconcile.', ok: false }
    }

    const choice = request?.choice

    const validChoice =
      phase === 'reconcile'
        ? choice === 'accept' || choice === 'abort'
        : choice === 'approve' || choice === 'deny'

    if (!validChoice) {
      return { error: `Invalid choice "${String(choice)}" for ${phase} gate.`, ok: false }
    }

    const operatorName = normalizeOperatorName(request?.operatorName)

    if (!operatorName) {
      return {
        error: 'Operator name is required (1 to 200 printable characters).',
        ok: false
      }
    }

    const checkNote = normalizeCheckNote(request?.checkNote)

    if (!checkNote) {
      return {
        error: '"What did you check?" note is required (1 to 1,000 characters).',
        ok: false
      }
    }

    const address = validateLoopbackAddress(request?.address)

    if (!address) {
      return { error: 'Temporal address must stay on loopback (127.0.0.1:<port>).', ok: false }
    }

    const runtime = await resolveRuntime()

    if (!runtime) {
      return {
        error:
          'Temporal Python environment not found (expected framework/.venv-temporal with temporalio and websockets).',
        ok: false
      }
    }

    const isoUtc = nowUtc()
    const evidenceNote = formatDesktopEvidenceNote(operatorName, isoUtc, checkNote)
    const decisionId = `desktop-${stepId}-${phase}-${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`

    const args = [
      '-m',
      'hermes_temporal.cli',
      '--address',
      address,
      'decision',
      childWorkflowId,
      '--step-id',
      stepId,
      '--phase',
      phase,
      '--choice',
      choice,
      '--decision-id',
      decisionId,
      '--decided-by',
      operatorName,
      '--via',
      'cli',
      '--evidence-note',
      evidenceNote
    ]

    const result = await runPython(runtime, args, { timeoutMs: 15_000 })

    if (result.code !== 0) {
      return {
        error: result.stderr.trim() || result.stdout.trim() || 'Temporal gate decision signal failed.',
        ok: false
      }
    }

    log(`[hunt-workbench] sent ${choice} decision on ${childWorkflowId} (${stepId}/${phase}) by ${operatorName}`)

    return {
      decidedAtUtc: isoUtc,
      decidedBy: operatorName,
      decisionId,
      ok: true,
      via: 'cli',
      workflowId: childWorkflowId
    }
  }

  return {
    decideGate,
    discoverBoards,
    dispose: () => {
      boardStartSeq += 1
      cleanupManagedBoard()
    },
    gateStatus,
    startBoard,
    stopBoard
  }
}

export function registerHuntWorkbenchIpc(
  ipcMain: Pick<IpcMain, 'handle'>,
  deps: HuntWorkbenchDeps
): HuntWorkbenchApi & { dispose: () => void } {
  const workbench = createHuntWorkbench(deps)

  ipcMain.handle('hermes:hunt:boards:discover', (_event, options) => workbench.discoverBoards(options))
  ipcMain.handle('hermes:hunt:boards:start', (_event, request) => workbench.startBoard(request))
  ipcMain.handle('hermes:hunt:boards:stop', () => workbench.stopBoard())
  ipcMain.handle('hermes:hunt:gates:status', (_event, request) => workbench.gateStatus(request))
  ipcMain.handle('hermes:hunt:gates:decide', (_event, request) => workbench.decideGate(request))

  return workbench
}
