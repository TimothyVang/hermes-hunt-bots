import { EventEmitter } from 'node:events'
import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import { PassThrough } from 'node:stream'

import { afterEach, describe, expect, it } from 'vitest'

import {
  createHuntWorkbench,
  defaultProbeBoardPort,
  formatDesktopEvidenceNote,
  normalizeCheckNote,
  normalizeOperatorName,
  validateLoopbackAddress
} from './hunt-workbench'

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'hunt-workbench-test-'))
}

function fakeChildProcess(url?: string, exitCode?: number, stderrText = '') {
  const child = new EventEmitter() as any
  child.stdout = new PassThrough()
  child.stderr = new PassThrough()
  child.killed = false

  child.kill = () => {
    child.killed = true
    child.emit('close', 0)
  }

  setImmediate(() => {
    if (stderrText) {
      child.stderr.write(stderrText)
    }

    if (url) {
      child.stdout.write(`${JSON.stringify({ status: 'serving', url })}\n`)
    } else if (exitCode !== undefined) {
      child.emit('close', exitCode)
    }
  })

  return child
}

describe('hunt-workbench', () => {
  const tempDirs: string[] = []
  const servers: http.Server[] = []

  afterEach(async () => {
    for (const server of servers.splice(0)) {
      await new Promise<void>(resolve => server.close(() => resolve()))
    }

    for (const dir of tempDirs.splice(0)) {
      fs.rmSync(dir, { force: true, recursive: true })
    }
  })

  it('validates loopback-only Temporal addresses and operator decision inputs', () => {
    expect(validateLoopbackAddress()).toBe('127.0.0.1:7233')
    expect(validateLoopbackAddress('127.0.0.1:17233')).toBe('127.0.0.1:17233')
    expect(validateLoopbackAddress('localhost:7233')).toBeNull()
    expect(validateLoopbackAddress('0.0.0.0:7233')).toBeNull()
    expect(validateLoopbackAddress('192.168.1.5:7233')).toBeNull()
    expect(validateLoopbackAddress('http://127.0.0.1:7233')).toBeNull()
    expect(validateLoopbackAddress('127.0.0.1:0')).toBeNull()
    expect(validateLoopbackAddress('127.0.0.1:65536')).toBeNull()

    expect(normalizeOperatorName('  Alice   Chen ')).toBe('Alice Chen')
    expect(normalizeOperatorName('   ')).toBeNull()
    expect(normalizeOperatorName('x'.repeat(201))).toBeNull()
    expect(normalizeOperatorName('Alice\nBob')).toBeNull()

    expect(normalizeCheckNote('  Verified scope against case.json  ')).toBe('Verified scope against case.json')
    expect(normalizeCheckNote('')).toBeNull()
    expect(normalizeCheckNote('x'.repeat(1001))).toBeNull()

    const note = formatDesktopEvidenceNote('Alice Chen', '2026-11-14T05:30:00Z', 'Checked event IDs evt-000101')
    expect(note).toBe(
      'Decided by Alice Chen via Hunt Command Desktop at 2026-11-14T05:30:00Z. Checked: Checked event IDs evt-000101'
    )
    expect(Buffer.byteLength(note, 'utf8')).toBeLessThanOrEqual(4096)
  })

  it('refuses every action when not running in the Hunt Command variant', async () => {
    const wb = createHuntWorkbench({
      hermesHome: () => '/tmp/unused',
      huntEnabled: false
    })

    expect(await wb.discoverBoards()).toEqual({ boards: [], error: 'hunt_variant_only', ok: false })
    expect(await wb.startBoard({ workflowId: 'practice-1' })).toEqual({ error: 'hunt_variant_only', ok: false })
    expect(await wb.gateStatus({ workflowId: 'practice-1' })).toEqual({ error: 'hunt_variant_only', ok: false })
    expect(
      await wb.decideGate({
        checkNote: 'checked',
        childWorkflowId: 'practice-1:round:001',
        choice: 'approve',
        operatorName: 'Alice',
        phase: 'review',
        stepId: 'wave-1'
      })
    ).toEqual({ error: 'hunt_variant_only', ok: false })
  })

  it('discovers active dynamic Hunt Board ports from HERMES_HOME/hunt-board and removes stale entries', async () => {
    const home = makeTempDir()
    tempDirs.push(home)

    const boardState = {
      case: { case_id: 'dns-lab-001' },
      live: {
        owners: [
          { frames: 1, profile: 'framework-researcher' },
          { frames: 3, profile: 'framework-network-analyst' }
        ]
      },
      mode: 'tool_driven',
      run: {
        child: { workflow_id: 'practice-1:round:001' },
        parent: { child_workflow_id: 'practice-1:round:001', workflow_id: 'practice-1' }
      },
      steps: [{ step_id: 'scope' }]
    }

    const liveServer = http.createServer((req, res) => {
      if (req.url === '/state.json') {
        res.writeHead(200, { 'Content-Type': 'application/json', Server: 'HuntBoard Python/3.13' })
        res.end(JSON.stringify(boardState))
      } else {
        res.writeHead(404)
        res.end()
      }
    })

    servers.push(liveServer)
    await new Promise<void>(resolve => liveServer.listen(0, '127.0.0.1', () => resolve()))
    const livePort = (liveServer.address() as { port: number }).port

    const otherServer = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json', Server: 'OtherService/1.0' })
      res.end(JSON.stringify(boardState))
    })

    servers.push(otherServer)
    await new Promise<void>(resolve => otherServer.listen(0, '127.0.0.1', () => resolve()))
    const otherPort = (otherServer.address() as { port: number }).port

    const regDir = path.join(home, 'hunt-board')
    fs.mkdirSync(regDir, { recursive: true })
    fs.writeFileSync(
      path.join(regDir, `board-${livePort}.json`),
      JSON.stringify({ address: '127.0.0.1:7233', port: livePort, workflow_id: 'practice-1' })
    )
    const staleFile = path.join(regDir, 'board-59998.json')
    fs.writeFileSync(staleFile, JSON.stringify({ port: 59998, workflow_id: 'dead' }))

    const wb = createHuntWorkbench({
      hermesHome: () => home,
      huntEnabled: true,
      probeBoardPort: defaultProbeBoardPort
    })

    const discovered = await wb.discoverBoards({ port: otherPort })
    expect(discovered.ok).toBe(true)
    expect(discovered.boards.some(b => b.port === otherPort)).toBe(false)
    const found = discovered.boards.find(b => b.port === livePort)
    expect(found).toMatchObject({
      address: '127.0.0.1:7233',
      caseId: 'dns-lab-001',
      childWorkflowId: 'practice-1:round:001',
      liveEnabled: true,
      liveProfiles: ['framework-researcher', 'framework-network-analyst'],
      mode: 'tool_driven',
      port: livePort,
      url: `http://127.0.0.1:${livePort}/`,
      workflowId: 'practice-1'
    })
    expect(fs.existsSync(staleFile)).toBe(false)
  })

  it('starts Hunt Board with --lab-state-dir and --hermes-home for tool-driven inputs and omits --lab-state-dir for inline', async () => {
    const home = makeTempDir()
    tempDirs.push(home)
    const analystDir = path.join(home, 'profiles', 'framework-network-analyst')
    fs.mkdirSync(path.join(analystDir, 'hunt-lab-vm'), { recursive: true })

    const pythonCalls: string[][] = []
    const boardSpawns: string[][] = []

    const wb = createHuntWorkbench({
      allocateFreePort: async () => 54321,
      hermesHome: () => home,
      huntEnabled: true,
      probeBoardPort: async port =>
        port === DEFAULT_OCCUPIED
          ? ({
              address: '127.0.0.1:7233',
              caseId: 'other',
              childWorkflowId: null,
              liveEnabled: true,
              liveProfiles: [],
              managed: false,
              mode: 'tool_driven',
              port,
              url: `http://127.0.0.1:${port}/`,
              workflowId: 'other'
            } as any)
          : null,
      resolvePython: async () => ({ frameworkRoot: '/repo/framework', pythonExe: '/repo/framework/.venv-temporal/bin/python' }),
      runPythonCommand: async (_rt, args) => {
        pythonCalls.push(args)
        const outIdx = args.indexOf('--output')

        if (outIdx >= 0) {
          fs.writeFileSync(args[outIdx + 1], JSON.stringify({ mode: 'tool_driven', synthetic_only: true }))
        }

        return { code: 0, stderr: '', stdout: '{"status":"exported"}' }
      },
      spawnBoardProcess: (_rt, args) => {
        boardSpawns.push(args)
        const portArg = args[args.indexOf('--port') + 1]

        return fakeChildProcess(`http://127.0.0.1:${portArg}/`)
      }
    })

    const DEFAULT_OCCUPIED = 8790
    const started = await wb.startBoard({ workflowId: 'practice-dns-001' })
    expect(started.ok).toBe(true)
    expect(started.board?.url).toBe('http://127.0.0.1:54321/')
    expect(pythonCalls[0]).toContain('lab-input')
    expect(pythonCalls[0]).toContain('--tool-driven')
    expect(boardSpawns[0]).toContain('--lab-state-dir')
    expect(boardSpawns[0]).toContain(path.join(analystDir, 'hunt-lab-vm'))
    expect(boardSpawns[0]).toContain('--hermes-home')
    expect(boardSpawns[0]).toContain(home)

    const inlineFile = path.join(home, 'inline.json')
    fs.writeFileSync(inlineFile, JSON.stringify({ scope: 'synthetic', synthetic_only: true }))
    const inlineStarted = await wb.startBoard({ inputPath: inlineFile, port: 8891, workflowId: 'inline-1' })
    expect(inlineStarted.ok).toBe(true)
    expect(boardSpawns[1]).not.toContain('--lab-state-dir')
    expect(boardSpawns[1]).toContain('--hermes-home')

    const stopped = await wb.stopBoard()
    expect(stopped).toEqual({ ok: true, stopped: true })
  })

  it('enforces Rule 4 summary stripping on non-synthetic cases and sends governed CLI human gate decisions', async () => {
    const cliInvocations: string[][] = []

    const wb = createHuntWorkbench({
      hermesHome: () => '/tmp/unused',
      huntEnabled: true,
      nowUtc: () => '2026-11-14T05:35:00Z',
      resolvePython: async () => ({ frameworkRoot: '/repo/framework', pythonExe: '/repo/framework/.venv-temporal/bin/python' }),
      runPythonCommand: async (_rt, args, opts) => {
        if (args[0] === '-c') {
          const req = JSON.parse(opts?.stdin || '{}') as { workflow_id: string }
          const isPublic = req.workflow_id === 'public-hunt'

          return {
            code: 0,
            stderr: '',
            stdout: JSON.stringify({
              ok: true,
              status: {
                address: '127.0.0.1:7233',
                caseId: isPublic ? 'mordor-001' : 'dns-lab-001',
                childWorkflowId: `${req.workflow_id}:round:001`,
                completedRounds: 0,
                currentRound: 1,
                dataOrigin: isPublic ? 'public-dataset' : 'synthetic',
                decisions: [],
                openGate: {
                  choices: ['approve', 'deny'],
                  gateKind: 'scope',
                  label: 'Human Gate 1 of 2: Scope & Framing Review',
                  phase: 'review',
                  stepId: 'wave-1',
                  waitingSteps: ['scope'],
                  wave: 1
                },
                parentStage: 'running_round',
                roundsRequested: 1,
                stage: 'awaiting_review',
                steps: [],
                syntheticOnly: !isPublic,
                temporalStatus: 'RUNNING',
                unverifiedBotSummary: 'Should be stripped if non-synthetic',
                workflowId: req.workflow_id
              }
            })
          }
        }

        cliInvocations.push(args)

        return {
          code: 0,
          stderr: '',
          stdout: JSON.stringify({ decision_id: 'd-1', signal_sent: true, workflow_id: args[4] })
        }
      }
    })

    const synth = await wb.gateStatus({ workflowId: 'synth-hunt' })
    expect(synth.ok).toBe(true)
    expect(synth.status?.syntheticOnly).toBe(true)
    expect(synth.status?.unverifiedBotSummary).toBe('Should be stripped if non-synthetic')

    const nonSynth = await wb.gateStatus({ workflowId: 'public-hunt' })
    expect(nonSynth.ok).toBe(true)
    expect(nonSynth.status?.syntheticOnly).toBe(false)
    expect(nonSynth.status?.unverifiedBotSummary).toBeNull()

    const missingNote = await wb.decideGate({
      checkNote: '   ',
      childWorkflowId: 'synth-hunt:round:001',
      choice: 'approve',
      operatorName: 'Alice Operator',
      phase: 'review',
      stepId: 'wave-1'
    })

    expect(missingNote.ok).toBe(false)
    expect(cliInvocations).toHaveLength(0)

    const decided = await wb.decideGate({
      checkNote: 'Reviewed case scope and confirmed time window.',
      childWorkflowId: 'synth-hunt:round:001',
      choice: 'approve',
      operatorName: '  Alice   Operator ',
      phase: 'review',
      stepId: 'wave-1'
    })

    expect(decided.ok).toBe(true)
    expect(decided.decidedBy).toBe('Alice Operator')
    expect(decided.via).toBe('cli')
    expect(cliInvocations).toHaveLength(1)
    expect(cliInvocations[0]).toEqual([
      '-m',
      'hermes_temporal.cli',
      '--address',
      '127.0.0.1:7233',
      'decision',
      'synth-hunt:round:001',
      '--step-id',
      'wave-1',
      '--phase',
      'review',
      '--choice',
      'approve',
      '--decision-id',
      expect.stringMatching(/^desktop-wave-1-review-[a-z0-9]+-[0-9a-f]{8}$/),
      '--decided-by',
      'Alice Operator',
      '--via',
      'cli',
      '--evidence-note',
      'Decided by Alice Operator via Hunt Command Desktop at 2026-11-14T05:35:00Z. Checked: Reviewed case scope and confirmed time window.'
    ])
  })
})
