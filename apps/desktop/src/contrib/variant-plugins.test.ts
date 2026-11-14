import { host, TOOL_CARD_AREA } from '@hermes/plugin-sdk'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { createElement, type ReactNode } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { variantPluginModules as huntModules } from './variant-plugins.hunt'

vi.mock('./runtime-loader', () => ({ watchRuntimePlugins: vi.fn() }))

// Fresh plugin discovery (its one-shot guard and stores) with the given variant module set.
async function discover(modules: typeof huntModules) {
  vi.resetModules()
  vi.doMock('@/contrib/variant-plugins', () => ({ variantPluginModules: modules }))

  // Fresh module instances after resetModules: discovery runs once per module instance.
  const [{ discoverBundledPlugins }, store, { registry }] = await Promise.all([
    import('./plugins'),
    import('./plugins-store'),
    import('./registry')
  ])

  // Other in-tree bundled plugins are outside this test.
  store.$pluginDecisions.set({ accent: false, kanban: false, 'hermes-bots': false })
  discoverBundledPlugins()

  return { records: store.$pluginRecords.get(), registry }
}

describe('variant-bundled plugins', () => {
  afterEach(() => {
    cleanup()
    delete (globalThis as Record<string, unknown>).__HUNT_COMMAND_HANDOFF__
    delete (globalThis as Record<string, unknown>).__HUNT_COMMAND_ON_HANDOFF__
    delete (globalThis as Record<string, unknown>).__HUNT_COMMAND_WORKFLOW_ID__
    delete (globalThis as Record<string, unknown>).__HUNT_COMMAND_TEMPORAL_ADDRESS__
    vi.restoreAllMocks()
    vi.doUnmock('@/contrib/variant-plugins')
    vi.resetModules()
  })

  it('the Hunt Command set is the two framework/ plugins, both on by default', () => {
    const plugins = Object.values(huntModules).map(mod => mod.default)
    expect(plugins.map(plugin => [plugin.id, plugin.defaultEnabled])).toEqual([
      ['cybersecurity-workspace', true],
      ['hunt-lab', true]
    ])
  })

  it('stock Hermes bundles no variant plugin', async () => {
    const { records } = await discover({})
    expect(records['hunt-lab']).toBeUndefined()
    expect(records['cybersecurity-workspace']).toBeUndefined()
  })

  it('hunt: both plugins load as bundled with their pages and the Hunt Command theme', async () => {
    const { records, registry } = await discover(huntModules)

    for (const id of ['hunt-lab', 'cybersecurity-workspace']) {
      expect(records[id]).toMatchObject({ kind: 'bundled', status: 'loaded' })
    }

    const routes = registry.getArea('routes').map(item => item.data)

    for (const path of ['/hunt-lab', '/hunt-board', '/cybersecurity-workspace']) {
      expect(routes).toContainEqual(expect.objectContaining({ path }))
    }

    expect(registry.getArea('themes').map(item => item.data)).toContainEqual(
      expect.objectContaining({ name: 'hunt-command' })
    )
  })

  it('auto-selects local framework routes and fetches read-only status only after clicking Find profiles', async () => {
    const profileRoutesSpy = vi.spyOn(host, 'profileRoutes').mockResolvedValue([
      {
        connectionId: 'local',
        mode: 'local',
        profile: 'framework-coordinator',
        targetProfile: 'framework-coordinator'
      },
      {
        connectionId: 'local',
        mode: 'local',
        profile: 'framework-network-analyst',
        targetProfile: 'framework-network-analyst'
      }
    ])

    const requestProfileSpy = vi.spyOn(host, 'requestProfile').mockImplementation(async (_route, method) => {
      if (method === 'cli.exec') {
        return {
          blocked: false,
          code: 0,
          output: JSON.stringify({
            case_id: 'dns-tunnel-001',
            origin: 'synthetic',
            profile: 'framework-network-analyst',
            project: 'hunt-lab-dns',
            reason: null,
            state: 'running'
          })
        } as never
      }

      return { state: 'stopped' } as never
    })

    const { registry } = await discover(huntModules)

    const routeEntries = registry.getArea('routes') as unknown as ReadonlyArray<{
      data: { path: string }
      render?: () => ReactNode
    }>

    const labPage = routeEntries.find(item => item.data.path === '/hunt-lab')
    const workspacePage = routeEntries.find(item => item.data.path === '/cybersecurity-workspace')

    expect(profileRoutesSpy).not.toHaveBeenCalled()
    expect(requestProfileSpy).not.toHaveBeenCalled()

    render(createElement('div', null, labPage?.render?.()))
    expect(profileRoutesSpy).not.toHaveBeenCalled()
    expect(requestProfileSpy).not.toHaveBeenCalled()

    fireEvent.click(screen.getByRole('button', { name: 'Find profiles' }))

    await waitFor(() => {
      expect(requestProfileSpy).toHaveBeenCalledWith(
        expect.objectContaining({ targetProfile: 'framework-network-analyst' }),
        'cli.exec',
        expect.objectContaining({ argv: ['-p', 'framework-network-analyst', 'hunt-lab', 'status'] }),
        expect.any(Number),
        expect.objectContaining({ spawnPriority: 'foreground' })
      )
    })

    await waitFor(() => {
      expect(screen.getAllByText('dns-tunnel-001').length).toBeGreaterThan(0)
    })

    cleanup()
    requestProfileSpy.mockClear()

    render(createElement('div', null, workspacePage?.render?.()))
    expect(requestProfileSpy).not.toHaveBeenCalled()

    fireEvent.click(screen.getByRole('button', { name: 'Find profiles' }))

    await waitFor(() => {
      expect(requestProfileSpy).toHaveBeenCalledWith(
        expect.objectContaining({ targetProfile: 'framework-coordinator' }),
        'display.status',
        {},
        15_000,
        expect.objectContaining({ spawnPriority: 'foreground' })
      )
    })

    await waitFor(() => {
      expect(screen.getByText(/Selected framework-coordinator · screen stopped\./)).toBeTruthy()
    })
  })

  it('starts and attaches a dynamic-port Hunt Board on click and updates LabBrowserCard live MJPEG URLs', async () => {
    const startBoardSpy = vi.spyOn(host.huntWorkbench, 'startBoard').mockResolvedValue({
      board: {
        address: '127.0.0.1:7233',
        caseId: 'dns-tunnel-001',
        childWorkflowId: 'practice-dns-001-round-001',
        liveEnabled: true,
        liveProfiles: ['framework-network-analyst'],
        managed: true,
        mode: 'tool_driven',
        port: 54321,
        url: 'http://127.0.0.1:54321/',
        workflowId: 'practice-dns-001'
      },
      ok: true
    })

    const navigateSpy = vi.spyOn(host, 'navigate').mockImplementation(() => undefined)
    const { registry } = await discover(huntModules)

    const routeEntries = registry.getArea('routes') as unknown as ReadonlyArray<{
      data: { path: string }
      render?: () => ReactNode
    }>

    const toolCards = registry.getArea(TOOL_CARD_AREA) as unknown as ReadonlyArray<{
      data: { render: (props: Record<string, unknown>) => ReactNode; tool: string }
    }>

    const boardPage = routeEntries.find(item => item.data.path === '/hunt-board')
    const browserCard = toolCards.find(item => item.data.tool === 'lab_browser')

    render(
      createElement(
        'div',
        null,
        boardPage?.render?.(),
        browserCard?.data.render({
          args: { action: 'open', page: 'arkime_sessions' },
          profile: 'framework-network-analyst',
          status: 'running'
        })
      )
    )

    expect(startBoardSpy).not.toHaveBeenCalled()

    fireEvent.change(screen.getByLabelText('Workflow ID'), { target: { value: 'practice-dns-001' } })
    fireEvent.click(screen.getByRole('button', { name: /Start & attach board/i }))

    await waitFor(() => {
      expect(startBoardSpy).toHaveBeenCalledWith({
        address: '127.0.0.1:7233',
        inputPath: undefined,
        port: undefined,
        workflowId: 'practice-dns-001'
      })
    })

    await waitFor(() => {
      const liveImg = screen.getByAltText('Live lab browser of framework-network-analyst') as HTMLImageElement
      expect(liveImg.src).toContain('http://127.0.0.1:54321/live/framework-network-analyst.mjpg')
    })

    fireEvent.click(screen.getByRole('button', { name: 'Human gates' }))
    expect(navigateSpy).toHaveBeenCalledWith('/cybersecurity-workspace')
    expect((globalThis as Record<string, unknown>).__HUNT_COMMAND_WORKFLOW_ID__).toBe('practice-dns-001')
  })

  it('enforces Rule 3 and Rule 4 on Human Gates approvals in Cybersecurity workspace', async () => {
    ;(globalThis as Record<string, unknown>).__HUNT_COMMAND_WORKFLOW_ID__ = 'practice-dns-001'

    const gateStatusSpy = vi
      .spyOn(host.huntWorkbench, 'gateStatus')
      .mockResolvedValueOnce({
        ok: true,
        status: {
          address: '127.0.0.1:7233',
          caseId: 'dns-tunnel-001',
          childWorkflowId: 'practice-dns-001-round-001',
          completedRounds: 0,
          currentRound: 1,
          dataOrigin: 'synthetic',
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
          syntheticOnly: true,
          temporalStatus: 'RUNNING',
          unverifiedBotSummary: '[scope] disposition=review_ready, claims=1\n- scope-01: Scoped DNS investigation',
          workflowId: 'practice-dns-001'
        }
      })
      .mockResolvedValueOnce({
        ok: true,
        status: {
          address: '127.0.0.1:7233',
          caseId: 'dns-tunnel-001',
          childWorkflowId: 'practice-dns-001-round-001',
          completedRounds: 0,
          currentRound: 1,
          dataOrigin: 'public-dataset',
          decisions: [
            {
              decidedBy: 'Alice Analyst',
              decision: 'approve',
              decisionId: 'desktop-wave-1-review-approve-1',
              phase: 'review',
              slackUser: '',
              stepId: 'wave-1',
              via: 'cli'
            }
          ],
          openGate: {
            choices: ['approve', 'deny'],
            gateKind: 'incident',
            label: 'Human Gate 2 of 2: Incident Report Review',
            phase: 'review',
            stepId: 'wave-4',
            waitingSteps: ['incident'],
            wave: 4
          },
          parentStage: 'running_round',
          roundsRequested: 1,
          stage: 'awaiting_review',
          steps: [],
          syntheticOnly: false,
          temporalStatus: 'RUNNING',
          unverifiedBotSummary: 'MUST NEVER DISPLAY ON PUBLIC DATASET',
          workflowId: 'practice-dns-001'
        }
      })

    const decideGateSpy = vi.spyOn(host.huntWorkbench, 'decideGate').mockResolvedValue({
      decidedAtUtc: '2026-11-14T05:30:00Z',
      decidedBy: 'Alice Analyst',
      decisionId: 'desktop-wave-1-review-approve-1',
      ok: true,
      via: 'cli',
      workflowId: 'practice-dns-001-round-001'
    })

    const { registry } = await discover(huntModules)

    const routeEntries = registry.getArea('routes') as unknown as ReadonlyArray<{
      data: { path: string }
      render?: () => ReactNode
    }>

    const workspacePage = routeEntries.find(item => item.data.path === '/cybersecurity-workspace')
    render(createElement('div', null, workspacePage?.render?.()))

    expect(gateStatusSpy).not.toHaveBeenCalled()
    expect((screen.getByLabelText('Workflow ID') as HTMLInputElement).value).toBe('practice-dns-001')

    fireEvent.click(screen.getByRole('button', { name: 'Load gate status' }))

    await waitFor(() => {
      expect(screen.getByText('Bot-written, unverified:')).toBeTruthy()
      expect(screen.getByText(/scope-01: Scoped DNS investigation/)).toBeTruthy()
    })

    const approveButton = screen.getByRole('button', { name: 'Approve gate' }) as HTMLButtonElement
    expect(approveButton.disabled).toBe(true)

    fireEvent.change(screen.getByLabelText('Operator name'), { target: { value: 'Alice Analyst' } })
    expect(approveButton.disabled).toBe(true)

    fireEvent.change(screen.getByLabelText('What did you check?'), {
      target: { value: 'Verified case.json bounds and evt-0001 scope' }
    })
    expect(approveButton.disabled).toBe(false)

    fireEvent.click(approveButton)

    await waitFor(() => {
      expect(decideGateSpy).toHaveBeenCalledWith({
        address: '127.0.0.1:7233',
        checkNote: 'Verified case.json bounds and evt-0001 scope',
        childWorkflowId: 'practice-dns-001-round-001',
        choice: 'approve',
        operatorName: 'Alice Analyst',
        phase: 'review',
        stepId: 'wave-1'
      })
    })

    await waitFor(() => {
      expect(screen.getByText(/ID-and-status view only/)).toBeTruthy()
      expect(screen.queryByText('Bot-written, unverified:')).toBeNull()
      expect(screen.queryByText(/MUST NEVER DISPLAY ON PUBLIC DATASET/)).toBeNull()
      expect(screen.getByText(/wave-1 \(review\): approve · decided_by=Alice Analyst · via=cli/)).toBeTruthy()
    })
  })

  it('verifies Hunt Board iframe postMessage source and propagates non-7233 address + second-workflow handoffs cleanly', async () => {
    vi.spyOn(host.huntWorkbench, 'startBoard')
      .mockResolvedValueOnce({
        board: {
          address: '127.0.0.1:58288',
          caseId: 'dns-tunnel-001',
          childWorkflowId: 'wf-1-round-001',
          liveEnabled: true,
          liveProfiles: ['framework-network-analyst'],
          managed: true,
          mode: 'tool_driven',
          port: 54321,
          url: 'http://127.0.0.1:54321/',
          workflowId: 'wf-1'
        },
        ok: true
      })
      .mockResolvedValueOnce({
        board: {
          address: '127.0.0.1:59111',
          caseId: 'beaconing-002',
          childWorkflowId: 'wf-2-round-001',
          liveEnabled: true,
          liveProfiles: ['framework-network-analyst'],
          managed: true,
          mode: 'tool_driven',
          port: 54322,
          url: 'http://127.0.0.1:54322/',
          workflowId: 'wf-2'
        },
        ok: true
      })

    const gateStatusSpy = vi
      .spyOn(host.huntWorkbench, 'gateStatus')
      .mockResolvedValueOnce({
        ok: true,
        status: {
          address: '127.0.0.1:58288',
          caseId: 'dns-tunnel-001',
          childWorkflowId: 'wf-1-round-001',
          completedRounds: 0,
          currentRound: 1,
          dataOrigin: 'synthetic',
          decisions: [],
          openGate: null,
          parentStage: 'running_round',
          roundsRequested: 1,
          stage: 'completed',
          steps: [],
          syntheticOnly: true,
          temporalStatus: 'COMPLETED',
          unverifiedBotSummary: null,
          workflowId: 'wf-1'
        }
      })
      .mockResolvedValueOnce({
        ok: true,
        status: {
          address: '127.0.0.1:59111',
          caseId: 'beaconing-002',
          childWorkflowId: 'wf-2-round-001',
          completedRounds: 0,
          currentRound: 1,
          dataOrigin: 'synthetic',
          decisions: [],
          openGate: null,
          parentStage: 'running_round',
          roundsRequested: 1,
          stage: 'awaiting_review',
          steps: [],
          syntheticOnly: true,
          temporalStatus: 'RUNNING',
          unverifiedBotSummary: null,
          workflowId: 'wf-2'
        }
      })

    const navigateSpy = vi.spyOn(host, 'navigate').mockImplementation(() => undefined)
    const { registry } = await discover(huntModules)

    const routeEntries = registry.getArea('routes') as unknown as ReadonlyArray<{
      data: { path: string }
      render?: () => ReactNode
    }>

    const boardPage = routeEntries.find(item => item.data.path === '/hunt-board')
    const workspacePage = routeEntries.find(item => item.data.path === '/cybersecurity-workspace')

    render(createElement('div', null, boardPage?.render?.(), workspacePage?.render?.()))

    fireEvent.change(screen.getAllByLabelText('Workflow ID')[0], { target: { value: 'wf-1' } })
    fireEvent.change(screen.getByLabelText('Temporal address'), { target: { value: '127.0.0.1:58288' } })
    fireEvent.click(screen.getByRole('button', { name: /Start & attach board/i }))

    await waitFor(() => {
      expect((screen.getByLabelText('Temporal loopback address') as HTMLInputElement).value).toBe('127.0.0.1:58288')
      expect((screen.getAllByLabelText('Workflow ID')[1] as HTMLInputElement).value).toBe('wf-1')
    })

    expect(gateStatusSpy).not.toHaveBeenCalled()

    navigateSpy.mockClear()
    window.dispatchEvent(
      new MessageEvent('message', {
        data: { type: 'hunt-board:open-human-gates', workflowId: 'spoofed-wf' },
        source: window
      })
    )
    expect(navigateSpy).not.toHaveBeenCalled()
    expect((screen.getAllByLabelText('Workflow ID')[1] as HTMLInputElement).value).toBe('wf-1')

    const iframe = screen.getByTitle('Live hunt board') as HTMLIFrameElement
    Object.defineProperty(iframe, 'contentWindow', { configurable: true, value: null })
    expect(iframe.contentWindow).toBeNull()

    window.dispatchEvent(
      new MessageEvent('message', {
        data: { type: 'hunt-board:open-human-gates', workflowId: 'null-spoof-wf' },
        source: null
      })
    )
    window.dispatchEvent(
      new MessageEvent('message', {
        data: { type: 'hunt-board:open-human-gates', workflowId: 'null-spoof-wf' },
        source: window
      })
    )
    expect(navigateSpy).not.toHaveBeenCalled()
    expect((screen.getAllByLabelText('Workflow ID')[1] as HTMLInputElement).value).toBe('wf-1')

    Reflect.deleteProperty(iframe, 'contentWindow')
    expect(iframe.contentWindow).toBeTruthy()
    window.dispatchEvent(
      new MessageEvent('message', {
        data: { type: 'hunt-board:open-human-gates', workflowId: 'wf-1' },
        source: iframe.contentWindow
      })
    )
    expect(navigateSpy).toHaveBeenCalledWith('/cybersecurity-workspace')

    fireEvent.click(screen.getByRole('button', { name: 'Load gate status' }))

    await waitFor(() => {
      expect(gateStatusSpy).toHaveBeenCalledWith({
        address: '127.0.0.1:58288',
        workflowId: 'wf-1'
      })
      expect(screen.getByText(/dns-tunnel-001 · origin=synthetic/)).toBeTruthy()
    })

    fireEvent.change(screen.getAllByLabelText('Workflow ID')[0], { target: { value: 'wf-2' } })
    fireEvent.change(screen.getByLabelText('Temporal address'), { target: { value: '127.0.0.1:59111' } })
    fireEvent.click(screen.getByRole('button', { name: /Start & attach board/i }))

    await waitFor(() => {
      expect((screen.getByLabelText('Temporal loopback address') as HTMLInputElement).value).toBe('127.0.0.1:59111')
      expect((screen.getAllByLabelText('Workflow ID')[1] as HTMLInputElement).value).toBe('wf-2')
      expect(screen.queryByText(/dns-tunnel-001 · origin=synthetic/)).toBeNull()
    })

    expect(gateStatusSpy).toHaveBeenCalledTimes(1)

    fireEvent.click(screen.getByRole('button', { name: 'Load gate status' }))

    await waitFor(() => {
      expect(gateStatusSpy).toHaveBeenCalledWith({
        address: '127.0.0.1:59111',
        workflowId: 'wf-2'
      })
      expect(screen.getByText(/beaconing-002 · origin=synthetic/)).toBeTruthy()
    })

    vi.spyOn(host.huntWorkbench, 'discoverBoards').mockResolvedValueOnce({
      boards: [
        {
          address: '127.0.0.1:59333',
          caseId: 'lateral-003',
          childWorkflowId: 'wf-attached-round-001',
          liveEnabled: true,
          liveProfiles: ['framework-network-analyst'],
          managed: false,
          mode: 'tool_driven',
          port: 54323,
          url: 'http://127.0.0.1:54323/',
          workflowId: 'wf-attached'
        }
      ],
      ok: true
    })

    fireEvent.change(screen.getAllByLabelText('Workflow ID')[0], { target: { value: 'wf-stale' } })
    fireEvent.click(screen.getByRole('button', { name: 'Attach active board' }))

    await waitFor(() => {
      expect((screen.getAllByLabelText('Workflow ID')[0] as HTMLInputElement).value).toBe('wf-attached')
      expect((screen.getAllByLabelText('Workflow ID')[1] as HTMLInputElement).value).toBe('wf-attached')
      expect((screen.getByLabelText('Temporal loopback address') as HTMLInputElement).value).toBe('127.0.0.1:59333')
    })

    fireEvent.click(screen.getAllByRole('button', { name: 'Human gates' })[0])
    expect((screen.getAllByLabelText('Workflow ID')[1] as HTMLInputElement).value).toBe('wf-attached')
  })

  it('guards HumanGatesPanel against target edits, stale gateStatus responses, and unrecorded or failed refreshes', async () => {
    type GateStatusReply = Awaited<ReturnType<typeof host.huntWorkbench.gateStatus>>
    type GateStatusPayload = NonNullable<GateStatusReply['status']>
    let resolveDeferredWf1!: (value: GateStatusReply) => void

    const makeOpenStatus = (workflowId: string, address: string, caseId: string): GateStatusPayload => ({
      address,
      caseId,
      childWorkflowId: `${workflowId}-round-001`,
      completedRounds: 0,
      currentRound: 1,
      dataOrigin: 'synthetic',
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
      syntheticOnly: true,
      temporalStatus: 'RUNNING',
      unverifiedBotSummary: null,
      workflowId
    })

    const gateStatusSpy = vi
      .spyOn(host.huntWorkbench, 'gateStatus')
      .mockImplementationOnce(
        () =>
          new Promise(resolve => {
            resolveDeferredWf1 = resolve
          })
      )
      .mockResolvedValueOnce({
        ok: true,
        status: makeOpenStatus('wf-2', '127.0.0.1:17233', 'active-case-2')
      })
      .mockResolvedValueOnce({
        ok: true,
        status: makeOpenStatus('wf-3', '127.0.0.1:27233', 'active-case-3')
      })
      .mockResolvedValueOnce({
        ok: true,
        status: {
          ...makeOpenStatus('wf-3', '127.0.0.1:27233', 'active-case-3'),
          decisions: [],
          openGate: null,
          stage: 'completed',
          temporalStatus: 'COMPLETED'
        }
      })
      .mockResolvedValueOnce({
        ok: true,
        status: makeOpenStatus('wf-3', '127.0.0.1:27233', 'active-case-3')
      })
      .mockResolvedValueOnce({
        error: 'Temporal unavailable',
        ok: false
      })

    const decideGateSpy = vi
      .spyOn(host.huntWorkbench, 'decideGate')
      .mockResolvedValueOnce({
        decidedAtUtc: '2026-11-14T06:00:00Z',
        decidedBy: 'Alice Analyst',
        decisionId: 'dec-unrecorded-1',
        ok: true,
        via: 'cli',
        workflowId: 'wf-3-round-001'
      })
      .mockResolvedValueOnce({
        decidedAtUtc: '2026-11-14T06:01:00Z',
        decidedBy: 'Alice Analyst',
        decisionId: 'dec-refresh-fail-2',
        ok: true,
        via: 'cli',
        workflowId: 'wf-3-round-001'
      })

    const { registry } = await discover(huntModules)

    const routeEntries = registry.getArea('routes') as unknown as ReadonlyArray<{
      data: { path: string }
      render?: () => ReactNode
    }>

    const workspacePage = routeEntries.find(item => item.data.path === '/cybersecurity-workspace')
    render(createElement('div', null, workspacePage?.render?.()))

    fireEvent.change(screen.getByLabelText('Workflow ID'), { target: { value: 'wf-1' } })
    fireEvent.click(screen.getByRole('button', { name: 'Load gate status' }))
    expect(gateStatusSpy).toHaveBeenCalledTimes(1)

    act(() => {
      ;(globalThis as Record<string, unknown>).__HUNT_COMMAND_HANDOFF__ = {
        address: '127.0.0.1:17233',
        seq: 77,
        workflowId: 'wf-2'
      }
      ;((globalThis as Record<string, unknown>).__HUNT_COMMAND_ON_HANDOFF__ as (() => void) | undefined)?.()
    })

    await waitFor(() => {
      expect((screen.getByLabelText('Workflow ID') as HTMLInputElement).value).toBe('wf-2')
      expect((screen.getByLabelText('Temporal loopback address') as HTMLInputElement).value).toBe('127.0.0.1:17233')
    })

    await act(async () => {
      resolveDeferredWf1({
        ok: true,
        status: makeOpenStatus('wf-1', '127.0.0.1:7233', 'stale-case-1')
      })
      await Promise.resolve()
    })
    expect(screen.queryByText(/stale-case-1/)).toBeNull()
    expect(screen.queryByRole('button', { name: 'Approve gate' })).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: 'Load gate status' }))

    await waitFor(() => {
      expect(screen.getByText(/active-case-2 · origin=synthetic/)).toBeTruthy()
      expect(screen.getByRole('button', { name: 'Approve gate' })).toBeTruthy()
    })

    fireEvent.change(screen.getByLabelText('Temporal loopback address'), { target: { value: '127.0.0.1:27233' } })
    expect(screen.queryByRole('button', { name: 'Approve gate' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Load gate status' })).toBeTruthy()

    fireEvent.change(screen.getByLabelText('Workflow ID'), { target: { value: 'wf-3' } })
    fireEvent.click(screen.getByRole('button', { name: 'Load gate status' }))

    await waitFor(() => {
      expect(screen.getByText(/active-case-3 · origin=synthetic/)).toBeTruthy()
      expect(screen.getByRole('button', { name: 'Approve gate' })).toBeTruthy()
    })

    fireEvent.change(screen.getByLabelText('Operator name'), { target: { value: 'Alice Analyst' } })
    fireEvent.change(screen.getByLabelText('What did you check?'), { target: { value: 'Verified scope boundaries' } })
    fireEvent.click(screen.getByRole('button', { name: 'Approve gate' }))

    await waitFor(() => {
      expect(decideGateSpy).toHaveBeenCalledWith({
        address: '127.0.0.1:27233',
        checkNote: 'Verified scope boundaries',
        childWorkflowId: 'wf-3-round-001',
        choice: 'approve',
        operatorName: 'Alice Analyst',
        phase: 'review',
        stepId: 'wave-1'
      })
      expect(
        screen.getByText(
          /Decision signal sent \(dec-unrecorded-1\), but dec-unrecorded-1 was not recorded in workflow state\./
        )
      ).toBeTruthy()
    })

    expect(screen.queryByText(/^Recorded /)).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: 'Refresh gate status' }))

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Approve gate' })).toBeTruthy()
    })

    fireEvent.click(screen.getByRole('button', { name: 'Approve gate' }))

    await waitFor(() => {
      expect(screen.getByText(/workflow refresh failed\. Click Load gate status before deciding again\./)).toBeTruthy()
    })

    expect(screen.queryByRole('button', { name: 'Approve gate' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Load gate status' })).toBeTruthy()
  })
})
