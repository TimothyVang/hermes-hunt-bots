import { host, TOOL_CARD_AREA } from '@hermes/plugin-sdk'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
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
      expect(startBoardSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          address: '127.0.0.1:7233',
          port: 8790,
          workflowId: 'practice-dns-001'
        })
      )
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
})
