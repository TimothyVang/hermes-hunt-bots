import { type ThreadMessage } from '@assistant-ui/react'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { registry } from '@/contrib/registry'
import { TOOL_CARD_AREA, type ToolCardContribution, type ToolCardProps } from '@/lib/tool-card-renderers'

import { stubThreadEnvironment, stubThreadViewportSize, ThreadRuntime } from '../test-utils'
import { Thread } from '../thread'

stubThreadEnvironment()
stubThreadViewportSize()

const createdAt = new Date('2026-11-08T12:00:00Z')
const ARGS = { action: 'open', case_id: 'case-1', page: 'kibana_discover', q: 'host.name:ws01' }
const RESULT = { ok: true, profile: 'framework-researcher', result: { action: 'open', title: 'Discover' } }

function labBrowserTurn(result?: unknown): ThreadMessage {
  return {
    id: 'assistant-lab',
    role: 'assistant',
    content: [
      {
        type: 'tool-call',
        toolCallId: 'lab-1',
        toolName: 'lab_browser',
        args: ARGS,
        argsText: JSON.stringify(ARGS),
        ...(result === undefined ? {} : { result })
      }
    ],
    status: result === undefined ? { type: 'running' } : { type: 'complete', reason: 'stop' },
    createdAt,
    metadata: { unstable_state: null, unstable_annotations: [], unstable_data: [], steps: [], custom: {} }
  } as unknown as ThreadMessage
}

const seen: ToolCardProps[] = []

function claim(cardRender?: ToolCardContribution['render']) {
  return registry.register({
    id: 'hunt-lab:lab-browser-card',
    area: TOOL_CARD_AREA,
    source: 'plugin:hunt-lab',
    data: {
      tool: 'lab_browser',
      render:
        cardRender ??
        (props => {
          seen.push(props)

          return <div data-testid="lab-card">{props.status}</div>
        })
    } satisfies ToolCardContribution
  })
}

const Harness = ({ message }: { message: ThreadMessage }) => (
  <ThreadRuntime messages={[message]}>
    <Thread />
  </ThreadRuntime>
)

describe('plugin tool cards', () => {
  const disposers: (() => void)[] = []

  afterEach(() => {
    disposers.splice(0).forEach(dispose => dispose())
    cleanup()
    seen.length = 0
    vi.restoreAllMocks()
  })

  it('draws the claiming plugin card in place of the generic row, with the decoded result', async () => {
    disposers.push(claim())
    const { container } = render(<Harness message={labBrowserTurn(JSON.stringify(RESULT))} />)

    expect((await screen.findByTestId('lab-card')).textContent).toBe('complete')
    expect(container.querySelector('[data-tool-row]')).toBeNull()

    expect(seen.at(-1)).toMatchObject({
      args: ARGS,
      result: RESULT,
      status: 'complete',
      toolCallId: 'lab-1',
      toolName: 'lab_browser'
    })
    expect(typeof seen.at(-1)!.resolveImageUrl).toBe('function')
    expect(seen.at(-1)!.fallback).toBeTruthy()
  })

  it('passes running while the call has no result, and error when it reported failure', async () => {
    disposers.push(claim())
    const { unmount } = render(<Harness message={labBrowserTurn()} />)

    expect((await screen.findByTestId('lab-card')).textContent).toBe('running')
    unmount()

    render(<Harness message={labBrowserTurn({ ok: false, profile: 'framework-researcher', error: 'stale_ref' })} />)
    expect((await screen.findByTestId('lab-card')).textContent).toBe('error')
  })

  it('falls back to the generic row when the plugin card throws', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    disposers.push(
      claim(() => {
        throw new Error('card broke')
      })
    )
    const { container } = render(<Harness message={labBrowserTurn(RESULT)} />)

    await waitFor(() => expect(container.querySelector('[data-tool-row]')).not.toBeNull())
    expect(screen.queryByTestId('lab-card')).toBeNull()
  })

  it('renders the generic row when no plugin claims the tool', async () => {
    const { container } = render(<Harness message={labBrowserTurn(RESULT)} />)

    await waitFor(() => expect(container.querySelector('[data-tool-row]')).not.toBeNull())
    expect(screen.queryByTestId('lab-card')).toBeNull()
  })
})
