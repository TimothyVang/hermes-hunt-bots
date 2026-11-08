import { afterEach, describe, expect, it, type MockInstance, vi } from 'vitest'

import { registry } from '@/contrib/registry'
import type { Contribution } from '@/contrib/types'

import { $toolCardOwners, resolveToolCardOwners, TOOL_CARD_AREA, type ToolCardContribution } from './tool-card-renderers'
import { isCardTool } from './tool-render-class'

const render: ToolCardContribution['render'] = () => null

function claim(pluginId: string, tool: string, extra: Partial<Contribution> = {}): Contribution {
  return {
    id: `${pluginId}:card`,
    area: TOOL_CARD_AREA,
    source: `plugin:${pluginId}`,
    data: { tool, render } satisfies ToolCardContribution,
    ...extra
  }
}

describe('resolveToolCardOwners', () => {
  it('gives each tool to its first claim and refuses the rest with the owner named', () => {
    const refused: [string, string, null | string][] = []

    const owners = resolveToolCardOwners(
      new Map(),
      [claim('lab', 'lab_browser'), claim('copycat', 'lab_browser'), claim('other', 'other_tool')],
      (c, tool, owner) => refused.push([c.id, tool, owner?.id ?? null])
    )

    expect([...owners].map(([tool, owner]) => [tool, owner.id])).toEqual([
      ['lab_browser', 'lab:card'],
      ['other_tool', 'other:card']
    ])
    expect(refused).toEqual([['copycat:card', 'lab_browser', 'lab:card']])
  })

  it('never lets a plugin claim a surface core draws', () => {
    const refused: [string, null | string][] = []

    const owners = resolveToolCardOwners(
      new Map(),
      ['clarify', 'image_generate', 'patch', 'manage_connections:card', 'todo', 'react_to_message'].map((tool, i) =>
        claim(`p${i}`, tool)
      ),
      (_c, tool, owner) => refused.push([tool, owner?.id ?? null])
    )

    expect(owners.size).toBe(0)
    expect(refused.map(([tool]) => tool)).toEqual([
      'clarify',
      'image_generate',
      'patch',
      'manage_connections:card',
      'todo',
      'react_to_message'
    ])
    expect(refused.every(([, owner]) => owner === null)).toBe(true)
  })

  it('keeps an existing owner even when a later claim sorts ahead of it', () => {
    const first = claim('lab', 'lab_browser')
    const previous = resolveToolCardOwners(new Map(), [first], () => {})
    const refused: string[] = []
    const owners = resolveToolCardOwners(previous, [claim('jumper', 'lab_browser'), first], c => refused.push(c.id))

    expect(owners.get('lab_browser')?.id).toBe('lab:card')
    expect(refused).toEqual(['jumper:card'])
  })

  it('ignores a contribution without a tool name or render function', () => {
    const malformed = [
      { ...claim('a', 'lab_browser'), data: { tool: 'lab_browser' } },
      { ...claim('b', 'lab_browser'), data: { render } },
      { ...claim('c', ''), data: { tool: '', render } }
    ]

    expect(resolveToolCardOwners(new Map(), malformed, () => {}).size).toBe(0)
  })
})

describe('TOOL_CARD_AREA registry ownership', () => {
  const disposers: (() => void)[] = []
  let warn: MockInstance<typeof console.warn>

  afterEach(() => {
    disposers.splice(0).forEach(dispose => dispose())
    warn?.mockRestore()
  })

  it('claims a tool as a card, refuses and logs a later claim, and hands over when the owner leaves', () => {
    warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    expect(isCardTool('lab_browser')).toBe(false)

    const disposeOwner = registry.register(claim('hunt-lab', 'lab_browser'))
    // A later registration cannot take the name, even with a lower `order`.
    disposers.push(registry.register(claim('copycat', 'lab_browser', { order: -100 })))

    expect($toolCardOwners.get().get('lab_browser')?.id).toBe('hunt-lab:card')
    expect(isCardTool('lab_browser')).toBe(true)
    expect(warn.mock.calls.map(call => String(call[0])).join('\n')).toMatch(
      /refused copycat:card \(plugin:copycat\): "lab_browser" is already claimed by hunt-lab:card/
    )

    disposeOwner()
    expect($toolCardOwners.get().get('lab_browser')?.id).toBe('copycat:card')

    disposers.splice(0).forEach(dispose => dispose())
    expect($toolCardOwners.get().size).toBe(0)
    expect(isCardTool('lab_browser')).toBe(false)
  })

  it('refuses and logs a claim on a built-in card', () => {
    warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    disposers.push(registry.register(claim('thief', 'clarify')))

    expect($toolCardOwners.get().has('clarify')).toBe(false)
    expect(warn.mock.calls.map(call => String(call[0])).join('\n')).toMatch(
      /refused thief:card \(plugin:thief\): "clarify" is drawn by core/
    )
  })
})
