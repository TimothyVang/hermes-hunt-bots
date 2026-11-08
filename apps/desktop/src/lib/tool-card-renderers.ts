import { atom } from 'nanostores'
import type { ReactNode } from 'react'

import { registry } from '@/contrib/registry'
import type { Contribution } from '@/contrib/types'
import { $claimedCardTools, isBuiltInCardTool, isSilentTool } from '@/lib/tool-render-class'

/**
 * TOOL CARDS — a plugin draws the transcript card for one tool call.
 *
 * A `transcript.toolCard` contribution names one tool; while it is registered
 * every call of that tool renders the plugin's `render` in place of the
 * generic tool row, live and settled, and the call counts as a card (never
 * folded into a run summary). One owner per tool name: the earliest
 * registration holds it until it unregisters, a later claim on the same name
 * is refused with a console warning, and core's own surfaces (the built-in
 * cards, file-edit diffs, silent tools) can never be claimed.
 */

export const TOOL_CARD_AREA = 'transcript.toolCard'

export type ToolCardStatus = 'complete' | 'error' | 'running'

/** Props handed to a tool card's `render`. */
export interface ToolCardProps {
  toolName: string
  toolCallId: string
  args: Readonly<Record<string, unknown>>
  /** `running` until the result arrives; `error` when the call reported failure. */
  status: ToolCardStatus
  /** The tool's result, JSON-decoded when it is a JSON string; undefined while running. */
  result: unknown
  /** The chat whose transcript renders this (stored id, else runtime id), or null. */
  sessionId: null | string
  /** The profile that owns this chat (a Bot tile's own profile), or null when the
   *  window has no owner for it. */
  profile: null | string
  /** A URL this window can load for a file path on the chat's backend (a data
   *  URL for a local file); http(s) and data URLs pass through unchanged. */
  resolveImageUrl: (path: string) => Promise<string>
  /** The generic tool row for this call: return it for anything you don't draw. */
  fallback: ReactNode
}

/** Payload of a `transcript.toolCard` contribution's `data`. */
export interface ToolCardContribution {
  /** The exact tool name this card draws. */
  tool: string
  /** Mounted inside an error boundary whose fallback is the generic tool row. */
  render: (props: ToolCardProps) => ReactNode
}

function claimedTool(contribution: Contribution): null | string {
  const data = contribution.data as Partial<ToolCardContribution> | undefined

  return typeof data?.tool === 'string' && data.tool !== '' && typeof data.render === 'function' ? data.tool : null
}

/**
 * Fold an area snapshot into tool owners. An owner keeps its tool while the
 * same contribution still claims it; an unowned tool goes to its first claim
 * in the snapshot. Every other claim is reported to `onRefused` with the
 * contribution that holds the name (null: core draws it).
 */
export function resolveToolCardOwners(
  previous: ReadonlyMap<string, Contribution>,
  claims: readonly Contribution[],
  onRefused: (claim: Contribution, tool: string, owner: Contribution | null) => void
): Map<string, Contribution> {
  const live = new Map(claims.map(claim => [claim.id, claim]))
  const owners = new Map<string, Contribution>()

  for (const [tool, owner] of previous) {
    const current = live.get(owner.id)

    if (current && claimedTool(current) === tool) {
      owners.set(tool, current)
    }
  }

  for (const claim of claims) {
    const tool = claimedTool(claim)

    if (tool === null) {
      continue
    }

    if (isBuiltInCardTool(tool) || isSilentTool(tool)) {
      onRefused(claim, tool, null)

      continue
    }

    const owner = owners.get(tool)

    if (!owner) {
      owners.set(tool, claim)
    } else if (owner.id !== claim.id) {
      onRefused(claim, tool, owner)
    }
  }

  return owners
}

/** The contribution that owns each claimed tool name. */
export const $toolCardOwners = atom<ReadonlyMap<string, Contribution>>(new Map())

const warned = new Set<string>()

function warnRefused(claim: Contribution, tool: string, owner: Contribution | null) {
  const key = `${claim.id}\u0000${tool}\u0000${owner?.id ?? ''}`

  if (warned.has(key)) {
    return
  }

  warned.add(key)
  console.warn(
    `[tool-card] refused ${claim.id} (${claim.source ?? 'core'}): "${tool}" is ` +
      (owner ? `already claimed by ${owner.id}` : 'drawn by core')
  )
}

// Follows the area as contributions come and go. Registrations arrive one at a
// time, so the snapshot seen here assigns each tool to its earliest claim
// whatever `order` a later one sets.
function syncToolCardOwners() {
  const previous = $toolCardOwners.get()
  const next = resolveToolCardOwners(previous, registry.getArea(TOOL_CARD_AREA), warnRefused)

  if (next.size === previous.size && [...next].every(([tool, owner]) => previous.get(tool) === owner)) {
    return
  }

  $toolCardOwners.set(next)
  $claimedCardTools.set(new Set(next.keys()))
}

registry.subscribeArea(TOOL_CARD_AREA, syncToolCardOwners)
syncToolCardOwners()
