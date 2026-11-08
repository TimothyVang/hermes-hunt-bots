import type { ToolCallMessagePartProps } from '@assistant-ui/react'
import { useStore } from '@nanostores/react'
import { type FC, useCallback, useMemo } from 'react'

import { useComposerScope } from '@/app/chat/composer/scope'
import { useSessionView } from '@/app/chat/session-view'
import { TimelineTimestamp } from '@/components/assistant-ui/thread/timeline-timestamp'
import { useMediaOwner } from '@/components/assistant-ui/tool-media-slot'
import { ToolFallback } from '@/components/assistant-ui/tool/fallback'
import { toolCallFailed } from '@/components/assistant-ui/tool/fallback-model'
import { ErrorBoundary } from '@/components/error-boundary'
import type { Contribution } from '@/contrib/types'
import { resolveMediaDisplaySrc } from '@/lib/media'
import {
  $toolCardOwners,
  type ToolCardContribution,
  type ToolCardProps,
  type ToolCardStatus
} from '@/lib/tool-card-renderers'
import { $sessions, knownSessionOwner } from '@/store/session'

type PluginToolCardPartProps = ToolCallMessagePartProps & { completedAt?: number; timestamp?: number }

/** The plugin contribution that owns `toolName`'s card, or null. */
export function useToolCardOwner(toolName: string): Contribution | null {
  return useStore($toolCardOwners).get(toolName) ?? null
}

/** The Hermes profile that runs `sessionId`: a Bot tile's own profile, else the
 *  session's known owner (its row or open-time route; a route's target profile
 *  is the backend's own name). Null when the window cannot say. */
function useOwnerProfile(sessionId: null | string, scopeProfile: null | string | undefined): null | string {
  const sessions = useStore($sessions)

  return useMemo(() => {
    if (scopeProfile) {
      return scopeProfile
    }

    const owner = knownSessionOwner(sessions, sessionId)

    return typeof owner === 'string' ? owner : owner?.targetProfile || owner?.profile || null
  }, [scopeProfile, sessionId, sessions])
}

function decodedResult(result: unknown): unknown {
  if (typeof result !== 'string') {
    return result
  }

  try {
    return JSON.parse(result)
  } catch {
    return result
  }
}

/**
 * A plugin's card for one tool call. A render that throws (or draws nothing)
 * leaves the generic row in its place; the boundary is keyed by status so a
 * card that failed while running gets a fresh try once the result lands.
 */
export const PluginToolCard: FC<PluginToolCardPartProps & { contribution: Contribution }> = ({
  contribution,
  ...part
}) => {
  const status: ToolCardStatus =
    part.result === undefined ? 'running' : toolCallFailed(part) ? 'error' : 'complete'

  const fallback = <ToolFallback {...part} />

  return (
    <ErrorBoundary fallback={() => fallback} key={status} label={`contrib:${contribution.id}`}>
      <PluginToolCardLeaf contribution={contribution} fallback={fallback} part={part} status={status} />
    </ErrorBoundary>
  )
}

const PluginToolCardLeaf: FC<{
  contribution: Contribution
  fallback: ToolCardProps['fallback']
  part: PluginToolCardPartProps
  status: ToolCardStatus
}> = ({ contribution, fallback, part, status }) => {
  const render = (contribution.data as ToolCardContribution).render
  const view = useSessionView()
  const storedId = useStore(view.$storedId)
  const runtimeId = useStore(view.$runtimeId)
  const scope = useComposerScope()
  const profile = useOwnerProfile(storedId || null, scope.profile)
  const mediaOwner = useMediaOwner()

  // Read from the backend that owns this chat, like the generic row's thumbnail.
  const resolveImageUrl = useCallback((path: string) => resolveMediaDisplaySrc(path, mediaOwner), [mediaOwner])

  const args = useMemo(
    () => (part.args && typeof part.args === 'object' ? (part.args as Record<string, unknown>) : {}),
    [part.args]
  )

  const result = useMemo(() => decodedResult(part.result), [part.result])

  // Stable component identity per renderer, so a re-render never remounts the card.
  // Nothing drawn (null/undefined) keeps the generic row.
  const Card = useMemo(
    () =>
      function ToolCardRendererHost(props: ToolCardProps) {
        return <>{render(props) ?? props.fallback}</>
      },
    [render]
  )

  return (
    <>
      <TimelineTimestamp className="mb-0.5 block" completedAt={part.completedAt} timestamp={part.timestamp} />
      <Card
        args={args}
        fallback={fallback}
        profile={profile}
        resolveImageUrl={resolveImageUrl}
        result={result}
        sessionId={storedId || runtimeId || null}
        status={status}
        toolCallId={part.toolCallId}
        toolName={part.toolName}
      />
    </>
  )
}
