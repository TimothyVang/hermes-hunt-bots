import { describe, expect, it, vi } from 'vitest'

import { openNativeScreen, registerNativeScreenProvider } from './native-screen'

const route = {
  connectionId: 'guest-a',
  mode: 'remote' as const,
  profile: 'framework-coordinator',
  targetProfile: 'framework-coordinator'
}

describe('native screen provider lifecycle', () => {
  it('registers and disposes the bundled provider', () => {
    const provider = vi.fn(() => ({ status: 'opened' as const }))
    const dispose = registerNativeScreenProvider(provider)

    expect(openNativeScreen(route, 'cloud')).toEqual({ status: 'opened' })
    expect(provider).toHaveBeenCalledWith(route, 'cloud')
    dispose()
    expect(openNativeScreen(route, 'remote')).toEqual({ status: 'plugin_disabled' })
  })

  it('returns a fixed failure when the provider action throws', () => {
    const dispose = registerNativeScreenProvider(() => {
      throw new Error('private native error')
    })

    expect(openNativeScreen(route, 'ssh')).toEqual({ status: 'action_failed' })
    dispose()
  })
})
