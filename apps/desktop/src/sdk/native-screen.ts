import type { PluginProfileRoute } from './profile-request'

export type NativeScreenOpenResult =
  | { status: 'opened' }
  | {
      status:
        | 'action_failed'
        | 'connection_missing'
        | 'plugin_disabled'
        | 'provider_unavailable'
        | 'route_ambiguous'
        | 'route_not_registered'
        | 'unsupported_version'
    }

export type NativeScreenConnectionKind = 'cloud' | 'local' | 'remote' | 'ssh'

export type NativeScreenProvider = (
  route: PluginProfileRoute,
  connectionKind: NativeScreenConnectionKind
) => NativeScreenOpenResult

let provider: NativeScreenProvider | null = null
let providerWasRegistered = false

/** Internal bundled-plugin seam. Registration lifetime follows plugin disable/unload. */
export function registerNativeScreenProvider(next: NativeScreenProvider): () => void {
  if (provider) {
    throw new Error('A native screen provider is already registered')
  }

  provider = next
  providerWasRegistered = true
  return () => {
    if (provider === next) {
      provider = null
    }
  }
}

export function openNativeScreen(
  route: PluginProfileRoute,
  connectionKind: NativeScreenConnectionKind
): NativeScreenOpenResult {
  if (!provider) {
    return { status: providerWasRegistered ? 'plugin_disabled' : 'provider_unavailable' }
  }

  try {
    const result = provider({ ...route }, connectionKind)

    switch (result?.status) {
      case 'opened':
      case 'action_failed':
      case 'connection_missing':
      case 'plugin_disabled':
      case 'provider_unavailable':
      case 'route_ambiguous':
      case 'route_not_registered':
      case 'unsupported_version':
        return { status: result.status }
      default:
        return { status: 'action_failed' }
    }
  } catch {
    return { status: 'action_failed' }
  }
}
