// updater/external.ts — the steward-owned strategy.
//
// The stamp declares 'external' when the package owner handles updates
// without an in-app check or apply action.

import type { InstallStamp } from '../install-stamp'

import type { UpdaterApplyResultWire, UpdaterStatusWire } from './index'

export const EXTERNAL_UNSUPPORTED_MESSAGE = 'Updates are managed by the package owner outside this app.'

export const COMMIT_BUILD_UPDATE_MESSAGE: string =
  "This build doesn't get updates. Ask the developer who gave it to you for a new build."

// The Hunt Command build (stamp variant 'hunt') is rebuilt from its repo, never updated in place.
export const HUNT_BUILD_UPDATE_MESSAGE: string =
  'Hunt Command updates by rebuilding: pull the repo and run npm run pack:hunt.'

export class ExternalStrategy {
  constructor(private readonly stamp: Pick<InstallStamp, 'source' | 'variant'> | null = null) {}
  readonly mechanism = 'external' as const
  readonly supported = false

  // A self-built artifact (Hunt Command, a one-commit build) has no package owner to name.
  private get selfBuilt(): { reason: string; message: string } | null {
    if (this.stamp?.variant === 'hunt') {
      return { reason: 'hunt-build', message: HUNT_BUILD_UPDATE_MESSAGE }
    }

    return this.stamp?.source === 'commit-build' ? { reason: 'commit-build', message: COMMIT_BUILD_UPDATE_MESSAGE } : null
  }

  async check(): Promise<UpdaterStatusWire> {
    return {
      supported: false,
      mechanism: 'external',
      reason: this.selfBuilt?.reason ?? 'bundled-not-appinstaller',
      message: this.selfBuilt?.message ?? EXTERNAL_UNSUPPORTED_MESSAGE,
      fetchedAt: Date.now()
    }
  }

  async apply(): Promise<UpdaterApplyResultWire> {
    const selfBuilt = this.selfBuilt

    if (selfBuilt) {
      return { ok: false, mechanism: 'external', error: selfBuilt.reason, message: selfBuilt.message }
    }

    return { ok: true, manual: true, bundled: true, mechanism: 'external' }
  }
}
