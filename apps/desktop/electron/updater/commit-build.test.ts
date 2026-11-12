import { describe, expect, it } from 'vitest'

import type { InstallStamp } from '../install-stamp'

import { ExternalStrategy } from './external'

import { resolveUpdaterMechanism, type UpdaterStrategy } from './index'

const message: string = "This build doesn't get updates. Ask the developer who gave it to you for a new build."

describe('one-commit artifacts', (): void => {
  it.each(['win32', 'darwin', 'linux'] as const)(
    'cannot select an active updater on %s',
    (platform: NodeJS.Platform): void => {
      for (const updateMechanism of [
        'self',
        'app-installer',
        'electron-updater',
        'microsoft-store',
        'external'
      ] as const) {
        expect(resolveUpdaterMechanism({ platform, updateMechanism, source: 'commit-build' })).toBe('external')
      }
    }
  )

  it('refuses both checks and apply with no manual-update escape', async (): Promise<void> => {
    const stamp: InstallStamp = { source: 'commit-build' } as InstallStamp
    const strategy: UpdaterStrategy = new ExternalStrategy(stamp)
    expect(await strategy.check({ force: true })).toMatchObject({
      supported: false,
      mechanism: 'external',
      reason: 'commit-build',
      message
    })
    expect(await strategy.apply()).toMatchObject({
      ok: false,
      mechanism: 'external',
      error: 'commit-build',
      message
    })
    expect(await strategy.apply()).not.toHaveProperty('command')
  })
})

describe('Hunt Command artifacts', (): void => {
  const hunt: string = 'Hunt Command updates by rebuilding: pull the repo and run npm run pack:hunt.'

  it('say how to update by rebuilding instead of naming a package owner', async (): Promise<void> => {
    const strategy: UpdaterStrategy = new ExternalStrategy({ source: 'local', variant: 'hunt' } as InstallStamp)
    expect(await strategy.check({ force: true })).toMatchObject({ supported: false, reason: 'hunt-build', message: hunt })
    expect(await strategy.apply()).toMatchObject({ ok: false, error: 'hunt-build', message: hunt })
  })

  it('leave the stock external copy alone', async (): Promise<void> => {
    const strategy: UpdaterStrategy = new ExternalStrategy({ source: 'ci' } as InstallStamp)
    expect(await strategy.check({ force: true })).toMatchObject({
      reason: 'bundled-not-appinstaller',
      message: 'Updates are managed by the package owner outside this app.'
    })
    expect(await strategy.apply()).toMatchObject({ ok: true, manual: true })
  })
})
