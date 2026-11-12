import { describe, expect, it, vi } from 'vitest'

import { de } from './de'
import { en } from './en'
import { huntTranslations } from './hunt-catalog'
import type { BundledLocale, Translations } from './types'

// hunt-catalog reads PRODUCT_NAME at call time; tests run without the build's variant define.
vi.mock('@/variant', () => ({ DESKTOP_VARIANT: 'hunt', IS_HUNT_VARIANT: true, PRODUCT_NAME: 'Hunt Command' }))

const { en: hunt, de: huntDe } = huntTranslations({ en, de } as Record<BundledLocale, Translations>)

describe('the Hunt Command catalogs', () => {
  it('name the desktop app Hunt Command', () => {
    expect(hunt.settings.searchPlaceholder.about).toBe('About Hunt Command')
    expect(hunt.boot.ready).toBe('Hunt Command is ready')
    expect(hunt.shell.statusbar.desktopVersion('1.2.3')).toBe('Hunt Command v1.2.3')
    expect(hunt.install.setupChoiceTitle).toBe('Set up Hunt Command')
    expect(hunt.notifications.desktopOutOfDateTitle).toBe('Hunt Command app out of date')
    expect(hunt.settings.config.minimizeToTrayDesc).toContain('Use Quit Hunt Command from the tray menu')
    expect(hunt.settings.config.minimizeToTrayDesc).not.toContain('Hermes')
    expect(hunt.settings.appearance.pet.restartHint).toContain('Quit and reopen Hunt Command')
    expect(hunt.settings.notifications.testTitle).toBe('Hunt Command')
  })

  it('say the build came from pack:hunt, not `hermes desktop`, in every locale', () => {
    expect(hunt.updates.versionDetailsDistributionSourceDesktop).toBe('Source + pack:hunt')
    expect(hunt.updates.versionDetailsDistributionSourceInstallerDesktop).toBe('Source (install script) + pack:hunt')
    expect(huntDe.updates.versionDetailsDistributionSourceDesktop).toBe('Quellcode + pack:hunt')
  })

  it('keep Hermes where it names the agent, and Nous where it names a Nous service', () => {
    expect(hunt.notifications.native.turnDoneTitle).toBe(en.notifications.native.turnDoneTitle)
    expect(hunt.notifications.native.turnDoneTitle).toContain('Hermes')
    expect(hunt.sendDiagnostics.title).toBe(en.sendDiagnostics.title)
    expect(hunt.updates.versionDetailsDistributionStore).toBe('Microsoft Store')
  })
})
