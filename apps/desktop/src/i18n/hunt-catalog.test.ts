import { describe, expect, it, vi } from 'vitest'

import { ar } from './ar'
import { de } from './de'
import { en } from './en'
import { es } from './es'
import { fr } from './fr'
import { huntTranslations } from './hunt-catalog'
import { ja } from './ja'
import { ru } from './ru'
import type { BundledLocale, Translations } from './types'
import { zh } from './zh'
import { zhHant } from './zh-hant'

// hunt-catalog reads PRODUCT_NAME at call time; tests run without the build's variant define.
vi.mock('@/variant', () => ({ DESKTOP_VARIANT: 'hunt', IS_HUNT_VARIANT: true, PRODUCT_NAME: 'Hunt Command' }))

const stock: Record<BundledLocale, Translations> = { en, zh, 'zh-hant': zhHant, ja, ar, ru, fr, de, es }
const huntCatalogs = huntTranslations(stock)
const hunt = huntCatalogs.en

// Every way a bundled catalog names the desktop app Hermes: Hermes Desktop/desktop/-Desktop, the
// Hermes (desktop) app, Hermes-App, (l')application (de bureau) Hermes, aplicación/app (de escritorio)
// de Hermes, приложение/приложении… Hermes, تطبيق Hermes, Hermes 桌面版/桌面端/应用/應用程式/アプリ/デスクトップ.
const APP_NAMED_HERMES =
  /\bHermes[- ][Dd]esktop|\bHermes(?: [Dd]esktop)? app\b|\bHermes-App\b|(?:[Aa]pplication|[Aa]plicación|\b[Aa]pp)(?: de bureau| de escritorio)?(?: de)? Hermes\b|приложени\p{L}* Hermes|تطبيق Hermes|Hermes ?(?:桌面|应用|應用|アプリ|デスクトップ)/u

/** Every string a catalog renders, formatters called with placeholder arguments. */
function strings(value: unknown, key: string, out: [string, string][] = []): [string, string][] {
  if (typeof value === 'string') {
    out.push([key, value])
  } else if (typeof value === 'function') {
    try {
      strings(value('X', 'Y', 'Z'), key, out)
    } catch {
      // A formatter that needs structured arguments renders no plain string here.
    }
  } else if (value && typeof value === 'object') {
    for (const [name, child] of Object.entries(value)) {
      strings(child, `${key}.${name}`, out)
    }
  }

  return out
}

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

  it('name it Hunt Command in each language’s own forms', () => {
    expect(huntCatalogs.de.notifications.desktopOutOfDateTitle).toBe('Hunt-Command-App veraltet')
    expect(huntCatalogs.fr.notifications.desktopOutOfDateTitle).toBe('Application Hunt Command obsolète')
    expect(huntCatalogs.es.notifications.desktopOutOfDateTitle).toBe('Aplicación de Hunt Command desactualizada')
    expect(huntCatalogs.ja.notifications.desktopOutOfDateMessage).toMatch(/^この Hunt Command アプリは/)
    expect(huntCatalogs.ru.notifications.desktopOutOfDateMessage).toMatch(/^Это приложение Hunt Command /)
    expect(huntCatalogs.zh.notifications.desktopOutOfDateMessage).toMatch(/^此 Hunt Command 应用/)
    expect(huntCatalogs.zh.boot.ready).toBe('Hunt Command 已就绪')
    expect(huntCatalogs['zh-hant'].notifications.desktopOutOfDateMessage).toMatch(/^此 Hunt Command 應用程式/)
    expect(huntCatalogs.ar.notifications.desktopOutOfDateMessage).toMatch(/^تطبيق Hunt Command /)
  })

  it.each(Object.keys(stock) as BundledLocale[])('%s: no string still names the desktop app Hermes', locale => {
    const offenders = strings(huntCatalogs[locale], locale).filter(([, text]) => APP_NAMED_HERMES.test(text))

    expect(offenders).toEqual([])
  })

  it('say the build came from pack:hunt, not `hermes desktop`, in every locale', () => {
    expect(hunt.updates.versionDetailsDistributionSourceDesktop).toBe('Source + pack:hunt')
    expect(hunt.updates.versionDetailsDistributionSourceInstallerDesktop).toBe('Source (install script) + pack:hunt')
    expect(huntCatalogs.de.updates.versionDetailsDistributionSourceDesktop).toBe('Quellcode + pack:hunt')
  })

  it('keep Hermes where it names the agent, its backend or runtime, and Nous where it names a Nous service', () => {
    expect(hunt.notifications.native.turnDoneTitle).toBe(en.notifications.native.turnDoneTitle)
    expect(hunt.notifications.native.turnDoneTitle).toContain('Hermes')
    expect(hunt.sendDiagnostics.title).toBe(en.sendDiagnostics.title)
    expect(hunt.updates.versionDetailsDistributionStore).toBe('Microsoft Store')

    for (const locale of Object.keys(stock) as BundledLocale[]) {
      const catalog = huntCatalogs[locale]
      // The backend, the agent and its runtime keep their name in every language.
      expect(catalog.notifications.backendOutOfDateMessage, locale).toBe(stock[locale].notifications.backendOutOfDateMessage)
      expect(catalog.notifications.backendOutOfDateMessage, locale).toContain('Hermes')
    }
  })
})
