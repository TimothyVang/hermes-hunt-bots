import { PRODUCT_NAME } from '@/variant'

import type { BundledLocale, Translations } from './types'

// The Hunt Command build (IS_HUNT_VARIANT) renames the desktop app, not the Hermes agent it runs.
// A string naming the app ("Hermes Desktop", "the Hermes app") says PRODUCT_NAME in every bundled
// locale; "Hermes" as the agent, its backend or CLI stays, and so does Nous where it names a
// service the app still talks to (Portal sign-in, the plugin catalog, diagnostics uploads).
const APP_PHRASE = /\bHermes(?: [Dd]esktop\b|(?= app\b))/g

// Strings where a bare "Hermes" is the app (the tray's Quit menu, relaunching it, its test notification).
const APP_WORD_KEYS = new Set([
  'settings.config.minimizeToTrayDesc',
  'settings.appearance.pet.restartHint',
  'settings.notifications.testTitle'
])

// Stock names a source install that ran `hermes desktop`; Hunt Command is built from its repo instead.
const DISTRIBUTION_KEYS = new Set([
  'updates.versionDetailsDistributionSourceDesktop',
  'updates.versionDetailsDistributionSourceInstallerDesktop'
])

function rename(text: string, key: string): string {
  const named = text.replace(APP_PHRASE, PRODUCT_NAME)

  if (APP_WORD_KEYS.has(key)) {
    return named.replace(/\bHermes\b/g, PRODUCT_NAME)
  }

  return DISTRIBUTION_KEYS.has(key) ? named.replace('hermes desktop', 'pack:hunt') : named
}

function rebrand(value: unknown, key: string): unknown {
  if (typeof value === 'string') {
    return rename(value, key)
  }

  if (typeof value === 'function') {
    // Formatters: rename what they format; anything else they return passes through.
    return (...args: unknown[]) => {
      const out: unknown = value(...args)

      return typeof out === 'string' ? rename(out, key) : out
    }
  }

  if (Array.isArray(value)) {
    return value.map(item => rebrand(item, key))
  }

  if (value && Object.getPrototypeOf(value) === Object.prototype) {
    return Object.fromEntries(
      Object.entries(value).map(([name, child]) => [name, rebrand(child, key ? `${key}.${name}` : name)])
    )
  }

  return value
}

/** The bundled catalogs as the Hunt Command build shows them. */
export function huntTranslations(catalogs: Record<BundledLocale, Translations>): Record<BundledLocale, Translations> {
  return Object.fromEntries(
    Object.entries(catalogs).map(([locale, translations]) => [locale, rebrand(translations, '')])
  ) as Record<BundledLocale, Translations>
}
