import { PRODUCT_NAME } from '@/variant'

import type { BundledLocale, Translations } from './types'

// The Hunt Command build (IS_HUNT_VARIANT) renames the desktop app, not the Hermes agent it runs.
// A string naming the app ("Hermes Desktop", "the Hermes app" and each bundled language's forms of
// them) says PRODUCT_NAME; "Hermes" as the agent, its backend or CLI stays, and so does Nous where it
// names a service the app still talks to (Portal sign-in, the plugin catalog, diagnostics uploads).
// Applied in order; each keeps the language's own word for "app" and drops only Hermes (and "Desktop").
const APP_NAME_RULES: readonly [RegExp, (name: string) => string][] = [
  // German compounds: Hermes-App, Hermes-Desktop-App.
  [/\bHermes-(?:Desktop-)?(?=App\b)/g, name => `${name.replace(/ /g, '-')}-`],
  // English: the Hermes app, the Hermes desktop app.
  [/\bHermes(?: [Dd]esktop)?(?= app\b)/g, name => name],
  // Hermes Desktop (every language), Hermes desktop (ar, ru), Hermes-Desktop (de).
  [/\bHermes[ -][Dd]esktop\b/g, name => name],
  // Chinese and Japanese desktop editions: Hermes 桌面版 / 桌面端 / デスクトップ(版), spaced from CJK text after it.
  [/Hermes ?(?:桌面版|桌面端|デスクトップ版?(?!アプリ))(?=[\p{sc=Han}\p{sc=Hiragana}\p{sc=Katakana}])/gu, name => `${name} `],
  [/Hermes ?(?:桌面版|桌面端|デスクトップ版?(?!アプリ))/g, name => name],
  // Chinese and Japanese "app" after the name: Hermes 应用, Hermes 桌面應用程式, Hermes デスクトップアプリ.
  [/Hermes(?= ?(?:桌面|デスクトップ)?(?:应用|應用|アプリ))/g, name => name],
  // "app" before the name: application (de bureau) Hermes, aplicación (de escritorio) de Hermes,
  // приложение / приложении Hermes (every case), تطبيق Hermes.
  [/(?<=(?:\b[Aa]pplication|\b[Aa]plicación|\b[Aa]pp)(?: de bureau| de escritorio)?(?: de)? |приложени\p{L}* |تطبيق )Hermes\b/gu, name => name]
]

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
  const named = APP_NAME_RULES.reduce((out, [pattern, to]) => out.replace(pattern, to(PRODUCT_NAME)), text)

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
