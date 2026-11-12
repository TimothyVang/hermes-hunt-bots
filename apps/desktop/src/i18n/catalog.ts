import { IS_HUNT_VARIANT } from '@/variant'

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

const BUNDLED: Record<BundledLocale, Translations> = {
  en,
  zh,
  'zh-hant': zhHant,
  ja,
  ar,
  ru,
  fr,
  de,
  es
}

/** The catalogs compiled into the app. Runtime-registered languages (plugin
 *  packs, backend `.desktop.yaml` packs) are NOT here — resolve through
 *  `resolveTranslations()` in `./registry`, which layers them over these.
 *  The Hunt Command build names itself where they name the desktop app. */
export const TRANSLATIONS: Record<BundledLocale, Translations> = IS_HUNT_VARIANT ? huntTranslations(BUNDLED) : BUNDLED

export const BUNDLED_LOCALES = Object.keys(TRANSLATIONS) as readonly BundledLocale[]

export function isBundledLocale(value: unknown): value is BundledLocale {
  return typeof value === 'string' && Object.hasOwn(TRANSLATIONS, value)
}
