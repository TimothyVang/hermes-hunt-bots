// The build variant (HERMES_DESKTOP_VARIANT) as vite.config.ts baked it. '' is stock Hermes;
// 'hunt' is this fork's Hunt Command build (HUNT-BOTS.md). Runners without the define see ''.
declare const __HERMES_DESKTOP_VARIANT__: string | undefined

export const DESKTOP_VARIANT: string =
  typeof __HERMES_DESKTOP_VARIANT__ === 'string' ? __HERMES_DESKTOP_VARIANT__ : ''

export const IS_HUNT_VARIANT: boolean = DESKTOP_VARIANT === 'hunt'

/** The product name the renderer shows where stock Hermes says "Hermes" (document titles). */
export const PRODUCT_NAME: string = IS_HUNT_VARIANT ? 'Hunt Command' : 'Hermes'

/** The GitHub repository this build's source lives in (product-identity.cjs `sourceRepo` for Hunt Command). */
export const SOURCE_REPO: string = IS_HUNT_VARIANT ? 'TimothyVang/hermes-hunt-bots' : 'NousResearch/hermes-agent'
