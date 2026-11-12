import type { HermesPlugin } from './plugin'

/** Plugins a build variant bundles beside `src/plugins`, keyed like `import.meta.glob`. Stock
 *  Hermes bundles none; vite.config.ts aliases this module to `variant-plugins.hunt.ts` for
 *  HERMES_DESKTOP_VARIANT=hunt. */
export const variantPluginModules: Record<string, { default: HermesPlugin }> = {}
