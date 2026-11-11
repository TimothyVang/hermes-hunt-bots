import type { HermesPlugin } from './plugin'

// Hunt Command (HERMES_DESKTOP_VARIANT=hunt) bundles this fork's two Desktop plugins from their
// one source under framework/; both declare defaultEnabled: true. scripts/build/desktop.mjs
// hashes the same two files into the renderer's freshness receipt.
export const variantPluginModules = import.meta.glob<{ default: HermesPlugin }>(
  ['../../../../framework/hunt_lab/desktop/plugin.js', '../../../../framework/desktop/cybersecurity-workspace/plugin.js'],
  { eager: true }
)
