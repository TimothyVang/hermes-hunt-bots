// The Hunt Bots fork's own pages. vite.config.ts aliases '@/fork-plugins' to this
// module only for HERMES_DESKTOP_VARIANT=hunt-bots builds; every Hermes build gets
// fork-plugins.none.ts, so it ships none of this code.
import type { HermesPlugin } from './contrib/plugin'

const forkPlugins: Record<string, { default: HermesPlugin }> = import.meta.glob<{ default: HermesPlugin }>(
  './plugins/hunt-lab/plugin.js',
  { eager: true }
)

export default forkPlugins
