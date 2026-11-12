// Hermes builds ship no fork plugins; see fork-plugins.ts.
import type { HermesPlugin } from './contrib/plugin'

const forkPlugins: Record<string, { default: HermesPlugin }> = {}

export default forkPlugins
