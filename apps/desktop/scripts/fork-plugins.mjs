// The renderer module behind the '@/fork-plugins' alias: the hunt-bots fork's own
// plugins for its variant's build, an empty set for every Hermes build.
import path from 'node:path'

/** @param {string} desktopDir @param {Record<string, string | undefined>} env */
export function forkPluginsEntry(desktopDir, env) {
  return path.resolve(desktopDir, env.HERMES_DESKTOP_VARIANT === 'hunt-bots' ? 'src/fork-plugins.ts' : 'src/fork-plugins.none.ts')
}
