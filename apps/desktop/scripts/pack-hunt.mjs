// Hunt Command build (HERMES_DESKTOP_VARIANT=hunt; BUILDING.md "Hunt Command variant").
// The --icons hook copies the variant's icons over the committed assets/, which
// electron-builder packages. Restore them afterwards, even when the build fails,
// so a later stock build in the same checkout never ships Hunt Command icons.
// Arguments after the script name go to electron-builder (pack:hunt adds --dir).
import { execFileSync } from 'node:child_process'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const app = join(fileURLToPath(new URL('.', import.meta.url)), '..')
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm'
const env = { ...process.env, HERMES_DESKTOP_VARIANT: 'hunt' }
const run = (cmd, args) => execFileSync(cmd, args, { cwd: app, env, stdio: 'inherit', shell: cmd === npm })
const git = (...args) => execFileSync('git', ['-C', app, ...args], { encoding: 'utf8' })

// Restoring with checkout would also drop someone's own edits to assets/.
if (git('status', '--porcelain', '--', 'assets').trim()) {
  console.error('pack-hunt: apps/desktop/assets has uncommitted changes; commit or restore them first.')
  process.exit(1)
}

try {
  run(npm, ['run', 'build', '--', '--icons', '../../variants/hunt/icons'])
  run(npm, ['run', 'builder', '--', ...process.argv.slice(2)])
} finally {
  git('checkout', '--', 'assets')
}
