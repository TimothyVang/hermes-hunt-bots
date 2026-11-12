// Hunt Command build (HERMES_DESKTOP_VARIANT=hunt; BUILDING.md "Hunt Command variant").
// The --icons hook copies the variant's icons over the committed assets/, which
// electron-builder packages. Restore them afterwards, even when the build fails,
// so a later stock build in the same checkout never ships Hunt Command icons.
// Arguments after the script name go to electron-builder (pack:hunt adds --dir).
import { execFileSync } from 'node:child_process'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const app = join(fileURLToPath(new URL('.', import.meta.url)), '..')
// Under npm, rerun npm's own CLI with this Node and no shell (a shell with args is Node 26's
// DEP0190). Run directly without npm, fall back to the npm launcher, which on Windows needs one.
const npmCli = process.env.npm_execpath
const npm = npmCli
  ? { cmd: process.execPath, args: [npmCli], shell: false }
  : { cmd: process.platform === 'win32' ? 'npm.cmd' : 'npm', args: [], shell: true }
const env = { ...process.env, HERMES_DESKTOP_VARIANT: 'hunt' }
const runNpm = args => execFileSync(npm.cmd, [...npm.args, ...args], { cwd: app, env, stdio: 'inherit', shell: npm.shell })
const git = (...args) => execFileSync('git', ['-C', app, ...args], { encoding: 'utf8' })

// Restoring with checkout would also drop someone's own edits to assets/.
if (git('status', '--porcelain', '--', 'assets').trim()) {
  console.error('pack-hunt: apps/desktop/assets has uncommitted changes; commit or restore them first.')
  process.exit(1)
}

// dist:hunt makes copies for others; their SOURCE.txt must name source they can get (AGPL-3.0 section 6).
if (!process.argv.includes('--dir')) {
  if (git('status', '--porcelain', '--untracked-files=no').trim()) {
    console.error('pack-hunt: dist:hunt needs a clean tree; commit your changes first.')
    process.exit(1)
  }
  if (!git('branch', '-r', '--contains', 'HEAD').trim()) {
    console.error('pack-hunt: dist:hunt needs HEAD pushed to a remote branch, so SOURCE.txt points at published source.')
    process.exit(1)
  }
}

try {
  runNpm(['run', 'build', '--', '--icons', '../../variants/hunt/icons'])
  runNpm(['run', 'builder', '--', ...process.argv.slice(2)])
} finally {
  git('checkout', '--', 'assets')
}
