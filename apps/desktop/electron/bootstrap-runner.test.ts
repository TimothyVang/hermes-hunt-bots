import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { test } from 'vitest'

import {
  buildPinArgs,
  buildPosixPinArgs,
  cachedScriptPath,
  cleanInstallerLogLine,
  hasExistingGitCheckout,
  installerEnv,
  installerGetsStampBranch,
  installRefForStamp,
  installScriptUrl,
  isPinnedCommit,
  resolveInstallScript,
  resolveMarkerPinnedCommit,
  runBootstrap
} from './bootstrap-runner'

const SCRIPT_NAME = process.platform === 'win32' ? 'install.ps1' : 'install.sh'
const ZERO_COMMIT = '0000000000000000000000000000000000000000'

function mkTmpHome() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-bootstrap-test-'))
}

test('the installer comes from upstream unless the build names its own source repo', () => {
  const hunt = { sourceRepo: 'TimothyVang/hermes-hunt-bots' }
  assert.equal(installScriptUrl('abc123', {}), `https://raw.githubusercontent.com/NousResearch/hermes-agent/abc123/scripts/${SCRIPT_NAME}`)
  assert.equal(installScriptUrl('abc123', hunt), `https://raw.githubusercontent.com/TimothyVang/hermes-hunt-bots/abc123/scripts/${SCRIPT_NAME}`)

  const saved = process.env.HERMES_REPO_URL
  delete process.env.HERMES_REPO_URL

  try {
    // install.ps1 / install.sh clone HERMES_REPO_URL, else NousResearch/hermes-agent, and on an
    // existing checkout they repoint its origin to it.
    for (const freshInstall of [true, false]) {
      assert.equal(installerEnv('/home', { freshInstall, identity: {} }).HERMES_REPO_URL, undefined)
    }

    assert.equal(
      installerEnv('/home', { freshInstall: true, identity: hunt }).HERMES_REPO_URL,
      'https://github.com/TimothyVang/hermes-hunt-bots.git'
    )
    // A repair keeps the shared checkout's origin, so stock Hermes never follows the fork.
    assert.equal(installerEnv('/home', { freshInstall: false, identity: hunt }).HERMES_REPO_URL, undefined)
    process.env.HERMES_REPO_URL = 'https://example.test/own.git'
    assert.equal(installerEnv('/home', { freshInstall: true, identity: hunt }).HERMES_REPO_URL, 'https://example.test/own.git')
  } finally {
    if (saved === undefined) {
      delete process.env.HERMES_REPO_URL
    } else {
      process.env.HERMES_REPO_URL = saved
    }
  }
})

test('a fork build repairs with its branch only a checkout of its own repo; other origins get none', () => {
  const hunt = { sourceRepo: 'TimothyVang/hermes-hunt-bots' }

  const repair = (origin: string | Error, identity: { sourceRepo?: string } = hunt) =>
    installerGetsStampBranch({
      freshInstall: false,
      activeRoot: '/root',
      identity,
      execGit: (args: string[]) => {
        assert.deepEqual(args, ['config', '--get', 'remote.origin.url'])

        if (origin instanceof Error) {
          throw origin
        }

        return origin
      }
    })

  // The checkout Hunt Command cloned, in every remote spelling: keep its branch.
  for (const origin of [
    'https://github.com/TimothyVang/hermes-hunt-bots.git',
    'https://github.com/timothyvang/Hermes-Hunt-Bots',
    'https://token@github.com/TimothyVang/hermes-hunt-bots.git/',
    'git@github.com:TimothyVang/hermes-hunt-bots.git',
    'ssh://git@github.com/TimothyVang/hermes-hunt-bots'
  ]) {
    assert.equal(repair(origin), true, origin)
  }

  // Upstream (the checkout stock Hermes shares), a lookalike, or an unreadable origin: no branch.
  for (const origin of [
    'https://github.com/NousResearch/hermes-agent.git',
    'https://github.com/TimothyVang/hermes-hunt-bots-old.git',
    'https://gitlab.com/TimothyVang/hermes-hunt-bots.git',
    '',
    new Error('no origin')
  ]) {
    assert.equal(repair(origin), false, String(origin))
  }

  // Fresh installs and stock builds always pass the branch, without reading git.
  const noGit = () => assert.fail('git must not be read')
  assert.equal(installerGetsStampBranch({ freshInstall: true, activeRoot: '/root', identity: hunt, execGit: noGit }), true)
  assert.equal(installerGetsStampBranch({ freshInstall: false, activeRoot: '/root', identity: {}, execGit: noGit }), true)

  const stamp = { commit: 'a'.repeat(40), branch: 'hunt-bots' }
  const posix = { installStamp: stamp, activeRoot: '/root', hermesHome: '/home' }
  assert.deepEqual(buildPinArgs(stamp, { pinCommit: false, passBranch: true }), ['-Branch', 'hunt-bots'])
  assert.deepEqual(buildPinArgs(stamp, { pinCommit: false, passBranch: false }), [])
  assert.deepEqual(buildPosixPinArgs({ ...posix, pinCommit: false, passBranch: false }), ['--dir', '/root', '--hermes-home', '/home'])
  assert.deepEqual(buildPinArgs(stamp), ['-Commit', stamp.commit, '-Branch', 'hunt-bots'])
})

test('runBootstrap bails immediately when the signal is already aborted', async () => {
  const controller = new AbortController()
  controller.abort()

  const events = []

  const result = await runBootstrap({
    installStamp: null,
    activeRoot: '/tmp/hermes-runner-test',
    sourceRepoRoot: null,
    hermesHome: '/tmp/hermes-runner-test',
    logRoot: '/tmp/hermes-runner-test',
    onEvent: ev => events.push(ev),
    abortSignal: controller.signal
  })

  // Cancelled before any install script is spawned.
  assert.deepEqual(result, { ok: false, cancelled: true })
  assert.ok(
    events.some(ev => ev.type === 'failed' && /cancelled/i.test(ev.error)),
    'should emit a cancelled failure event'
  )
})

test('existing checkout detection requires git metadata', () => {
  const home = mkTmpHome()

  try {
    const activeRoot = path.join(home, 'hermes-agent')
    assert.equal(hasExistingGitCheckout(activeRoot), false)

    fs.mkdirSync(path.join(activeRoot, '.git'), { recursive: true })
    assert.equal(hasExistingGitCheckout(activeRoot), true)
  } finally {
    fs.rmSync(home, { recursive: true, force: true })
  }
})

test('fresh bootstrap args include the packaged commit pin', () => {
  const installStamp = { commit: 'a'.repeat(40), branch: 'main' }

  assert.deepEqual(buildPinArgs(installStamp), ['-Commit', installStamp.commit, '-Branch', 'main'])
  assert.deepEqual(
    buildPosixPinArgs({
      installStamp,
      activeRoot: '/tmp/hermes-agent',
      hermesHome: '/tmp/hermes'
    }),
    ['--dir', '/tmp/hermes-agent', '--hermes-home', '/tmp/hermes', '--branch', 'main', '--commit', installStamp.commit]
  )
})

test('existing-checkout bootstrap args keep branch but skip the packaged commit pin', () => {
  const installStamp = { commit: 'a'.repeat(40), branch: 'main' }

  assert.deepEqual(buildPinArgs(installStamp, { pinCommit: false }), ['-Branch', 'main'])
  assert.deepEqual(
    buildPosixPinArgs({
      installStamp,
      activeRoot: '/tmp/hermes-agent',
      hermesHome: '/tmp/hermes',
      pinCommit: false
    }),
    ['--dir', '/tmp/hermes-agent', '--hermes-home', '/tmp/hermes', '--branch', 'main']
  )
})

test('fallback install stamps use an unpinned branch ref', () => {
  const stamp = { commit: ZERO_COMMIT, branch: 'main' }

  assert.equal(isPinnedCommit(ZERO_COMMIT), false)
  assert.deepEqual(installRefForStamp(stamp), {
    ref: 'main',
    cacheKey: 'branch-main',
    pinned: false
  })
  // Must NOT pass -Commit / --commit for the all-zero placeholder.
  assert.deepEqual(buildPinArgs(stamp), ['-Branch', 'main'])
  assert.deepEqual(
    buildPosixPinArgs({
      installStamp: stamp,
      activeRoot: '/tmp/hermes',
      hermesHome: '/tmp/home'
    }),
    ['--dir', '/tmp/hermes', '--hermes-home', '/tmp/home', '--branch', 'main']
  )
})

test('existing-checkout installer ref follows the branch instead of the packaged commit', () => {
  const stamp = { commit: 'a'.repeat(40), branch: 'main' }

  assert.deepEqual(installRefForStamp(stamp, { pinCommit: false }), {
    ref: 'main',
    cacheKey: 'branch-main',
    pinned: false
  })
  assert.deepEqual(installRefForStamp(stamp), {
    ref: stamp.commit,
    cacheKey: stamp.commit,
    pinned: true
  })
})

test('resolveMarkerPinnedCommit prefers installed checkout HEAD over the packaged artifact', () => {
  const realHead = 'c'.repeat(40)
  assert.equal(
    resolveMarkerPinnedCommit({ commit: ZERO_COMMIT, branch: 'main' }, '/tmp/checkout', {
      resolveHead: () => realHead
    }),
    realHead
  )
  assert.equal(
    resolveMarkerPinnedCommit({ commit: 'd'.repeat(40), branch: 'main' }, '/tmp/checkout', {
      resolveHead: () => realHead
    }),
    realHead,
    'the installed checkout owns source runtime identity'
  )
  assert.equal(
    resolveMarkerPinnedCommit({ commit: ZERO_COMMIT, branch: 'main' }, '/tmp/missing', {
      resolveHead: () => null
    }),
    null
  )
})

test('resolveInstallScript downloads fallback stamps by branch instead of zero commit', async () => {
  const home = mkTmpHome()

  try {
    const cached = cachedScriptPath(home, 'branch-main')
    fs.mkdirSync(path.dirname(cached), { recursive: true })
    fs.writeFileSync(cached, 'stale branch installer\n')

    const refs = []

    const result = await resolveInstallScript({
      installStamp: { commit: ZERO_COMMIT, branch: 'main' },
      sourceRepoRoot: null,
      hermesHome: home,
      emit: () => {},
      _download: async (ref, destPath) => {
        refs.push(ref)
        fs.mkdirSync(path.dirname(destPath), { recursive: true })
        fs.writeFileSync(destPath, '#!/bin/sh\necho fallback branch\n')

        return destPath
      }
    })

    assert.deepEqual(refs, ['main'])
    assert.equal(result.source, 'download')
    assert.equal(result.commit, null)
    assert.equal(result.path, cached)
    assert.match(fs.readFileSync(cached, 'utf8'), /fallback branch/)
  } finally {
    fs.rmSync(home, { recursive: true, force: true })
  }
})

test('resolveInstallScript refreshes the live branch for an existing checkout', async () => {
  const home = mkTmpHome()

  try {
    const commit = 'a'.repeat(40)
    const cached = cachedScriptPath(home, 'branch-main')
    fs.mkdirSync(path.dirname(cached), { recursive: true })
    fs.writeFileSync(cached, 'stale installer\n')

    const refs = []

    const result = await resolveInstallScript({
      installStamp: { commit, branch: 'main' },
      sourceRepoRoot: null,
      hermesHome: home,
      emit: () => {},
      pinCommit: false,
      _download: async (ref, destPath) => {
        refs.push(ref)
        fs.writeFileSync(destPath, 'fresh branch installer\n')

        return destPath
      }
    })

    assert.deepEqual(refs, ['main'])
    assert.equal(result.source, 'download')
    assert.equal(result.commit, null)
    assert.equal(result.path, cached)
    assert.equal(fs.readFileSync(cached, 'utf8'), 'fresh branch installer\n')
  } finally {
    fs.rmSync(home, { recursive: true, force: true })
  }
})

test('resolveInstallScript refreshes an immutable-pin cache on a fresh install', async () => {
  const home = mkTmpHome()

  try {
    const commit = 'a'.repeat(40)
    const cached = cachedScriptPath(home, commit)
    fs.mkdirSync(path.dirname(cached), { recursive: true })
    fs.writeFileSync(cached, 'stale installer\n')

    const refs = []

    const result = await resolveInstallScript({
      installStamp: { commit, branch: 'main' },
      sourceRepoRoot: null,
      hermesHome: home,
      emit: () => {},
      _download: async (ref, destPath) => {
        refs.push(ref)
        fs.writeFileSync(destPath, 'fresh pinned installer\n')

        return destPath
      }
    })

    assert.deepEqual(refs, [commit])
    assert.equal(result.source, 'download')
    assert.equal(result.commit, commit)
    assert.equal(result.path, cached)
    assert.equal(fs.readFileSync(cached, 'utf8'), 'fresh pinned installer\n')
  } finally {
    fs.rmSync(home, { recursive: true, force: true })
  }
})

test('resolveInstallScript fails closed instead of executing an installed stale script', async () => {
  const home = mkTmpHome()

  try {
    const commit = 'a'.repeat(40)
    const scriptsDir = path.join(home, 'hermes-agent', 'scripts')
    fs.mkdirSync(scriptsDir, { recursive: true })
    fs.writeFileSync(path.join(scriptsDir, SCRIPT_NAME), 'stale installed script\n')

    await assert.rejects(
      resolveInstallScript({
        installStamp: { commit, branch: 'main' },
        sourceRepoRoot: null,
        hermesHome: home,
        emit: () => {},
        _download: async () => {
          throw new Error('Failed to download install script: HTTP 404')
        }
      }),
      /HTTP 404/
    )
  } finally {
    fs.rmSync(home, { recursive: true, force: true })
  }
})

// #112675: install.sh colours its banners and curl/uv redraw progress with \r
// even into a pipe; the overlay renders lines as plain text, so the emitter
// must hand every consumer (log ring, Details panel, Copy output) the text a
// terminal would be left showing.
test('installer log lines reach the emitter without escape sequences; \\r redraws keep the last frame', () => {
  assert.equal(cleanInstallerLogLine('\u001b[0;32m✓\u001b[0m Detected: macos (macos)'), '✓ Detected: macos (macos)')
  assert.equal(cleanInstallerLogLine('\u001b[2K\u001b[1GCloning repository…\u001b[K'), 'Cloning repository…')
  assert.equal(cleanInstallerLogLine('\u001b]0;hermes\u0007Installing Hermes'), 'Installing Hermes')
  assert.equal(cleanInstallerLogLine('\r 12%\r 67%\r100%\u001b[K'), '100%')
  assert.equal(cleanInstallerLogLine('Resolving dependencies…\r'), 'Resolving dependencies…')
  // Only-escape frames drop entirely, so the caller emits nothing for them.
  assert.equal(cleanInstallerLogLine('\u001b[0m\r'), '')
  // Plain multi-byte text is untouched.
  assert.equal(cleanInstallerLogLine('Ready — café ✓ 中文'), 'Ready — café ✓ 中文')
})

test.skipIf(process.platform === 'win32')(
  'a manifest-step failure surfaces the installer tail without escape sequences',
  async () => {
    const home = mkTmpHome()
    fs.mkdirSync(path.join(home, 'scripts'))
    fs.writeFileSync(
      path.join(home, 'scripts', 'install.sh'),
      '#!/usr/bin/env bash\nprintf "\\033[0;31m\\xe2\\x9c\\x97\\033[0m manifest broke\\n" >&2\nexit 3\n'
    )

    const result = await runBootstrap({
      installStamp: null,
      activeRoot: home,
      sourceRepoRoot: home,
      hermesHome: home,
      logRoot: home,
      onEvent: () => {}
    })

    assert.equal(result.ok, false)
    assert.equal(result.error, 'install.sh --manifest failed: exit 3\n✗ manifest broke')
  }
)
