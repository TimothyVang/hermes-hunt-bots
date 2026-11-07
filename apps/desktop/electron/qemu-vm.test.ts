import { EventEmitter } from 'node:events'
import { PassThrough } from 'node:stream'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import type { ChildProcessWithoutNullStreams } from 'node:child_process'
import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('electron', () => ({ app: { getPath: () => os.tmpdir() } }))

import { QmpStdio, QemuVmController } from './qemu-vm'

type Command = { id: number; execute: string; arguments?: Record<string, unknown> }
const roots: string[] = []
const controllers: QemuVmController[] = []
const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=', 'base64')

function transport() {
  const emitter = new EventEmitter()
  const stdin = new PassThrough()
  const stdout = new PassThrough()
  const commands: Command[] = []
  const child = Object.assign(emitter, {
    stdin, stdout, stderr: new PassThrough(), exitCode: null as number | null,
    kill: vi.fn(() => { exit(0); return true })
  })
  const exit = (code: number) => { child.exitCode = code; emitter.emit('exit', code, null) }
  stdin.on('data', chunk => commands.push(JSON.parse(chunk.toString())))
  const reply = (command: Command, value: unknown) => stdout.write(`${JSON.stringify({ id: command.id, return: value })}\r\n`)
  return { child: child as unknown as ChildProcessWithoutNullStreams, stdin, stdout, commands, reply, exit }
}

function engineFixture() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'hermes-qemu-test-')))
  roots.push(root)
  const engine = path.join(root, 'engine')
  const userData = path.join(root, 'user-data')
  fs.mkdirSync(userData)
  const files = [
    'ucrt64/bin/qemu-system-x86_64.exe', 'ucrt64/bin/qemu-img.exe',
    'ucrt64/share/qemu/edk2-x86_64-code.fd', 'ucrt64/share/qemu/edk2-i386-vars.fd',
    'ucrt64/share/locale/sr@latin/LC_MESSAGES/at-spi2-core.mo'
  ].map(relative => {
    const bytes = Buffer.from(`Synthetic fixture only: ${relative}`)
    const filename = path.join(engine, relative)
    fs.mkdirSync(path.dirname(filename), { recursive: true })
    fs.writeFileSync(filename, bytes)
    return { path: relative, size: bytes.length, sha256: crypto.createHash('sha256').update(bytes).digest('hex') }
  })
  fs.writeFileSync(path.join(engine, 'engine.json'), JSON.stringify({
    schemaVersion: 1, platform: 'win32-x64', qemuExecutable: files[0].path,
    qemuImgExecutable: files[1].path, firmwareDirectory: 'ucrt64/share/qemu', files
  }))
  return { root, engine, userData }
}

function controllerFixture() {
  const fixture = engineFixture()
  const wire = transport()
  const guestKeys = new Set<string>()
  const guestButtons = new Set<string>()
  let screenshot: Command | undefined
  const spawn = vi.fn(() => {
    queueMicrotask(() => wire.stdout.write('{"QMP":{"version":{}}}\r\n'))
    return wire.child
  })
  const diskGate = Promise.withResolvers<void>()
  const diskStarted = Promise.withResolvers<void>()
  let delayDisk = false
  const execFile = vi.fn(async (_file: string, args: string[]) => {
    diskStarted.resolve()
    if (delayDisk) await diskGate.promise
    fs.writeFileSync(args[3], 'Synthetic disk fixture')
    return { stdout: '', stderr: '' }
  })
  wire.stdin.on('data', chunk => {
    const command = JSON.parse(chunk.toString()) as Command
    if (command.execute === 'screendump') { screenshot = command; return }
    if (command.execute === 'input-send-event') {
      const events = command.arguments?.events as Array<{ type: string; data: { down: boolean; key?: { type: string; data: string }; button?: string } }>
      for (const event of events) {
        if (event.type === 'key') {
          expect(event.data.key?.type).toBe('qcode')
          const key = event.data.key!.data
          if (event.data.down) guestKeys.add(key)
          else guestKeys.delete(key)
        } else if (event.type === 'btn') {
          const button = event.data.button!
          if (event.data.down) guestButtons.add(button)
          else guestButtons.delete(button)
        }
      }
    }
    wire.reply(command, {})
  })
  const controller = new QemuVmController({
    userDataPath: () => fixture.userData, engineRoot: () => fixture.engine,
    freeMemory: () => 16 * 1024 ** 3, spawn: spawn as never, execFile: execFile as never
  })
  controllers.push(controller)
  controller.setPaneVisible(true)
  return {
    ...fixture, ...wire, controller, spawn, execFile, guestKeys, guestButtons,
    delayDisk: () => { delayDisk = true }, releaseDisk: diskGate.resolve,
    diskStarted: diskStarted.promise,
    finishScreenshot: () => {
      if (!screenshot) throw new Error('No screenshot request is pending')
      const filename = String(screenshot.arguments?.filename)
      fs.writeFileSync(filename, png)
      wire.reply(screenshot, {})
      return filename
    }
  }
}

afterEach(async () => {
  for (const controller of controllers.splice(0)) await controller.stop(false)
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true })
  vi.restoreAllMocks()
})

describe('QMP protocol boundaries', () => {
  it('waits for each reply before sending another command and ignores unrelated messages', async () => {
    const wire = transport()
    const qmp = new QmpStdio(wire.child)
    wire.stdout.write('{"QM')
    wire.stdout.write('P":{"version":{}}}\r\n')
    await qmp.greeting
    const status = qmp.command('query-status')
    const machines = qmp.command('query-machines')
    const settled = Promise.allSettled([status, machines])
    try {
      await Promise.resolve()
      expect(wire.commands.map(command => command.execute)).toEqual(['query-status'])
      wire.stdout.write('{"event":"RESET"}\r\n{"id":999,"return":{"status":"wrong"}}\r\n')
      wire.reply(wire.commands[0], { status: 'running' })
      expect((await status).return).toEqual({ status: 'running' })
      await Promise.resolve()
      expect(wire.commands.map(command => command.execute)).toEqual(['query-status', 'query-machines'])
      wire.reply(wire.commands[1], [{ name: 'q35' }])
      expect((await machines).return).toEqual([{ name: 'q35' }])
    } finally {
      wire.child.kill()
      await settled
    }
  })

  it('fails queued and future commands when the active command times out', async () => {
    vi.useFakeTimers()
    const wire = transport()
    const qmp = new QmpStdio(wire.child)
    wire.stdout.write('{"QMP":{}}\n')
    await qmp.greeting
    const active = expect(qmp.command('query-status', undefined, 10)).rejects.toThrow('timed out')
    const queued = expect(qmp.command('query-machines')).rejects.toThrow('timed out')
    try {
      await vi.advanceTimersByTimeAsync(11)
      await Promise.all([active, queued])
      await expect(qmp.command('quit')).rejects.toThrow('timed out')
      expect(wire.commands.map(command => command.execute)).toEqual(['query-status'])
    } finally {
      wire.child.kill()
      vi.useRealTimers()
    }
  })

  it.each([
    { label: 'null', output: 'null\n' },
    { label: 'array', output: '[]\n' },
    { label: 'missing result', output: '{"id":1}\n' },
    { label: 'oversized line', output: `${'x'.repeat(1024 * 1024 + 1)}\n` }
  ])('fails pending and future operations on $label', async ({ output }) => {
    const wire = transport()
    const qmp = new QmpStdio(wire.child)
    wire.stdout.write('{"QMP":{}}\n')
    await qmp.greeting
    const pending = expect(qmp.command('query-status')).rejects.toBeInstanceOf(Error)
    wire.stdout.write(output)
    await pending
    const sentBefore = wire.commands.length
    await expect(qmp.command('query-status')).rejects.toBeInstanceOf(Error)
    expect(wire.commands.length).toBe(sentBefore)
    wire.child.kill()
  })

  it('rejects readiness when the process exits before its greeting', async () => {
    const wire = transport()
    const qmp = new QmpStdio(wire.child)
    const readiness = expect(qmp.greeting).rejects.toBeInstanceOf(Error)
    wire.child.kill()
    await readiness
    await expect(qmp.command('query-status')).rejects.toBeInstanceOf(Error)
  })

  it('contains a broken input pipe instead of emitting an unhandled stream error', async () => {
    const wire = transport()
    const qmp = new QmpStdio(wire.child)
    wire.stdout.write('{"QMP":{}}\n')
    await qmp.greeting
    const pending = expect(qmp.command('query-status')).rejects.toBeInstanceOf(Error)
    wire.stdin.emit('error', new Error('Synthetic closed pipe'))
    await pending
    wire.child.kill()
  })
})

describe.skipIf(process.platform !== 'win32')('owned VM lifecycle', () => {
  it('rejects concurrent startup and cancels a pending disk creation before spawning', async () => {
    const f = controllerFixture()
    expect(f.controller.status().state).toBe('stopped')
    f.delayDisk()
    const iso = path.join(f.root, 'installation.iso')
    fs.writeFileSync(iso, 'Synthetic ISO fixture')
    const startup = f.controller.start({ iso })
    const cancelled = expect(startup).rejects.toBeInstanceOf(Error)
    expect(f.controller.status().state).toBe('starting')
    await expect(f.controller.start({ iso })).rejects.toBeInstanceOf(Error)
    await f.diskStarted
    await f.controller.stop(false)
    f.releaseDisk()
    await cancelled
    expect(f.execFile).toHaveBeenCalledTimes(1)
    expect(f.spawn).not.toHaveBeenCalled()
    expect(f.controller.hasOwnedVmOrStartup()).toBe(false)
  })

  it('refuses an unindexed DLL before creating VM state or starting a process', async () => {
    const f = controllerFixture()
    fs.writeFileSync(path.join(f.engine, 'ucrt64/bin/unindexed.dll'), 'Benign synthetic injected DLL fixture')
    await expect(f.controller.start({ developerSmoke: true })).rejects.toBeInstanceOf(Error)
    expect(f.execFile).not.toHaveBeenCalled()
    expect(f.spawn).not.toHaveBeenCalled()
    expect(fs.existsSync(path.join(f.userData, 'qemu-vms'))).toBe(false)
  })

  it('refuses unexpected root directories and aliases in unindexed subtrees', async () => {
    const rootDirectory = controllerFixture()
    fs.mkdirSync(path.join(rootDirectory.engine, 'unexpected-directory'))
    await expect(rootDirectory.controller.start({ developerSmoke: true })).rejects.toBeInstanceOf(Error)
    expect(rootDirectory.spawn).not.toHaveBeenCalled()
    expect(fs.existsSync(path.join(rootDirectory.userData, 'qemu-vms'))).toBe(false)

    const alias = controllerFixture()
    const outside = path.join(alias.root, 'outside')
    fs.mkdirSync(outside)
    fs.symlinkSync(outside, path.join(alias.engine, 'ucrt64/alias'), 'junction')
    await expect(alias.controller.start({ developerSmoke: true })).rejects.toBeInstanceOf(Error)
    expect(alias.spawn).not.toHaveBeenCalled()
    expect(fs.existsSync(path.join(alias.userData, 'qemu-vms'))).toBe(false)
    expect(fs.readdirSync(outside)).toEqual([])
  })

  it('cancels during asynchronous verification without creating VM state', async () => {
    const f = controllerFixture()
    const startup = f.controller.start({ developerSmoke: true })
    const cancelled = expect(startup).rejects.toBeInstanceOf(Error)
    await f.controller.stop(false)
    await cancelled
    expect(f.controller.hasOwnedVmOrStartup()).toBe(false)
    expect(f.execFile).not.toHaveBeenCalled()
    expect(f.spawn).not.toHaveBeenCalled()
    expect(fs.existsSync(path.join(f.userData, 'qemu-vms'))).toBe(false)
  })

  it('releases delivered keys and buttons when the pane hides and refuses new input', async () => {
    const f = controllerFixture()
    await f.controller.start({ developerSmoke: true })
    f.controller.takeInput()
    await f.controller.sendKey('a', true)
    await f.controller.sendPointer(100, 200, 'left', true)
    expect(f.guestKeys.has('a')).toBe(true)
    expect(f.guestButtons.has('left')).toBe(true)
    f.controller.setPaneVisible(false)
    await f.controller.releaseInput()
    expect(f.guestKeys.size).toBe(0)
    expect(f.guestButtons.size).toBe(0)
    expect(f.controller.status().inputEnabled).toBe(false)
    await expect(f.controller.sendKey('b', true)).rejects.toBeInstanceOf(Error)
  })

  it('releases repeated key and button presses after earlier release acknowledgements', async () => {
    const f = controllerFixture()
    await f.controller.start({ developerSmoke: true })
    f.controller.takeInput()
    await Promise.all([
      f.controller.sendKey('a', true),
      f.controller.sendKey('a', false),
      f.controller.sendKey('a', true),
      f.controller.sendPointer(100, 200, 'left', true),
      f.controller.sendPointer(100, 200, 'left', false),
      f.controller.sendPointer(100, 200, 'left', true)
    ])
    expect(f.guestKeys.has('a')).toBe(true)
    expect(f.guestButtons.has('left')).toBe(true)
    f.controller.setPaneVisible(false)
    await f.controller.releaseInput()
    expect(f.guestKeys.has('a')).toBe(false)
    expect(f.guestButtons.has('left')).toBe(false)
    expect(f.controller.status()).toMatchObject({ inputEnabled: false, inputReleaseFailed: false })
  })

  it('keeps an unacknowledged key release visible and refuses another takeover', async () => {
    const f = controllerFixture()
    await f.controller.start({ developerSmoke: true })
    f.controller.takeInput()
    await f.controller.sendKey('ctrl', true)
    f.stdout.emit('end')
    await f.controller.releaseInput()
    expect(f.guestKeys.has('ctrl')).toBe(true)
    expect(f.controller.status()).toMatchObject({
      state: 'running', owned: true, inputEnabled: false, inputReleaseFailed: true
    })
    expect(() => f.controller.takeInput()).toThrow()
    await expect(f.controller.sendKey('a', true)).rejects.toBeInstanceOf(Error)
    await f.controller.stop(false)
    expect(f.controller.status()).toMatchObject({ owned: false, inputReleaseFailed: false })
  })

  it('distinguishes explicit forced termination from an unexpected nonzero exit', async () => {
    const requested = controllerFixture()
    await requested.controller.start({ developerSmoke: true })
    vi.mocked(requested.child.kill).mockImplementation(() => {
      requested.exit(1)
      return true
    })
    await requested.controller.stop(false)
    expect(requested.controller.status()).toMatchObject({ state: 'stopped', owned: false })

    const unexpected = controllerFixture()
    await unexpected.controller.start({ developerSmoke: true })
    unexpected.exit(1)
    expect(unexpected.controller.status()).toMatchObject({ state: 'error', owned: false })
  })

  it('allows only one capture and discards an in-flight frame after visibility changes', async () => {
    const f = controllerFixture()
    await f.controller.start({ developerSmoke: true })
    const first = expect(f.controller.capture()).rejects.toBeInstanceOf(Error)
    expect(await f.controller.capture()).toBeNull()
    f.controller.setPaneVisible(false)
    const filename = f.finishScreenshot()
    await first
    expect(fs.existsSync(filename)).toBe(false)
    expect(await f.controller.capture()).toBeNull()
  })

  it('rejects tampered runtime bytes before creating VM state or launching a process', async () => {
    const f = controllerFixture()
    fs.appendFileSync(path.join(f.engine, 'ucrt64/bin/qemu-system-x86_64.exe'), 'tampered')
    await expect(f.controller.start({ developerSmoke: true })).rejects.toBeInstanceOf(Error)
    expect(f.spawn).not.toHaveBeenCalled()
    expect(fs.existsSync(path.join(f.userData, 'qemu-vms'))).toBe(false)
  })

  it('refuses a junction before creating VM files outside its owned directory', async () => {
    const f = controllerFixture()
    const outside = path.join(f.root, 'outside')
    fs.mkdirSync(outside)
    fs.symlinkSync(outside, path.join(f.userData, 'qemu-vms'), 'junction')
    await expect(f.controller.start({ developerSmoke: true })).rejects.toBeInstanceOf(Error)
    expect(fs.readdirSync(outside)).toEqual([])
    expect(f.spawn).not.toHaveBeenCalled()
  })
})
