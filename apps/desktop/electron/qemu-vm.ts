import { execFile as execFileCallback, spawn, type ChildProcessWithoutNullStreams } from 'node:child_process'
import { promisify } from 'node:util'
import crypto from 'node:crypto'
import os from 'node:os'
import fs from 'node:fs'
import path from 'node:path'
import { app } from 'electron'

const execFile = promisify(execFileCallback)
const MAX_ENGINE_INDEX = 65_536
const MAX_ENGINE_MANIFEST_BYTES = 16 * 1024 * 1024
const MAX_FRAME_BYTES = 8 * 1024 * 1024
const MAX_QMP_LINE = 1024 * 1024
const WINDOWS_RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i

type EngineManifest = {
  schemaVersion: 1
  platform: 'win32-x64'
  qemuExecutable: string
  qemuImgExecutable: string
  firmwareDirectory: string
  files: Array<{ path: string; sha256: string; size: number }>
}
type QmpReply = { return?: unknown; error?: { desc?: string; class?: string }; event?: string }
type VmState = 'stopped' | 'starting' | 'running' | 'error'

export interface QemuVmStatus {
  state: VmState
  owned: boolean
  available: boolean
  developerSmokeAvailable: boolean
  hasDisk: boolean
  inputEnabled: boolean
  inputReleaseFailed: boolean
  networkEnabled: boolean
}

function isSafeEnginePath(value: unknown): value is string {
  if (typeof value !== 'string' || !value || value.startsWith('/') || value.includes('\\') || /[<>:"|?*\x00-\x1f]/.test(value)) return false
  return value.split('/').every(part => part && part !== '.' && part !== '..' && !part.endsWith('.') && !part.endsWith(' ') && !WINDOWS_RESERVED.test(part))
}

function contained(root: string, relative: string): string {
  if (!isSafeEnginePath(relative)) throw new Error('Invalid engine path')
  const full = path.resolve(root, ...relative.split('/'))
  if (!full.startsWith(`${path.resolve(root)}${path.sep}`)) throw new Error('Engine path escapes its root')
  return full
}

function rejectReparseAncestors(root: string, target: string): void {
  const rel = path.relative(root, target)
  let current = root
  for (const part of rel.split(path.sep)) {
    current = path.join(current, part)
    const stat = fs.lstatSync(current)
    const canonical = fs.realpathSync.native(current)
    const expected = path.resolve(current)
    const samePath = process.platform === 'win32'
      ? canonical.toLowerCase() === expected.toLowerCase()
      : canonical === expected
    if (stat.isSymbolicLink() || !samePath) {
      throw new Error('QEMU paths must not contain links or aliases')
    }
  }
}

export async function validateQemuEngine(engineRoot: string, signal?: AbortSignal): Promise<EngineManifest> {
  if (process.platform !== 'win32' || !path.isAbsolute(engineRoot)) throw new Error('Portable QEMU requires an absolute Windows engine directory')
  const root = path.resolve(engineRoot)
  const manifestPath = path.join(root, 'engine.json')
  rejectReparseAncestors(path.parse(root).root, manifestPath)
  const manifestStat = await fs.promises.stat(manifestPath)
  if (!manifestStat.isFile() || manifestStat.nlink !== 1 || manifestStat.size > MAX_ENGINE_MANIFEST_BYTES) throw new Error('QEMU engine index is too large or not a single-link regular file')
  const raw = await fs.promises.readFile(manifestPath, { signal })
  if (raw.length > MAX_ENGINE_MANIFEST_BYTES) throw new Error('QEMU engine index is too large')
  const manifest = JSON.parse(raw.toString('utf8')) as EngineManifest
  if (manifest.schemaVersion !== 1 || manifest.platform !== 'win32-x64' || manifest.qemuExecutable !== 'ucrt64/bin/qemu-system-x86_64.exe' || manifest.qemuImgExecutable !== 'ucrt64/bin/qemu-img.exe' || manifest.firmwareDirectory !== 'ucrt64/share/qemu' || !Array.isArray(manifest.files) || manifest.files.length > MAX_ENGINE_INDEX) throw new Error('Unsupported QEMU engine index')
  const seen = new Set<string>()
  for (const file of manifest.files) {
    signal?.throwIfAborted()
    if (!file || !isSafeEnginePath(file.path) || !file.path.startsWith('ucrt64/') || seen.has(file.path.toLowerCase()) || !Number.isSafeInteger(file.size) || file.size < 0 || !/^[a-f0-9]{64}$/i.test(file.sha256)) throw new Error('Invalid QEMU engine file entry')
    seen.add(file.path.toLowerCase())
    const target = contained(root, file.path)
    rejectReparseAncestors(root, target)
    const stat = fs.statSync(target)
    if (!stat.isFile() || stat.nlink !== 1 || stat.size !== file.size) throw new Error(`QEMU engine file does not match index: ${file.path}`)
    const digest = crypto.createHash('sha256').update(await fs.promises.readFile(target, { signal })).digest('hex')
    if (digest.toLowerCase() !== file.sha256.toLowerCase()) throw new Error(`QEMU engine hash mismatch: ${file.path}`)
  }
  for (const required of [manifest.qemuExecutable, manifest.qemuImgExecutable, `${manifest.firmwareDirectory}/edk2-x86_64-code.fd`, `${manifest.firmwareDirectory}/edk2-i386-vars.fd`]) {
    if (!seen.has(required.toLowerCase())) throw new Error(`QEMU engine is missing ${required}`)
  }
  let indexedCount = 0
  const verifyTree = async (directory: string, prefix = ''): Promise<void> => {
    signal?.throwIfAborted()
    for (const entry of await fs.promises.readdir(directory, { withFileTypes: true })) {
      signal?.throwIfAborted()
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name
      if (!prefix && !['ucrt64', 'engine.json', 'provenance.json'].includes(entry.name)) throw new Error('Unexpected QEMU engine root entry')
      const target = path.join(directory, entry.name)
      const stat = await fs.promises.lstat(target)
      const canonical = await fs.promises.realpath(target)
      if (stat.isSymbolicLink() || canonical.toLowerCase() !== path.resolve(target).toLowerCase()) throw new Error('QEMU engine tree contains a link or alias')
      if (stat.isDirectory()) {
        if (relative !== 'ucrt64' && !relative.startsWith('ucrt64/')) throw new Error('Unexpected QEMU engine metadata directory')
        // Signed packages include empty structural directories. No unindexed file is allowed within them.
        await verifyTree(target, relative)
      } else {
        if (!stat.isFile() || stat.nlink !== 1) throw new Error('QEMU engine tree contains a non-regular or hard-linked file')
        if (relative !== 'engine.json' && relative !== 'provenance.json') {
          if (!seen.has(relative.toLowerCase())) throw new Error(`Unindexed QEMU runtime file: ${relative}`)
          indexedCount++
        }
      }
    }
  }
  await verifyTree(root)
  if (indexedCount !== seen.size) throw new Error('QEMU engine inventory changed during verification')
  return manifest
}

export class QmpStdio {
  private buffer = ''
  private nextId = 0
  private failure: Error | null = null
  private commandTail: Promise<void> = Promise.resolve()
  private readonly pending = new Map<number, { resolve(value: QmpReply): void; reject(error: Error): void; timer: NodeJS.Timeout }>()
  private readonly greetingCompletion = Promise.withResolvers<QmpReply>()
  readonly greeting = this.greetingCompletion.promise

  constructor(private readonly child: ChildProcessWithoutNullStreams) {
    child.stdout.setEncoding('utf8')
    child.stdout.on('data', (chunk: string) => this.consume(chunk))
    child.stdout.on('error', () => this.failAll(new Error('QMP output pipe failed')))
    child.stdout.on('end', () => this.failAll(new Error('QMP output pipe closed')))
    child.stdin.on('error', () => this.failAll(new Error('QMP input pipe failed')))
    child.on('exit', () => this.failAll(new Error('QEMU exited')))
    child.on('error', () => this.failAll(new Error('QEMU failed to launch')))
  }
  private consume(chunk: string) {
    if (this.failure) return
    this.buffer += chunk
    if (this.buffer.length > MAX_QMP_LINE && !this.buffer.includes('\n')) return this.failAll(new Error('QMP response exceeded limit'))
    for (;;) {
      const end = this.buffer.indexOf('\n')
      if (end < 0) break
      const line = this.buffer.slice(0, end).trim()
      this.buffer = this.buffer.slice(end + 1)
      if (line.length > MAX_QMP_LINE) return this.failAll(new Error('QMP response exceeded limit'))
      if (!line) continue
      let value: unknown
      try { value = JSON.parse(line) } catch { return this.failAll(new Error('Invalid QMP response')) }
      if (!value || typeof value !== 'object' || Array.isArray(value)) return this.failAll(new Error('Invalid QMP response'))
      const reply = value as QmpReply & { id?: number; QMP?: unknown }
      if ('QMP' in reply) {
        this.greetingCompletion.resolve(reply)
        continue
      }
      if (typeof reply.event === 'string') continue
      const id = reply.id
      if (!Number.isSafeInteger(id) || (('return' in reply) === ('error' in reply))) {
        return this.failAll(new Error('Invalid QMP response envelope'))
      }
      const waiter = this.pending.get(id as number)
      if (!waiter) continue
      clearTimeout(waiter.timer)
      this.pending.delete(id as number)
      if (reply.error) waiter.reject(new Error(reply.error.desc || 'QMP command failed'))
      else waiter.resolve(reply)
    }
  }
  private failAll(error: Error) {
    if (this.failure) return
    this.failure = error
    this.buffer = ''
    this.greetingCompletion.reject(error)
    for (const p of this.pending.values()) { clearTimeout(p.timer); p.reject(error) }
    this.pending.clear()
  }
  command(execute: string, args?: Record<string, unknown>, timeoutMs = 5000): Promise<QmpReply> {
    // Windows stdio can corrupt pipelined QMP input. Send only after the prior reply.
    const result = this.commandTail.then(() => this.sendCommand(execute, args, timeoutMs))
    this.commandTail = result.then(() => undefined, () => undefined)
    return result
  }
  private async sendCommand(execute: string, args: Record<string, unknown> | undefined, timeoutMs: number): Promise<QmpReply> {
    if (this.failure) throw this.failure
    const id = ++this.nextId
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.failAll(new Error('QMP command timed out')), timeoutMs)
      this.pending.set(id, { resolve, reject, timer })
      this.child.stdin.write(`${JSON.stringify({ execute, ...(args ? { arguments: args } : {}), id })}\r\n`, error => {
        if (error) this.failAll(new Error('QMP pipe closed'))
      })
    })
  }
}
export const qemuDrivePath = (value: string) => value.replace(/,/g, ',,')
export function qemuInputReleaseEvents(keys: Iterable<string>, buttons: Iterable<'left' | 'right'>): Array<Record<string, unknown>> {
  return [
    ...Array.from(keys, qcode => ({ type: 'key', data: { down: false, key: { type: 'qcode', data: qcode.toLowerCase() } } })),
    ...Array.from(buttons, button => ({ type: 'btn', data: { down: false, button } }))
  ]
}
export function qemuNetworkingArguments(enabled: boolean, developerSmoke = false): string[] {
  if (!enabled || developerSmoke) return []
  return ['-netdev', 'user,id=hermes-nat', '-device', 'virtio-net-pci,netdev=hermes-nat']
}

type QemuVmDependencies = {
  userDataPath: () => string
  engineRoot: () => string
  freeMemory: () => number
  spawn: typeof spawn
  execFile: typeof execFile
}
const defaultDependencies: QemuVmDependencies = {
  userDataPath: () => app.getPath('userData'),
  engineRoot: () => process.env.HERMES_DESKTOP_QEMU_ROOT || path.join(app.getPath('userData'), 'portable-qemu'),
  freeMemory: () => os.freemem(),
  spawn,
  execFile
}

export class QemuVmController {
  private child: ChildProcessWithoutNullStreams | null = null
  private qmp: QmpStdio | null = null
  private state: VmState = 'stopped'
  private inputLease = false
  private inputRelease: Promise<void> | null = null
  private inputReleaseFailed = false
  private networkEnabled = false
  private paneVisible = false
  private paneEpoch = 0
  private starting = false
  private verificationAbort: AbortController | null = null
  private forceStopping = false
  private capturing = false
  private vmRoot: string
  private readonly deps: QemuVmDependencies
  constructor(dependencies: Partial<QemuVmDependencies> = {}) {
    this.deps = { ...defaultDependencies, ...dependencies }
    this.vmRoot = path.join(this.deps.userDataPath(), 'qemu-vms', 'default')
  }
  private startCompletion: Promise<void> | null = null
  private resolveStartCompletion: (() => void) | null = null

  private inputGeneration = 0
  private heldKeys = new Map<string, number>()
  private heldButtons = new Map<'left' | 'right', number>()
  status(): QemuVmStatus {
    const root = this.deps.engineRoot()
    const disk = path.join(this.deps.userDataPath(), 'qemu-vms', 'default', 'system.qcow2')
    return { state: this.state, owned: this.hasOwnedVmOrStartup(), available: process.platform === 'win32' && fs.existsSync(path.join(root, 'engine.json')), developerSmokeAvailable: !app.isPackaged, hasDisk: fs.existsSync(disk), inputEnabled: this.inputLease, inputReleaseFailed: this.inputReleaseFailed, networkEnabled: this.networkEnabled }
  }
  setPaneVisible(visible: boolean) {
    if (this.paneVisible !== visible) this.paneEpoch += 1
    this.paneVisible = visible
    if (!visible) {
      this.verificationAbort?.abort()
      this.releaseInput()
    }
  }
  async start(options: { developerSmoke?: boolean; bootExisting?: boolean; iso?: string; networkEnabled?: boolean } = {}) {
    if (process.platform !== 'win32') throw new Error('Portable QEMU is available only on Windows x64')
    if (this.child || this.starting) throw new Error('QEMU VM is already owned or starting')
    if (!this.paneVisible) throw new Error('Open the QEMU console pane before starting a VM')
    if (options.developerSmoke !== true && !options.bootExisting && !options.iso) throw new Error('Select an installation ISO or boot an existing VM')
    if (options.developerSmoke && options.networkEnabled) throw new Error('Firmware smoke never enables guest networking')
    const epoch = this.paneEpoch
    this.starting = true
    const verificationAbort = new AbortController()
    this.verificationAbort = verificationAbort
    const completion = Promise.withResolvers<void>()
    this.startCompletion = completion.promise
    this.resolveStartCompletion = completion.resolve
    this.vmRoot = path.join(this.deps.userDataPath(), 'qemu-vms', options.developerSmoke ? 'firmware-smoke' : 'default')
    const engineRoot = this.deps.engineRoot()
    this.state = 'starting'
    try {
      const manifest = await validateQemuEngine(engineRoot, verificationAbort.signal)
      if (epoch !== this.paneEpoch || !this.paneVisible) throw new Error('QEMU console ownership changed during engine verification')
      const userData = this.deps.userDataPath()
      rejectReparseAncestors(path.parse(userData).root, userData)
      const vmParent = path.dirname(this.vmRoot)
      if (fs.existsSync(vmParent)) rejectReparseAncestors(userData, vmParent)
      fs.mkdirSync(this.vmRoot, { recursive: true })
      rejectReparseAncestors(this.deps.userDataPath(), this.vmRoot)
      const varsTemplate = contained(engineRoot, `${manifest.firmwareDirectory}/edk2-i386-vars.fd`)
      const vars = path.join(this.vmRoot, 'vars.fd')
      if (fs.existsSync(vars)) rejectReparseAncestors(this.vmRoot, vars)
      if (options.developerSmoke) fs.copyFileSync(varsTemplate, vars)
      else if (!fs.existsSync(vars)) fs.copyFileSync(varsTemplate, vars)
      const code = contained(engineRoot, `${manifest.firmwareDirectory}/edk2-x86_64-code.fd`)
      const memoryMiB = options.developerSmoke ? 768 : 4096
      const memoryBytes = memoryMiB * 1024 * 1024
      const requiredHeadroom = (options.developerSmoke ? 1024 : 2048) * 1024 * 1024
      if (this.deps.freeMemory() < memoryBytes + requiredHeadroom) throw new Error(`Not enough available memory for the ${memoryMiB} MiB QEMU VM`)
      const argv = ['-machine', 'q35,accel=tcg', '-m', String(memoryMiB), '-smp', '2', '-nodefaults', '-device', 'VGA', '-device', 'qemu-xhci,id=usb', '-device', 'usb-kbd,bus=usb.0', '-device', 'usb-tablet,bus=usb.0', '-no-user-config', '-display', 'none', '-monitor', 'none', '-serial', 'none', '-parallel', 'none', '-L', contained(engineRoot, manifest.firmwareDirectory), '-drive', `if=pflash,format=raw,readonly=on,file=${qemuDrivePath(code)}`, '-drive', `if=pflash,format=raw,file=${qemuDrivePath(vars)}`, '-qmp', 'stdio']
      argv.push(...qemuNetworkingArguments(options.networkEnabled === true, options.developerSmoke === true))
      if (!options.developerSmoke) {
        const disk = path.join(this.vmRoot, 'system.qcow2')
        if (fs.existsSync(disk)) rejectReparseAncestors(this.vmRoot, disk)
        if (options.bootExisting && !fs.existsSync(disk)) throw new Error('No owned VM disk exists yet; choose an installation ISO first')
        if (!options.bootExisting && !fs.existsSync(disk)) {
          await this.deps.execFile(contained(engineRoot, manifest.qemuImgExecutable), ['create', '-f', 'qcow2', disk, '32G'], {
            cwd: this.vmRoot, windowsHide: true, timeout: 10_000, maxBuffer: 16 * 1024,
            env: { SystemRoot: process.env.SystemRoot || 'C:\\Windows', WINDIR: process.env.WINDIR || process.env.SystemRoot || 'C:\\Windows', TEMP: this.vmRoot, TMP: this.vmRoot, HOME: this.vmRoot, PATH: path.join(engineRoot, 'ucrt64', 'bin') }
          })
        }
        if (!fs.existsSync(disk)) throw new Error('Owned VM disk was not created')
        argv.push('-drive', `if=virtio,format=qcow2,file=${qemuDrivePath(disk)}`)
      }
      if (epoch !== this.paneEpoch || !this.paneVisible) throw new Error('QEMU console ownership changed during VM startup')
      if (options.iso) {
        const iso = path.resolve(options.iso)
        if (!fs.statSync(iso).isFile()) throw new Error('Installation ISO is unavailable')
        argv.push('-drive', `media=cdrom,readonly=on,file=${qemuDrivePath(iso)}`)
      }
      if (epoch !== this.paneEpoch || !this.paneVisible) throw new Error('QEMU console ownership changed during VM startup')
      const child = this.deps.spawn(contained(engineRoot, manifest.qemuExecutable), argv, {
        cwd: this.vmRoot, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
        env: { SystemRoot: process.env.SystemRoot || 'C:\\Windows', WINDIR: process.env.WINDIR || process.env.SystemRoot || 'C:\\Windows', TEMP: this.vmRoot, TMP: this.vmRoot, HOME: this.vmRoot, PATH: path.join(engineRoot, 'ucrt64', 'bin') }
      })
      this.networkEnabled = options.networkEnabled === true
      this.child = child
      this.forceStopping = false
      child.once('exit', code => {
        if (this.child === child) {
          this.child = null
          this.qmp = null
          this.networkEnabled = false
          this.inputLease = false
          this.inputRelease = null
          this.inputReleaseFailed = false
          this.heldKeys.clear()
          this.heldButtons.clear()
          this.state = code === 0 || this.forceStopping ? 'stopped' : 'error'
          this.forceStopping = false
        }
      })
      child.stderr.on('data', () => undefined)
      const qmp = new QmpStdio(child)
      this.qmp = qmp
      let readyTimer: NodeJS.Timeout | undefined
      await Promise.race([qmp.greeting, new Promise<never>((_, reject) => { readyTimer = setTimeout(() => reject(new Error('QEMU QMP did not become ready')), 10000) })]).finally(() => clearTimeout(readyTimer))
      await qmp.command('qmp_capabilities')
      if (epoch !== this.paneEpoch || !this.paneVisible) throw new Error('QEMU console ownership changed during VM startup')
      this.state = 'running'
    } catch (error) {
      await this.stop(false).catch(() => undefined)
      this.state = 'error'
      throw error
    }
    finally {
      if (this.verificationAbort === verificationAbort) this.verificationAbort = null
      this.starting = false
      this.resolveStartCompletion?.()
      this.resolveStartCompletion = null
      this.startCompletion = null
    }
  }
  async stop(graceful = true) {
    this.paneEpoch += 1
    this.verificationAbort?.abort()
    this.releaseInput()
    const child = this.child
    const qmp = this.qmp
    if (!child) { this.state = 'stopped'; this.networkEnabled = false; return }
    if (graceful) {
      if (qmp) await qmp.command('system_powerdown', undefined, 1500)
      if (child.exitCode === null) {
        await Promise.race([new Promise<void>(resolve => child.once('exit', () => resolve())), new Promise<void>(resolve => setTimeout(resolve, 2500))])
      }
      return
    }
    this.forceStopping = true
    if (qmp) {
      try { await qmp.command('quit', undefined, 1500) } catch { /* process may already have exited */ }
    }
    if (child.exitCode === null) child.kill()
    if (child.exitCode === null) {
      await Promise.race([new Promise<void>(resolve => child.once('exit', () => resolve())), new Promise<void>(resolve => setTimeout(resolve, 2500))])
    }
    if (this.child === child && child.exitCode !== null) {
      this.child = null
      this.qmp = null
      this.state = 'stopped'
      this.networkEnabled = false
      return
    }
    if (this.child === child) throw new Error('QEMU process did not exit after the explicit power-off request')
  }
  hasOwnedVmOrStartup(): boolean {
    return this.starting || this.child !== null
  }
  async stopForAppExit(): Promise<boolean> {
    if (!this.hasOwnedVmOrStartup()) return true
    await this.stop(false)
    if (this.startCompletion) await this.startCompletion
    if (this.child) await this.stop(false)
    return !this.hasOwnedVmOrStartup()
  }
  takeInput() {
    if (!this.paneVisible || this.state !== 'running') throw new Error('Open the VM console before taking input control')
    if (this.inputRelease) throw new Error('Wait for the pending guest input release')
    if (this.inputReleaseFailed) throw new Error('Guest input release was not acknowledged; explicitly power off this VM before taking control again')
    this.inputLease = true
  }
  releaseInput(): Promise<void> {
    this.inputLease = false
    const events = qemuInputReleaseEvents(this.heldKeys.keys(), this.heldButtons.keys())
    this.heldKeys.clear()
    this.heldButtons.clear()
    const qmp = this.qmp
    if (!qmp || !events.length) return this.inputRelease ?? Promise.resolve()
    // A revoked permission is not proof that the guest received key-up events.
    // Keep failures visible in status and refuse another takeover of this VM.
    const release = qmp.command('input-send-event', { events }).then(() => undefined, () => {
      if (this.qmp === qmp) {
        this.inputReleaseFailed = true
        this.inputLease = false
      }
    })
    this.inputRelease = release
    void release.then(() => { if (this.inputRelease === release) this.inputRelease = null })
    return release
  }
  async capture(): Promise<string | null> {
    if (!this.paneVisible || this.state !== 'running' || !this.qmp || !this.child || this.capturing) return null
    this.capturing = true
    const qmp = this.qmp
    const child = this.child
    const epoch = this.paneEpoch
    const frame = path.join(this.vmRoot, 'console.png')
    try {
      if (fs.existsSync(frame)) rejectReparseAncestors(this.vmRoot, frame)
      await qmp.command('screendump', { filename: frame, format: 'png' }, 5000)
      if (!this.paneVisible || epoch !== this.paneEpoch || this.child !== child || this.qmp !== qmp || child.exitCode !== null) throw new Error('QEMU console ownership changed during frame capture')
      const stat = fs.statSync(frame)
      if (!stat.isFile() || stat.size < 8 || stat.size > MAX_FRAME_BYTES) throw new Error('QEMU console frame is invalid or too large')
      const bytes = fs.readFileSync(frame)
      if (!bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) throw new Error('QEMU console frame is not PNG')
      return `data:image/png;base64,${bytes.toString('base64')}`
    } finally {
      try { fs.unlinkSync(frame) } catch { /* no prior frame */ }
      this.capturing = false
    }
  }
  async sendKey(key: string, down: boolean) {
    const qmp = this.qmp
    const held = this.heldKeys.has(key)
    if (!qmp || !/^[A-Za-z0-9_+-]{1,32}$/.test(key) || (!this.inputLease && !(down === false && held)) || (!this.paneVisible && !(down === false && held))) throw new Error('VM input is not enabled')
    const generation = down ? ++this.inputGeneration : this.heldKeys.get(key)
    if (down) this.heldKeys.set(key, generation!)
    try {
      await qmp.command('input-send-event', { events: [{ type: 'key', data: { down, key: { type: 'qcode', data: key.toLowerCase() } } }] })
    } catch (error) {
      if (down && this.heldKeys.get(key) === generation) this.heldKeys.delete(key)
      throw error
    }
    if (!down && this.heldKeys.get(key) === generation) this.heldKeys.delete(key)
  }
  async sendPointer(x: number, y: number, button?: string, down?: boolean) {
    const qmp = this.qmp
    const held = button === 'left' || button === 'right' ? this.heldButtons.has(button) : false
    if (!qmp || (!this.inputLease && !(button && down === false && held)) || (!this.paneVisible && !(button && down === false && held)) || !Number.isInteger(x) || !Number.isInteger(y) || x < 0 || x > 32767 || y < 0 || y > 32767) throw new Error('VM input is not enabled')
    const events: Array<Record<string, unknown>> = [
      { type: 'abs', data: { axis: 'x', value: x } },
      { type: 'abs', data: { axis: 'y', value: y } }
    ]
    const generation = button === 'left' || button === 'right'
      ? down ? ++this.inputGeneration : this.heldButtons.get(button)
      : undefined
    if (button === 'left' || button === 'right') {
      events.push({ type: 'btn', data: { down: down === true, button } })
      if (down) this.heldButtons.set(button, generation!)
    }
    try {
      await qmp.command('input-send-event', { events })
    } catch (error) {
      if ((button === 'left' || button === 'right') && down && this.heldButtons.get(button) === generation) this.heldButtons.delete(button)
      throw error
    }
    if ((button === 'left' || button === 'right') && !down && this.heldButtons.get(button) === generation) this.heldButtons.delete(button)
  }
}
