import { app, BrowserWindow, dialog, ipcMain, type IpcMainInvokeEvent, type MessageBoxOptions } from 'electron'
import { QemuVmController } from './qemu-vm'
import { QemuPaneOwner } from './qemu-pane-owner'

const paneOwner = new QemuPaneOwner()
let controller: QemuVmController | undefined
let expectedUrl: URL | undefined

export function isTrustedQemuRendererUrl(actual: string, expected: URL): boolean {
  try {
    const url = new URL(actual)
    return url.protocol === expected.protocol && url.host === expected.host && url.pathname === expected.pathname
  } catch {
    return false
  }
}

function trusted(event: IpcMainInvokeEvent, requireVisible = true): boolean {
  const window = BrowserWindow.fromWebContents(event.sender)
  return Boolean(
    controller && expectedUrl && window && !window.isDestroyed() &&
    (!requireVisible || (window.isVisible() && !window.isMinimized())) &&
    event.senderFrame === event.sender.mainFrame &&
    isTrustedQemuRendererUrl(event.senderFrame.url, expectedUrl)
  )
}
const ownerListeners = new Map<number, { window: BrowserWindow; sender: IpcMainInvokeEvent['sender']; release: () => void; blur: () => void }>()

function releaseOwner(ownerId: number): void {
  const released = paneOwner.release(ownerId)
  const listeners = ownerListeners.get(ownerId)
  if (listeners) {
    listeners.window.removeListener('hide', listeners.release)
    listeners.window.removeListener('minimize', listeners.release)
    listeners.window.removeListener('blur', listeners.blur)
    listeners.sender.removeListener('render-process-gone', listeners.release)
    listeners.sender.removeListener('did-navigate', listeners.release)
    listeners.sender.removeListener('destroyed', listeners.release)
    ownerListeners.delete(ownerId)
  }
  if (released) controller?.setPaneVisible(false)
}

function watchOwner(event: IpcMainInvokeEvent, window: BrowserWindow): void {
  if (ownerListeners.has(event.sender.id)) return
  const release = () => releaseOwner(event.sender.id)
  const blur = () => { if (paneOwner.owns(event.sender.id)) controller?.releaseInput() }
  ownerListeners.set(event.sender.id, { window, sender: event.sender, release, blur })
  window.on('hide', release)
  window.on('minimize', release)
  window.on('blur', blur)
  event.sender.on('render-process-gone', release)
  event.sender.on('did-navigate', release)
  event.sender.on('destroyed', release)
}

export function registerQemuVmIpc(rendererUrl: string): void {
  controller = new QemuVmController()
  expectedUrl = new URL(rendererUrl)
  ipcMain.handle('hermes:qemu:status', event => {
    if (!trusted(event, false)) throw new Error('Untrusted QEMU status request')
    const status = controller!.status()
    return { ...status, inputEnabled: paneOwner.owns(event.sender.id) && status.inputEnabled }
  })
  ipcMain.handle('hermes:qemu:visible', (event, visible: unknown) => {
    if (!trusted(event, visible !== false) || typeof visible !== 'boolean') throw new Error('Invalid QEMU pane visibility')
    if (visible) {
      if (paneOwner.current !== null && paneOwner.current !== event.sender.id) releaseOwner(paneOwner.current)
      paneOwner.claim(event.sender.id)
      const window = BrowserWindow.fromWebContents(event.sender)
      if (!window || window.isDestroyed()) throw new Error('QEMU console window is unavailable')
      watchOwner(event, window)
      controller!.setPaneVisible(true)
    } else {
      releaseOwner(event.sender.id)
    }
    return controller!.status()
  })
  ipcMain.handle('hermes:qemu:start', async (event, request?: unknown) => {
    if (!trusted(event)) throw new Error('Untrusted QEMU start request')
    if (!paneOwner.owns(event.sender.id)) throw new Error('Open the QEMU console pane before starting a VM')
    if (request !== undefined && request !== 'firmware-smoke' && request !== 'boot-existing' && request !== 'install') throw new Error('Invalid QEMU start mode')
    if (request === 'firmware-smoke' && app.isPackaged) throw new Error('Firmware smoke is available only in an unpackaged developer build')
    const developerSmoke = !app.isPackaged && request === 'firmware-smoke'
    const bootExisting = request === 'boot-existing'
    let iso: string | undefined
    if (!developerSmoke && !bootExisting) {
      const choice = await dialog.showOpenDialog(BrowserWindow.fromWebContents(event.sender)!, {
        title: 'Choose an operating system installation ISO', properties: ['openFile'],
        filters: [{ name: 'ISO images', extensions: ['iso'] }]
      })
      if (choice.canceled || !choice.filePaths[0]) return { state: controller!.status().state, cancelled: true }
      iso = choice.filePaths[0]
    }
    let networkEnabled = false
    if (!developerSmoke) {
      if (!paneOwner.owns(event.sender.id)) throw new Error('QEMU console pane closed before network choice')
      const networking = await dialog.showMessageBox(BrowserWindow.fromWebContents(event.sender)!, {
        type: 'warning',
        title: 'Guest network access for this boot',
        message: 'The guest can boot offline or use outbound NAT for this boot.',
        detail: 'NAT can reach the Internet and host services; it is not sandbox isolation. No port forwarding, host shares, clipboard, or device passthrough is configured. Hermes will not connect the guest to a gateway or sign in for you.',
        buttons: ['Cancel', 'Boot offline', 'Enable outbound NAT for this boot'],
        defaultId: 1,
        cancelId: 0,
        noLink: true
      })
      if (networking.response === 0) return { state: controller!.status().state, cancelled: true }
      networkEnabled = networking.response === 2
    }
    if (!paneOwner.owns(event.sender.id)) throw new Error('QEMU console pane closed before VM start')
    await controller!.start({ developerSmoke, bootExisting, iso, networkEnabled })
    return controller!.status()
  })
  ipcMain.handle('hermes:qemu:stop', async (event, graceful: unknown) => {
    if (!trusted(event) || !paneOwner.owns(event.sender.id) || typeof graceful !== 'boolean') throw new Error('Invalid QEMU stop request')
    await controller!.stop(graceful)
    return controller!.status()
  })
  ipcMain.handle('hermes:qemu:capture', async event => {
    if (!trusted(event) || !paneOwner.owns(event.sender.id)) throw new Error('Untrusted QEMU frame request')
    return controller!.capture()
  })
  ipcMain.handle('hermes:qemu:input-control', async (event, enabled: unknown) => {
    if (typeof enabled !== 'boolean' || !trusted(event, enabled)) throw new Error('Invalid QEMU control request')
    if (enabled) {
      if (!paneOwner.owns(event.sender.id)) throw new Error('Open the QEMU console before taking control')
      controller!.takeInput()
    } else if (paneOwner.owns(event.sender.id)) {
      await controller!.releaseInput()
    }
    const status = controller!.status()
    return { ...status, inputEnabled: paneOwner.owns(event.sender.id) && status.inputEnabled }
  })
  ipcMain.handle('hermes:qemu:key', async (event, key: unknown, down: unknown) => {
    if (!trusted(event) || !paneOwner.owns(event.sender.id) || typeof key !== 'string' || typeof down !== 'boolean') throw new Error('Invalid QEMU key request')
    await controller!.sendKey(key, down)
  })
  ipcMain.handle('hermes:qemu:pointer', async (event, x: unknown, y: unknown, button?: unknown, down?: unknown) => {
    if (!trusted(event) || !paneOwner.owns(event.sender.id) || typeof x !== 'number' || typeof y !== 'number' || (button !== undefined && typeof button !== 'string') || (down !== undefined && typeof down !== 'boolean')) throw new Error('Invalid QEMU pointer request')
    await controller!.sendPointer(x, y, button as string | undefined, down as boolean | undefined)
  })
}

function showVmMessage(parent: BrowserWindow | null, options: MessageBoxOptions) {
  const owner = parent && !parent.isDestroyed() ? parent : BrowserWindow.getFocusedWindow()
  return owner ? dialog.showMessageBox(owner, options) : dialog.showMessageBox(options)
}

export async function confirmQemuVmExit(parent: BrowserWindow | null): Promise<boolean> {
  const vm = controller
  if (!vm || !vm.hasOwnedVmOrStartup()) return true
  const result = await showVmMessage(parent, {
    type: 'warning',
    title: 'A local QEMU VM is running',
    message: 'Quitting will force the local QEMU VM to power off.',
    detail: 'The guest may lose unsaved work. Choose Cancel to keep Hermes and the VM running.',
    buttons: ['Cancel', 'Power off VM and quit'],
    defaultId: 0,
    cancelId: 0,
    noLink: true
  })
  if (result.response !== 1) return false
  try {
    const stopped = await vm.stopForAppExit()
    if (!stopped) throw new Error('QEMU process is still owned')
    return true
  } catch (error) {
    await showVmMessage(parent, {
      type: 'error',
      title: 'QEMU VM is still running',
      message: 'Hermes will remain open because the owned QEMU process did not exit.',
      detail: error instanceof Error ? error.message : String(error),
      buttons: ['OK'],
      noLink: true
    })
    return false
  }
}
