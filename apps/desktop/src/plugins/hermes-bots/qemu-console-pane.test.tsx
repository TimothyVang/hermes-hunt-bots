import { useStore } from '@nanostores/react'
import { act, cleanup, fireEvent, render, type RenderResult } from '@testing-library/react'
import { atom, type WritableAtom } from 'nanostores'
import type { ButtonHTMLAttributes } from 'react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import type { QemuVmStatus } from '../../../electron/qemu-vm'

vi.mock('@hermes/plugin-sdk', () => {
  return {
    Button: ({ children, ...props }: ButtonHTMLAttributes<HTMLButtonElement>) => <button {...props}>{children}</button>,
    useValue: (store: WritableAtom<boolean>) => useStore(store),
    host: { paneVisibility: () => visible, notifyError: vi.fn() }
  }
})

import { QemuConsolePane } from './qemu-console-pane'

type Bridge = Window['hermesDesktop']['qemu']
const visible = atom(true)
const syntheticFrame = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII='
let vm: QemuVmStatus
let bridge: Bridge
let keyEvents: Array<[string, boolean]>

beforeEach(() => {
  visible.set(true)
  keyEvents = []
  vm = {
    state: 'running', owned: true, available: true, developerSmokeAvailable: true,
    hasDisk: false, inputEnabled: false, inputReleaseFailed: false, networkEnabled: false
  }
  bridge = {
    status: vi.fn(async () => ({ ...vm })),
    setPaneVisible: vi.fn(async shown => { if (!shown) vm.inputEnabled = false; return { ...vm } }),
    capture: vi.fn(async () => null),
    inputControl: vi.fn(async enabled => { vm.inputEnabled = enabled; return { ...vm } }),
    key: vi.fn(async (key, down) => { keyEvents.push([key, down]) }),
    pointer: vi.fn(async () => undefined),
    start: vi.fn(async () => { vm.state = 'running'; vm.owned = true; return { ...vm } }),
    stop: vi.fn(async () => { vm.state = 'stopped'; vm.owned = false; vm.inputEnabled = false; return { ...vm } })
  }
  vi.stubGlobal('hermesDesktop', { qemu: bridge })
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

async function openConsole() {
  let view!: RenderResult
  await act(async () => { view = render(<QemuConsolePane />) })
  return view
}

it('requires takeover and translates physical modifiers and digits without duplicate key-downs', async () => {
  const view = await openConsole()
  const pane = view.getByLabelText('Local QEMU boot console')
  fireEvent.keyDown(pane, { code: 'KeyA', key: 'a' })
  expect(keyEvents).toEqual([])
  await act(async () => { fireEvent.click(view.getByRole('button', { name: 'Take keyboard/mouse control' })) })
  await act(async () => {
    fireEvent.keyDown(pane, { code: 'ControlLeft', key: 'Control' })
    fireEvent.keyDown(pane, { code: 'Digit1', key: '1' })
    fireEvent.keyDown(pane, { code: 'Digit1', key: '1', repeat: true })
    fireEvent.keyUp(pane, { code: 'Digit1', key: '1' })
    fireEvent.keyUp(pane, { code: 'ControlLeft', key: 'Control' })
  })
  expect(keyEvents).toEqual([['ctrl', true], ['1', true], ['1', false], ['ctrl', false]])
})

it('revokes takeover on window blur even when there is no related focus target', async () => {
  const view = await openConsole()
  const pane = view.getByLabelText('Local QEMU boot console')
  await act(async () => { fireEvent.click(view.getByRole('button', { name: 'Take keyboard/mouse control' })) })
  const release = Promise.withResolvers<void>()
  vi.mocked(bridge.inputControl).mockImplementation(async enabled => {
    vm.inputEnabled = enabled
    if (!enabled) await release.promise
    return { ...vm }
  })
  await act(async () => { fireEvent.blur(window) })
  expect(vm.inputEnabled).toBe(false)
  await act(async () => { release.resolve(); await release.promise })
  expect(pane.tabIndex).toBe(-1)
  expect(view.getByRole('button', { name: 'Take keyboard/mouse control' })).toBeTruthy()
  fireEvent.keyDown(pane, { code: 'KeyA', key: 'a' })
  expect(keyEvents).toEqual([])
})

it('does not paint a frame completed after hiding, but resumes with a fresh visible capture', async () => {
  vi.useFakeTimers()
  const stale = Promise.withResolvers<string>()
  vi.mocked(bridge.capture).mockReturnValueOnce(stale.promise).mockResolvedValue(syntheticFrame)
  const view = await openConsole()
  await act(async () => { await vi.advanceTimersByTimeAsync(750) })
  await act(async () => { visible.set(false) })
  await act(async () => { stale.resolve(syntheticFrame); await stale.promise })
  expect(view.queryByRole('img')).toBeNull()
  await act(async () => { visible.set(true) })
  await act(async () => { await vi.advanceTimersByTimeAsync(750) })
  expect(view.getByRole('img').getAttribute('src')).toBe(syntheticFrame)
})

it('gates boot actions on engine availability and the native developer-smoke capability', async () => {
  vi.useFakeTimers()
  Object.assign(vm, { state: 'stopped', owned: false, available: false, hasDisk: true })
  const view = await openConsole()
  for (const name of ['Install from ISO…', 'Boot existing VM', 'Firmware smoke (diskless)']) {
    expect((view.getByRole('button', { name }) as HTMLButtonElement).disabled).toBe(true)
  }
  Object.assign(vm, { available: true, developerSmokeAvailable: false })
  await act(async () => { await vi.advanceTimersByTimeAsync(1200) })
  expect(view.queryByRole('button', { name: 'Firmware smoke (diskless)' })).toBeNull()
  expect((view.getByRole('button', { name: 'Boot existing VM' }) as HTMLButtonElement).disabled).toBe(false)
})

it('keeps power-off available but disables takeover after an unacknowledged input release', async () => {
  vm.inputReleaseFailed = true
  const view = await openConsole()
  expect(view.getByRole('alert')).toBeTruthy()
  expect((view.getByRole('button', { name: 'Take keyboard/mouse control' }) as HTMLButtonElement).disabled).toBe(true)
  expect((view.getByRole('button', { name: 'Power off immediately' }) as HTMLButtonElement).disabled).toBe(false)
})

it('does not hide an owned process behind launch failure and permits explicit power-off', async () => {
  vm.state = 'error'
  const view = await openConsole()
  expect(view.queryByRole('button', { name: 'Install from ISO…' })).toBeNull()
  expect((view.getByRole('button', { name: 'Take keyboard/mouse control' }) as HTMLButtonElement).disabled).toBe(true)
  await act(async () => { fireEvent.click(view.getByRole('button', { name: 'Power off immediately' })) })
  expect(vm.owned).toBe(false)
  expect(view.getByRole('button', { name: 'Install from ISO…' })).toBeTruthy()
})
