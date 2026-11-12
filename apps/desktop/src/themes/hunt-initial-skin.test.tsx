import { act, cleanup, render } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { useTheme } from './context'

// HUNT_COMMAND_THEME, as the bundled hunt-lab plugin (framework/hunt_lab/desktop/plugin.js) contributes it.
const huntTheme = {
  name: 'hunt-command',
  label: 'Hunt Command',
  description: 'Neutral dark, white ink, colour only for state',
  colors: {
    background: '#141414',
    foreground: '#FFFFFF',
    card: '#161616',
    cardForeground: '#FFFFFF',
    muted: '#1C1C1C',
    mutedForeground: '#999999',
    popover: '#232323',
    popoverForeground: '#FFFFFF',
    primary: '#FFFFFF',
    primaryForeground: '#161616',
    secondary: '#1C1C1C',
    secondaryForeground: '#B4B4B4',
    accent: '#222222',
    accentForeground: '#FFFFFF',
    border: '#2B2B2B',
    input: '#3A3A3A',
    ring: '#5D9BFF',
    midground: '#FFFFFF',
    midgroundForeground: '#0A0A0A',
    destructive: '#F0565B',
    destructiveForeground: '#FFFFFF'
  }
}

const stockDefaultSkin = { name: 'default', colors: {} }

interface LaunchOptions {
  pluginTheme?: boolean
  /** The bridge's `display.skin` for the boot profile; null when the config sets none. */
  localSkin?: typeof stockDefaultSkin | null
}

/** A fresh renderer launch of one build variant: module state reloads, localStorage survives.
 *  `painted` lists every skin the document wore, boot paint first. */
async function launch(variant: '' | 'hunt', { pluginTheme = true, localSkin = stockDefaultSkin }: LaunchOptions = {}) {
  cleanup()
  Object.defineProperty(window, 'hermesDesktop', {
    configurable: true,
    value: localSkin ? { localSkin: { profile: 'default', skin: localSkin } } : {}
  })
  vi.resetModules()
  vi.doMock('@/variant', () => ({ DESKTOP_VARIANT: variant, IS_HUNT_VARIANT: variant === 'hunt' }))

  const root = window.document.documentElement
  root.removeAttribute('data-hermes-theme')
  const records: MutationRecord[] = []
  const paints = new MutationObserver(list => records.push(...list))
  paints.observe(root, { attributeFilter: ['data-hermes-theme'], attributeOldValue: true })

  // In the app one synchronous module graph evaluates the theme context and then the bundled
  // plugins (app/contrib/controller.tsx), and a deferred boot paint runs after both. Vitest
  // evaluates modules asynchronously, so hold the deferred paint and run it after registration.
  const realQueueMicrotask = globalThis.queueMicrotask
  const deferredPaints: VoidFunction[] = []
  vi.stubGlobal('queueMicrotask', (task: VoidFunction) =>
    task.name === 'bootPaint' ? deferredPaints.push(task) : realQueueMicrotask(task)
  )

  // Fresh module instances after resetModules: the variant is read at module load.
  const [context, { registry }, { THEMES_AREA }] = await Promise.all([
    import('./context'),
    import('@/contrib/registry'),
    import('./user-themes')
  ])

  if (pluginTheme) {
    registry.register({ area: THEMES_AREA, data: huntTheme, id: 'theme', source: 'plugin:hunt-lab' })
  }

  vi.unstubAllGlobals()
  deferredPaints.forEach(paint => paint())

  const api: { theme: ReturnType<typeof useTheme> | null; painted: string[] } = { theme: null, painted: [] }

  function Probe() {
    api.theme = context.useTheme()

    return null
  }

  render(
    <context.ThemeProvider>
      <Probe />
    </context.ThemeProvider>
  )

  records.push(...paints.takeRecords())
  paints.disconnect()
  // Each record holds the value before its change: the first one's is the cleared marker.
  api.painted = [...records.map(record => record.oldValue ?? ''), root.dataset.hermesTheme ?? '']
    .slice(1)
    .filter((skin, index, all) => skin !== all[index - 1])

  return api
}

describe('the Hunt Command build opens a fresh profile on its plugin theme', () => {
  beforeEach(() => window.localStorage.clear())

  afterEach(() => {
    cleanup()
    window.localStorage.clear()
    Reflect.deleteProperty(window, 'hermesDesktop')
    vi.doUnmock('@/variant')
    vi.resetModules()
  })

  it.each([
    ['display.skin: default', stockDefaultSkin],
    ['display.skin unset', null]
  ])('hunt: a profile with no pick (%s) paints hunt-command from the first boot paint on', async (_label, localSkin) => {
    const api = await launch('hunt', { localSkin })
    expect(api.theme?.themeName).toBe('hunt-command')
    // No nous frame before the plugin's theme registers.
    expect(api.painted).toEqual(['hunt-command'])
  })

  it('hunt: falls back to nous while the plugin theme is not registered (plugin turned off)', async () => {
    const api = await launch('hunt', { pluginTheme: false })
    expect(api.theme?.themeName).toBe('nous')
  })

  it("hunt: the user's explicit pick wins over the initial theme across relaunch", async () => {
    let api = await launch('hunt')
    act(() => api.theme?.setTheme('nous'))
    expect(api.theme?.themeName).toBe('nous')

    api = await launch('hunt')
    expect(api.theme?.themeName).toBe('nous')
  })

  it('stock Hermes keeps nous for a profile with no pick even with the theme registered', async () => {
    const api = await launch('')
    expect(api.theme?.themeName).toBe('nous')
    expect(api.painted).toEqual(['nous'])
  })

  it('hunt: a profile with no mode pick starts dark; an explicit pick wins across relaunch', async () => {
    let api = await launch('hunt')
    expect(api.theme?.mode).toBe('dark')
    act(() => api.theme?.setMode('light'))

    api = await launch('hunt')
    expect(api.theme?.mode).toBe('light')
  })

  it('stock Hermes keeps following the OS for a profile with no mode pick', async () => {
    const api = await launch('')
    expect(api.theme?.mode).toBe('system')
  })
})
