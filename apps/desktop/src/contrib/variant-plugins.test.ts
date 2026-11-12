import { afterEach, describe, expect, it, vi } from 'vitest'

import { variantPluginModules as huntModules } from './variant-plugins.hunt'

vi.mock('./runtime-loader', () => ({ watchRuntimePlugins: vi.fn() }))

// Fresh plugin discovery (its one-shot guard and stores) with the given variant module set.
async function discover(modules: typeof huntModules) {
  vi.resetModules()
  vi.doMock('@/contrib/variant-plugins', () => ({ variantPluginModules: modules }))

  // Fresh module instances after resetModules: discovery runs once per module instance.
  const [{ discoverBundledPlugins }, store, { registry }] = await Promise.all([
    import('./plugins'),
    import('./plugins-store'),
    import('./registry')
  ])

  // Other in-tree bundled plugins are outside this test.
  store.$pluginDecisions.set({ accent: false, kanban: false, 'hermes-bots': false })
  discoverBundledPlugins()

  return { records: store.$pluginRecords.get(), registry }
}

describe('variant-bundled plugins', () => {
  afterEach(() => {
    vi.doUnmock('@/contrib/variant-plugins')
    vi.resetModules()
  })

  it('the Hunt Command set is the two framework/ plugins, both on by default', () => {
    const plugins = Object.values(huntModules).map(mod => mod.default)
    expect(plugins.map(plugin => [plugin.id, plugin.defaultEnabled])).toEqual([
      ['cybersecurity-workspace', true],
      ['hunt-lab', true]
    ])
  })

  it('stock Hermes bundles no variant plugin', async () => {
    const { records } = await discover({})
    expect(records['hunt-lab']).toBeUndefined()
    expect(records['cybersecurity-workspace']).toBeUndefined()
  })

  it('hunt: both plugins load as bundled with their pages and the Hunt Command theme', async () => {
    const { records, registry } = await discover(huntModules)

    for (const id of ['hunt-lab', 'cybersecurity-workspace']) {
      expect(records[id]).toMatchObject({ kind: 'bundled', status: 'loaded' })
    }

    const routes = registry.getArea('routes').map(item => item.data)

    for (const path of ['/hunt-lab', '/hunt-board', '/cybersecurity-workspace']) {
      expect(routes).toContainEqual(expect.objectContaining({ path }))
    }

    expect(registry.getArea('themes').map(item => item.data)).toContainEqual(
      expect.objectContaining({ name: 'hunt-command' })
    )
  })
})
