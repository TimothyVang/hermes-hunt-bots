import fs from 'node:fs'
import path from 'node:path'
import { afterAll, afterEach, beforeAll, expect, it, vi } from 'vitest'

const boundary = vi.hoisted(() => {
  const root = `${process.env.TEMP || process.env.TMPDIR || '/tmp'}/hermes-favicon-isolation-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}`
  return { root, userData: `${root}/default` }
})

vi.mock('electron', () => ({
  app: { getPath: () => boundary.userData },
  BrowserWindow: vi.fn(),
  session: {},
  net: { fetch: async () => new Response('<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><path fill="blue" d="M0 0h1v1H0z"/></svg>', { headers: { 'content-type': 'image/svg+xml' } }) }
}))

import { resolveFaviconCached } from './link-metadata'

let ownsRoot = false
beforeAll(() => {
  fs.mkdirSync(boundary.root)
  ownsRoot = true
  fs.mkdirSync(path.join(boundary.root, 'default'))
  fs.mkdirSync(path.join(boundary.root, 'isolated'))
})
afterEach(() => {
  vi.restoreAllMocks()
  vi.useRealTimers()
})
afterAll(() => {
  if (ownsRoot) fs.rmSync(boundary.root, { recursive: true, force: true })
})

it('reads and persists favicons only in the userData override applied after module import', async () => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-01-01T00:00:00Z'))
  const defaultFile = path.join(boundary.root, 'default/favicon-cache.json')
  const isolatedFile = path.join(boundary.root, 'isolated/favicon-cache.json')
  const defaultIcon = 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg"><text>default synthetic canary</text></svg>'
  const isolatedIcon = 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg"><text>isolated synthetic canary</text></svg>'
  const defaultBytes = JSON.stringify({ icons: { 'cached.example.invalid': { at: Date.now(), icon: defaultIcon } } })
  fs.writeFileSync(defaultFile, defaultBytes)
  fs.writeFileSync(isolatedFile, JSON.stringify({ icons: { 'cached.example.invalid': { at: Date.now(), icon: isolatedIcon } } }))
  boundary.userData = path.join(boundary.root, 'isolated')
  const reads = vi.spyOn(fs, 'readFileSync')
  const writes = vi.spyOn(fs, 'writeFileSync')

  expect(await resolveFaviconCached('https://cached.example.invalid/page')).toBe(isolatedIcon)
  await resolveFaviconCached('https://new.example.invalid/page')
  await vi.runOnlyPendingTimersAsync()
  expect(reads.mock.calls.some(([file]) => path.resolve(String(file)) === path.resolve(defaultFile))).toBe(false)
  expect(writes.mock.calls.map(([file]) => path.resolve(String(file)))).toEqual([path.resolve(isolatedFile)])
  vi.restoreAllMocks()
  expect(fs.readFileSync(defaultFile, 'utf8')).toBe(defaultBytes)
  const saved = JSON.parse(fs.readFileSync(isolatedFile, 'utf8')).icons
  expect(Object.keys(saved).sort()).toEqual(['cached.example.invalid', 'new.example.invalid'])
  expect(saved['cached.example.invalid'].icon).toBe(isolatedIcon)
})
