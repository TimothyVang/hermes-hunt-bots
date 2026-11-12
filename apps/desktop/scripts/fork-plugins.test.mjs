import assert from 'node:assert/strict'
import path from 'node:path'
import { test } from 'vitest'

import { forkPluginsEntry } from './fork-plugins.mjs'

const desktop = path.resolve(import.meta.dirname, '..')

test('only a hunt-bots build resolves the fork plugins; every Hermes variant gets none', () => {
  assert.equal(forkPluginsEntry(desktop, { HERMES_DESKTOP_VARIANT: 'hunt-bots' }), path.join(desktop, 'src/fork-plugins.ts'))
  for (const variant of [undefined, '', 'light', 'bundled', 'store']) {
    assert.equal(forkPluginsEntry(desktop, { HERMES_DESKTOP_VARIANT: variant }), path.join(desktop, 'src/fork-plugins.none.ts'), String(variant))
  }
})
