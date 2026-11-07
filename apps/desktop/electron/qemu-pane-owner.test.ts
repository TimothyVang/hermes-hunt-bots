import assert from 'node:assert/strict'
import { test } from 'vitest'
import { QemuPaneOwner } from './qemu-pane-owner'

test('a replacement pane takes ownership and a stale close cannot release it', () => {
  const owners = new QemuPaneOwner()
  owners.claim(11)
  owners.claim(22)

  assert.equal(owners.release(11), false)
  assert.equal(owners.owns(22), true)
  assert.equal(owners.active, true)
})

test('hide and destruction release only the currently owning pane', () => {
  const owners = new QemuPaneOwner()
  owners.claim(11)

  // Both BrowserWindow.hide and WebContents.destroyed route through release.
  assert.equal(owners.release(11), true)
  assert.equal(owners.active, false)
  assert.equal(owners.release(11), false)
  owners.claim(22)
  assert.equal(owners.release(22), true)
  assert.equal(owners.current, null)
})
