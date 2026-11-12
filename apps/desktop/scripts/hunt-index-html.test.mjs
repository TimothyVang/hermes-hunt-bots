import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { expect, test } from 'vitest'

import { huntIndexHtml } from '../vite.config.ts'

test('the hunt build retitles index.html and pre-paints dark; nothing else in it changes', () => {
  const stock = readFileSync(join(import.meta.dirname, '../index.html'), 'utf8')
  const hunt = huntIndexHtml.transformIndexHtml(stock)

  expect(stock).toContain('<title>Hermes</title>')
  expect(stock).toContain("const dark = window.matchMedia('(prefers-color-scheme: dark)').matches")
  expect(hunt).toContain('<title>Hunt Command</title>')
  // With no boot palette yet (a fresh profile), the first frame is the dark fallback, not the OS's.
  expect(hunt).toContain('const dark = true')
  expect(
    hunt
      .replace('<title>Hunt Command</title>', '<title>Hermes</title>')
      .replace('const dark = true', "const dark = window.matchMedia('(prefers-color-scheme: dark)').matches")
  ).toBe(stock)
})
