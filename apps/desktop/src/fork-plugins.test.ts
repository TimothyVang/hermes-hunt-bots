import { expect, test } from 'vitest'

import forkPlugins from '@/fork-plugins'

import huntBotsPlugins from './fork-plugins'
import noPlugins from './fork-plugins.none'

test('the hunt-bots entry carries the Hunting Lab, the Hermes entry nothing, and this build gets its variant', () => {
  expect(Object.values(huntBotsPlugins).map(module => module.default.id)).toEqual(['hunt-lab'])
  expect(noPlugins).toEqual({})
  expect(forkPlugins).toBe(process.env.HERMES_DESKTOP_VARIANT === 'hunt-bots' ? huntBotsPlugins : noPlugins)
})
