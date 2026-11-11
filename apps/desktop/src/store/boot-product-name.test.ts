import { afterEach, expect, it, vi } from 'vitest'

// The boot overlay's first line, read at module load for one build variant.
async function initialBootMessage(variant: '' | 'hunt') {
  vi.resetModules()
  vi.doMock('@/variant', () => ({
    DESKTOP_VARIANT: variant,
    IS_HUNT_VARIANT: variant === 'hunt',
    PRODUCT_NAME: variant === 'hunt' ? 'Hunt Command' : 'Hermes'
  }))

  // Fresh module instance after resetModules: the variant is read at module load.
  const { $desktopBoot } = await import('./boot')

  return $desktopBoot.get().message
}

afterEach(() => {
  vi.doUnmock('@/variant')
  vi.resetModules()
})

it('the boot overlay names Hunt Command in the hunt build and keeps the stock copy otherwise', async () => {
  expect(await initialBootMessage('hunt')).toBe('Starting Hunt Command…')
  expect(await initialBootMessage('')).toBe('Starting Hermes Desktop…')
})
