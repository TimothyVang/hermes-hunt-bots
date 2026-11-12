import { afterEach, expect, it, vi } from 'vitest'

async function offerPending(variant: '' | 'hunt') {
  vi.resetModules()
  vi.doMock('@/variant', () => ({
    DESKTOP_VARIANT: variant,
    IS_HUNT_VARIANT: variant === 'hunt',
    PRODUCT_NAME: variant === 'hunt' ? 'Hunt Command' : 'Hermes'
  }))
  // A fresh module instance after resetModules: the variant is read at module load.
  const { sharedMetricsOfferPending } = await import('./shared-metrics')

  return [
    sharedMetricsOfferPending({ decided: false, enabled: false, send: false }),
    sharedMetricsOfferPending({ decided: true, enabled: false, send: false }),
    sharedMetricsOfferPending(null)
  ]
}

afterEach(() => {
  vi.doUnmock('@/variant')
  vi.resetModules()
})

it('stock Hermes offers usage stats to a profile that never answered', async () => {
  expect(await offerPending('')).toEqual([true, false, false])
})

it('Hunt Command never offers usage stats, so an unanswered profile stays off', async () => {
  expect(await offerPending('hunt')).toEqual([false, false, false])
})
