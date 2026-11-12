// product-identity.cjs is the single derivation of the desktop product
// identity; electron/product-identity.ts re-exports it. These tests hold
// the identity contract: the TS accessor resolves to the .cjs object, and
// the two variants disagree on every OS-visible marker (side-by-side
// installs must not collide).
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import { createRequire } from 'node:module'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import type { AppInfo as BuilderAppInfo, Configuration, Metadata, Packager, Protocol } from 'app-builder-lib'
import { build, type BuildResult } from 'esbuild'
import { afterEach, beforeEach, test, vi } from 'vitest'

import type { applyDesktopIdentity, defaultThemeSource, ProductIdentity } from './product-identity'

type PackagingConfiguration = Omit<Configuration, 'extraMetadata' | 'mac' | 'msix' | 'protocols' | 'win'> & {
  extraMetadata: Metadata
  mac: Omit<NonNullable<Configuration['mac']>, 'extendInfo'> & { extendInfo: { CFBundleExecutable: string } }
  msix: NonNullable<Configuration['msix']>
  protocols: Protocol[]
  win: NonNullable<Configuration['win']>
}

const require: NodeJS.Require = createRequire(import.meta.url)

beforeEach((): void => {
  vi.resetModules()
})

afterEach((): void => {
  delete process.env.HERMES_DESKTOP_VARIANT
  delete process.env.HERMES_PAYLOAD_TAG
  delete process.env.HERMES_BUILD_COMMIT
  delete process.env.HERMES_PAYLOAD_VERSION
  vi.resetModules()
})

async function identityForVariant(variant: string | undefined): Promise<ProductIdentity> {
  if (variant === undefined) {
    delete process.env.HERMES_DESKTOP_VARIANT
  } else {
    process.env.HERMES_DESKTOP_VARIANT = variant
  }

  delete require.cache[require.resolve('../product-identity.cjs')]
  vi.resetModules()

  return (await import('./product-identity')).PRODUCT_IDENTITY
}

test('baked runtime identity never evaluates ambient build selectors', async (): Promise<void> => {
  const dir: string = fs.mkdtempSync(path.join(os.tmpdir(), 'baked-identity-'))

  try {
    const identity: ProductIdentity = await identityForVariant('bundled')

    const result: BuildResult<{ write: false }> = await build({
      stdin: {
        contents: "import {PRODUCT_IDENTITY} from './product-identity'; console.log(JSON.stringify(PRODUCT_IDENTITY))",
        resolveDir: import.meta.dirname
      },
      bundle: true,
      platform: 'node',
      format: 'esm',
      write: false,
      define: { __HERMES_PRODUCT_IDENTITY__: JSON.stringify(identity) }
    })

    const file: string = path.join(dir, 'identity.mjs')
    fs.writeFileSync(file, result.outputFiles[0].text)

    const actual: unknown = JSON.parse(
      execFileSync(process.execPath, [file], {
        encoding: 'utf8',
        env: { ...process.env, HERMES_DESKTOP_VARIANT: 'store', HERMES_BUILD_COMMIT: 'a'.repeat(40) }
      })
    )

    assert.deepEqual(actual, identity)
  } finally {
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

test('nonstable runtime pins userData before the app name can change', async (): Promise<void> => {
  const stable: ProductIdentity = await identityForVariant('bundled')
  process.env.HERMES_PAYLOAD_TAG = 'v0.28.0+canary.20260818T000000Z'
  const canary: ProductIdentity = await identityForVariant('bundled')
  const runtime: { applyDesktopIdentity: typeof applyDesktopIdentity } = await import('./product-identity')
  const root: string = fs.mkdtempSync(path.join(os.tmpdir(), 'identity-userdata-'))
  const paths: Record<string, string> = { appData: root, userData: path.join(root, 'Hermes') }
  let name: string = 'Hermes'

  const app: Parameters<typeof applyDesktopIdentity>[0] = {
    getPath: (key: string): string => paths[key],
    setPath: (key: string, value: string): void => {
      assert.ok(fs.statSync(value).isDirectory())
      paths[key] = value
    },
    setName: (value: string): void => {
      name = value
    }
  }

  try {
    assert.equal(runtime.applyDesktopIdentity(app, stable), null)
    assert.equal(paths.userData, path.join(root, 'Hermes'))
    assert.equal(runtime.applyDesktopIdentity(app, canary), canary.displayName)
    assert.equal(paths.userData, path.join(paths.appData, canary.appNamePascal))
    assert.equal(name, canary.displayName)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('nonstable identity preserves an explicit isolated userData directory', async (): Promise<void> => {
  process.env.HERMES_PAYLOAD_TAG = 'v0.28.0+canary.20260818T000000Z'
  const canary = await identityForVariant('bundled')
  const runtime = await import('./product-identity')
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'identity-isolated-'))
  const isolated = path.join(root, 'isolated')
  let selected = ''
  let displayedName = ''

  try {
    assert.equal(runtime.applyDesktopIdentity({
      getPath: (): string => assert.fail('The default appData path must not be accessed'),
      setPath: (_name: 'userData', value: string): void => { selected = value },
      setName: (value: string): void => { displayedName = value }
    }, canary, { HERMES_DESKTOP_USER_DATA_DIR: isolated }), canary.displayName)
    assert.equal(selected, isolated)
    assert.equal(displayedName, canary.displayName)
    assert.ok(fs.statSync(isolated).isDirectory())
    assert.deepEqual(fs.readdirSync(root), ['isolated'])
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test.each([
  [undefined, 'Hermes', 'hermes', 'latest', 'canary'],
  ['bundled', 'Hermes Agent', 'hermes', 'latest', 'canary'],
  ['light', 'Hermes Light', 'hermes-light', 'light', 'light-canary']
] as const)(
  '%s separates stable, canary and independent commits',
  async (
    variant: string | undefined,
    display: string,
    cli: string,
    channel: string,
    canaryChannel: string
  ): Promise<void> => {
    const stable: ProductIdentity = await identityForVariant(variant)
    assert.equal(stable.displayName, display)
    assert.equal(stable.channel, channel)
    assert.equal(stable.light, variant === 'light')
    assert.equal(stable.storeMsix, undefined)
    const identities: ProductIdentity[] = [stable]

    for (const [tag, commit, expectedCli, expectedChannel] of [
      ['v1.2.3+canary.20260818T000000Z', '', `${cli}-canary`, canaryChannel],
      ['', 'abcdef1234567890abcdef1234567890abcdef12', `${cli}-abcdef1`, null],
      ['', '1234567890abcdef1234567890abcdef12345678', `${cli}-1234567`, null]
    ] as const) {
      process.env.HERMES_PAYLOAD_TAG = tag
      process.env.HERMES_BUILD_COMMIT = commit
      const current: ProductIdentity = await identityForVariant(variant)
      assert.equal(current.channel, expectedChannel)
      assert.equal(current.cliName, expectedCli)
      assert.equal(current.windowsExecutableName, expectedCli)
      assert.equal(current.artifactNamePascal, stable.artifactNamePascal)
      assert.deepEqual(current, await identityForVariant(variant))

      if (commit) {
        assert.equal(current.displayName, `${display} ${commit.slice(0, 7)}`)
      }

      for (const previous of identities) {
        for (const field of [
          'displayName',
          'appId',
          'appNamePascal',
          'msixAppIdWithOrg',
          'windowsExecutableName',
          'cliName'
        ] as const) {
          assert.notEqual(current[field], previous[field], `${field} must isolate installations`)

          if (commit) {
            assert.ok(current[field].includes(commit.slice(0, 7)))
          }
        }
      }

      identities.push(current)
    }

    process.env.HERMES_BUILD_COMMIT = 'not-a-sha'
    process.env.HERMES_PAYLOAD_TAG = 'v1.2.3'
    assert.deepEqual(await identityForVariant(variant), stable)
  }
)

test('light and bundled retain distinct OS markers from the full client', async (): Promise<void> => {
  const full: ProductIdentity = await identityForVariant(undefined)

  for (const variant of ['bundled', 'light']) {
    const other: ProductIdentity = await identityForVariant(variant)

    for (const field of ['displayName', 'appId', 'appNamePascal'] as const) {
      assert.notEqual(other[field], full[field])
    }

    if (variant === 'light') {
      assert.notEqual(other.msixAppIdWithOrg, full.msixAppIdWithOrg)
      assert.notEqual(other.channel, full.channel)
    }
  }
})

test('hunt is a stable Hunt Command identity with its own userData and no release feed', async (): Promise<void> => {
  const full: ProductIdentity = await identityForVariant(undefined)
  assert.equal(full.hunt, undefined)
  assert.equal(full.displayName, 'Hermes')
  assert.equal(full.appNamePascal, 'Hermes')
  assert.equal(full.channel, 'latest')

  for (const variant of ['bundled', 'light', 'store']) {
    assert.equal((await identityForVariant(variant)).hunt, undefined, `variant ${variant} must not be hunt`)
  }

  const hunt: ProductIdentity = await identityForVariant('hunt')
  assert.equal(hunt.hunt, true)
  assert.equal(hunt.displayName, 'Hunt Command')
  assert.equal(hunt.appId, 'io.github.timothyvang.hunt-command')
  assert.equal(hunt.appNamePascal, 'HuntCommand')
  assert.equal(hunt.artifactNamePascal, 'HuntCommand')
  assert.equal(hunt.windowsExecutableName, 'Hunt Command')
  assert.equal(hunt.channel, null)
  assert.equal(hunt.sourceRepo, 'TimothyVang/hermes-hunt-bots')
  assert.equal(full.sourceRepo, undefined)
  process.env.HERMES_PAYLOAD_TAG = 'v0.28.0+canary.20260818T000000Z'
  assert.equal((await identityForVariant('hunt')).channel, null)
  delete process.env.HERMES_PAYLOAD_TAG
  assert.deepEqual(await identityForVariant('hunt'), hunt)

  for (const field of ['displayName', 'appId', 'appNamePascal', 'msixAppIdWithOrg'] as const) {
    assert.notEqual(hunt[field], full[field])
  }

  const runtime: {
    applyDesktopIdentity: typeof applyDesktopIdentity
    defaultThemeSource: typeof defaultThemeSource
  } = await import('./product-identity')

  // Before the renderer reports a mode: stock follows the OS, Hunt Command's design is dark.
  assert.equal(runtime.defaultThemeSource(full), 'system')
  assert.equal(runtime.defaultThemeSource(hunt), 'dark')
  const root: string = fs.mkdtempSync(path.join(os.tmpdir(), 'identity-hunt-'))
  const paths: Record<string, string> = { appData: root, userData: path.join(root, 'Hermes') }
  let name: string = 'Hermes'

  const app: Parameters<typeof applyDesktopIdentity>[0] = {
    getPath: (key: string): string => paths[key],
    setPath: (key: string, value: string): void => {
      paths[key] = value
    },
    setName: (value: string): void => {
      name = value
    }
  }

  try {
    assert.equal(runtime.applyDesktopIdentity(app, full), null)
    assert.equal(paths.userData, path.join(root, 'Hermes'))
    assert.equal(runtime.applyDesktopIdentity(app, hunt), 'Hunt Command')
    assert.equal(paths.userData, path.join(root, 'HuntCommand'))
    assert.equal(name, 'Hunt Command')
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }

  delete require.cache[require.resolve('../electron-builder.config.cjs')]
  const config: PackagingConfiguration = require('../electron-builder.config.cjs')
  // Electron's boot-time userData lookup must already use the Hunt Command name.
  assert.equal(config.extraMetadata.productName, 'Hunt Command')
  assert.equal(config.extraMetadata.name, 'HuntCommand')
  assert.equal(config.publish, null)
  assert.equal(config.mac.publish, null)
})

test('Hunt Command ships under its own publisher; every Hermes variant keeps Nous Research', async (): Promise<void> => {
  const load = (): PackagingConfiguration & { copyright?: string } => {
    delete require.cache[require.resolve('../electron-builder.config.cjs')]

    return require('../electron-builder.config.cjs')
  }

  const hunt: ProductIdentity = await identityForVariant('hunt')
  assert.equal(hunt.msixAppIdWithOrg, 'TimothyVang.HuntCommand')
  assert.equal(hunt.publisher, 'TimothyVang')
  assert.match(hunt.copyright ?? '', /^Copyright © 2026 TimothyVang\. Based on Hermes, Copyright © 2026 Nous Research\.$/)
  const huntConfig = load()
  // electron-builder writes the exe CompanyName from the package author and LegalCopyright from `copyright`.
  assert.deepEqual(huntConfig.extraMetadata.author, { name: 'TimothyVang' })
  assert.equal(huntConfig.extraMetadata.desktopName, 'io.github.timothyvang.hunt-command')
  assert.equal(huntConfig.copyright, hunt.copyright)
  assert.equal(huntConfig.msix.identityName, 'TimothyVang.HuntCommand')
  assert.equal(huntConfig.msix.publisher, 'CN=TimothyVang')
  assert.equal(huntConfig.msix.publisherDisplayName, 'TimothyVang')

  process.env.HERMES_BUILD_COMMIT = 'abcdef1234567890abcdef1234567890abcdef12'
  const commit: ProductIdentity = await identityForVariant('hunt')
  assert.equal(commit.appId, 'io.github.timothyvang.hunt-command-abcdef1')
  assert.equal(commit.msixAppIdWithOrg, 'TimothyVang.HuntCommandCommitabcdef1')
  delete process.env.HERMES_BUILD_COMMIT

  for (const variant of [undefined, 'light', 'bundled', 'store']) {
    const identity: ProductIdentity = await identityForVariant(variant)
    assert.match(identity.appId, /^com\.nousresearch\./)
    assert.match(identity.msixAppIdWithOrg, /^NousResearch\./)
    assert.equal(identity.publisher, undefined)
    assert.equal(identity.copyright, undefined)
    const config = load()
    assert.equal('copyright' in config, false)
    assert.equal('author' in config.extraMetadata, false)
    assert.match(String(config.msix.publisherDisplayName), /^Nous Research/)
  }
})

test('packaging isolates boot metadata and executable names without renaming release artifacts', async (): Promise<void> => {
  const pkg: { name: string; productName: string; version: string; description: string } = require('../package.json')

  const load: () => PackagingConfiguration = (): PackagingConfiguration => {
    delete require.cache[require.resolve('../electron-builder.config.cjs')]

    return require('../electron-builder.config.cjs')
  }

  const stableIdentity: ProductIdentity = await identityForVariant('bundled')
  const stable: PackagingConfiguration = load()
  assert.equal(stable.extraMetadata.productName || pkg.productName, pkg.productName)

  process.env.HERMES_PAYLOAD_TAG = 'v0.28.0'
  process.env.HERMES_BUILD_COMMIT = ''
  assert.equal(load().msix.customManifestPath, 'build/msix-manifest.xml')

  for (const build of ['canary', 'abcdef1234567890abcdef1234567890abcdef12']) {
    process.env.HERMES_PAYLOAD_TAG = build === 'canary' ? 'v0.28.0+canary.20260818T000000Z' : ''
    process.env.HERMES_BUILD_COMMIT = build === 'canary' ? '' : build
    const identity: ProductIdentity = await identityForVariant('bundled')
    const config: PackagingConfiguration = load()
    // Electron bootstrap gives productName precedence over name. appId alone
    // changes neither its early userData lookup nor its single-instance lock.
    assert.equal(config.extraMetadata.productName, identity.displayName)
    assert.equal(config.extraMetadata.name, identity.appNamePascal)
    assert.notEqual(config.extraMetadata.name, stableIdentity.appNamePascal)
    assert.equal(config.win.executableName, identity.windowsExecutableName)

    const {
      AppInfo
    }: { AppInfo: typeof BuilderAppInfo } = require('../../../node_modules/app-builder-lib/dist/appInfo.js')

    const appInfo: BuilderAppInfo = new AppInfo(
      { config, metadata: { ...pkg, ...config.extraMetadata } } as Packager,
      null,
      config.win
    )

    // Windows packaging, afterPack, rollback preservation and final signing
    // all consume this resolved name, not the display name.
    assert.equal(appInfo.productFilename, identity.windowsExecutableName)
    assert.equal(config.mac.extendInfo.CFBundleExecutable, config.executableName)
    assert.equal(config.artifactName, stable.artifactName)
    assert.equal(config.msix.customManifestPath, 'build/msix-manifest.xml')

    const {
      appIdentity
    }: {
      appIdentity: (desktopDir: string) => { name: string; identity: ProductIdentity }
    } = require('../../../scripts/msix-shared.mjs')

    process.env.HERMES_PAYLOAD_VERSION = '0.28.0'
    const artifact: ReturnType<typeof appIdentity> = appIdentity(fileURLToPath(new URL('../', import.meta.url)))
    assert.equal(artifact.name, identity.artifactNamePascal)
    assert.equal(artifact.identity.msixAppIdWithOrg, config.msix.identityName)
    assert.deepEqual(config.protocols[0].schemes, ['hermes'])

    if (build !== 'canary') {
      assert.equal(config.publish, null)
      assert.equal(config.mac.publish, null)
    }
  }
})

test('store inherits the bundled app identity (shared userData) but swaps the MSIX packaging identity', async (): Promise<void> => {
  const bundled: ProductIdentity = await identityForVariant('bundled')
  const store: ProductIdentity = await identityForVariant('store')

  // Same Electron app: displayName/appNamePascal (-> shared userData dir),
  // appId, and the out-of-store org-prefixed name are all inherited.
  assert.equal(store.store, true)
  assert.equal(store.light, false)
  assert.equal(store.displayName, bundled.displayName)
  assert.equal(store.appNamePascal, bundled.appNamePascal)
  assert.equal(store.appId, bundled.appId)
  assert.equal(store.msixAppIdWithOrg, bundled.msixAppIdWithOrg)
  // The store build never publishes to a feed.
  assert.equal(store.channel, null)
})

test('nonstable builds cannot claim the official Store package', async (): Promise<void> => {
  process.env.HERMES_PAYLOAD_TAG = 'v0.28.0+canary.20260818T000000Z'
  await assert.rejects(identityForVariant('store'), /Store.*stable/)
  delete process.env.HERMES_PAYLOAD_TAG
  process.env.HERMES_BUILD_COMMIT = 'abcdef1234567890abcdef1234567890abcdef12'
  await assert.rejects(identityForVariant('store'), /Store.*stable/)
})

test('store carries the Partner Center MSIX identity and no other variant does', async (): Promise<void> => {
  const store: ProductIdentity = await identityForVariant('store')
  assert.deepEqual(store.storeMsix, {
    identityName: 'NousResearchInc.HermesAgent',
    publisher: 'CN=EE6D86E4-606F-4E38-B940-AD7248C9D519',
    publisherDisplayName: 'Nous Research Inc.'
  })

  for (const v of [undefined, 'bundled', 'light'] as const) {
    assert.equal((await identityForVariant(v)).storeMsix, undefined, `variant ${v} must carry no storeMsix`)
  }
})
