#!/usr/bin/env node

/**
 * Copyright 2026 AyanWorks Technology Solutions Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Build a CycloneDX 1.6 Cryptography BOM (CBOM) from crypto-inventory.json.
 *
 * The inventory is deliberately declarative: every cryptographic asset records
 * where it is used and which provider implements it. This script fails when an
 * evidence pattern disappears from the source, when a dependency that looks
 * like a crypto library is not mapped, or when a weak algorithm appears in a
 * string literal. That keeps the CBOM aligned with the code instead of letting
 * it rot after a refactor or dependency update.
 */

import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

const ASSET_TYPES = new Set(['algorithm', 'certificate', 'protocol', 'related-crypto-material'])
const PRIMITIVES = new Set([
  'drbg',
  'mac',
  'block-cipher',
  'stream-cipher',
  'signature',
  'hash',
  'pke',
  'xof',
  'kdf',
  'key-agree',
  'kem',
  'ae',
  'combiner',
  'other',
  'unknown',
])
const MODES = new Set(['cbc', 'ecb', 'ccm', 'gcm', 'cfb', 'ofb', 'ctr', 'other', 'unknown'])
const PADDINGS = new Set(['pkcs5', 'pkcs7', 'pkcs1v15', 'oaep', 'raw', 'other', 'unknown'])
const CRYPTO_FUNCTIONS = new Set([
  'generate',
  'keygen',
  'encrypt',
  'decrypt',
  'digest',
  'tag',
  'keyderive',
  'sign',
  'verify',
  'encapsulate',
  'decapsulate',
  'other',
  'unknown',
])
const EXECUTION_ENVIRONMENTS = new Set([
  'software-plain-ram',
  'software-encrypted-ram',
  'software-tee',
  'hardware',
  'other',
  'unknown',
])
const IMPLEMENTATION_PLATFORMS = new Set([
  'generic',
  'x86_32',
  'x86_64',
  'armv7-a',
  'armv7-m',
  'armv8-a',
  'armv8-m',
  'armv9-a',
  'armv9-m',
  's390x',
  'ppc64',
  'ppc64le',
  'other',
  'unknown',
])
const CERTIFICATION_LEVELS = new Set([
  'none',
  'fips140-1-l1',
  'fips140-1-l2',
  'fips140-1-l3',
  'fips140-1-l4',
  'fips140-2-l1',
  'fips140-2-l2',
  'fips140-2-l3',
  'fips140-2-l4',
  'fips140-3-l1',
  'fips140-3-l2',
  'fips140-3-l3',
  'fips140-3-l4',
  'cc-eal1',
  'cc-eal1+',
  'cc-eal2',
  'cc-eal2+',
  'cc-eal3',
  'cc-eal3+',
  'cc-eal4',
  'cc-eal4+',
  'cc-eal5',
  'cc-eal5+',
  'cc-eal6',
  'cc-eal6+',
  'cc-eal7',
  'cc-eal7+',
  'other',
  'unknown',
])
const RELATED_TYPES = new Set([
  'private-key',
  'public-key',
  'secret-key',
  'key',
  'ciphertext',
  'signature',
  'digest',
  'initialization-vector',
  'nonce',
  'seed',
  'salt',
  'shared-secret',
  'tag',
  'additional-data',
  'password',
  'credential',
  'token',
  'other',
  'unknown',
])
const MATERIAL_STATES = new Set(['pre-activation', 'active', 'suspended', 'deactivated', 'compromised', 'destroyed'])
const PROTOCOL_TYPES = new Set(['tls', 'ssh', 'ipsec', 'ike', 'sstp', 'wpa', 'other', 'unknown'])

// Algorithm names that must not appear in a string literal unless the
// inventory explicitly says why they are present. This is a safety net for
// weak or out-of-scope crypto; it is intentionally not a full parser.
const SENSITIVE_LITERAL =
  /\b(?:md5|sha-?1\b|sha-?224\b|aes-?128|aes-?192|chacha20|hmac|des\b|3des|rc4|blowfish|p-?192|p-?224|ed448|x448|rsa-?(?:512|1024)|ml-kem|ml-dsa|slh-dsa|pbkdf2|scrypt|argon2|ecdh|diffie-hellman|dsa\b)/i

const CRYPTO_PACKAGE =
  /^(?:@noble\/|@scure\/|crypto-js$|elliptic$|node-forge$|tweetnacl$|libsodium|sodium-native$|@peculiar\/|jose$|openpgp$|pkijs$|asn1js$)/

function fail(message) {
  console.error(`generate-cbom: ${message}`)
  process.exit(1)
}

function parseArgs(argv) {
  const options = {
    inventory: join(ROOT, 'crypto-inventory.json'),
    sbom: join(ROOT, 'sbom', 'sbom.cdx.json'),
    output: join(ROOT, 'sbom', 'cbom.cdx.json'),
  }

  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index]
    const next = argv[index + 1]
    if (arg === '--inventory' && next) {
      options.inventory = resolve(next)
      index++
    } else if (arg === '--sbom' && next) {
      options.sbom = resolve(next)
      index++
    } else if (arg === '--output' && next) {
      options.output = resolve(next)
      index++
    } else if (arg === '--help' || arg === '-h') {
      console.log('Usage: node scripts/generate-cbom.mjs [--inventory FILE] [--sbom FILE] [--output FILE]')
      process.exit(0)
    } else {
      fail(`unknown argument '${arg}'`)
    }
  }

  return options
}

function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'))
  } catch (error) {
    fail(`cannot read ${relative(ROOT, file)}: ${error.message}`)
  }
}

function walk(directory) {
  if (!existsSync(directory)) return []
  const files = []
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry)
    const stat = statSync(path)
    if (stat.isDirectory()) files.push(...walk(path))
    else if (stat.isFile() && entry.endsWith('.ts')) files.push(path)
  }
  return files.sort()
}

function lineNumberAt(content, index) {
  let line = 1
  for (let cursor = 0; cursor < index; cursor++) if (content.charCodeAt(cursor) === 10) line++
  return line
}

function lineAt(content, line) {
  return content.split('\n')[line - 1]?.trim() ?? ''
}

function occurrencesFor(asset, sourceFiles, root) {
  const evidenceFiles = asset.evidenceFiles?.map((file) => resolve(root, file)) ?? sourceFiles
  const occurrences = new Map()

  for (const file of evidenceFiles) {
    if (!existsSync(file)) {
      fail(`${asset.id}: evidence file '${relative(root, file)}' does not exist`)
    }
    const content = readFileSync(file, 'utf8')
    for (const pattern of asset.detect ?? []) {
      let expression
      try {
        expression = new RegExp(pattern, 'gi')
      } catch (error) {
        fail(`${asset.id}: invalid detect pattern '${pattern}': ${error.message}`)
      }
      for (const match of content.matchAll(expression)) {
        if (match.index === undefined) continue
        const line = lineNumberAt(content, match.index)
        const key = `${file}:${line}`
        if (!occurrences.has(key)) {
          occurrences.set(key, {
            location: relative(root, file).split(sep).join('/'),
            line,
            additionalContext: lineAt(content, line).slice(0, 200),
          })
        }
      }
    }
  }

  if (occurrences.size === 0) {
    fail(
      `${asset.id}: none of the detect patterns matched. Update crypto-inventory.json or the source: ` +
        `${(asset.detect ?? []).join(', ')}`,
    )
  }

  return [...occurrences.values()].sort(
    (left, right) => left.location.localeCompare(right.location) || left.line - right.line,
  )
}

function validateOid(oid, id) {
  if (!/^\d+(?:\.\d+)+$/.test(oid)) fail(`${id}: invalid OID '${oid}'`)
}

function validateAlgorithm(properties, id) {
  if (!PRIMITIVES.has(properties.primitive)) fail(`${id}: invalid primitive '${properties.primitive}'`)
  if (properties.mode && !MODES.has(properties.mode)) fail(`${id}: invalid mode '${properties.mode}'`)
  if (properties.padding && !PADDINGS.has(properties.padding)) fail(`${id}: invalid padding '${properties.padding}'`)
  for (const fn of properties.cryptoFunctions ?? []) {
    if (!CRYPTO_FUNCTIONS.has(fn)) fail(`${id}: invalid crypto function '${fn}'`)
  }
  if (properties.executionEnvironment && !EXECUTION_ENVIRONMENTS.has(properties.executionEnvironment)) {
    fail(`${id}: invalid executionEnvironment '${properties.executionEnvironment}'`)
  }
  if (properties.implementationPlatform && !IMPLEMENTATION_PLATFORMS.has(properties.implementationPlatform)) {
    fail(`${id}: invalid implementationPlatform '${properties.implementationPlatform}'`)
  }
  for (const level of properties.certificationLevel ?? []) {
    if (!CERTIFICATION_LEVELS.has(level)) fail(`${id}: invalid certificationLevel '${level}'`)
  }
  if (properties.classicalSecurityLevel !== undefined && !Number.isInteger(properties.classicalSecurityLevel)) {
    fail(`${id}: classicalSecurityLevel must be an integer`)
  }
  if (properties.nistQuantumSecurityLevel !== undefined) {
    const level = properties.nistQuantumSecurityLevel
    if (!Number.isInteger(level) || level < 0 || level > 6) fail(`${id}: nistQuantumSecurityLevel must be 0-6`)
  }
}

function validateRelatedMaterial(properties, id) {
  if (!RELATED_TYPES.has(properties.type)) fail(`${id}: invalid related crypto material type '${properties.type}'`)
  if (properties.state && !MATERIAL_STATES.has(properties.state)) {
    fail(`${id}: invalid related crypto material state '${properties.state}'`)
  }
  if (properties.size !== undefined && !Number.isInteger(properties.size)) {
    fail(`${id}: related crypto material size must be an integer`)
  }
}

function validateProtocol(properties, id) {
  if (!PROTOCOL_TYPES.has(properties.type)) fail(`${id}: invalid protocol type '${properties.type}'`)
}

function providerComponents(inventory, sbom) {
  const components = []
  const byId = new Map()

  for (const [id, definition] of Object.entries(inventory.providers ?? {})) {
    if (definition.fromSbom) {
      const found = (sbom.components ?? []).find(
        (component) =>
          component.name === definition.fromSbom ||
          (component.group ? `${component.group}/${component.name}` : undefined) === definition.fromSbom,
      )
      if (!found) fail(`provider '${id}': '${definition.fromSbom}' is not present in the SBOM`)
      const component = {
        type: found.type ?? 'library',
        'bom-ref': found['bom-ref'] ?? found.purl ?? `provider/${id}`,
        name: found.name,
        version: found.version,
        description: definition.description ?? found.description,
        ...(found.group ? { group: found.group } : {}),
        ...(found.purl ? { purl: found.purl } : {}),
        ...(found.licenses ? { licenses: found.licenses } : {}),
        ...(found.externalReferences ? { externalReferences: found.externalReferences } : {}),
        ...(definition.properties ? { properties: definition.properties } : {}),
      }
      components.push(component)
      byId.set(id, component['bom-ref'])
    } else {
      if (!definition.name) fail(`provider '${id}': name is required`)
      const component = {
        type: definition.type ?? 'library',
        'bom-ref': `provider/${id}`,
        name: definition.name,
        ...(definition.version ? { version: definition.version } : {}),
        ...(definition.description ? { description: definition.description } : {}),
        ...(definition.externalReferences ? { externalReferences: definition.externalReferences } : {}),
        ...(definition.properties ? { properties: definition.properties } : {}),
      }
      components.push(component)
      byId.set(id, component['bom-ref'])
    }
  }

  return { components, byId }
}

function assetComponent(asset, inventory, providerRefs, sourceFiles, root) {
  const bomRef = `crypto/${asset.assetType}/${asset.id}`
  if (!ASSET_TYPES.has(asset.assetType)) fail(`${asset.id}: invalid assetType '${asset.assetType}'`)

  const cryptoProperties = { assetType: asset.assetType }
  if (asset.oid) {
    validateOid(asset.oid, asset.id)
    cryptoProperties.oid = asset.oid
  }

  if (asset.assetType === 'algorithm') {
    if (!asset.algorithmProperties) fail(`${asset.id}: algorithmProperties is required`)
    validateAlgorithm(asset.algorithmProperties, asset.id)
    cryptoProperties.algorithmProperties = asset.algorithmProperties
  } else if (asset.assetType === 'related-crypto-material') {
    if (!asset.relatedCryptoMaterialProperties) fail(`${asset.id}: relatedCryptoMaterialProperties is required`)
    validateRelatedMaterial(asset.relatedCryptoMaterialProperties, asset.id)
    const related = { ...asset.relatedCryptoMaterialProperties }
    if (related.algorithmRef) {
      const target = inventory.assets.find((candidate) => candidate.id === related.algorithmRef)
      if (!target || target.assetType !== 'algorithm') {
        fail(`${asset.id}: algorithmRef '${related.algorithmRef}' does not resolve to an algorithm asset`)
      }
      related.algorithmRef = `crypto/algorithm/${target.id}`
    }
    cryptoProperties.relatedCryptoMaterialProperties = related
  } else if (asset.assetType === 'protocol') {
    if (!asset.protocolProperties) fail(`${asset.id}: protocolProperties is required`)
    validateProtocol(asset.protocolProperties, asset.id)
    cryptoProperties.protocolProperties = asset.protocolProperties
  } else {
    fail(`${asset.id}: certificate assets are not supported by this inventory yet`)
  }

  const providers = asset.providers ?? []
  const unresolved = providers.filter((provider) => !providerRefs.has(provider))
  if (unresolved.length > 0) fail(`${asset.id}: unknown provider(s): ${unresolved.join(', ')}`)

  return {
    type: 'cryptographic-asset',
    'bom-ref': bomRef,
    name: asset.name,
    ...(asset.description ? { description: asset.description } : {}),
    cryptoProperties,
    ...(asset.properties ? { properties: asset.properties } : {}),
    evidence: { occurrences: occurrencesFor(asset, sourceFiles, root) },
    providers: providers.map((provider) => providerRefs.get(provider)),
  }
}

function checkQuotedLiterals(sourceFiles, ignoredLiterals, root) {
  const ignored = new Set(ignoredLiterals.map((value) => value.toLowerCase()))
  const violations = []

  for (const file of sourceFiles) {
    const content = readFileSync(file, 'utf8')
    const literal = /(['"`])([^'"`\n]{1,200})\1/g
    for (const match of content.matchAll(literal)) {
      const value = match[2]
      if (value.includes('${')) continue
      if (!SENSITIVE_LITERAL.test(value)) continue
      if (ignored.has(value.toLowerCase())) continue
      const line = lineNumberAt(content, match.index ?? 0)
      violations.push(`${relative(root, file)}:${line} contains '${value}'`)
    }
  }

  if (violations.length > 0) {
    fail(
      'unexpected cryptography-related string literal(s):\n  ' +
        violations.join('\n  ') +
        '\nAdd a cryptographic asset to crypto-inventory.json, or add the literal to ignoredLiterals with a reason.',
    )
  }
}

function checkDriftWatch(ignoredLiterals, driftWatch) {
  const entries = (driftWatch ?? []).map((entry) => {
    if (!entry.pattern || !entry.reason) fail('every driftWatch entry needs a pattern and a reason')
    try {
      return new RegExp(entry.pattern, 'i')
    } catch (error) {
      fail(`invalid driftWatch pattern '${entry.pattern}': ${error.message}`)
    }
  })

  for (const literal of ignoredLiterals) {
    if (!entries.some((expression) => expression.test(literal))) {
      fail(
        `ignored literal '${literal}' is not explained by any driftWatch pattern. ` +
          'Add a driftWatch entry with a reason so the exception stays reviewable.',
      )
    }
  }
}

function checkCryptoDependencies(packageJson, inventory, providerRefs) {
  const ignored = new Set(Object.keys(inventory.ignoredDependencies ?? {}).map((name) => name.toLowerCase()))
  const direct = new Set([
    ...Object.keys(packageJson.dependencies ?? {}),
    ...Object.keys(packageJson.devDependencies ?? {}),
    ...Object.keys(packageJson.optionalDependencies ?? {}),
    ...Object.keys(packageJson.peerDependencies ?? {}),
  ])

  for (const name of direct) {
    if (!CRYPTO_PACKAGE.test(name)) continue
    const provider = inventory.dependencyProviders?.[name]
    if (provider && providerRefs.has(provider)) continue
    if (ignored.has(name.toLowerCase())) continue
    fail(
      `direct dependency '${name}' looks like a cryptography library but is not mapped in ` +
        'crypto-inventory.json (dependencyProviders or ignoredDependencies).',
    )
  }
}

function main() {
  const options = parseArgs(process.argv.slice(2))
  const inventory = readJson(options.inventory)
  const sbom = readJson(options.sbom)
  const packageJson = readJson(join(ROOT, 'package.json'))
  const sourceFiles = walk(join(ROOT, 'src'))

  if (sourceFiles.length === 0) fail('no TypeScript source files found under src/')
  if (sbom.bomFormat !== 'CycloneDX') fail('the SBOM is not a CycloneDX document')
  if (!sbom.metadata?.component) fail('the SBOM has no metadata.component')

  const providers = providerComponents(inventory, sbom)
  checkCryptoDependencies(packageJson, inventory, providers.byId)
  checkQuotedLiterals(sourceFiles, inventory.ignoredLiterals ?? [], ROOT)
  checkDriftWatch(inventory.ignoredLiterals ?? [], inventory.driftWatch ?? [])

  const assets = []
  const refs = new Set()
  for (const asset of inventory.assets ?? []) {
    if (!asset.id) fail('every asset needs an id')
    const component = assetComponent(asset, inventory, providers.byId, sourceFiles, ROOT)
    if (refs.has(component['bom-ref'])) fail(`duplicate asset id '${asset.id}'`)
    refs.add(component['bom-ref'])
    assets.push(component)
  }

  const providerRefs = [...new Set([...providers.byId.values()])]
  const rootRef = sbom.metadata.component['bom-ref'] ?? sbom.metadata.component.purl
  if (!rootRef) fail('the SBOM main component has no bom-ref or purl')

  const dependencyMap = new Map()
  dependencyMap.set(rootRef, [...assets.map((asset) => asset['bom-ref']), ...providerRefs])
  for (const asset of assets) {
    dependencyMap.set(asset['bom-ref'], asset.providers)
  }
  for (const provider of providerRefs) {
    if (!dependencyMap.has(provider)) dependencyMap.set(provider, [])
  }

  const dependencies = [...dependencyMap.entries()].map(([ref, dependsOn]) => {
    const unique = [...new Set(dependsOn)].filter((entry) => entry !== ref)
    return { ref, ...(unique.length > 0 ? { dependsOn: unique } : {}) }
  })

  const components = [...assets.map(({ providers: _providers, ...component }) => component), ...providers.components]

  const output = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: {
      component: { ...sbom.metadata.component, type: 'library' },
      tools: {
        components: [
          {
            type: 'application',
            name: 'credo-ts-openbao-cbom-generator',
            version: '1.0.0',
          },
        ],
      },
      lifecycles: [{ phase: 'build' }],
    },
    components,
    dependencies,
  }

  writeFileSync(options.output, `${JSON.stringify(output, null, 2)}\n`)
  const algorithms = assets.filter((asset) => asset.cryptoProperties.assetType === 'algorithm').length
  const material = assets.filter((asset) => asset.cryptoProperties.assetType === 'related-crypto-material').length
  const protocols = assets.filter((asset) => asset.cryptoProperties.assetType === 'protocol').length
  const occurrences = assets.reduce((total, asset) => total + asset.evidence.occurrences.length, 0)
  console.log(
    `CBOM written to ${relative(ROOT, options.output)}: ` +
      `${algorithms} algorithms, ${material} key material, ${protocols} protocols, ` +
      `${occurrences} source occurrences, ${providers.components.length} providers.`,
  )
}

main()
