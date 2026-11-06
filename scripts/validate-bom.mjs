#!/usr/bin/env node

/**
 * Copyright 2026 AyanWorks Technology Solutions Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Structural validator for the generated CycloneDX 1.6 SBOM and CBOM.
 *
 * The official CycloneDX schema is also checked in CI. This script adds the
 * project-specific invariants: unique references, resolvable dependency graph,
 * real source locations for crypto evidence, and a complete mapping between
 * crypto-inventory.json and the CBOM.
 */

import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const DEFAULT_FILES = [join(ROOT, 'sbom', 'sbom.cdx.json'), join(ROOT, 'sbom', 'cbom.cdx.json')]

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
const PROTOCOL_TYPES = new Set(['tls', 'ssh', 'ipsec', 'ike', 'sstp', 'wpa', 'other', 'unknown'])

function fail(message) {
  console.error(`validate-bom: ${message}`)
  process.exit(1)
}

function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'))
  } catch (error) {
    fail(`cannot read ${relative(ROOT, file)}: ${error.message}`)
  }
}

function assert(condition, message) {
  if (!condition) fail(message)
}

function validateCryptoComponent(component, algorithmRefs, file) {
  const crypto = component.cryptoProperties
  const id = component['bom-ref']
  assert(crypto && typeof crypto === 'object', `${file}: ${id} has no cryptoProperties`)
  assert(ASSET_TYPES.has(crypto.assetType), `${file}: ${id} has invalid assetType '${crypto.assetType}'`)
  if (crypto.oid !== undefined) assert(/^\d+(?:\.\d+)+$/.test(crypto.oid), `${file}: ${id} has invalid OID`)

  if (crypto.assetType === 'algorithm') {
    const algorithm = crypto.algorithmProperties
    assert(algorithm && typeof algorithm === 'object', `${file}: ${id} has no algorithmProperties`)
    assert(PRIMITIVES.has(algorithm.primitive), `${file}: ${id} has invalid primitive '${algorithm.primitive}'`)
    if (algorithm.mode !== undefined) assert(MODES.has(algorithm.mode), `${file}: ${id} has invalid mode`)
    if (algorithm.padding !== undefined) assert(PADDINGS.has(algorithm.padding), `${file}: ${id} has invalid padding`)
    for (const fn of algorithm.cryptoFunctions ?? []) {
      assert(CRYPTO_FUNCTIONS.has(fn), `${file}: ${id} has invalid crypto function '${fn}'`)
    }
    algorithmRefs.add(id)
  } else if (crypto.assetType === 'related-crypto-material') {
    const material = crypto.relatedCryptoMaterialProperties
    assert(material && typeof material === 'object', `${file}: ${id} has no relatedCryptoMaterialProperties`)
    assert(RELATED_TYPES.has(material.type), `${file}: ${id} has invalid related crypto material type`)
  } else if (crypto.assetType === 'protocol') {
    const protocol = crypto.protocolProperties
    assert(protocol && typeof protocol === 'object', `${file}: ${id} has no protocolProperties`)
    assert(PROTOCOL_TYPES.has(protocol.type), `${file}: ${id} has invalid protocol type`)
  }
}

function validateEvidence(component, file) {
  const occurrences = component.evidence?.occurrences
  if (occurrences === undefined) return
  assert(Array.isArray(occurrences) && occurrences.length > 0, `${file}: ${component['bom-ref']} has empty evidence`)
  for (const occurrence of occurrences) {
    assert(
      typeof occurrence.location === 'string' && occurrence.location.length > 0,
      `${file}: evidence has no location`,
    )
    assert(Number.isInteger(occurrence.line) && occurrence.line > 0, `${file}: evidence has no line number`)
    const path = resolve(ROOT, occurrence.location)
    assert(existsSync(path), `${file}: evidence path '${occurrence.location}' does not exist`)
    const lines = readFileSync(path, 'utf8').split('\n').length
    assert(occurrence.line <= lines, `${file}: evidence line ${occurrence.line} is outside '${occurrence.location}'`)
  }
}

function validateBom(file) {
  const bom = readJson(file)
  const label = relative(ROOT, file)

  assert(bom.bomFormat === 'CycloneDX', `${label}: bomFormat must be 'CycloneDX'`)
  assert(bom.specVersion === '1.6', `${label}: specVersion must be '1.6'`)
  assert(
    /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(bom.serialNumber ?? ''),
    `${label}: invalid serialNumber`,
  )
  assert(Number.isInteger(bom.version) && bom.version > 0, `${label}: invalid version`)
  assert(bom.metadata && typeof bom.metadata === 'object', `${label}: metadata is required`)
  assert(
    bom.metadata.timestamp && !Number.isNaN(Date.parse(bom.metadata.timestamp)),
    `${label}: invalid metadata.timestamp`,
  )
  assert(
    bom.metadata.component && typeof bom.metadata.component === 'object',
    `${label}: metadata.component is required`,
  )

  const rootRef = bom.metadata.component['bom-ref']
  assert(typeof rootRef === 'string' && rootRef.length > 0, `${label}: metadata.component needs a bom-ref`)
  assert(Array.isArray(bom.components) && bom.components.length > 0, `${label}: components are required`)

  const refs = new Set([rootRef])
  const algorithmRefs = new Set()
  for (const component of bom.components) {
    const ref = component['bom-ref']
    assert(typeof ref === 'string' && ref.length > 0, `${label}: component without bom-ref`)
    assert(!refs.has(ref), `${label}: duplicate bom-ref '${ref}'`)
    refs.add(ref)
    assert(typeof component.type === 'string', `${label}: ${ref} has no component type`)
    assert(typeof component.name === 'string' && component.name.length > 0, `${label}: ${ref} has no name`)
    if (component.purl !== undefined) {
      assert(/^pkg:[a-z][a-z0-9.+-]*\/.+/.test(component.purl), `${label}: ${ref} has invalid purl '${component.purl}'`)
    }
    if (component.type === 'cryptographic-asset') {
      validateCryptoComponent(component, algorithmRefs, label)
      validateEvidence(component, label)
    }
  }

  for (const component of bom.components) {
    const material = component.cryptoProperties?.relatedCryptoMaterialProperties
    if (material?.algorithmRef) {
      assert(
        algorithmRefs.has(material.algorithmRef),
        `${label}: ${component['bom-ref']} references unknown algorithm '${material.algorithmRef}'`,
      )
    }
  }

  assert(Array.isArray(bom.dependencies) && bom.dependencies.length > 0, `${label}: dependencies are required`)
  const dependencyRefs = new Set()
  for (const dependency of bom.dependencies) {
    assert(typeof dependency.ref === 'string', `${label}: dependency without ref`)
    assert(refs.has(dependency.ref), `${label}: dependency references unknown component '${dependency.ref}'`)
    assert(!dependencyRefs.has(dependency.ref), `${label}: duplicate dependency entry for '${dependency.ref}'`)
    dependencyRefs.add(dependency.ref)
    for (const target of dependency.dependsOn ?? []) {
      assert(target !== dependency.ref, `${label}: ${dependency.ref} depends on itself`)
      assert(refs.has(target), `${label}: ${dependency.ref} depends on unknown component '${target}'`)
    }
  }

  const cryptoComponents = bom.components.filter((component) => component.type === 'cryptographic-asset')
  const algorithmCount = cryptoComponents.filter(
    (component) => component.cryptoProperties?.assetType === 'algorithm',
  ).length
  console.log(
    `${label}: valid CycloneDX 1.6 (${bom.components.length} components, ` +
      `${cryptoComponents.length} crypto assets, ${algorithmCount} algorithms, ${bom.dependencies.length} dependency entries)`,
  )

  return { bom, cryptoComponents, kind: label.includes('cbom') ? 'cbom' : 'sbom' }
}

function validateInventoryCoverage(result) {
  if (result.kind !== 'cbom') return
  const inventory = readJson(join(ROOT, 'crypto-inventory.json'))
  const refs = new Set(result.cryptoComponents.map((component) => component['bom-ref']))
  for (const asset of inventory.assets ?? []) {
    const ref = `crypto/${asset.assetType}/${asset.id}`
    assert(refs.has(ref), `CBOM is missing inventory asset '${ref}'`)
  }
  assert(
    refs.size === (inventory.assets ?? []).length,
    `CBOM contains ${refs.size} crypto assets but the inventory defines ${(inventory.assets ?? []).length}`,
  )
}

function main() {
  const files = process.argv.slice(2).filter((arg) => !arg.startsWith('-'))
  const targets = files.length > 0 ? files.map((file) => resolve(file)) : DEFAULT_FILES
  for (const file of targets) {
    if (!existsSync(file)) fail(`missing ${relative(ROOT, file)}`)
  }
  const results = targets.map(validateBom)
  for (const result of results) validateInventoryCoverage(result)
}

main()
