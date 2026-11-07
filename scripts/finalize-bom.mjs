#!/usr/bin/env node

/**
 * Copyright 2026 AyanWorks Technology Solutions Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Add provenance metadata and deterministic identity to the generated BOMs.
 *
 * - timestamp: commit time of the last change to BOM inputs, not "now". This
 *   makes repeated runs on the same commit byte-for-byte identical, so the CI
 *   bot only commits a BOM when a dependency or the crypto inventory changed.
 * - serialNumber: UUIDv5 derived from the BOM content (excluding the
 *   timestamp). Same inputs produce the same serial number.
 */

import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const DEFAULT_FILES = [join(ROOT, 'sbom', 'sbom.cdx.json'), join(ROOT, 'sbom', 'cbom.cdx.json')]
const INPUT_PATHS = [
  'package.json',
  'package-lock.json',
  'crypto-inventory.json',
  'src',
  'scripts/generate-cbom.mjs',
  'scripts/finalize-bom.mjs',
  'scripts/validate-bom.mjs',
  'scripts/package-bom.mjs',
  '.github/workflows/bom.yml',
]
const GENERATOR = 'credo-openbao-kms-bom-finalizer'
const GENERATOR_VERSION = '1.0.0'

function fail(message) {
  console.error(`finalize-bom: ${message}`)
  process.exit(1)
}

function git(args, fallback = '') {
  try {
    return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()
  } catch {
    return fallback
  }
}

function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'))
  } catch (error) {
    fail(`cannot read ${relative(ROOT, file)}: ${error.message}`)
  }
}

function sha256(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex')
}

function repositoryUrl() {
  const configured = git(['config', '--get', 'remote.origin.url'])
  if (configured) {
    return configured
      .replace(/^git\+/, '')
      .replace(/^git@github\.com:/, 'https://github.com/')
      .replace(/\.git$/, '')
  }
  const server = process.env.GITHUB_SERVER_URL
  const repository = process.env.GITHUB_REPOSITORY
  return server && repository ? `${server}/${repository}` : ''
}

function inputTimestamp() {
  if (process.env.SOURCE_DATE_EPOCH) {
    const seconds = Number(process.env.SOURCE_DATE_EPOCH)
    if (Number.isFinite(seconds)) return new Date(seconds * 1000).toISOString()
  }
  const timestamp = git(['log', '-1', '--format=%cI', '--', ...INPUT_PATHS])
  const fallback = git(['show', '-s', '--format=%cI', 'HEAD'])
  const value = timestamp || fallback
  if (!value) return new Date().toISOString()
  return new Date(value).toISOString()
}

function addProperty(metadata, name, value) {
  metadata.properties ??= []
  const existing = metadata.properties.find((property) => property.name === name)
  if (existing) existing.value = value
  else metadata.properties.push({ name, value })
}

function deterministicUuid(kind, bom) {
  const copy = JSON.parse(JSON.stringify(bom))
  delete copy.serialNumber
  if (copy.metadata) delete copy.metadata.timestamp
  const digest = createHash('sha256').update(JSON.stringify(copy)).digest()

  // UUIDv5 in the DNS namespace; the content hash makes the name unique per BOM.
  const namespace = Buffer.from('6ba7b8109dad11d180b400c04fd430c8', 'hex')
  const bytes = createHash('sha1').update(namespace).update(`${kind}:`).update(digest).digest().subarray(0, 16)
  bytes[6] = (bytes[6] & 0x0f) | 0x50
  bytes[8] = (bytes[8] & 0x3f) | 0x80
  const hex = bytes.toString('hex')
  return `urn:uuid:${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

function finalize(file, context) {
  const bom = readJson(file)
  if (bom.bomFormat !== 'CycloneDX') fail(`${relative(ROOT, file)} is not a CycloneDX document`)
  if (!bom.metadata?.component) fail(`${relative(ROOT, file)} has no metadata.component`)

  bom.version ??= 1
  bom.metadata.timestamp = context.timestamp
  bom.metadata.component.type = 'library'
  bom.metadata.lifecycles ??= [{ phase: 'build' }]

  bom.metadata.tools ??= {}
  bom.metadata.tools.components ??= []
  if (!bom.metadata.tools.components.some((component) => component.name === GENERATOR)) {
    bom.metadata.tools.components.push({
      type: 'application',
      name: GENERATOR,
      version: GENERATOR_VERSION,
    })
  }

  addProperty(bom.metadata, 'bom:generator', GENERATOR)
  addProperty(bom.metadata, 'bom:generator:version', GENERATOR_VERSION)
  addProperty(bom.metadata, 'bom:git:commit', context.commit)
  addProperty(bom.metadata, 'bom:git:repository', context.repository)
  addProperty(bom.metadata, 'bom:package-lock:sha256', context.lockHash)
  addProperty(bom.metadata, 'bom:crypto-inventory:sha256', context.inventoryHash)

  if (context.repository) {
    bom.externalReferences ??= []
    if (!bom.externalReferences.some((reference) => reference.type === 'vcs' && reference.url === context.repository)) {
      bom.externalReferences.push({ type: 'vcs', url: context.repository })
    }
  }

  bom.serialNumber = deterministicUuid(relative(ROOT, file), bom)
  writeFileSync(file, `${JSON.stringify(bom, null, 2)}\n`)
  console.log(`finalized ${relative(ROOT, file)} (${bom.serialNumber})`)
}

function main() {
  const files = process.argv.slice(2).filter((arg) => !arg.startsWith('-'))
  const targets = files.length > 0 ? files.map((file) => resolve(file)) : DEFAULT_FILES
  for (const file of targets) {
    if (!existsSync(file)) fail(`missing ${relative(ROOT, file)}; run the SBOM/CBOM generation first`)
  }

  const context = {
    timestamp: inputTimestamp(),
    commit: git(['rev-parse', 'HEAD'], process.env.GITHUB_SHA ?? 'unknown'),
    repository: repositoryUrl(),
    lockHash: sha256(join(ROOT, 'package-lock.json')),
    inventoryHash: sha256(join(ROOT, 'crypto-inventory.json')),
  }

  for (const file of targets) finalize(file, context)
}

main()
