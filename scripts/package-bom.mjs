#!/usr/bin/env node

/**
 * Copyright 2026 AyanWorks Technology Solutions Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copy the crypto inventory next to the BOMs and write a portable SHA-256
 * checksum file. Node implements both operations so the command behaves the
 * same on Linux and macOS.
 */

import { createHash } from 'node:crypto'
import { copyFileSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const OUTPUT_DIRECTORY = join(ROOT, 'sbom')
const FILES = ['sbom/sbom.cdx.json', 'sbom/cbom.cdx.json', 'sbom/crypto-inventory.json']

function sha256(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex')
}

copyFileSync(join(ROOT, 'crypto-inventory.json'), join(OUTPUT_DIRECTORY, 'crypto-inventory.json'))

const lines = FILES.map((file) => `${sha256(join(ROOT, file))}  ${file}`)
writeFileSync(join(OUTPUT_DIRECTORY, 'SHA256SUMS'), `${lines.join('\n')}\n`)
console.log(`wrote ${relative(ROOT, join(OUTPUT_DIRECTORY, 'SHA256SUMS'))} for ${FILES.length} files`)
