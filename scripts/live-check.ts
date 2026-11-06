/**
 * Copyright 2026 AyanWorks Technology Solutions Pvt. Ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * End-to-end check against a running OpenBao dev server.
 *
 *   docker run -d --name openbao-dev -p 8200:8200 \
 *     -e BAO_DEV_ROOT_TOKEN_ID=root -e BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
 *     openbao/openbao:latest server -dev
 *
 *   npm run live-check
 *
 * The check runs a real Credo agent with Drizzle storage on SQLite. This
 * exercises the same storage layer a production agent uses, including the
 * Node.js KMS fallback (whose keys are persisted as `GenericRecord`s) and the
 * DID records written by did:key, did:jwk and did:peer.
 */
import {
  Agent,
  ConsoleLogger,
  CredoWebCrypto,
  GenericRecord,
  InjectionSymbols,
  LogLevel,
  TypedArrayEncoder,
  X509KeyUsage,
  X509Service,
  getPublicJwkFromVerificationMethod,
  type StorageService,
} from '@credo-ts/core'
import {
  KeyManagementModule,
  PublicJwk,
  type KmsCreateKeyType,
  type KmsJwkPrivate,
  type KmsJwkPublic,
  type KnownJwaSignatureAlgorithm,
} from '@credo-ts/core/kms'
import { DrizzleStorageModule } from '@credo-ts/drizzle-storage'
import { coreBundle } from '@credo-ts/drizzle-storage/core'
import { NodeKeyManagementService, agentDependencies } from '@credo-ts/node'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import Database from 'better-sqlite3'
import { drizzle } from 'drizzle-orm/better-sqlite3'
import { generateKeyPairSync, type KeyObject } from 'node:crypto'
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { FetchOpenBaoClient, OpenBaoKeyManagementService, type OpenBaoTransitKey } from '../src/index.js'
import { DrizzleNodeKeyManagementStorage } from './drizzleNodeKeyManagementStorage.js'

const ADDRESS = process.env.OPENBAO_ADDR ?? 'http://127.0.0.1:8200'
const TOKEN = process.env.OPENBAO_TOKEN ?? 'root'
const KV_MOUNT = 'secret'

let failures = 0
function check(name: string, condition: boolean, detail?: unknown): void {
  if (condition) {
    console.log(`  ok   ${name}`)
  } else {
    failures += 1
    console.log(`  FAIL ${name}`, detail ?? '')
  }
}

/**
 * Node.js KMS keys are persisted as `GenericRecord`s through the agent's
 * storage service. With Drizzle this means they survive restarts and live in
 * the same SQLite database as DIDs and credentials.
 */
function toPrivateJwk(key: KeyObject): KmsJwkPrivate {
  return key.export({ format: 'jwk' }) as KmsJwkPrivate
}

/**
 * Generate a secp256k1 key with @noble/curves rather than node:crypto, because
 * some runtimes (e.g. Bun) ship an OpenSSL build without the curve.
 */
function generateSecp256k1SourceKey(): {
  privateJwk: KmsJwkPrivate
  publicJwk: Record<string, unknown>
} {
  const privateKey = secp256k1.utils.randomSecretKey()
  const publicKey = secp256k1.getPublicKey(privateKey, false)
  const x = Buffer.from(publicKey.subarray(1, 33)).toString('base64url')
  const y = Buffer.from(publicKey.subarray(33, 65)).toString('base64url')

  return {
    privateJwk: {
      kty: 'EC',
      crv: 'secp256k1',
      x,
      y,
      d: Buffer.from(privateKey).toString('base64url'),
    } as KmsJwkPrivate,
    publicJwk: { kty: 'EC', crv: 'secp256k1', x, y },
  }
}

function publicJwkMatches(publicJwk: KmsJwkPublic, expected: Record<string, unknown>): boolean {
  if (publicJwk.kty === 'EC' && expected.kty === 'EC') {
    return publicJwk.crv === expected.crv && publicJwk.x === expected.x && publicJwk.y === expected.y
  }
  if (publicJwk.kty === 'OKP' && expected.kty === 'OKP') {
    return publicJwk.crv === expected.crv && publicJwk.x === expected.x
  }
  if (publicJwk.kty === 'RSA' && expected.kty === 'RSA') {
    return publicJwk.n === expected.n && publicJwk.e === expected.e
  }
  return false
}

/**
 * Apply the SQL migrations shipped with @credo-ts/drizzle-storage. SQLite is
 * the only supported database in this script; real deployments normally run
 * `drizzle-kit migrate` or the package's migration CLI instead.
 */
function applyCoreSqliteMigrations(database: { exec(sql: string): unknown }): void {
  const packageEntry = fileURLToPath(import.meta.resolve('@credo-ts/drizzle-storage'))
  const migrationsDirectory = join(dirname(packageEntry), '..', 'migrations', 'core', 'sqlite')

  for (const file of readdirSync(migrationsDirectory)
    .filter((name) => name.endsWith('.sql'))
    .sort()) {
    database.exec(readFileSync(join(migrationsDirectory, file), 'utf8'))
  }
}

async function main(): Promise<void> {
  console.log(`OpenBao at ${ADDRESS}\n`)

  // The SQLite database is temporary, but every write goes through the real
  // Drizzle storage module, exactly like a persistent agent database.
  const databaseDirectory = mkdtempSync(join(tmpdir(), 'credo-openbao-live-check-'))
  const databasePath = join(databaseDirectory, 'agent.sqlite')
  const sqlite = new Database(databasePath)
  sqlite.pragma('foreign_keys = ON')
  applyCoreSqliteMigrations(sqlite)

  const client = new FetchOpenBaoClient({ address: ADDRESS, token: TOKEN })
  const openbao = new OpenBaoKeyManagementService({
    client,
    kvMount: KV_MOUNT,
  })
  const node = new NodeKeyManagementService(new DrizzleNodeKeyManagementStorage())

  const agent = new Agent({
    config: {
      logger: new ConsoleLogger(LogLevel.Warn),
    },
    dependencies: agentDependencies,
    modules: {
      storage: new DrizzleStorageModule({
        database: drizzle(sqlite),
        bundles: [coreBundle],
      }),
      kms: new KeyManagementModule({
        backends: [openbao, node],
        defaultBackend: 'openbao',
      }),
    },
  })

  await agent.initialize()

  const storage = agent.context.resolve<StorageService<GenericRecord>>(InjectionSymbols.StorageService)
  const webCrypto = new CredoWebCrypto(agent.context)
  const data = TypedArrayEncoder.fromUtf8String('Hello from Credo')

  const transitKey = async (keyId: string): Promise<OpenBaoTransitKey | null> => {
    try {
      return await client.getKey(openbao.keyName(keyId))
    } catch {
      return null
    }
  }
  const kvPath = (keyId: string): string => `credo-keys/${openbao.keyName(keyId)}`
  const kvRecord = (keyId: string): Promise<Record<string, unknown> | null> => client.getKv(KV_MOUNT, kvPath(keyId))

  try {
    console.log('routing')
    const routableKeyTypes: Array<{ label: string; type: KmsCreateKeyType }> = [
      { label: 'Ed25519', type: { kty: 'OKP', crv: 'Ed25519' } },
      { label: 'P-256', type: { kty: 'EC', crv: 'P-256' } },
      { label: 'P-384', type: { kty: 'EC', crv: 'P-384' } },
      { label: 'P-521', type: { kty: 'EC', crv: 'P-521' } },
      { label: 'RSA-2048', type: { kty: 'RSA', modulusLength: 2048 } },
      { label: 'secp256k1', type: { kty: 'EC', crv: 'secp256k1' } },
      { label: 'X25519', type: { kty: 'OKP', crv: 'X25519' } },
    ]
    for (const { label, type } of routableKeyTypes) {
      check(
        `${label} createKey -> openbao`,
        agent.kms.supportedBackendsForOperation({ operation: 'createKey', type })[0] === 'openbao',
      )
    }
    check(
      'ES256K sign -> openbao',
      agent.kms.supportedBackendsForOperation({ operation: 'sign', algorithm: 'ES256K' })[0] === 'openbao',
    )
    check(
      'randomBytes -> not openbao',
      !agent.kms.supportedBackendsForOperation({ operation: 'randomBytes' }).includes('openbao'),
    )

    console.log('\ncreate / sign / verify (all Credo key types)')
    const createCases: Array<{
      label: string
      type: KmsCreateKeyType
      algorithms: KnownJwaSignatureAlgorithm[]
      store: 'transit' | 'kv'
    }> = [
      {
        label: 'Ed25519 (EdDSA)',
        type: { kty: 'OKP', crv: 'Ed25519' },
        algorithms: ['EdDSA'],
        store: 'transit',
      },
      {
        label: 'P-256 (ES256)',
        type: { kty: 'EC', crv: 'P-256' },
        algorithms: ['ES256'],
        store: 'transit',
      },
      {
        label: 'P-384 (ES384)',
        type: { kty: 'EC', crv: 'P-384' },
        algorithms: ['ES384'],
        store: 'transit',
      },
      {
        label: 'P-521 (ES512)',
        type: { kty: 'EC', crv: 'P-521' },
        algorithms: ['ES512'],
        store: 'transit',
      },
      {
        label: 'RSA-2048 (RS256/PS256)',
        type: { kty: 'RSA', modulusLength: 2048 },
        algorithms: ['RS256', 'PS256'],
        store: 'transit',
      },
      {
        label: 'secp256k1 (ES256K, KV fallback)',
        type: { kty: 'EC', crv: 'secp256k1' },
        algorithms: ['ES256K'],
        store: 'kv',
      },
      {
        label: 'X25519 (KV fallback)',
        type: { kty: 'OKP', crv: 'X25519' },
        algorithms: [],
        store: 'kv',
      },
    ]

    for (const testCase of createCases) {
      const key = await agent.kms.createKey({ type: testCase.type })
      check(
        `${testCase.label}: stored in ${testCase.store === 'transit' ? 'Transit' : 'KV'}`,
        testCase.store === 'transit' ? (await transitKey(key.keyId)) !== null : (await kvRecord(key.keyId)) !== null,
      )

      const publicKey = await agent.kms.getPublicKey({ keyId: key.keyId })
      check(
        `${testCase.label}: public key readable with key id`,
        publicKey !== null && publicKey.kid === key.keyId,
        publicKey,
      )

      for (const algorithm of testCase.algorithms) {
        const { signature } = await agent.kms.sign({
          keyId: key.keyId,
          algorithm,
          data,
        })

        const byKeyId = await agent.kms.verify({
          key: { keyId: key.keyId },
          algorithm,
          data,
          signature,
        })
        const byPublicJwk = await agent.kms.verify({
          key: { publicJwk: key.publicJwk },
          algorithm,
          data,
          signature,
        })
        const tampered = await agent.kms.verify({
          key: { keyId: key.keyId },
          algorithm,
          data: TypedArrayEncoder.fromUtf8String('Hello from Credo!'),
          signature,
        })

        check(`${testCase.label}: ${algorithm} verifies by keyId`, byKeyId.verified)
        check(`${testCase.label}: ${algorithm} verifies by publicJwk`, byPublicJwk.verified)
        check(`${testCase.label}: ${algorithm} rejects tampered data`, !tampered.verified)
      }
    }

    console.log('\nRSA modulus sizes')
    for (const modulusLength of [2048, 3072, 4096] as const) {
      const key = await agent.kms.createKey({ type: { kty: 'RSA', modulusLength } })
      const publicKey = await agent.kms.getPublicKey({ keyId: key.keyId })
      check(
        `RSA-${modulusLength} stored in Transit and exposes an RSA public key`,
        (await transitKey(key.keyId)) !== null && publicKey?.kty === 'RSA',
      )
    }

    console.log('\nimportKey (every Credo key type)')
    const p256Keys = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    const p256PrivateJwk = toPrivateJwk(p256Keys.privateKey)
    const secp256k1Source = generateSecp256k1SourceKey()
    const x25519Keys = generateKeyPairSync('x25519')
    check(
      'importKey with a secp256k1 JWK -> openbao',
      agent.kms.supportedBackendsForOperation({
        operation: 'importKey',
        privateJwk: secp256k1Source.privateJwk,
      })[0] === 'openbao',
    )

    const keyPairImportCase = (
      label: string,
      keys: { privateKey: KeyObject; publicKey: KeyObject },
      algorithm: KnownJwaSignatureAlgorithm | undefined,
      store: 'transit' | 'kv',
    ) => ({
      label,
      privateJwk: toPrivateJwk(keys.privateKey),
      expectedPublicJwk: keys.publicKey.export({ format: 'jwk' }) as Record<string, unknown>,
      ...(algorithm ? { algorithm } : {}),
      store,
    })

    const importCases: Array<{
      label: string
      privateJwk: KmsJwkPrivate
      expectedPublicJwk: Record<string, unknown>
      algorithm?: KnownJwaSignatureAlgorithm
      store: 'transit' | 'kv'
    }> = [
      keyPairImportCase('Ed25519', generateKeyPairSync('ed25519'), 'EdDSA', 'transit'),
      keyPairImportCase('P-256', p256Keys, 'ES256', 'transit'),
      keyPairImportCase('P-384', generateKeyPairSync('ec', { namedCurve: 'P-384' }), 'ES384', 'transit'),
      keyPairImportCase('P-521', generateKeyPairSync('ec', { namedCurve: 'P-521' }), 'ES512', 'transit'),
      keyPairImportCase('RSA-2048', generateKeyPairSync('rsa', { modulusLength: 2048 }), 'PS256', 'transit'),
      {
        label: 'secp256k1',
        privateJwk: secp256k1Source.privateJwk,
        expectedPublicJwk: secp256k1Source.publicJwk,
        algorithm: 'ES256K',
        store: 'kv',
      },
      {
        label: 'X25519',
        privateJwk: toPrivateJwk(x25519Keys.privateKey),
        expectedPublicJwk: x25519Keys.publicKey.export({ format: 'jwk' }) as Record<string, unknown>,
        store: 'kv',
      },
    ]

    const imported = new Map<string, Awaited<ReturnType<typeof agent.kms.importKey>>>()

    for (const testCase of importCases) {
      const key = await agent.kms.importKey({ privateJwk: testCase.privateJwk })
      imported.set(testCase.label, key)

      check(
        `${testCase.label}: imported into ${testCase.store === 'transit' ? 'Transit' : 'KV'}`,
        testCase.store === 'transit' ? (await transitKey(key.keyId)) !== null : (await kvRecord(key.keyId)) !== null,
      )
      check(
        `${testCase.label}: imported public key matches the source key`,
        publicJwkMatches(key.publicJwk, testCase.expectedPublicJwk) && key.publicJwk.kid === key.keyId,
      )

      if (testCase.algorithm) {
        const { signature } = await agent.kms.sign({
          keyId: key.keyId,
          algorithm: testCase.algorithm,
          data,
        })
        check(
          `${testCase.label}: imported key signs ${testCase.algorithm} and verifies`,
          (
            await agent.kms.verify({
              key: { publicJwk: key.publicJwk },
              algorithm: testCase.algorithm,
              data,
              signature,
            })
          ).verified,
        )
      }
    }

    const importedP256 = imported.get('P-256')
    if (!importedP256) throw new Error('P-256 import did not return a key')
    check(
      'importing an existing key id throws KeyManagementKeyExistsError',
      await agent.kms.importKey({ privateJwk: { ...p256PrivateJwk, kid: importedP256.keyId } as KmsJwkPrivate }).then(
        () => false,
        (error) => error.name === 'KeyManagementKeyExistsError',
      ),
    )

    console.log('\ndid:key / did:jwk / did:peer from keys imported into OpenBao')
    const importedEd = imported.get('Ed25519')
    const importedSecp = imported.get('secp256k1')
    const importedX25519 = imported.get('X25519')
    if (!importedEd || !importedSecp || !importedX25519) {
      throw new Error('DID checks require the Ed25519, secp256k1 and X25519 imports')
    }

    const didCases = [
      {
        label: 'did:key (Ed25519, Transit)',
        key: importedEd,
        create: () =>
          agent.dids.create({
            method: 'key',
            options: { keyId: importedEd.keyId },
          }),
      },
      {
        label: 'did:jwk (secp256k1, KV fallback)',
        key: importedSecp,
        create: () =>
          agent.dids.create({
            method: 'jwk',
            options: { keyId: importedSecp.keyId },
          }),
      },
      {
        label: 'did:peer numAlgo 0 (X25519, KV fallback)',
        key: importedX25519,
        create: () =>
          agent.dids.create({
            method: 'peer',
            options: { numAlgo: 0, keyId: importedX25519.keyId },
          }),
      },
    ]

    const createdDids: string[] = []
    for (const testCase of didCases) {
      const result = await testCase.create()
      if (result.didState.state !== 'finished') {
        check(`${testCase.label}: created`, false, result.didState)
        continue
      }
      createdDids.push(result.didState.did)
      check(`${testCase.label}: created`, true)

      const resolved = await agent.dids.resolve(result.didState.did)
      const verificationMethod =
        resolved.didDocument?.verificationMethod?.[0] ??
        resolved.didDocument?.keyAgreement?.find((method) => typeof method !== 'string')
      const resolvedPublicJwk =
        verificationMethod && typeof verificationMethod !== 'string'
          ? getPublicJwkFromVerificationMethod(verificationMethod)
          : undefined

      check(
        `${testCase.label}: resolves to the imported key`,
        resolvedPublicJwk !== undefined && resolvedPublicJwk.equals(PublicJwk.fromPublicJwk(testCase.key.publicJwk)),
        resolved.didDocument,
      )
    }

    const createdDidRecords = await agent.dids.getCreatedDids()
    check(
      'did records are persisted through Drizzle storage',
      createdDids.every((did) => createdDidRecords.some((record) => record.did === did)),
    )

    console.log('\nX.509 certificates signed by keys held in OpenBao')
    const validity = {
      notBefore: new Date(Date.now() - 60_000),
      notAfter: new Date(Date.now() + 3_600_000),
    }

    const caKeys = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    const ca = await agent.kms.importKey({ privateJwk: toPrivateJwk(caKeys.privateKey) })
    const caPublicJwk = PublicJwk.fromUnknown(ca.publicJwk)
    const caCert = await X509Service.createCertificate(agent.context, {
      authorityKey: caPublicJwk,
      issuer: { commonName: 'OpenBao Test Root CA', countryName: 'IN' },
      validity,
      extensions: {
        basicConstraints: { ca: true, pathLenConstraint: 0 },
        keyUsage: { usages: [X509KeyUsage.KeyCertSign, X509KeyUsage.CrlSign] },
      },
    })
    check(
      'self-signed CA certificate verifies',
      await caCert.verify({}, webCrypto).then(
        () => true,
        () => false,
      ),
    )
    check('CA certificate carries the imported key id', caCert.keyId === ca.keyId, caCert.keyId)

    const leafKeys = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    const leaf = await agent.kms.importKey({ privateJwk: toPrivateJwk(leafKeys.privateKey) })
    const leafPublicJwk = PublicJwk.fromUnknown(leaf.publicJwk)
    const leafCert = await X509Service.createCertificate(agent.context, {
      authorityKey: caPublicJwk,
      subjectPublicKey: leafPublicJwk,
      issuer: { commonName: 'OpenBao Test Root CA' },
      subject: { commonName: 'Credo Issuer Agent', organizationalUnit: 'Issuance' },
      validity,
      extensions: {
        basicConstraints: { ca: false },
        keyUsage: { usages: [X509KeyUsage.DigitalSignature] },
      },
    })
    check(
      'leaf certificate signed via the CA key in OpenBao verifies',
      await leafCert.verify({ publicJwk: caPublicJwk }, webCrypto).then(
        () => true,
        () => false,
      ),
    )
    check('leaf certificate binds the imported leaf key id', leafCert.keyId === leaf.keyId, leafCert.keyId)

    const credentialPayload = TypedArrayEncoder.fromUtf8String('{"iss":"Credo Issuer Agent"}')
    const credentialSignature = await agent.kms.sign({
      keyId: leaf.keyId,
      algorithm: 'ES256',
      data: credentialPayload,
    })
    check(
      'credential signed by the imported leaf key verifies against the certificate key',
      (
        await agent.kms.verify({
          key: { publicJwk: leafCert.publicJwk.toJson({ includeKid: true }) as KmsJwkPublic },
          algorithm: 'ES256',
          data: credentialPayload,
          signature: credentialSignature.signature,
        })
      ).verified,
    )

    console.log('\nlifecycle')
    const throwaway = await agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })
    check('key exists before delete', (await transitKey(throwaway.keyId)) !== null)
    check('deleteKey returns true', await agent.kms.deleteKey({ keyId: throwaway.keyId }))
    check('key gone after delete', (await transitKey(throwaway.keyId)) === null)
    check(
      'getPublicKey throws after delete',
      await agent.kms.getPublicKey({ keyId: throwaway.keyId }).then(
        () => false,
        (error) => error.name === 'KeyManagementKeyNotFoundError',
      ),
    )

    const throwawayKv = await agent.kms.createKey({ type: { kty: 'EC', crv: 'secp256k1' } })
    check('KV key exists before delete', (await kvRecord(throwawayKv.keyId)) !== null)
    check('KV deleteKey returns true', await agent.kms.deleteKey({ keyId: throwawayKv.keyId }))
    check('KV key gone after delete', (await kvRecord(throwawayKv.keyId)) === null)
    check('deleteKey returns false for unknown key', !(await agent.kms.deleteKey({ keyId: 'does-not-exist' })))

    console.log('\nNode.js backend on Drizzle storage')
    const nodeKey = await agent.kms.createKey({
      type: { kty: 'EC', crv: 'P-256' },
      backend: 'node',
    })
    const nodeKeyRecord = await storage.getById(agent.context, GenericRecord, `node-kms-${nodeKey.keyId}`)
    check(
      'Node KMS private key is persisted as a GenericRecord in SQLite',
      (nodeKeyRecord.content as { privateJwk?: KmsJwkPrivate }).privateJwk !== undefined,
    )
    const nodeSignature = await agent.kms.sign({
      keyId: nodeKey.keyId,
      algorithm: 'ES256',
      data,
    })
    check(
      'Node KMS key signs and verifies using the Drizzle-backed storage',
      (
        await agent.kms.verify({
          key: { keyId: nodeKey.keyId },
          algorithm: 'ES256',
          data,
          signature: nodeSignature.signature,
        })
      ).verified,
    )

    const random = agent.kms.randomBytes({ length: 16 })
    check('randomBytes handled by Node backend', random.length === 16)

    const aesKey = await agent.kms.createKey({ type: { kty: 'oct', algorithm: 'aes', length: 256 } })
    const encrypted = await agent.kms.encrypt({
      key: { keyId: aesKey.keyId },
      encryption: { algorithm: 'A256GCM' },
      data,
    })
    const decrypted = await agent.kms.decrypt({
      key: { keyId: aesKey.keyId },
      decryption: {
        algorithm: 'A256GCM',
        iv: encrypted.iv!,
        tag: encrypted.tag!,
      },
      encrypted: encrypted.encrypted,
    })
    check(
      'A256GCM encrypt/decrypt handled by Node backend',
      Buffer.from(decrypted.data).toString('utf8') === 'Hello from Credo',
    )

    console.log(failures === 0 ? '\nAll checks passed.' : `\n${failures} check(s) failed.`)
  } finally {
    await agent.shutdown()
    sqlite.close()
    rmSync(databaseDirectory, { recursive: true, force: true })
  }

  process.exit(failures === 0 ? 0 : 1)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
