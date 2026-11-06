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
 * A small long-running Credo agent for local development and testing.
 *
 * It uses Drizzle storage on SQLite, OpenBao Transit as the default KMS
 * backend, and the Node.js backend for random bytes, symmetric crypto, and the
 * key types OpenBao does not support. A tiny HTTP API exposes the KMS so the
 * backend can be exercised with curl, a test suite, or the demo web app in
 * `demo/`.
 *
 *   npm run dev-agent
 *
 * Environment:
 *   OPENBAO_ADDR         default http://127.0.0.1:8200
 *   OPENBAO_TOKEN        required unless OPENBAO_TOKEN_FILE is set
 *   OPENBAO_TOKEN_FILE   file containing the token (used by docker compose)
 *   OPENBAO_KV_MOUNT     KV v2 mount for secp256k1/X25519, default "secret"
 *   AGENT_SQLITE_PATH    default ./data/agent.sqlite
 *   AGENT_HTTP_HOST      default 0.0.0.0
 *   AGENT_HTTP_PORT      default 3000
 */
import {
  Agent,
  ConsoleLogger,
  CredoWebCrypto,
  LogLevel,
  MdocModule,
  MdocRecord,
  SdJwtVcModule,
  SdJwtVcRecord,
  TypedArrayEncoder,
  X509KeyUsage,
  X509Service,
  isMdocSupportedSignatureAlgorithm,
  type DidCreateResult,
  type IDisclosureFrame,
  type IPresentationFrame,
  type MdocNameSpaces,
  type SdJwtVcPayload,
} from '@credo-ts/core'
import {
  KeyManagementModule,
  PublicJwk,
  type KmsCreateKeyType,
  type KmsJwkPrivate,
  type KmsJwkPublic,
  type KmsOperation,
  type KnownJwaSignatureAlgorithm,
} from '@credo-ts/core/kms'
import { DrizzleStorageModule } from '@credo-ts/drizzle-storage'
import { coreBundle } from '@credo-ts/drizzle-storage/core'
import { NodeKeyManagementService, agentDependencies } from '@credo-ts/node'
import Database from 'better-sqlite3'
import { drizzle } from 'drizzle-orm/better-sqlite3'
import { migrate } from 'drizzle-orm/better-sqlite3/migrator'
import { generateKeyPairSync, type KeyObject } from 'node:crypto'
import { readFileSync, mkdirSync } from 'node:fs'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { FetchOpenBaoClient, OpenBaoKeyManagementService, OpenBaoNotFoundError } from '../src/index.js'
import { generateSecp256k1KeyPair } from '../src/secp256k1.js'
import { DrizzleNodeKeyManagementStorage } from './drizzleNodeKeyManagementStorage.js'

const OPENBAO_ADDRESS = process.env.OPENBAO_ADDR ?? 'http://127.0.0.1:8200'
const KV_MOUNT = process.env.OPENBAO_KV_MOUNT ?? 'secret'
const SQLITE_PATH = process.env.AGENT_SQLITE_PATH ?? './data/agent.sqlite'
const HTTP_HOST = process.env.AGENT_HTTP_HOST ?? '0.0.0.0'
const HTTP_PORT = Number(process.env.AGENT_HTTP_PORT ?? 3000)

type DemoKeyStore = 'transit' | 'kv' | 'node'

/** A public JWK that can be used for signature verification (no `oct` keys). */
type AsymmetricKmsJwkPublic = Exclude<KmsJwkPublic, { kty: 'oct' }>

interface DemoKeyType {
  id: string
  label: string
  type: KmsCreateKeyType
  algorithms: KnownJwaSignatureAlgorithm[]
  store: DemoKeyStore
  signing: boolean
  dids: string[]
  note: string
}

/**
 * Everything the demo UI offers. Keeping the catalog on the server means the
 * UI does not have to duplicate the key type -> algorithm mapping.
 */
const DEMO_KEY_TYPES: DemoKeyType[] = [
  {
    id: 'ed25519',
    label: 'Ed25519',
    type: { kty: 'OKP', crv: 'Ed25519' },
    algorithms: ['EdDSA'],
    store: 'transit',
    signing: true,
    dids: ['did:key', 'did:jwk', 'did:peer'],
    note: 'Created and signed natively by Transit.',
  },
  {
    id: 'p256',
    label: 'P-256',
    type: { kty: 'EC', crv: 'P-256' },
    algorithms: ['ES256'],
    store: 'transit',
    signing: true,
    dids: ['did:key', 'did:jwk', 'did:peer'],
    note: 'Native ECDSA signing in Transit.',
  },
  {
    id: 'p384',
    label: 'P-384',
    type: { kty: 'EC', crv: 'P-384' },
    algorithms: ['ES384'],
    store: 'transit',
    signing: true,
    dids: ['did:key', 'did:jwk', 'did:peer'],
    note: 'Native ECDSA signing in Transit.',
  },
  {
    id: 'p521',
    label: 'P-521',
    type: { kty: 'EC', crv: 'P-521' },
    algorithms: ['ES512'],
    store: 'transit',
    signing: true,
    dids: ['did:key', 'did:jwk', 'did:peer'],
    note: 'Native ECDSA signing in Transit.',
  },
  {
    id: 'rsa2048',
    label: 'RSA-2048',
    type: { kty: 'RSA', modulusLength: 2048 },
    algorithms: ['RS256', 'PS256'],
    store: 'transit',
    signing: true,
    dids: ['did:key', 'did:jwk', 'did:peer'],
    note: 'RSASSA-PKCS1-v1_5 and RSA-PSS in Transit.',
  },
  {
    id: 'rsa3072',
    label: 'RSA-3072',
    type: { kty: 'RSA', modulusLength: 3072 },
    algorithms: ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'],
    store: 'transit',
    signing: true,
    dids: ['did:key', 'did:jwk', 'did:peer'],
    note: 'RSASSA-PKCS1-v1_5 and RSA-PSS in Transit.',
  },
  {
    id: 'rsa4096',
    label: 'RSA-4096',
    type: { kty: 'RSA', modulusLength: 4096 },
    algorithms: ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'],
    store: 'transit',
    signing: true,
    dids: ['did:key', 'did:jwk', 'did:peer'],
    note: 'RSASSA-PKCS1-v1_5 and RSA-PSS in Transit.',
  },
  {
    id: 'secp256k1',
    label: 'secp256k1',
    type: { kty: 'EC', crv: 'secp256k1' },
    algorithms: ['ES256K'],
    store: 'kv',
    signing: true,
    dids: ['did:key', 'did:jwk', 'did:ethr'],
    note: 'Transit cannot represent secp256k1. Stored in KV v2 and signed in-process.',
  },
  {
    id: 'x25519',
    label: 'X25519',
    type: { kty: 'OKP', crv: 'X25519' },
    algorithms: [],
    store: 'kv',
    signing: false,
    dids: ['did:key', 'did:jwk'],
    note: 'Key agreement only. Stored in the KV v2 fallback, no signing.',
  },
  {
    id: 'aes256',
    label: 'AES-256-GCM',
    type: { kty: 'oct', algorithm: 'aes', length: 256 },
    algorithms: [],
    store: 'node',
    signing: false,
    dids: [],
    note: 'Symmetric encryption. OpenBao Transit is not used for encrypt/decrypt here, so the Node.js backend handles it.',
  },
]

/** Demo credential types. Kept here so the UI and API share one definition. */
const SDJWT_VCT = 'https://credo.js.org/demo/identity'
const MDOC_DOCTYPE = 'org.iso.18013.5.1.mDL'
const MDOC_NAMESPACE = 'org.iso.18013.5.1'

class HttpError extends Error {
  public readonly status: number

  public constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

function resolveOpenBaoToken(): string {
  if (process.env.OPENBAO_TOKEN) return process.env.OPENBAO_TOKEN
  if (process.env.OPENBAO_TOKEN_FILE) {
    return readFileSync(process.env.OPENBAO_TOKEN_FILE, 'utf8').trim()
  }
  throw new Error('Set OPENBAO_TOKEN or OPENBAO_TOKEN_FILE')
}

function coreSqliteMigrationsFolder(): string {
  const packageEntry = fileURLToPath(import.meta.resolve('@credo-ts/drizzle-storage'))
  return join(dirname(packageEntry), '..', 'migrations', 'core', 'sqlite')
}

function asString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new HttpError(400, `'${field}' must be a non-empty string`)
  }
  return value
}

function asRecord(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new HttpError(400, `'${field}' must be an object`)
  }
  return value as Record<string, unknown>
}

function asInteger(value: unknown, field: string, min: number, max: number): number {
  const parsed = typeof value === 'number' ? value : Number(value)
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new HttpError(400, `'${field}' must be an integer between ${min} and ${max}`)
  }
  return parsed
}

function dataFromBody(body: Record<string, unknown>): Uint8Array {
  const data = asString(body.data, 'data')
  const encoding = body.encoding === 'base64url' ? 'base64url' : 'utf8'
  return new Uint8Array(Buffer.from(data, encoding))
}

function signatureFromBody(body: Record<string, unknown>): Uint8Array {
  return new Uint8Array(Buffer.from(asString(body.signature, 'signature'), 'base64url'))
}

function bytesFromBase64Url(value: unknown, field: string): Uint8Array {
  return new Uint8Array(Buffer.from(asString(value, field), 'base64url'))
}

function encodeSignature(signature: Uint8Array): string {
  return Buffer.from(signature).toString('base64url')
}

function demoKeyType(id: string): DemoKeyType {
  const found = DEMO_KEY_TYPES.find((keyType) => keyType.id === id)
  if (!found) throw new HttpError(400, `Unknown demo key type '${id}'`)
  return found
}

function keyObjectToPrivateJwk(key: KeyObject): KmsJwkPrivate {
  return key.export({ format: 'jwk' }) as KmsJwkPrivate
}

async function readJson(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = []
  let size = 0

  for await (const chunk of request) {
    const buffer = Buffer.from(chunk)
    size += buffer.length
    if (size > 1_000_000) throw new HttpError(413, 'Request body is too large')
    chunks.push(buffer)
  }

  if (chunks.length === 0) return {}

  const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'))
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new HttpError(400, 'Request body must be a JSON object')
  }
  return parsed as Record<string, unknown>
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8' })
  response.end(JSON.stringify(body, null, 2))
}

function didState(result: DidCreateResult): unknown {
  const state = result.didState
  return {
    state: state.state,
    ...(state.state === 'finished' ? { did: state.did } : {}),
    ...(state.state === 'failed' ? { reason: state.reason } : {}),
    ...('didDocument' in state && state.didDocument ? { didDocument: state.didDocument } : {}),
  }
}

async function main(): Promise<void> {
  mkdirSync(dirname(SQLITE_PATH), { recursive: true })

  const sqlite = new Database(SQLITE_PATH)
  sqlite.pragma('foreign_keys = ON')

  const database = drizzle(sqlite)
  migrate(database, { migrationsFolder: coreSqliteMigrationsFolder() })

  const client = new FetchOpenBaoClient({
    address: OPENBAO_ADDRESS,
    token: resolveOpenBaoToken(),
  })
  const openbao = new OpenBaoKeyManagementService({ client, kvMount: KV_MOUNT })
  const nodeStorage = new DrizzleNodeKeyManagementStorage()
  const node = new NodeKeyManagementService(nodeStorage)

  const agent = new Agent({
    config: {
      logger: new ConsoleLogger(LogLevel.Info),
    },
    dependencies: agentDependencies,
    modules: {
      storage: new DrizzleStorageModule({
        database,
        bundles: [coreBundle],
      }),
      kms: new KeyManagementModule({
        backends: [openbao, node],
        defaultBackend: 'openbao',
      }),
      sdJwtVc: new SdJwtVcModule(),
      mdoc: new MdocModule(),
    },
  })

  await agent.initialize()

  const webCrypto = new CredoWebCrypto(agent.context)

  const supportedBackends = (operation: KmsOperation): string[] => agent.kms.supportedBackendsForOperation(operation)

  /**
   * Determine where a key id lives: Transit, the OpenBao KV fallback, or the
   * Node.js backend. The UI uses this to show the actual storage location and
   * to route deletes to the right backend.
   */
  const detectKeyStore = async (keyId: string): Promise<DemoKeyStore | null> => {
    try {
      await client.getKey(openbao.keyName(keyId))
      return 'transit'
    } catch (error) {
      if (!(error instanceof OpenBaoNotFoundError)) throw error
    }

    if (await openbao.getPublicKey(agent.context, keyId)) return 'kv'
    if (await nodeStorage.has(agent.context, keyId)) return 'node'
    return null
  }

  const openBaoStatus = async (): Promise<Record<string, unknown>> => {
    try {
      const response = await fetch(`${OPENBAO_ADDRESS}/v1/sys/health`, {
        signal: AbortSignal.timeout(2_000),
      })
      const status = (await response.json()) as Record<string, unknown>
      return {
        reachable: true,
        httpStatus: response.status,
        initialized: status.initialized,
        sealed: status.sealed,
        version: status.version,
      }
    } catch (error) {
      return {
        reachable: false,
        error: error instanceof Error ? error.message : String(error),
      }
    }
  }

  const generateSampleJwk = (keyTypeId: string): KmsJwkPrivate => {
    const { type } = demoKeyType(keyTypeId)

    if (type.kty === 'OKP') {
      if (type.crv === 'Ed25519') {
        const { privateKey } = generateKeyPairSync('ed25519')
        return keyObjectToPrivateJwk(privateKey)
      }

      const { privateKey } = generateKeyPairSync('x25519')
      return keyObjectToPrivateJwk(privateKey)
    }

    if (type.kty === 'EC') {
      if (type.crv === 'secp256k1') return generateSecp256k1KeyPair('').privateJwk as KmsJwkPrivate
      const { privateKey } = generateKeyPairSync('ec', { namedCurve: type.crv })
      return keyObjectToPrivateJwk(privateKey)
    }

    if (type.kty === 'RSA') {
      const { privateKey } = generateKeyPairSync('rsa', { modulusLength: type.modulusLength })
      return keyObjectToPrivateJwk(privateKey)
    }

    throw new HttpError(400, `No sample asymmetric key is available for '${keyTypeId}'`)
  }

  const runX509Demo = async (): Promise<Record<string, unknown>> => {
    const validity = {
      notBefore: new Date(Date.now() - 60_000),
      notAfter: new Date(Date.now() + 3_600_000),
    }
    const verificationDate = new Date()

    const caKeys = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    const ca = await agent.kms.importKey({ privateJwk: keyObjectToPrivateJwk(caKeys.privateKey) })
    const caPublicJwk = PublicJwk.fromUnknown(ca.publicJwk)
    const caCert = await X509Service.createCertificate(agent.context, {
      authorityKey: caPublicJwk,
      issuer: { commonName: 'OpenBao Demo Root CA', countryName: 'IN' },
      validity,
      extensions: {
        basicConstraints: { ca: true, pathLenConstraint: 0 },
        keyUsage: { usages: [X509KeyUsage.KeyCertSign, X509KeyUsage.CrlSign] },
      },
    })
    const caSelfSigned = await caCert.verify({ verificationDate }, webCrypto).then(
      () => true,
      () => false,
    )

    const leafKeys = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    const leaf = await agent.kms.importKey({ privateJwk: keyObjectToPrivateJwk(leafKeys.privateKey) })
    const leafPublicJwk = PublicJwk.fromUnknown(leaf.publicJwk)
    const leafCert = await X509Service.createCertificate(agent.context, {
      authorityKey: caPublicJwk,
      subjectPublicKey: leafPublicJwk,
      issuer: { commonName: 'OpenBao Demo Root CA', countryName: 'IN' },
      subject: { commonName: 'Credo Demo Issuer', organizationalUnit: 'Issuance' },
      validity,
      extensions: {
        basicConstraints: { ca: false },
        keyUsage: { usages: [X509KeyUsage.DigitalSignature] },
      },
    })
    const leafSignedByCa = await leafCert.verify({ verificationDate, publicJwk: caPublicJwk }, webCrypto).then(
      () => true,
      () => false,
    )

    const caPem = caCert.toString('pem')
    const leafPem = leafCert.toString('pem')

    const chainValid = await X509Service.validateCertificateChain(agent.context, {
      certificateChain: [leafPem, caPem],
      trustedCertificates: [caPem],
      verificationDate,
    }).then(
      () => true,
      () => false,
    )

    const payload = TypedArrayEncoder.fromUtf8String(
      JSON.stringify({ iss: 'Credo Demo Issuer', sub: 'did:example:holder', iat: Math.floor(Date.now() / 1000) }),
    )
    const signature = await agent.kms.sign({ keyId: leaf.keyId, algorithm: 'ES256', data: payload })
    const credentialSignatureVerified = (
      await agent.kms.verify({
        key: { publicJwk: leafCert.publicJwk.toJson({ includeKid: true }) as unknown as AsymmetricKmsJwkPublic },
        algorithm: 'ES256',
        data: payload,
        signature: signature.signature,
      })
    ).verified

    return {
      checks: {
        caSelfSigned,
        leafSignedByCa,
        leafBindsImportedKeyId: leafCert.keyId === leaf.keyId,
        chainValid,
        credentialSignatureVerified,
      },
      ca: {
        keyId: ca.keyId,
        subject: caCert.subject,
        issuer: caCert.issuer,
        serialNumber: caCert.data.serialNumber,
        notBefore: caCert.data.notBefore,
        notAfter: caCert.data.notAfter,
        thumbprint: await caCert.getThumbprintInHex(agent.context),
        pem: caPem,
      },
      leaf: {
        keyId: leaf.keyId,
        subject: leafCert.subject,
        issuer: leafCert.issuer,
        serialNumber: leafCert.data.serialNumber,
        notBefore: leafCert.data.notBefore,
        notAfter: leafCert.data.notAfter,
        thumbprint: await leafCert.getThumbprintInHex(agent.context),
        pem: leafPem,
      },
      credential: {
        payload: Buffer.from(payload).toString('utf8'),
        signature: encodeSignature(signature.signature),
      },
    }
  }

  /**
   * Resolve a KMS key that can be used to sign credentials.
   */
  const resolveCredentialKey = async (keyId: string): Promise<{ keyId: string; publicJwk: PublicJwk }> => {
    const publicJwk = await agent.kms.getPublicKey({ keyId })
    if (!publicJwk) throw new HttpError(404, `No key with id '${keyId}'`)
    const resolved = PublicJwk.fromUnknown(publicJwk)
    if (resolved.supportedSignatureAlgorithms.length === 0) {
      throw new HttpError(400, `Key '${keyId}' does not support signatures and cannot be used for credentials`)
    }
    return { keyId, publicJwk: resolved }
  }

  const createP256Key = async (): Promise<{ keyId: string; publicJwk: PublicJwk }> => {
    const created = await agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })
    const publicJwk = await agent.kms.getPublicKey({ keyId: created.keyId })
    if (!publicJwk) throw new HttpError(500, `Created key '${created.keyId}' has no public key`)
    return { keyId: created.keyId, publicJwk: PublicJwk.fromUnknown(publicJwk) }
  }

  /**
   * `did:jwk` embeds the public key in the DID, and the created DID record keeps the
   * KMS key id. That is what lets the SD-JWT VC module sign through OpenBao.
   */
  const createJwkDid = async (keyId: string): Promise<string> => {
    const { didState } = await agent.dids.create({ method: 'jwk', options: { keyId } })
    if (didState.state === 'failed') {
      throw new HttpError(400, `Unable to create did:jwk for '${keyId}': ${didState.reason}`)
    }
    if (didState.state !== 'finished') {
      throw new HttpError(500, `did:jwk creation for '${keyId}' did not finish (state '${didState.state}')`)
    }
    return didState.did
  }

  const issueSdJwtVc = async (body: Record<string, unknown>): Promise<Record<string, unknown>> => {
    const key = await resolveCredentialKey(asString(body.keyId, 'keyId'))
    const claims = body.claims ? asRecord(body.claims, 'claims') : {}
    const disclosureFrame = body.disclosureFrame ? (body.disclosureFrame as IDisclosureFrame) : undefined
    const holderKeyId = body.holderKeyId ? asString(body.holderKeyId, 'holderKeyId') : undefined

    const issuerDid = await createJwkDid(key.keyId)
    const holderDid = holderKeyId ? await createJwkDid(holderKeyId) : undefined
    const holder = holderDid ? { method: 'did' as const, didUrl: `${holderDid}#0` } : undefined

    const sdJwtVc = await agent.sdJwtVc.sign({
      payload: { ...claims, vct: SDJWT_VCT } as SdJwtVcPayload,
      issuer: { method: 'did', didUrl: `${issuerDid}#0` },
      ...(holder ? { holder } : {}),
      ...(disclosureFrame ? { disclosureFrame } : {}),
    })
    const record = await agent.sdJwtVc.store({ record: SdJwtVcRecord.fromSdJwtVc(sdJwtVc) })

    return {
      id: record.id,
      vct: SDJWT_VCT,
      issuerDid,
      ...(holderDid ? { holderDid } : {}),
      compact: sdJwtVc.compact,
      header: sdJwtVc.header,
      payload: sdJwtVc.payload,
      prettyClaims: sdJwtVc.prettyClaims,
    }
  }

  const issueMdoc = async (body: Record<string, unknown>): Promise<Record<string, unknown>> => {
    const issuerKey = await resolveCredentialKey(asString(body.keyId, 'keyId'))
    const alg = issuerKey.publicJwk.supportedSignatureAlgorithms.find(isMdocSupportedSignatureAlgorithm)
    if (!alg) {
      throw new HttpError(400, `Key '${issuerKey.keyId}' cannot sign mDocs. Use ES256, ES384, ES512 or EdDSA.`)
    }

    const holderKeyId = body.holderKeyId ? asString(body.holderKeyId, 'holderKeyId') : undefined
    const holder = holderKeyId ? await resolveCredentialKey(holderKeyId) : await createP256Key()
    const ca = await createP256Key()

    const now = new Date()
    const validity = {
      notBefore: new Date(now.getTime() - 60_000),
      notAfter: new Date(now.getTime() + 3_600_000),
    }
    const caCert = await X509Service.createCertificate(agent.context, {
      authorityKey: ca.publicJwk,
      issuer: { commonName: 'OpenBao Demo mDL Root CA', countryName: 'IN' },
      validity,
      extensions: {
        basicConstraints: { ca: true, pathLenConstraint: 0 },
        keyUsage: { usages: [X509KeyUsage.KeyCertSign, X509KeyUsage.CrlSign] },
      },
    })
    const leafCert = await X509Service.createCertificate(agent.context, {
      authorityKey: ca.publicJwk,
      subjectPublicKey: issuerKey.publicJwk,
      issuer: { commonName: 'OpenBao Demo mDL Root CA', countryName: 'IN' },
      subject: { commonName: 'OpenBao Demo mDL Issuer', organizationalUnit: 'Credentials', countryName: 'IN' },
      validity,
      extensions: {
        basicConstraints: { ca: false },
        keyUsage: { usages: [X509KeyUsage.DigitalSignature] },
      },
    })

    const defaults = {
      given_name: 'Alex',
      family_name: 'Doe',
      birth_date: '1985-04-12',
      issue_date: now.toISOString().slice(0, 10),
      expiry_date: validity.notAfter.toISOString().slice(0, 10),
      issuing_country: 'IN',
      issuing_authority: 'OpenBao Demo Issuer',
      document_number: `OB-${String(now.getTime()).slice(-8)}`,
      age_over_18: true,
    }
    const claims = body.claims ? asRecord(body.claims, 'claims') : {}
    const namespaces: MdocNameSpaces = { [MDOC_NAMESPACE]: { ...defaults, ...claims } }

    const mdoc = await agent.mdoc.sign({
      docType: MDOC_DOCTYPE,
      validityInfo: {
        signed: now,
        validFrom: now,
        validUntil: validity.notAfter,
      },
      namespaces,
      issuerCertificate: [leafCert, caCert],
      holderKey: holder.publicJwk,
      keyAuthorizations: { namespaces: [MDOC_NAMESPACE] },
    })
    mdoc.deviceKeyId = holder.keyId

    const record = await agent.mdoc.store({ record: MdocRecord.fromMdoc(mdoc) })
    const caPem = caCert.toString('pem')
    await agent.genericRecords.save({
      id: `mdoc-trust-${record.id}`,
      content: {
        trustedCertificatePem: caPem,
        leafCertificatePem: leafCert.toString('pem'),
        issuerKeyId: issuerKey.keyId,
        holderKeyId: holder.keyId,
      },
    })

    return {
      id: record.id,
      docType: MDOC_DOCTYPE,
      namespace: MDOC_NAMESPACE,
      alg: mdoc.alg,
      base64Url: mdoc.base64Url,
      namespaces: mdoc.issuerSignedNamespaces,
      validityInfo: {
        signed: mdoc.validityInfo.signed.toISOString(),
        validFrom: mdoc.validityInfo.validFrom.toISOString(),
        validUntil: mdoc.validityInfo.validUntil.toISOString(),
      },
      issuer: {
        keyId: issuerKey.keyId,
        certificate: leafCert.toString('pem'),
        certificateChain: [leafCert.toString('pem'), caPem],
      },
      holderKeyId: holder.keyId,
      trustAnchorKeyId: ca.keyId,
    }
  }

  const findMdocRecord = async (id: string) => {
    const records = await agent.mdoc.getAll()
    const record = records.find((candidate) => candidate.id === id)
    if (!record) throw new HttpError(404, `No mdoc with id '${id}'`)
    return record
  }

  const server = createServer(async (request, response) => {
    response.setHeader('access-control-allow-origin', '*')
    response.setHeader('access-control-allow-headers', 'content-type')
    response.setHeader('access-control-allow-methods', 'GET,POST,DELETE,OPTIONS')

    if (request.method === 'OPTIONS') {
      response.writeHead(204)
      response.end()
      return
    }

    try {
      const url = new URL(request.url ?? '/', `http://${request.headers.host ?? 'localhost'}`)

      // The demo app talks to `/api/*` through nginx. Accept both forms so the
      // agent can also be called directly, e.g. with curl.
      const rawPath = url.pathname
      const path = rawPath === '/api' ? '/' : rawPath.startsWith('/api/') ? rawPath.slice(4) : rawPath

      if (request.method === 'GET' && path === '/health') {
        sendJson(response, 200, {
          status: 'ok',
          openbao: { address: OPENBAO_ADDRESS, kvMount: KV_MOUNT },
          storage: { type: 'sqlite', path: SQLITE_PATH },
          kms: { backends: ['openbao', 'node'], defaultBackend: 'openbao' },
        })
        return
      }

      if (request.method === 'GET' && path === '/info') {
        sendJson(response, 200, {
          service: 'credo-ts-openbao dev agent',
          environment: 'development',
          devOnly: true,
          warning:
            'DEVELOPMENT ONLY. This service exposes a root-token-backed OpenBao instance with a permissive CORS policy. Never deploy it to production.',
          openbao: {
            address: OPENBAO_ADDRESS,
            kvMount: KV_MOUNT,
            status: await openBaoStatus(),
          },
          storage: { type: 'sqlite', path: SQLITE_PATH },
          kms: {
            backends: ['openbao', 'node'],
            defaultBackend: 'openbao',
            operations: {
              createKey: supportedBackends({ operation: 'createKey', type: { kty: 'EC', crv: 'P-256' } }),
              importKey: supportedBackends({
                operation: 'importKey',
                privateJwk: { kty: 'OKP', crv: 'Ed25519', x: '', d: '' } as KmsJwkPrivate,
              }),
              sign: supportedBackends({ operation: 'sign', algorithm: 'EdDSA' }),
              verify: supportedBackends({ operation: 'verify', algorithm: 'ES256' }),
              deleteKey: supportedBackends({ operation: 'deleteKey' }),
              randomBytes: supportedBackends({ operation: 'randomBytes' }),
              encrypt: supportedBackends({ operation: 'encrypt', encryption: { algorithm: 'A256GCM' } }),
              decrypt: supportedBackends({
                operation: 'decrypt',
                decryption: {
                  algorithm: 'A256GCM',
                  iv: new Uint8Array(12),
                  tag: new Uint8Array(16),
                },
              }),
            },
          },
          keyTypes: DEMO_KEY_TYPES,
          credentials: {
            sdJwtVc: { vct: SDJWT_VCT, issuer: 'did:jwk backed by an OpenBao KMS key' },
            mdoc: {
              docType: MDOC_DOCTYPE,
              namespace: MDOC_NAMESPACE,
              issuer: 'X.509 leaf certificate backed by an OpenBao KMS key',
            },
          },
        })
        return
      }

      if (request.method === 'GET' && path === '/demo/jwk') {
        const keyTypeId = asString(url.searchParams.get('type'), 'type')
        sendJson(response, 200, {
          type: keyTypeId,
          privateJwk: generateSampleJwk(keyTypeId),
        })
        return
      }

      if (request.method === 'POST' && path === '/keys') {
        const body = await readJson(request)
        const type = asRecord(body.type, 'type') as unknown as KmsCreateKeyType
        const key = await agent.kms.createKey({
          type,
          ...(body.keyId ? { keyId: asString(body.keyId, 'keyId') } : {}),
          ...(body.backend ? { backend: asString(body.backend, 'backend') } : {}),
        })
        sendJson(response, 201, { ...key, store: await detectKeyStore(key.keyId) })
        return
      }

      if (request.method === 'POST' && path === '/keys/import') {
        const body = await readJson(request)
        const privateJwk = asRecord(body.privateJwk, 'privateJwk') as unknown as KmsJwkPrivate
        const key = await agent.kms.importKey({
          privateJwk,
          ...(body.keyId ? { keyId: asString(body.keyId, 'keyId') } : {}),
          ...(body.backend ? { backend: asString(body.backend, 'backend') } : {}),
        })
        sendJson(response, 201, { ...key, store: await detectKeyStore(key.keyId) })
        return
      }

      if (request.method === 'GET' && path.startsWith('/keys/')) {
        const keyId = decodeURIComponent(path.slice('/keys/'.length))
        const publicJwk = await agent.kms.getPublicKey({ keyId })
        if (!publicJwk) throw new HttpError(404, `No key with id '${keyId}'`)
        sendJson(response, 200, { keyId, publicJwk, store: await detectKeyStore(keyId) })
        return
      }

      if (request.method === 'DELETE' && path.startsWith('/keys/')) {
        const keyId = decodeURIComponent(path.slice('/keys/'.length))
        const backend = url.searchParams.get('backend')
        const deleted = await agent.kms.deleteKey({
          keyId,
          ...(backend ? { backend } : {}),
        })
        if (!deleted) throw new HttpError(404, `No key with id '${keyId}' in backend '${backend ?? 'default'}'`)
        sendJson(response, 200, { keyId, deleted: true })
        return
      }

      if (request.method === 'POST' && path === '/sign') {
        const body = await readJson(request)
        const keyId = asString(body.keyId, 'keyId')
        const algorithm = asString(body.algorithm, 'algorithm') as KnownJwaSignatureAlgorithm
        const { signature } = await agent.kms.sign({
          keyId,
          algorithm,
          data: dataFromBody(body),
        })
        sendJson(response, 200, {
          keyId,
          algorithm,
          data: Buffer.from(dataFromBody(body)).toString('utf8'),
          signature: encodeSignature(signature),
        })
        return
      }

      if (request.method === 'POST' && path === '/verify') {
        const body = await readJson(request)
        const algorithm = asString(body.algorithm, 'algorithm') as KnownJwaSignatureAlgorithm
        const key = body.keyId
          ? { keyId: asString(body.keyId, 'keyId') }
          : { publicJwk: asRecord(body.publicJwk, 'publicJwk') as unknown as AsymmetricKmsJwkPublic }

        const { verified } = await agent.kms.verify({
          key,
          algorithm,
          data: dataFromBody(body),
          signature: signatureFromBody(body),
        })
        sendJson(response, 200, { verified })
        return
      }

      if (request.method === 'POST' && path === '/random-bytes') {
        const body = await readJson(request)
        const length = asInteger(body.length ?? 32, 'length', 1, 1024)
        const bytes = agent.kms.randomBytes({ length })
        sendJson(response, 200, {
          length,
          backend: agent.kms.supportedBackendsForOperation({ operation: 'randomBytes' })[0] ?? 'unknown',
          base64url: Buffer.from(bytes).toString('base64url'),
          hex: Buffer.from(bytes).toString('hex'),
        })
        return
      }

      if (request.method === 'POST' && path === '/crypto/encrypt') {
        const body = await readJson(request)
        const data = dataFromBody(body)
        const providedKeyId = body.keyId ? asString(body.keyId, 'keyId') : undefined
        let keyId = providedKeyId
        let keyCreated = false

        if (!keyId) {
          const key = await agent.kms.createKey({
            type: { kty: 'oct', algorithm: 'aes', length: 256 },
            backend: 'node',
          })
          keyId = key.keyId
          keyCreated = true
        }

        const encrypted = await agent.kms.encrypt({
          key: { keyId },
          encryption: { algorithm: 'A256GCM' },
          data,
        })

        sendJson(response, 200, {
          keyId,
          keyCreated,
          backend: 'node',
          algorithm: 'A256GCM',
          plaintext: Buffer.from(data).toString('utf8'),
          encrypted: Buffer.from(encrypted.encrypted).toString('base64url'),
          iv: Buffer.from(encrypted.iv ?? new Uint8Array()).toString('base64url'),
          tag: Buffer.from(encrypted.tag ?? new Uint8Array()).toString('base64url'),
        })
        return
      }

      if (request.method === 'POST' && path === '/crypto/decrypt') {
        const body = await readJson(request)
        const keyId = asString(body.keyId, 'keyId')
        const decrypted = await agent.kms.decrypt({
          key: { keyId },
          decryption: {
            algorithm: 'A256GCM',
            iv: bytesFromBase64Url(body.iv, 'iv'),
            tag: bytesFromBase64Url(body.tag, 'tag'),
          },
          encrypted: bytesFromBase64Url(body.encrypted, 'encrypted'),
        })
        sendJson(response, 200, {
          keyId,
          backend: 'node',
          data: Buffer.from(decrypted.data).toString('utf8'),
          base64url: Buffer.from(decrypted.data).toString('base64url'),
        })
        return
      }

      if (request.method === 'POST' && path === '/x509/demo') {
        sendJson(response, 200, await runX509Demo())
        return
      }

      if (request.method === 'GET' && path === '/credentials') {
        const sdJwtVcRecords = await agent.sdJwtVc.getAll()
        const mdocRecords = await agent.mdoc.getAll()
        sendJson(response, 200, {
          sdJwtVc: sdJwtVcRecords.map((record) => {
            const credential = record.firstCredential
            return {
              id: record.id,
              createdAt: record.createdAt,
              vct: credential.payload.vct,
              issuer: credential.issuer,
              holder: credential.holder,
              alg: credential.header.alg,
              compact: credential.compact,
              payload: credential.payload,
              prettyClaims: credential.prettyClaims,
            }
          }),
          mdoc: mdocRecords.map((record) => {
            const credential = record.firstCredential
            return {
              id: record.id,
              createdAt: record.createdAt,
              docType: credential.docType,
              alg: credential.alg,
              base64Url: credential.base64Url,
              namespaces: credential.issuerSignedNamespaces,
              validityInfo: {
                signed: credential.validityInfo.signed.toISOString(),
                validFrom: credential.validityInfo.validFrom.toISOString(),
                validUntil: credential.validityInfo.validUntil.toISOString(),
              },
            }
          }),
        })
        return
      }

      if (request.method === 'POST' && path === '/credentials/sd-jwt-vc') {
        const body = await readJson(request)
        sendJson(response, 201, await issueSdJwtVc(body))
        return
      }

      if (request.method === 'POST' && path === '/credentials/sd-jwt-vc/verify') {
        const body = await readJson(request)
        const keyBindingInput = body.keyBinding ? asRecord(body.keyBinding, 'keyBinding') : undefined
        const keyBinding = keyBindingInput
          ? {
              audience: asString(keyBindingInput.audience, 'keyBinding.audience'),
              nonce: asString(keyBindingInput.nonce, 'keyBinding.nonce'),
            }
          : undefined

        const result = await agent.sdJwtVc.verify({
          compactSdJwtVc: asString(body.compact, 'compact'),
          ...(keyBinding ? { keyBinding } : {}),
          ...(body.requiredClaimKeys ? { requiredClaimKeys: body.requiredClaimKeys as string[] } : {}),
        })

        if (!result.isValid) {
          sendJson(response, 200, { valid: false, error: result.error.message })
          return
        }

        sendJson(response, 200, {
          valid: true,
          vct: result.sdJwtVc.payload.vct,
          issuer: result.sdJwtVc.issuer,
          holder: result.sdJwtVc.holder,
          header: result.sdJwtVc.header,
          payload: result.sdJwtVc.payload,
          prettyClaims: result.sdJwtVc.prettyClaims,
        })
        return
      }

      if (request.method === 'POST' && path === '/credentials/sd-jwt-vc/present') {
        const body = await readJson(request)
        const id = body.id ? asString(body.id, 'id') : undefined
        const compact = id
          ? (await agent.sdJwtVc.getAll()).find((record) => record.id === id)?.firstCredential.compact
          : body.compact
            ? asString(body.compact, 'compact')
            : undefined
        if (!compact) throw new HttpError(404, `No SD-JWT VC found for '${id ?? 'the supplied compact value'}'`)

        const verifierMetadataInput = body.verifierMetadata
          ? asRecord(body.verifierMetadata, 'verifierMetadata')
          : undefined
        const verifierMetadata = verifierMetadataInput
          ? {
              audience: asString(verifierMetadataInput.audience, 'verifierMetadata.audience'),
              nonce: asString(verifierMetadataInput.nonce, 'verifierMetadata.nonce'),
              issuedAt: Math.floor(Date.now() / 1000),
            }
          : undefined

        const presentation = await agent.sdJwtVc.present({
          sdJwtVc: compact,
          ...(body.presentationFrame ? { presentationFrame: body.presentationFrame as IPresentationFrame } : {}),
          ...(verifierMetadata ? { verifierMetadata } : {}),
        })

        sendJson(response, 200, {
          id,
          presentation,
          keyBinding: Boolean(verifierMetadata),
        })
        return
      }

      if (request.method === 'DELETE' && path.startsWith('/credentials/sd-jwt-vc/')) {
        const id = decodeURIComponent(path.slice('/credentials/sd-jwt-vc/'.length))
        const record = (await agent.sdJwtVc.getAll()).find((candidate) => candidate.id === id)
        if (!record) throw new HttpError(404, `No SD-JWT VC with id '${id}'`)
        await agent.sdJwtVc.deleteById(id)
        sendJson(response, 200, { id, deleted: true })
        return
      }

      if (request.method === 'POST' && path === '/credentials/mdoc') {
        const body = await readJson(request)
        sendJson(response, 201, await issueMdoc(body))
        return
      }

      if (request.method === 'POST' && path === '/credentials/mdoc/verify') {
        const body = await readJson(request)
        const id = asString(body.id, 'id')
        const record = await findMdocRecord(id)
        const trustRecord = await agent.genericRecords.findById(`mdoc-trust-${id}`)
        if (!trustRecord) throw new HttpError(404, `No trust anchor stored for mdoc '${id}'`)

        const mdoc = record.firstCredential
        const result = await agent.mdoc.verify(mdoc, {
          trustedCertificates: [asString(trustRecord.content.trustedCertificatePem, 'trustedCertificatePem')],
        })

        sendJson(response, 200, {
          id,
          valid: result.isValid,
          ...(result.isValid ? {} : { error: result.error }),
          docType: mdoc.docType,
          alg: mdoc.alg,
          namespaces: mdoc.issuerSignedNamespaces,
        })
        return
      }

      if (request.method === 'DELETE' && path.startsWith('/credentials/mdoc/')) {
        const id = decodeURIComponent(path.slice('/credentials/mdoc/'.length))
        const record = await findMdocRecord(id)
        await agent.mdoc.deleteById(record.id)
        const trustRecord = await agent.genericRecords.findById(`mdoc-trust-${id}`)
        if (trustRecord) await agent.genericRecords.delete(trustRecord)
        sendJson(response, 200, { id, deleted: true })
        return
      }

      if (request.method === 'GET' && path === '/dids') {
        const records = await agent.dids.getCreatedDids()
        sendJson(
          response,
          200,
          records.map((record) => ({ did: record.did, role: record.role, keys: record.keys })),
        )
        return
      }

      if (request.method === 'POST' && path === '/dids') {
        const body = await readJson(request)
        const method = asString(body.method, 'method')
        const keyId = asString(body.keyId, 'keyId')

        const result =
          method === 'peer'
            ? await agent.dids.create({ method: 'peer', options: { numAlgo: 0, keyId } })
            : method === 'key'
              ? await agent.dids.create({ method: 'key', options: { keyId } })
              : method === 'jwk'
                ? await agent.dids.create({ method: 'jwk', options: { keyId } })
                : (() => {
                    throw new HttpError(400, `Unsupported DID method '${method}' (use key, jwk or peer)`)
                  })()

        sendJson(response, 201, didState(result))
        return
      }

      throw new HttpError(404, `No route for ${request.method ?? 'GET'} ${path}`)
    } catch (error) {
      if (response.headersSent) return
      const status = error instanceof HttpError ? error.status : 500
      const message = error instanceof Error ? error.message : String(error)
      if (status === 500) console.error(error)
      sendJson(response, status, { error: message })
    }
  })

  server.listen(HTTP_PORT, HTTP_HOST, () => {
    console.log(`Credo dev agent listening on http://${HTTP_HOST}:${HTTP_PORT}`)
    console.log(`  OpenBao: ${OPENBAO_ADDRESS} (KV mount: ${KV_MOUNT})`)
    console.log(`  SQLite:  ${SQLITE_PATH}`)
    console.log('  Endpoints: /health, /info, /keys, /keys/import, /sign, /verify, /dids,')
    console.log('             /random-bytes, /crypto/encrypt, /crypto/decrypt, /x509/demo, /demo/jwk,')
    console.log('             /credentials, /credentials/sd-jwt-vc, /credentials/mdoc')
  })

  const shutdown = async (): Promise<void> => {
    console.log('Shutting down...')
    server.close()
    await agent.shutdown()
    sqlite.close()
    process.exit(0)
  }

  process.once('SIGTERM', () => void shutdown())
  process.once('SIGINT', () => void shutdown())
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
