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

import {
  constants,
  createHash,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
  verify as cryptoVerify,
} from 'node:crypto'

import { utils, type AgentContext } from '@credo-ts/core'
import {
  KeyManagementAlgorithmNotSupportedError,
  KeyManagementError,
  KeyManagementKeyExistsError,
  KeyManagementKeyNotFoundError,
  type KeyManagementService,
  type KmsCreateKeyOptions,
  type KmsCreateKeyReturn,
  type KmsCreateKeyType,
  type KmsDecryptOptions,
  type KmsDecryptReturn,
  type KmsDeleteKeyOptions,
  type KmsEncryptOptions,
  type KmsEncryptReturn,
  type KmsImportKeyOptions,
  type KmsImportKeyReturn,
  type KmsJwkPrivate,
  type KmsJwkPublic,
  type KmsOperation,
  type KmsRandomBytesOptions,
  type KmsRandomBytesReturn,
  type KmsSignOptions,
  type KmsSignReturn,
  type KmsVerifyOptions,
  type KmsVerifyReturn,
} from '@credo-ts/core/kms'

import {
  OpenBaoNotFoundError,
  OpenBaoRequestError,
  type OpenBaoClient,
  type OpenBaoHealth,
  type OpenBaoKeyType,
  type OpenBaoTransitKey,
} from './OpenBaoClient.js'
import { generateSecp256k1KeyPair, signSecp256k1, verifySecp256k1 } from './secp256k1.js'
import {
  privateJwkToPkcs8,
  publicJwkFromPrivateJwk,
  rsaModulusLengthFromPrivateJwk,
  wrapPrivateKeyForTransitImport,
} from './transitImport.js'

const BACKEND_NAME = 'openbao'

/**
 * Every key id returned by this backend is prefixed so it can never collide
 * with a key id from Askar or another local backend. Credo routes key-based
 * operations by asking each backend for the key in registration order, and
 * Askar keeps the `kid` of an imported JWK verbatim, so without this prefix a
 * key imported into both stores would silently resolve to Askar.
 */
export const OPENBAO_KEY_ID_PREFIX = 'ob_'

/** Namespace a Credo key id for OpenBao. Idempotent, so callers can pass an already namespaced id. */
export function openBaoKeyId(keyId: string): string {
  return keyId.startsWith(OPENBAO_KEY_ID_PREFIX) ? keyId : `${OPENBAO_KEY_ID_PREFIX}${keyId}`
}

/** Transit generic names are limited to 128 characters. */
const MAX_KEY_NAME_LENGTH = 128

/**
 * Resolve the isolation scope for an agent context. The default combines the
 * deployment id with Credo's context correlation id (`default` for the root
 * agent, `tenant-<id>` for a tenant), so two tenants that happen to use the
 * same key id never share a Transit key.
 */
export type KeyNameScopeResolver = (agentContext: AgentContext | undefined) => string

interface SignAlgorithm {
  nodeHash: string | null
  transitHash?: string
  marshaling?: 'asn1' | 'jws'
  signatureAlgorithm?: 'pss' | 'pkcs1v15'
  saltLength?: string
  /**
   * Transit cannot represent this key type. Signing happens in-process with
   * node:crypto, using key material stored in an OpenBao KV v2 mount.
   */
  local?: boolean
}

/**
 * JWA algorithm -> the parameters each engine needs.
 *
 * ECDSA uses `marshaling_algorithm=jws` so OpenBao returns the raw `r || s`
 * form JWA requires (instead of the default ASN.1 DER form).
 *
 * RSA PSS uses `salt_length=hash` because JWA requires the salt length to
 * equal the hash length, while Transit defaults to the maximum salt length.
 */
const SIGN_ALGORITHMS: Record<string, SignAlgorithm> = {
  EdDSA: { nodeHash: null },
  ES256: { nodeHash: 'sha256', transitHash: 'sha2-256', marshaling: 'jws' },
  ES384: { nodeHash: 'sha384', transitHash: 'sha2-384', marshaling: 'jws' },
  ES512: { nodeHash: 'sha512', transitHash: 'sha2-512', marshaling: 'jws' },
  RS256: { nodeHash: 'sha256', transitHash: 'sha2-256', signatureAlgorithm: 'pkcs1v15' },
  RS384: { nodeHash: 'sha384', transitHash: 'sha2-384', signatureAlgorithm: 'pkcs1v15' },
  RS512: { nodeHash: 'sha512', transitHash: 'sha2-512', signatureAlgorithm: 'pkcs1v15' },
  PS256: { nodeHash: 'sha256', transitHash: 'sha2-256', signatureAlgorithm: 'pss', saltLength: 'hash' },
  PS384: { nodeHash: 'sha384', transitHash: 'sha2-384', signatureAlgorithm: 'pss', saltLength: 'hash' },
  PS512: { nodeHash: 'sha512', transitHash: 'sha2-512', signatureAlgorithm: 'pss', saltLength: 'hash' },
  // secp256k1 (`did:ethr`, `did:key`). Transit has no such key type, so the
  // key is stored in OpenBao KV and signed in-process.
  ES256K: { nodeHash: 'sha256', local: true },
}

/**
 * Key types Credo supports in DID documents that Transit cannot represent.
 * They fall back to an OpenBao KV v2 mount when one is configured.
 */
type KvKeyType = 'secp256k1' | 'x25519'

interface KvKeyRecord {
  version: 1
  keyId: string
  keyType: KvKeyType
  privateJwk: Record<string, unknown>
  publicJwk: Record<string, unknown>
}

/** Options for {@link OpenBaoKeyManagementService}. */
export interface OpenBaoKeyManagementServiceOptions {
  /** A client for the OpenBao Transit engine, normally a {@link FetchOpenBaoClient}. */
  client: OpenBaoClient
  /**
   * Deployment identifier used to isolate this deployment from other
   * deployments that share the OpenBao cluster. Defaults to no deployment
   * prefix, i.e. the scope is only the context correlation id.
   */
  deploymentId?: string
  /**
   * Override how a scope is derived from an agent context. The default is
   * `<deploymentId>:<contextCorrelationId>`, or just the context correlation
   * id when no deployment id is configured.
   */
  scopeResolver?: KeyNameScopeResolver
  /**
   * Prefix for the generated Transit key name. The full name is
   * `<prefix>_<scopeHash>_<base64url(keyId)>`. Defaults to `ac`.
   */
  keyNamePrefix?: string
  /**
   * How long public keys are cached, in milliseconds. Credo resolves the
   * backend for a key id by calling `getPublicKey`, so without a cache every
   * `sign` costs two round trips. Defaults to 5 minutes. Set to `0` to disable.
   */
  publicKeyCacheTtlMs?: number
  /**
   * How long a "key not found" result is cached, in milliseconds. Without
   * this, a key that belongs to another backend costs a 404 on every route
   * lookup. Defaults to 30 seconds. Set to `0` to disable.
   */
  negativeCacheTtlMs?: number
  /**
   * Allow this backend to create, import, and delete keys. Defaults to `true`.
   * Set to `false` for a controlled rollback: existing keys can still sign and
   * verify, but new keys go to the next backend.
   */
  writeEnabled?: boolean
  /**
   * KV v2 mount used for key types Transit cannot represent (secp256k1 and
   * X25519). Leave unset to route those key types to another backend such as
   * Node.js or Askar. When set, the mount must exist and the token needs
   * read/write/delete permissions on `DATA`/`METADATA` under the prefix.
   */
  kvMount?: string
  /** Path prefix inside `kvMount`. Defaults to `credo-keys`. */
  kvPathPrefix?: string
}

/**
 * A Credo KMS backend backed by OpenBao.
 *
 * Ed25519, P-256, P-384, P-521 and RSA keys are created, imported and signed
 * inside the Transit secrets engine. secp256k1 and X25519 — which Transit
 * cannot represent — can be stored in a KV v2 mount (`kvMount`); secp256k1 is
 * then signed in-process so every DID method Credo supports can use OpenBao as
 * its key store. Unsupported on purpose: encrypt/decrypt, randomBytes and
 * symmetric import (see README for why).
 */
export class OpenBaoKeyManagementService implements KeyManagementService {
  /** Backend name used in Credo's `KeyManagementModule` (`defaultBackend`, `backend` option). */
  public readonly backend: string = BACKEND_NAME

  readonly #client: OpenBaoClient
  readonly #deploymentId?: string
  readonly #scopeResolver: KeyNameScopeResolver
  readonly #keyNamePrefix: string
  readonly #publicKeyCacheTtlMs: number
  readonly #negativeCacheTtlMs: number
  readonly #writeEnabled: boolean
  readonly #kvMount?: string
  readonly #kvPathPrefix: string
  readonly #publicKeyCache = new Map<string, { publicJwk: KmsJwkPublic; expiresAt: number }>()
  readonly #negativeCache = new Map<string, number>()

  /**
   * Create the backend.
   *
   * @param options OpenBao client and backend settings.
   */
  public constructor(options: OpenBaoKeyManagementServiceOptions) {
    this.#client = options.client
    if (options.deploymentId) this.#deploymentId = options.deploymentId
    this.#scopeResolver =
      options.scopeResolver ??
      ((agentContext) => this.scopeForCorrelationId(agentContext?.contextCorrelationId ?? 'default'))
    this.#keyNamePrefix = options.keyNamePrefix ?? 'ac'
    this.#publicKeyCacheTtlMs = options.publicKeyCacheTtlMs ?? 5 * 60 * 1000
    this.#negativeCacheTtlMs = options.negativeCacheTtlMs ?? 30 * 1000
    this.#writeEnabled = options.writeEnabled ?? true
    if (options.kvMount) this.#kvMount = options.kvMount.replace(/^\/+|\/+$/g, '')
    this.#kvPathPrefix = (options.kvPathPrefix ?? 'credo-keys').replace(/^\/+|\/+$/g, '')
  }

  /**
   * The Transit key name for a Credo key id. The name includes a hash of the
   * isolation scope, so the same key id in two tenants maps to two keys.
   */
  public keyName(keyId: string): string
  /** The Transit key name for a Credo key id within an agent context's scope. */
  public keyName(agentContext: AgentContext, keyId: string): string
  public keyName(agentContextOrKeyId: AgentContext | string, maybeKeyId?: string): string {
    const keyId = typeof agentContextOrKeyId === 'string' ? agentContextOrKeyId : maybeKeyId
    if (keyId === undefined) throw new KeyManagementError('A key id is required to build a Transit key name')
    const agentContext = typeof agentContextOrKeyId === 'string' ? undefined : agentContextOrKeyId
    return this.#keyName(this.#scopeResolver(agentContext), keyId)
  }

  /** The isolation scope for an agent context. */
  public scopeFor(agentContext: AgentContext): string {
    return this.#scopeResolver(agentContext)
  }

  /** The isolation scope for a Credo context correlation id (`tenant-<id>`, `default`). */
  public scopeForCorrelationId(correlationId: string): string {
    return this.#deploymentId ? `${this.#deploymentId}:${correlationId}` : correlationId
  }

  /** Clear the public-key and "not found" caches. */
  public clearPublicKeyCache(): void {
    this.#publicKeyCache.clear()
    this.#negativeCache.clear()
  }

  /** Read OpenBao's health. Throws `OpenBaoSealedError` or `OpenBaoUnreachableError`. */
  public health(): Promise<OpenBaoHealth> {
    return this.#client.health()
  }

  /** Fail fast at startup when OpenBao is sealed, uninitialised, or unreachable. */
  public assertHealthy(): Promise<void> {
    return this.#client.assertHealthy()
  }

  /**
   * Whether this backend can perform an operation. Returns `false` for
   * encrypt/decrypt, randomBytes and symmetric keys, so Credo routes them to
   * another backend.
   */
  public isOperationSupported(_agentContext: AgentContext, operation: KmsOperation): boolean {
    switch (operation.operation) {
      case 'createKey':
        return (
          this.#writeEnabled &&
          (openBaoKeyTypeForCreate(operation.type) !== undefined ||
            (this.#kvMount !== undefined && openBaoKvKeyTypeForCreate(operation.type) !== undefined))
        )
      case 'sign':
      case 'verify':
        return (
          operation.algorithm in SIGN_ALGORITHMS &&
          (!SIGN_ALGORITHMS[operation.algorithm]?.local || this.#kvMount !== undefined)
        )
      case 'importKey':
        return (
          this.#writeEnabled &&
          (openBaoKeyTypeForImport(operation.privateJwk) !== undefined ||
            (this.#kvMount !== undefined && openBaoKvKeyTypeForImport(operation.privateJwk) !== undefined))
        )
      case 'deleteKey':
        // A read-only deployment leaves deletion to a backend that owns the key.
        return this.#writeEnabled
      // Not implemented on purpose. The Node.js or Askar backend handles these.
      case 'encrypt':
      case 'decrypt':
      case 'randomBytes':
        return false
    }
  }

  /** Public JWK for a key id, or `null` when this backend does not hold the key. */
  public async getPublicKey(agentContext: AgentContext, keyId: string): Promise<KmsJwkPublic | null> {
    const scope = this.#scopeResolver(agentContext)
    const cacheKey = cacheKeyFor(scope, keyId)

    const cached = this.#publicKeyCache.get(cacheKey)
    if (cached && cached.expiresAt > Date.now()) return cached.publicJwk
    const negativeExpiry = this.#negativeCache.get(cacheKey)
    if (negativeExpiry && negativeExpiry > Date.now()) return null

    let key: OpenBaoTransitKey
    try {
      key = await this.#client.getKey(this.keyName(agentContext, keyId))
    } catch (error) {
      if (!(error instanceof OpenBaoNotFoundError)) throw error

      // Not in Transit. secp256k1/X25519 keys may live in the KV fallback.
      const record = await this.#readKvKey(agentContext, keyId)
      if (!record) {
        this.#cacheNotFound(scope, keyId)
        return null
      }

      const publicJwk = { ...record.publicJwk, kid: keyId } as KmsJwkPublic
      this.#cachePublicKey(scope, keyId, publicJwk)
      return publicJwk
    }

    const publicJwk = publicJwkFromTransitKey(key, keyId)
    if (!publicJwk) {
      throw new KeyManagementError(
        `OpenBao key '${key.name}' has type '${key.type}', which has no public JWK representation`,
      )
    }

    this.#cachePublicKey(scope, keyId, publicJwk)
    return publicJwk
  }

  /** Create a key in Transit (or KV v2 for secp256k1/X25519). The returned key id starts with `ob_`. */
  public async createKey<Type extends KmsCreateKeyType>(
    agentContext: AgentContext,
    options: KmsCreateKeyOptions<Type>,
  ): Promise<KmsCreateKeyReturn<Type>> {
    this.#assertWritable('create a key')

    const kvKeyType = openBaoKvKeyTypeForCreate(options.type)
    if (kvKeyType) return this.#createKvKey(agentContext, kvKeyType, options)

    const transitType = openBaoKeyTypeForCreate(options.type)
    if (!transitType) {
      throw new KeyManagementAlgorithmNotSupportedError(describeCreateKeyType(options.type), BACKEND_NAME)
    }

    // Credo stores the key id in DIDs and credential records, so it must be stable.
    const keyId = openBaoKeyId(options.keyId ?? utils.uuid())
    const name = this.keyName(agentContext, keyId)
    const key = await this.#client.createKey(name, transitType)

    // Transit silently returns an existing key, also if its type differs.
    if (key.type !== transitType) {
      throw new KeyManagementKeyExistsError(keyId, BACKEND_NAME)
    }

    const publicJwk = publicJwkFromTransitKey(key, keyId)
    if (!publicJwk) {
      throw new KeyManagementError(`Could not read the public key of OpenBao key '${name}' after creating it`)
    }

    this.#cachePublicKey(this.#scopeResolver(agentContext), keyId, publicJwk)
    return { keyId, publicJwk } as KmsCreateKeyReturn<Type>
  }

  /** Delete a key. Returns `false` when the key does not exist. */
  public async deleteKey(agentContext: AgentContext, options: KmsDeleteKeyOptions): Promise<boolean> {
    this.#assertWritable('delete a key')

    const scope = this.#scopeResolver(agentContext)
    const name = this.keyName(agentContext, options.keyId)
    let deleted = false

    const transitKey = await this.#getTransitKeyOrNull(name)
    if (transitKey) {
      // Transit refuses to delete a key unless this is explicitly allowed.
      await this.#client.updateKeyConfig(name, { deletionAllowed: true })
      await this.#client.deleteKey(name)
      deleted = true
    }

    // Also remove a KV-backed key, e.g. if the id was reused across key types.
    if (await this.#deleteKvKey(agentContext, options.keyId)) deleted = true

    if (deleted) {
      const cacheKey = cacheKeyFor(scope, options.keyId)
      this.#publicKeyCache.delete(cacheKey)
      this.#negativeCache.delete(cacheKey)
    }
    return deleted
  }

  /** Sign data with a key held by this backend. */
  public async sign(agentContext: AgentContext, options: KmsSignOptions): Promise<KmsSignReturn> {
    const algorithm = SIGN_ALGORITHMS[options.algorithm]
    if (!algorithm) {
      throw new KeyManagementAlgorithmNotSupportedError(`algorithm '${options.algorithm}'`, BACKEND_NAME)
    }

    if (algorithm.local) {
      return { signature: await this.#signLocally(agentContext, options.keyId, algorithm, options.data) }
    }

    const signature = await this.#client.sign(this.keyName(agentContext, options.keyId), {
      input: options.data,
      ...(algorithm.transitHash ? { hashAlgorithm: algorithm.transitHash } : {}),
      ...(algorithm.marshaling ? { marshalingAlgorithm: algorithm.marshaling } : {}),
      ...(algorithm.signatureAlgorithm ? { signatureAlgorithm: algorithm.signatureAlgorithm } : {}),
      ...(algorithm.saltLength ? { saltLength: algorithm.saltLength } : {}),
    })

    return { signature: decodeTransitSignature(signature, algorithm.marshaling === 'jws') }
  }

  /** Verify a signature locally, using only public key material. */
  public async verify(agentContext: AgentContext, options: KmsVerifyOptions): Promise<KmsVerifyReturn> {
    const algorithm = SIGN_ALGORITHMS[options.algorithm]
    if (!algorithm) {
      throw new KeyManagementAlgorithmNotSupportedError(`algorithm '${options.algorithm}'`, BACKEND_NAME)
    }

    // Verification only needs public material, so it is done locally. That
    // avoids Transit's per-version signature semantics (a signature is bound
    // to the key version that produced it) and also verifies keys that do not
    // live in OpenBao, e.g. RSA keys in an X.509 chain.
    let publicJwk: KmsJwkPublic | null = null
    let keyId: string | undefined

    if ('publicJwk' in options.key && options.key.publicJwk) {
      publicJwk = options.key.publicJwk
    } else if ('keyId' in options.key && typeof options.key.keyId === 'string') {
      keyId = options.key.keyId
      publicJwk = await this.getPublicKey(agentContext, keyId)
    }

    if (!publicJwk) {
      throw new KeyManagementKeyNotFoundError(keyId ?? 'unknown', [BACKEND_NAME])
    }

    return verifyWithPublicJwk(publicJwk, algorithm, options.data, options.signature)
      ? { verified: true, publicJwk }
      : { verified: false }
  }

  /**
   * Import an externally generated private key (e.g. the key matching an
   * X.509 certificate).
   *
   * Ed25519, P-256/384/521 and RSA keys use Transit's BYOK endpoint and never
   * travel in plaintext. secp256k1 and X25519 use the configured KV v2 mount;
   * secp256k1 signatures are then produced in-process.
   */
  public async importKey<Jwk extends KmsJwkPrivate>(
    agentContext: AgentContext,
    options: KmsImportKeyOptions<Jwk>,
  ): Promise<KmsImportKeyReturn<Jwk>> {
    this.#assertWritable('import a key')

    const keyId = openBaoKeyId(options.privateJwk.kid ?? utils.uuid())
    const name = this.keyName(agentContext, keyId)

    // Neither store overwrites an existing key. Check both so the caller gets
    // the same typed error as `createKey`.
    if (await this.#getTransitKeyOrNull(name)) throw new KeyManagementKeyExistsError(keyId, BACKEND_NAME)
    if (await this.#readKvKey(agentContext, keyId)) throw new KeyManagementKeyExistsError(keyId, BACKEND_NAME)

    const transitType = openBaoKeyTypeForImport(options.privateJwk)
    if (transitType) {
      const pkcs8 = privateJwkToPkcs8(options.privateJwk)
      const wrappingKey = await this.#client.getWrappingKey()
      const ciphertext = wrapPrivateKeyForTransitImport(pkcs8, wrappingKey)

      try {
        await this.#client.importKey(name, {
          type: transitType,
          ciphertext,
          hashFunction: 'SHA256',
          // Imported keys must not rotate: a Credo key id has to keep resolving
          // to the same public key for every DID and credential that references it.
          allowRotation: false,
        })
      } catch (error) {
        // Covers a race where the key was created between the check and the import.
        if (error instanceof OpenBaoRequestError && error.errors.some((message) => message.includes('existing key'))) {
          throw new KeyManagementKeyExistsError(keyId, BACKEND_NAME)
        }
        throw error
      }
    } else {
      const kvKeyType = openBaoKvKeyTypeForImport(options.privateJwk)
      if (!kvKeyType || !this.#kvMount) {
        throw new KeyManagementAlgorithmNotSupportedError(describePrivateJwk(options.privateJwk), BACKEND_NAME)
      }

      const publicJwk = publicJwkFromPrivateJwk(options.privateJwk, keyId)
      await this.#writeKvKey(agentContext, {
        version: 1,
        keyId,
        keyType: kvKeyType,
        privateJwk: options.privateJwk as unknown as Record<string, unknown>,
        publicJwk: publicJwk as unknown as Record<string, unknown>,
      })
    }

    const publicJwk = publicJwkFromPrivateJwk(options.privateJwk, keyId)
    this.#cachePublicKey(this.#scopeResolver(agentContext), keyId, publicJwk)
    return { keyId, publicJwk } as KmsImportKeyReturn<Jwk>
  }

  /** Not supported; always throws. Credo routes encryption to another backend. */
  public encrypt(_agentContext: AgentContext, _options: KmsEncryptOptions): Promise<KmsEncryptReturn> {
    return Promise.reject(
      new KeyManagementError(
        `Encrypting is not supported by backend '${BACKEND_NAME}'. ` +
          'Register the Askar or Node.js backend as well, and it will handle encryption.',
      ),
    )
  }

  /** Not supported; always throws. Credo routes decryption to another backend. */
  public decrypt(_agentContext: AgentContext, _options: KmsDecryptOptions): Promise<KmsDecryptReturn> {
    return Promise.reject(
      new KeyManagementError(
        `Decrypting is not supported by backend '${BACKEND_NAME}'. ` +
          'Register the Askar or Node.js backend as well, and it will handle decryption.',
      ),
    )
  }

  /**
   * Not supported: OpenBao is remote and Credo's `randomBytes` is synchronous.
   * The Node.js or Askar backend handles it.
   */
  public randomBytes(_agentContext: AgentContext, _options: KmsRandomBytesOptions): KmsRandomBytesReturn {
    throw new KeyManagementError(
      `Generating random bytes is not supported by backend '${BACKEND_NAME}' because it would require a ` +
        'synchronous network call. Register the Node.js or Askar backend as well.',
    )
  }

  async #createKvKey<Type extends KmsCreateKeyType>(
    agentContext: AgentContext,
    keyType: KvKeyType,
    options: KmsCreateKeyOptions<Type>,
  ): Promise<KmsCreateKeyReturn<Type>> {
    const keyId = openBaoKeyId(options.keyId ?? utils.uuid())

    // Neither store overwrites an existing key, so fail instead of silently
    // returning something that is not the requested key type.
    if (await this.#getTransitKeyOrNull(this.keyName(agentContext, keyId))) {
      throw new KeyManagementKeyExistsError(keyId, BACKEND_NAME)
    }
    if (await this.#readKvKey(agentContext, keyId)) throw new KeyManagementKeyExistsError(keyId, BACKEND_NAME)

    // secp256k1 is generated with @noble/curves so the same code works on
    // Node.js and on runtimes whose OpenSSL build lacks the curve (e.g. Bun).
    // X25519 uses node:crypto, which supports it everywhere we target.
    let privateJwk: Record<string, unknown>
    let publicJwk: KmsJwkPublic
    if (keyType === 'secp256k1') {
      const generated = generateSecp256k1KeyPair(keyId)
      privateJwk = generated.privateJwk
      publicJwk = generated.publicJwk as KmsJwkPublic
    } else {
      const { privateKey, publicKey } = generateKeyPairSync('x25519')
      privateJwk = privateKey.export({ format: 'jwk' }) as Record<string, unknown>
      publicJwk = {
        ...(publicKey.export({ format: 'jwk' }) as Record<string, unknown>),
        kid: keyId,
      } as KmsJwkPublic
    }

    await this.#writeKvKey(agentContext, {
      version: 1,
      keyId,
      keyType,
      privateJwk,
      publicJwk: publicJwk as unknown as Record<string, unknown>,
    })

    this.#cachePublicKey(this.#scopeResolver(agentContext), keyId, publicJwk)
    return { keyId, publicJwk } as KmsCreateKeyReturn<Type>
  }

  async #signLocally(
    agentContext: AgentContext,
    keyId: string,
    algorithm: SignAlgorithm,
    data: Uint8Array,
  ): Promise<Uint8Array> {
    if (algorithm.nodeHash === null) {
      throw new KeyManagementAlgorithmNotSupportedError(`algorithm for '${keyId}'`, BACKEND_NAME)
    }

    const record = await this.#readKvKey(agentContext, keyId)
    if (!record) throw new KeyManagementKeyNotFoundError(keyId, [BACKEND_NAME])
    if (record.keyType !== 'secp256k1') {
      throw new KeyManagementAlgorithmNotSupportedError(`signing with a ${record.keyType} key`, BACKEND_NAME)
    }

    // JWA ECDSA signatures are raw r || s, not ASN.1/DER. @noble/curves
    // returns that form directly and hashes the data with SHA-256.
    if (algorithm.nodeHash !== 'sha256') {
      throw new KeyManagementAlgorithmNotSupportedError(`algorithm for '${keyId}'`, BACKEND_NAME)
    }
    return signSecp256k1(record.privateJwk, data)
  }

  async #getTransitKeyOrNull(name: string): Promise<OpenBaoTransitKey | null> {
    try {
      return await this.#client.getKey(name)
    } catch (error) {
      if (error instanceof OpenBaoNotFoundError) return null
      throw error
    }
  }

  #kvPath(agentContext: AgentContext, keyId: string): string {
    return `${this.#kvPathPrefix}/${this.keyName(agentContext, keyId)}`
  }

  async #readKvKey(agentContext: AgentContext, keyId: string): Promise<KvKeyRecord | null> {
    if (!this.#kvMount) return null

    const data = await this.#client.getKv(this.#kvMount, this.#kvPath(agentContext, keyId))
    if (!data) return null

    if (
      data.version !== 1 ||
      (data.keyType !== 'secp256k1' && data.keyType !== 'x25519') ||
      typeof data.privateJwk !== 'object' ||
      data.privateJwk === null ||
      typeof data.publicJwk !== 'object' ||
      data.publicJwk === null
    ) {
      throw new KeyManagementError(
        `OpenBao KV entry '${this.#kvPath(agentContext, keyId)}' does not contain a Credo key record`,
      )
    }

    return data as unknown as KvKeyRecord
  }

  async #writeKvKey(agentContext: AgentContext, record: KvKeyRecord): Promise<void> {
    if (!this.#kvMount) {
      throw new KeyManagementError(
        `A KV v2 mount is required to store ${record.keyType} keys in OpenBao. Set the 'kvMount' option.`,
      )
    }
    await this.#client.putKv(
      this.#kvMount,
      this.#kvPath(agentContext, record.keyId),
      record as unknown as Record<string, unknown>,
    )
  }

  async #deleteKvKey(agentContext: AgentContext, keyId: string): Promise<boolean> {
    if (!this.#kvMount) return false
    if (!(await this.#readKvKey(agentContext, keyId))) return false
    await this.#client.deleteKv(this.#kvMount, this.#kvPath(agentContext, keyId))
    return true
  }

  #cachePublicKey(scope: string, keyId: string, publicJwk: KmsJwkPublic): void {
    this.#negativeCache.delete(cacheKeyFor(scope, keyId))
    if (this.#publicKeyCacheTtlMs <= 0) return
    this.#publicKeyCache.set(cacheKeyFor(scope, keyId), {
      publicJwk,
      expiresAt: Date.now() + this.#publicKeyCacheTtlMs,
    })
  }

  #cacheNotFound(scope: string, keyId: string): void {
    if (this.#negativeCacheTtlMs <= 0) return
    this.#negativeCache.set(cacheKeyFor(scope, keyId), Date.now() + this.#negativeCacheTtlMs)
  }

  #assertWritable(operation: string): void {
    if (this.#writeEnabled) return
    throw new KeyManagementError(
      `Backend '${BACKEND_NAME}' is read-only (writeEnabled is false); cannot ${operation}. ` +
        'Existing OpenBao keys can still sign and verify.',
    )
  }

  /**
   * Delete every Transit and KV key that belongs to an isolation scope. Used
   * when a tenant is deleted. The scope string must be exactly what
   * `scopeFor`/`scopeForCorrelationId` returns.
   */
  public async purgeScope(scope: string): Promise<number> {
    this.#assertWritable('purge keys')

    const prefix = this.#keyName(scope, '')
    let deleted = 0

    // Collect all names before deleting. Deleting while paging with `after`
    // can skip entries, because the cursor refers to a name that no longer
    // exists.
    const names: string[] = []
    let after: string | undefined
    for (;;) {
      const page = await this.#client.listKeys({
        ...(after ? { after } : {}),
        limit: 100,
      })
      if (page.length === 0) break
      names.push(...page)
      const last = page[page.length - 1]
      if (page.length < 100 || last === after) break
      after = last
    }

    for (const name of names) {
      if (!name.startsWith(prefix)) continue
      await this.#client.updateKeyConfig(name, { deletionAllowed: true })
      await this.#client.deleteKey(name)
      deleted++
    }

    if (this.#kvMount) {
      const kvPrefix = `${this.#kvPathPrefix}/${prefix}`
      const entries = await this.#client.listKv(this.#kvMount, this.#kvPathPrefix)
      for (const entry of entries) {
        if (`${this.#kvPathPrefix}/${entry}`.startsWith(kvPrefix)) {
          await this.#client.deleteKv(this.#kvMount, `${this.#kvPathPrefix}/${entry}`)
          deleted++
        }
      }
    }

    const cachePrefix = `${scope}\u0000`
    for (const key of this.#publicKeyCache.keys()) {
      if (key.startsWith(cachePrefix)) this.#publicKeyCache.delete(key)
    }
    for (const key of this.#negativeCache.keys()) {
      if (key.startsWith(cachePrefix)) this.#negativeCache.delete(key)
    }

    return deleted
  }

  /** Delete every key in the scope of an agent context. */
  public purgeAgentContext(agentContext: AgentContext): Promise<number> {
    return this.purgeScope(this.#scopeResolver(agentContext))
  }

  #keyName(scope: string, keyId: string): string {
    const scopeHash = createHash('sha256').update(scope, 'utf8').digest('hex').slice(0, 16)
    const prefix = `${this.#keyNamePrefix}_${scopeHash}_`
    const encoded = Buffer.from(keyId, 'utf8').toString('base64url')
    if (prefix.length + encoded.length <= MAX_KEY_NAME_LENGTH) return `${prefix}${encoded}`
    const digest = createHash('sha256').update(keyId, 'utf8').digest('base64url').slice(0, 32)
    return `${prefix}${digest}`
  }
}

function cacheKeyFor(scope: string, keyId: string): string {
  return `${scope}\u0000${keyId}`
}

function describeCreateKeyType(type: KmsCreateKeyType): string {
  if (type.kty === 'EC' || type.kty === 'OKP') return `${type.kty} curve '${type.crv}'`
  if (type.kty === 'RSA') return `RSA ${type.modulusLength}`
  return `oct algorithm '${type.algorithm}'`
}

function openBaoKeyTypeForCreate(type: KmsCreateKeyType): OpenBaoKeyType | undefined {
  if (type.kty === 'EC') {
    switch (type.crv) {
      case 'P-256':
        return 'ecdsa-p256'
      case 'P-384':
        return 'ecdsa-p384'
      case 'P-521':
        return 'ecdsa-p521'
      // Transit has no secp256k1 key type; stored in KV when configured.
      case 'secp256k1':
        return undefined
    }
  }

  if (type.kty === 'OKP') {
    // Transit has no X25519 key type; stored in KV when configured.
    return type.crv === 'Ed25519' ? 'ed25519' : undefined
  }

  if (type.kty === 'RSA') {
    return `rsa-${type.modulusLength}` as OpenBaoKeyType
  }

  // Transit has only AES128/256 and ChaCha20, and Credo does not use this
  // backend for encryption, so symmetric keys are left to another backend.
  return undefined
}

function describePrivateJwk(jwk: KmsJwkPrivate): string {
  if (jwk.kty === 'EC' || jwk.kty === 'OKP') return `${jwk.kty} curve '${jwk.crv}'`
  if (jwk.kty === 'RSA') return 'RSA key'
  return 'symmetric key'
}

function openBaoKeyTypeForImport(jwk: KmsJwkPrivate): OpenBaoKeyType | undefined {
  if (jwk.kty === 'EC') {
    switch (jwk.crv) {
      case 'P-256':
        return 'ecdsa-p256'
      case 'P-384':
        return 'ecdsa-p384'
      case 'P-521':
        return 'ecdsa-p521'
      // Transit cannot import secp256k1 key material.
      default:
        return undefined
    }
  }

  if (jwk.kty === 'OKP') {
    // X25519 is not a signing key and Transit has no such key type.
    return jwk.crv === 'Ed25519' ? 'ed25519' : undefined
  }

  if (jwk.kty === 'RSA') {
    let modulusLength: number
    try {
      modulusLength = rsaModulusLengthFromPrivateJwk(jwk)
    } catch {
      return undefined
    }
    switch (modulusLength) {
      case 2048:
        return 'rsa-2048'
      case 3072:
        return 'rsa-3072'
      case 4096:
        return 'rsa-4096'
      default:
        return undefined
    }
  }

  // Symmetric keys are useful only for encryption/HMAC, which this backend
  // does not implement.
  return undefined
}

/**
 * Key types Transit cannot represent, but which DID documents need. They are
 * stored in a KV v2 mount when `kvMount` is configured.
 */
function openBaoKvKeyTypeForCreate(type: KmsCreateKeyType): KvKeyType | undefined {
  if (type.kty === 'EC' && type.crv === 'secp256k1') return 'secp256k1'
  if (type.kty === 'OKP' && type.crv === 'X25519') return 'x25519'
  return undefined
}

function openBaoKvKeyTypeForImport(jwk: KmsJwkPrivate): KvKeyType | undefined {
  if (jwk.kty === 'EC' && jwk.crv === 'secp256k1') return 'secp256k1'
  if (jwk.kty === 'OKP' && jwk.crv === 'X25519') return 'x25519'
  return undefined
}

function publicJwkFromTransitKey(key: OpenBaoTransitKey, keyId: string): KmsJwkPublic | null {
  const version = key.latest_version ?? latestVersion(key)
  const versionInfo = version ? key.keys[String(version)] : undefined
  const publicKey = versionInfo?.public_key
  if (!publicKey) return null

  if (key.type === 'ed25519') {
    // Transit returns Ed25519 public keys as base64 of the raw 32 bytes.
    return {
      kty: 'OKP',
      crv: 'Ed25519',
      x: Buffer.from(publicKey, 'base64').toString('base64url'),
      kid: keyId,
    }
  }

  if (key.type.startsWith('ecdsa-') || key.type.startsWith('rsa-')) {
    // Transit returns EC and RSA public keys as PEM (PKIX).
    const jwk = createPublicKey(publicKey).export({ format: 'jwk' })
    return { ...jwk, kid: keyId } as KmsJwkPublic
  }

  return null
}

function latestVersion(key: OpenBaoTransitKey): number | undefined {
  const versions = Object.keys(key.keys).map(Number)
  return versions.length > 0 ? Math.max(...versions) : undefined
}

function decodeTransitSignature(signature: string, isJws: boolean): Uint8Array {
  // `vault:v1:<signature>` / `bao:v1:<signature>`
  const match = /^[^:]+:v\d+:(.*)$/.exec(signature)
  const encoded = match?.[1] ?? signature
  return new Uint8Array(Buffer.from(encoded, isJws ? 'base64url' : 'base64'))
}

function keyObjectFromPublicJwk(jwk: KmsJwkPublic): KeyObject {
  switch (jwk.kty) {
    case 'EC':
      return createPublicKey({
        key: { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y },
        format: 'jwk',
      })
    case 'OKP':
      return createPublicKey({ key: { kty: 'OKP', crv: jwk.crv, x: jwk.x }, format: 'jwk' })
    case 'RSA':
      return createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' })
    default:
      throw new KeyManagementError(`Cannot verify with a '${jwk.kty}' key`)
  }
}

function verifyWithPublicJwk(
  jwk: KmsJwkPublic,
  algorithm: SignAlgorithm,
  data: Uint8Array,
  signature: Uint8Array,
): boolean {
  // node:crypto cannot handle secp256k1 on every runtime, so verification of
  // that curve also uses @noble/curves.
  if (jwk.kty === 'EC' && jwk.crv === 'secp256k1') {
    return verifySecp256k1(jwk as unknown as Record<string, unknown>, data, signature)
  }

  const key = keyObjectFromPublicJwk(jwk)

  try {
    if (algorithm.nodeHash === null) {
      // Ed25519: no separate hash.
      return cryptoVerify(null, data, key, signature)
    }

    if (algorithm.signatureAlgorithm === 'pss') {
      return cryptoVerify(
        algorithm.nodeHash,
        data,
        {
          key,
          padding: constants.RSA_PKCS1_PSS_PADDING,
          saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
        },
        signature,
      )
    }

    if (algorithm.signatureAlgorithm === 'pkcs1v15') {
      return cryptoVerify(algorithm.nodeHash, data, { key, padding: constants.RSA_PKCS1_PADDING }, signature)
    }

    // ECDSA: JWA signatures are raw r || s, not DER.
    return cryptoVerify(algorithm.nodeHash, data, { key, dsaEncoding: 'ieee-p1363' }, signature)
  } catch {
    // Malformed signatures throw; treat them as invalid.
    return false
  }
}
