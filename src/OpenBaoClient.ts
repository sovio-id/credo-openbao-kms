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
 * Minimal client for the OpenBao Transit secrets engine.
 *
 * Credo's KMS backend only needs a handful of Transit endpoints, so this
 * avoids pulling in a vendor SDK. `fetch` is injected so the backend can be
 * tested without network access.
 */

export class OpenBaoNotFoundError extends Error {
  public constructor(message: string) {
    super(message)
    this.name = 'OpenBaoNotFoundError'
  }
}

export class OpenBaoRequestError extends Error {
  public readonly status: number
  public readonly errors: string[]

  public constructor(method: string, path: string, status: number, errors: string[]) {
    super(
      `OpenBao request ${method} ${path} failed with status ${status}` +
        (errors.length > 0 ? `: ${errors.join('; ')}` : ''),
    )
    this.name = 'OpenBaoRequestError'
    this.status = status
    this.errors = errors
  }
}

/**
 * The OpenBao node is reachable but sealed. This is operationally different
 * from a network failure: the node needs unsealing, not a retry or a firewall
 * change. Callers can catch this error separately and alert on it.
 */
export class OpenBaoSealedError extends OpenBaoRequestError {
  public constructor(method: string, path: string, errors: string[]) {
    super(method, path, 503, errors.length > 0 ? errors : ['OpenBao is sealed'])
    this.name = 'OpenBaoSealedError'
  }
}

/** The OpenBao address could not be reached, or the request timed out. */
export class OpenBaoUnreachableError extends Error {
  public readonly address: string

  public constructor(address: string, reason: string, options?: { cause?: unknown }) {
    super(`OpenBao at ${address} is unreachable: ${reason}`, options)
    this.name = 'OpenBaoUnreachableError'
    this.address = address
  }
}

export interface OpenBaoHealth {
  initialized: boolean
  sealed: boolean
  standby: boolean
  version?: string
}

export interface OpenBaoListKeysOptions {
  /** Return keys that sort after this name. Used for pagination. */
  after?: string
  /** Maximum number of names to return. OpenBao defaults to the server limit. */
  limit?: number
}

export interface OpenBaoResponse<T> {
  data: T
  warnings?: string[]
}

export interface OpenBaoClient {
  getKey(name: string): Promise<OpenBaoTransitKey>
  createKey(name: string, type: OpenBaoKeyType): Promise<OpenBaoTransitKey>
  updateKeyConfig(name: string, config: { deletionAllowed: boolean }): Promise<void>
  deleteKey(name: string): Promise<void>
  /** List Transit key names. Supports pagination with `after` and `limit`. */
  listKeys(options?: OpenBaoListKeysOptions): Promise<string[]>
  sign(name: string, options: OpenBaoSignOptions): Promise<string>
  /** RSA-4096 public key (PEM) used to wrap key material for BYOK import. */
  getWrappingKey(): Promise<string>
  /** Import externally generated key material (BYOK). */
  importKey(name: string, options: OpenBaoImportKeyOptions): Promise<void>
  /**
   * Read a JSON object from a KV v2 mount. Returns `null` when the path does
   * not exist. Used for key types Transit cannot represent (secp256k1, X25519).
   */
  getKv(mount: string, path: string): Promise<Record<string, unknown> | null>
  /** List keys below a path in a KV v2 mount (`LIST /v1/<mount>/metadata/<path>`). */
  listKv(mount: string, path: string): Promise<string[]>
  /** Write a JSON object to a KV v2 mount (creates a new version). */
  putKv(mount: string, path: string, data: Record<string, unknown>): Promise<void>
  /** Delete all versions and metadata of a KV v2 entry. */
  deleteKv(mount: string, path: string): Promise<void>
  /** Read `sys/health`. Unlike the other calls, this does not need a token. */
  health(): Promise<OpenBaoHealth>
  /** Fail fast at startup when the node is sealed, uninitialised, or unreachable. */
  assertHealthy(): Promise<void>
}

export interface OpenBaoImportKeyOptions {
  type: OpenBaoKeyType
  /**
   * `base64(RSA-OAEP(ephemeralAesKey) || AES-KWP(privateKeyPkcs8))`.
   * Mutually exclusive with `publicKey`.
   */
  ciphertext?: string
  /** PEM-encoded public key, for a public-key-only import. */
  publicKey?: string
  /** Hash used for RSA-OAEP. Defaults to `SHA256`, matching the wrapper here. */
  hashFunction?: 'SHA1' | 'SHA224' | 'SHA256' | 'SHA384' | 'SHA512'
  /**
   * Whether Transit may rotate the imported key. Defaults to `false`, which
   * matches Credo's requirement that a key id always maps to one public key.
   */
  allowRotation?: boolean
}

export type OpenBaoKeyType =
  | 'aes128-gcm96'
  | 'aes256-gcm96'
  | 'chacha20-poly1305'
  | 'ed25519'
  | 'ecdsa-p256'
  | 'ecdsa-p384'
  | 'ecdsa-p521'
  | 'rsa-2048'
  | 'rsa-3072'
  | 'rsa-4096'
  | 'hmac'

export interface OpenBaoTransitKeyVersion {
  name?: string
  public_key?: string
  creation_time?: string
  certificate_chain?: string
}

export interface OpenBaoTransitKey {
  name: string
  type: OpenBaoKeyType
  keys: Record<string, OpenBaoTransitKeyVersion>
  latest_version?: number
  min_decryption_version?: number
  supports_signing?: boolean
  supports_encryption?: boolean
  supports_decryption?: boolean
}

export interface OpenBaoSignOptions {
  /** Raw data. The client base64-encodes it for the Transit API. */
  input: Uint8Array
  /** Transit hash algorithm, e.g. `sha2-256`. Omitted for Ed25519. */
  hashAlgorithm?: string
  /** `jws` returns URL-safe base64 raw ECDSA `r || s`; omit for ASN.1/DER. */
  marshalingAlgorithm?: 'asn1' | 'jws'
  /** RSA only. */
  signatureAlgorithm?: 'pss' | 'pkcs1v15'
  /** RSA PSS only. `hash` matches the JWA requirement (salt length == hash length). */
  saltLength?: string
}

export interface FetchOpenBaoClientOptions {
  /** Base address, e.g. `https://openbao.example.com:8200`. */
  address: string
  /**
   * Token, or a function returning one. Use a function when the token is
   * renewed by an auth method (AppRole, Kubernetes, ...).
   */
  token: string | (() => string | Promise<string>)
  /** Mount path of the Transit engine. Defaults to `transit`. */
  mountPath?: string
  /** `X-Vault-Namespace`, for Vault-compatible deployments. */
  namespace?: string
  /** Request timeout. Defaults to 10 seconds. */
  timeoutMs?: number
  /** Injectable for tests / custom TLS setup. Defaults to global `fetch`. */
  fetch?: typeof fetch
}

export class FetchOpenBaoClient implements OpenBaoClient {
  readonly #address: string
  readonly #token: string | (() => string | Promise<string>)
  readonly #mountPath: string
  readonly #namespace?: string
  readonly #timeoutMs: number
  readonly #fetch: typeof fetch

  public constructor(options: FetchOpenBaoClientOptions) {
    this.#address = options.address.replace(/\/+$/, '')
    this.#token = options.token
    this.#mountPath = (options.mountPath ?? 'transit').replace(/^\/+|\/+$/g, '')
    if (options.namespace) this.#namespace = options.namespace
    this.#timeoutMs = options.timeoutMs ?? 10_000
    this.#fetch = options.fetch ?? globalThis.fetch
  }

  public async getKey(name: string): Promise<OpenBaoTransitKey> {
    return this.#request<OpenBaoTransitKey>('GET', `keys/${encodeURIComponent(name)}`)
  }

  public async createKey(name: string, type: OpenBaoKeyType): Promise<OpenBaoTransitKey> {
    return this.#request<OpenBaoTransitKey>('POST', `keys/${encodeURIComponent(name)}`, { type })
  }

  public async updateKeyConfig(name: string, config: { deletionAllowed: boolean }): Promise<void> {
    await this.#request('POST', `keys/${encodeURIComponent(name)}/config`, {
      deletion_allowed: config.deletionAllowed,
    })
  }

  public async deleteKey(name: string): Promise<void> {
    await this.#request('DELETE', `keys/${encodeURIComponent(name)}`)
  }

  public async listKeys(options: OpenBaoListKeysOptions = {}): Promise<string[]> {
    const query = new URLSearchParams()
    if (options.after) query.set('after', options.after)
    if (options.limit !== undefined) query.set('limit', String(options.limit))
    const queryString = query.toString()
    const suffix = queryString.length > 0 ? `?${queryString}` : ''
    const data = await this.#request<{ keys: string[] }>('LIST', `keys${suffix}`)
    return data.keys ?? []
  }

  public async getWrappingKey(): Promise<string> {
    const data = await this.#request<{ public_key: string }>('GET', 'wrapping_key')
    return data.public_key
  }

  public async importKey(name: string, options: OpenBaoImportKeyOptions): Promise<void> {
    const body: Record<string, unknown> = { type: options.type }
    if (options.ciphertext) body.ciphertext = options.ciphertext
    if (options.publicKey) body.public_key = options.publicKey
    if (options.hashFunction) body.hash_function = options.hashFunction
    if (options.allowRotation !== undefined) body.allow_rotation = options.allowRotation

    await this.#request('POST', `keys/${encodeURIComponent(name)}/import`, body)
  }

  public async getKv(mount: string, path: string): Promise<Record<string, unknown> | null> {
    try {
      const data = await this.#request<{ data: Record<string, unknown> }>('GET', `data/${path}`, undefined, mount)
      return data.data
    } catch (error) {
      if (error instanceof OpenBaoNotFoundError) return null
      throw error
    }
  }

  public async listKv(mount: string, path: string): Promise<string[]> {
    try {
      const data = await this.#request<{ keys: string[] }>('LIST', `metadata/${path}`, undefined, mount)
      return data.keys ?? []
    } catch (error) {
      if (error instanceof OpenBaoNotFoundError) return []
      throw error
    }
  }

  public async putKv(mount: string, path: string, data: Record<string, unknown>): Promise<void> {
    await this.#request('POST', `data/${path}`, { data }, mount)
  }

  public async deleteKv(mount: string, path: string): Promise<void> {
    await this.#request('DELETE', `metadata/${path}`, undefined, mount)
  }

  public async sign(name: string, options: OpenBaoSignOptions): Promise<string> {
    const hashPath = options.hashAlgorithm ? `/${options.hashAlgorithm}` : ''
    const body: Record<string, unknown> = {
      input: Buffer.from(options.input).toString('base64'),
    }
    if (options.marshalingAlgorithm) body.marshaling_algorithm = options.marshalingAlgorithm
    if (options.signatureAlgorithm) body.signature_algorithm = options.signatureAlgorithm
    if (options.saltLength) body.salt_length = options.saltLength

    const data = await this.#request<{ signature: string }>('POST', `sign/${encodeURIComponent(name)}${hashPath}`, body)
    return data.signature
  }

  public async health(): Promise<OpenBaoHealth> {
    // `standbyok=true` turns a healthy standby into a 200. Sealed (503) and
    // uninitialised (501) still have distinct statuses and bodies.
    const url = `${this.#address}/v1/sys/health?standbyok=true`
    let response: Response
    try {
      response = await this.#fetch(url, {
        method: 'GET',
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(this.#timeoutMs),
      })
    } catch (error) {
      throw new OpenBaoUnreachableError(this.#address, describeFetchFailure(error), { cause: error })
    }

    let body: {
      initialized?: boolean
      sealed?: boolean
      standby?: boolean
      version?: string
      errors?: string[]
    } = {}
    try {
      const text = await response.text()
      body = text.length > 0 ? (JSON.parse(text) as typeof body) : {}
    } catch {
      // A proxy may return HTML. The status code still tells us enough.
    }

    if (body.sealed === true || response.status === 503) {
      throw new OpenBaoSealedError('GET', 'sys/health', body.errors ?? ['OpenBao is sealed'])
    }
    if (body.initialized === false || response.status === 501) {
      throw new OpenBaoUnreachableError(this.#address, 'OpenBao is not initialized')
    }
    // 429 is a standby without `standbyok`, 472/473 are DR/perf standbys.
    if (!response.ok && ![429, 472, 473].includes(response.status)) {
      throw new OpenBaoUnreachableError(this.#address, `health check returned HTTP ${response.status}`)
    }

    return {
      initialized: body.initialized ?? true,
      sealed: false,
      standby: body.standby === true,
      ...(body.version ? { version: body.version } : {}),
    }
  }

  public async assertHealthy(): Promise<void> {
    await this.health()
  }

  async #request<T>(
    method: string,
    path: string,
    body?: Record<string, unknown>,
    mountPath: string = this.#mountPath,
  ): Promise<T> {
    const token = typeof this.#token === 'function' ? await this.#token() : this.#token
    const headers: Record<string, string> = {
      'X-Vault-Token': token,
      accept: 'application/json',
    }
    if (this.#namespace) headers['X-Vault-Namespace'] = this.#namespace
    if (body) headers['content-type'] = 'application/json'

    let response: Response
    try {
      response = await this.#fetch(`${this.#address}/v1/${mountPath}/${path}`, {
        method,
        headers,
        ...(body ? { body: JSON.stringify(body) } : {}),
        signal: AbortSignal.timeout(this.#timeoutMs),
      })
    } catch (error) {
      throw new OpenBaoUnreachableError(this.#address, describeFetchFailure(error), { cause: error })
    }

    const text = await response.text()
    let parsed: { data?: T; errors?: string[]; warnings?: string[] } = {}
    try {
      parsed = text.length > 0 ? (JSON.parse(text) as typeof parsed) : {}
    } catch {
      // Keep the status code and a short body excerpt for the error message.
      if (!response.ok) parsed.errors = [text.slice(0, 200)]
    }

    const errors = parsed.errors ?? []
    if (response.status === 503 && errors.some((message) => /seal/i.test(message))) {
      throw new OpenBaoSealedError(method, path, errors)
    }
    if (response.status === 404) {
      throw new OpenBaoNotFoundError(`OpenBao key not found for ${method} ${path}`)
    }
    if (!response.ok) {
      throw new OpenBaoRequestError(method, path, response.status, errors)
    }
    // 204 No Content (e.g. key import) is a success without a body.
    return (parsed.data ?? (undefined as T)) as T
  }
}

function describeFetchFailure(error: unknown): string {
  if (error instanceof Error) {
    if (error.name === 'AbortError' || error.name === 'TimeoutError') return 'request timed out'
    // Node's fetch wraps connection failures in a generic TypeError.
    if (error.name === 'TypeError' && error.message === 'fetch failed') {
      const cause = (error as { cause?: unknown }).cause
      if (cause instanceof Error) return cause.message
    }
    return error.message
  }
  return String(error)
}
