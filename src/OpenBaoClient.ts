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

/** The requested Transit key or KV entry does not exist (HTTP 404). */
export class OpenBaoNotFoundError extends Error {
  /**
   * Create the error.
   *
   * @param message Description of the missing resource.
   */
  public constructor(message: string) {
    super(message)
    this.name = 'OpenBaoNotFoundError'
  }
}

/** OpenBao answered with an error status other than 404. */
export class OpenBaoRequestError extends Error {
  /** HTTP status code returned by OpenBao. */
  public readonly status: number
  /** Error messages from the response body's `errors` array. */
  public readonly errors: string[]

  /**
   * Create the error from a failed response.
   *
   * @param method HTTP method of the failed request.
   * @param path API path of the failed request, relative to `/v1/`.
   * @param status HTTP status code returned by OpenBao.
   * @param errors Error messages from the response body.
   */
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
  /**
   * Create the error for a sealed node (HTTP 503).
   *
   * @param method HTTP method of the failed request.
   * @param path API path of the failed request.
   * @param errors Error messages from the response body.
   */
  public constructor(method: string, path: string, errors: string[]) {
    super(method, path, 503, errors.length > 0 ? errors : ['OpenBao is sealed'])
    this.name = 'OpenBaoSealedError'
  }
}

/** The OpenBao address could not be reached, or the request timed out. */
export class OpenBaoUnreachableError extends Error {
  /** The OpenBao base address that could not be reached. */
  public readonly address: string

  /**
   * Create the error.
   *
   * @param address The OpenBao base address.
   * @param reason Short description of the failure.
   * @param options Optional underlying cause.
   */
  public constructor(address: string, reason: string, options?: { cause?: unknown }) {
    super(`OpenBao at ${address} is unreachable: ${reason}`, options)
    this.name = 'OpenBaoUnreachableError'
    this.address = address
  }
}

/** Result of `sys/health`. */
export interface OpenBaoHealth {
  /** Whether the node has been initialised. */
  initialized: boolean
  /** Whether the node is sealed. */
  sealed: boolean
  /** Whether the node is a standby in an HA cluster. */
  standby: boolean
  /** OpenBao server version, when reported. */
  version?: string
}

/** Pagination options for {@link OpenBaoClient.listKeys}. */
export interface OpenBaoListKeysOptions {
  /** Return keys that sort after this name. Used for pagination. */
  after?: string
  /** Maximum number of names to return. OpenBao defaults to the server limit. */
  limit?: number
}

/** Envelope of an OpenBao API response. */
export interface OpenBaoResponse<T> {
  /** Response payload. */
  data: T
  /** Non-fatal warnings returned by OpenBao. */
  warnings?: string[]
}

/**
 * The subset of the OpenBao HTTP API used by {@link OpenBaoKeyManagementService}.
 * {@link FetchOpenBaoClient} is the default implementation; provide your own
 * to add retries, metrics or a different transport.
 */
export interface OpenBaoClient {
  /** Read a Transit key, including the public key of every version. */
  getKey(name: string): Promise<OpenBaoTransitKey>
  /**
   * Create a Transit key. OpenBao returns the existing key unchanged when the
   * name is already taken, even if the type differs.
   */
  createKey(name: string, type: OpenBaoKeyType): Promise<OpenBaoTransitKey>
  /** Update a Transit key's configuration. Deletion requires `deletionAllowed: true` first. */
  updateKeyConfig(name: string, config: { deletionAllowed: boolean }): Promise<void>
  /** Delete a Transit key and all of its versions. */
  deleteKey(name: string): Promise<void>
  /** List Transit key names. Supports pagination with `after` and `limit`. */
  listKeys(options?: OpenBaoListKeysOptions): Promise<string[]>
  /** Sign data with a Transit key. Returns the Transit signature string (`vault:v<n>:<base64>`). */
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

/** Options for a Transit BYOK import (`POST /transit/keys/:name/import`). */
export interface OpenBaoImportKeyOptions {
  /** Transit key type of the imported key. */
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

/** Transit key types. This package creates and imports only the asymmetric ones. */
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

/** One version of a Transit key, as returned by `GET /transit/keys/:name`. */
export interface OpenBaoTransitKeyVersion {
  /** Key name, for asymmetric keys. */
  name?: string
  /** Public key: raw base64 for Ed25519, PEM for ECDSA and RSA. */
  public_key?: string
  /** RFC 3339 creation time of this version. */
  creation_time?: string
  /** Certificate chain attached to this version, if any. */
  certificate_chain?: string
}

/** A Transit key as returned by `GET /transit/keys/:name` (fields used by this package). */
export interface OpenBaoTransitKey {
  /** Transit key name. */
  name: string
  /** Transit key type. */
  type: OpenBaoKeyType
  /** Key versions, keyed by version number. */
  keys: Record<string, OpenBaoTransitKeyVersion>
  /** Highest key version. */
  latest_version?: number
  /** Lowest version that may still decrypt. */
  min_decryption_version?: number
  /** Whether the key type supports signing. */
  supports_signing?: boolean
  /** Whether the key type supports encryption. */
  supports_encryption?: boolean
  /** Whether the key type supports decryption. */
  supports_decryption?: boolean
}

/** Options for a Transit sign request. */
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

/** Options for {@link FetchOpenBaoClient}. */
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

/**
 * {@link OpenBaoClient} implemented with `fetch`. It talks to the Transit
 * engine at `mountPath` and to KV v2 mounts for the secp256k1/X25519 fallback.
 *
 * @example
 * ```ts
 * const client = new FetchOpenBaoClient({
 *   address: 'https://openbao.example.com:8200',
 *   token: () => auth.getToken(),
 * })
 * ```
 */
export class FetchOpenBaoClient implements OpenBaoClient {
  readonly #address: string
  readonly #token: string | (() => string | Promise<string>)
  readonly #mountPath: string
  readonly #namespace?: string
  readonly #timeoutMs: number
  readonly #fetch: typeof fetch

  /**
   * Create a client.
   *
   * @param options Address, token and optional transport settings.
   */
  public constructor(options: FetchOpenBaoClientOptions) {
    this.#address = options.address.replace(/\/+$/, '')
    this.#token = options.token
    this.#mountPath = (options.mountPath ?? 'transit').replace(/^\/+|\/+$/g, '')
    if (options.namespace) this.#namespace = options.namespace
    this.#timeoutMs = options.timeoutMs ?? 10_000
    this.#fetch = options.fetch ?? globalThis.fetch
  }

  /** Read a Transit key, including the public key of every version. */
  public async getKey(name: string): Promise<OpenBaoTransitKey> {
    return this.#request<OpenBaoTransitKey>('GET', `keys/${encodeURIComponent(name)}`)
  }

  /** Create a Transit key, or return the existing key with the same name. */
  public async createKey(name: string, type: OpenBaoKeyType): Promise<OpenBaoTransitKey> {
    return this.#request<OpenBaoTransitKey>('POST', `keys/${encodeURIComponent(name)}`, { type })
  }

  /** Update a Transit key's `deletion_allowed` setting. */
  public async updateKeyConfig(name: string, config: { deletionAllowed: boolean }): Promise<void> {
    await this.#request('POST', `keys/${encodeURIComponent(name)}/config`, {
      deletion_allowed: config.deletionAllowed,
    })
  }

  /** Delete a Transit key and all of its versions. */
  public async deleteKey(name: string): Promise<void> {
    await this.#request('DELETE', `keys/${encodeURIComponent(name)}`)
  }

  /** List Transit key names, optionally paginated. */
  public async listKeys(options: OpenBaoListKeysOptions = {}): Promise<string[]> {
    const query = new URLSearchParams()
    if (options.after) query.set('after', options.after)
    if (options.limit !== undefined) query.set('limit', String(options.limit))
    const queryString = query.toString()
    const suffix = queryString.length > 0 ? `?${queryString}` : ''
    const data = await this.#request<{ keys: string[] }>('LIST', `keys${suffix}`)
    return data.keys ?? []
  }

  /** RSA-4096 public key (PEM) used to wrap key material for BYOK import. */
  public async getWrappingKey(): Promise<string> {
    const data = await this.#request<{ public_key: string }>('GET', 'wrapping_key')
    return data.public_key
  }

  /** Import externally generated key material (BYOK). */
  public async importKey(name: string, options: OpenBaoImportKeyOptions): Promise<void> {
    const body: Record<string, unknown> = { type: options.type }
    if (options.ciphertext) body.ciphertext = options.ciphertext
    if (options.publicKey) body.public_key = options.publicKey
    if (options.hashFunction) body.hash_function = options.hashFunction
    if (options.allowRotation !== undefined) body.allow_rotation = options.allowRotation

    await this.#request('POST', `keys/${encodeURIComponent(name)}/import`, body)
  }

  /** Read a JSON object from a KV v2 mount, or `null` when it does not exist. */
  public async getKv(mount: string, path: string): Promise<Record<string, unknown> | null> {
    try {
      const data = await this.#request<{ data: Record<string, unknown> }>('GET', `data/${path}`, undefined, mount)
      return data.data
    } catch (error) {
      if (error instanceof OpenBaoNotFoundError) return null
      throw error
    }
  }

  /** List keys below a path in a KV v2 mount. Returns `[]` when the path does not exist. */
  public async listKv(mount: string, path: string): Promise<string[]> {
    try {
      const data = await this.#request<{ keys: string[] }>('LIST', `metadata/${path}`, undefined, mount)
      return data.keys ?? []
    } catch (error) {
      if (error instanceof OpenBaoNotFoundError) return []
      throw error
    }
  }

  /** Write a JSON object to a KV v2 mount (creates a new version). */
  public async putKv(mount: string, path: string, data: Record<string, unknown>): Promise<void> {
    await this.#request('POST', `data/${path}`, { data }, mount)
  }

  /** Delete all versions and metadata of a KV v2 entry. */
  public async deleteKv(mount: string, path: string): Promise<void> {
    await this.#request('DELETE', `metadata/${path}`, undefined, mount)
  }

  /** Sign data with a Transit key and return the Transit signature string. */
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

  /**
   * Read `sys/health`. Throws {@link OpenBaoSealedError} when sealed and
   * {@link OpenBaoUnreachableError} when the node cannot be reached.
   */
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

  /** Fail fast at startup when the node is sealed, uninitialised, or unreachable. */
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
