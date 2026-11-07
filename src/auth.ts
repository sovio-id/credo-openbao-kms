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
 * Authentication helpers for OpenBao.
 *
 * `FetchOpenBaoClient` accepts a token or a token callback. AppRole needs more
 * than a static token: it has to log in, track the lease, renew it, and log in
 * again when renewal is no longer possible. `AppRoleAuth` does that and is
 * passed to the client as `token: () => auth.getToken()`.
 */

import { readFile } from 'node:fs/promises'

import { OpenBaoSealedError, OpenBaoUnreachableError } from './OpenBaoClient.js'

/** Supplies the OpenBao token for each request. */
export interface AuthProvider {
  /** Return a currently valid token, refreshing it if needed. */
  getToken(): Promise<string>
}

/** Options for {@link AppRoleAuth}. */
export interface AppRoleAuthOptions {
  /** OpenBao base address, e.g. `https://openbao.example.com:8200`. */
  address: string
  /** AppRole role id. */
  roleId: string
  /** Secret id value. Mutually exclusive with `secretIdFile`. */
  secretId?: string
  /** Read the secret id from a file instead of keeping it in the environment. */
  secretIdFile?: string
  /** AppRole auth mount path. Defaults to `approle`. */
  mountPath?: string
  /** `X-Vault-Namespace`, for Vault-compatible deployments. */
  namespace?: string
  /** Request timeout. Defaults to 10 seconds. */
  timeoutMs?: number
  /** Renew this long before the token expires. Defaults to 30 seconds. */
  renewBeforeMs?: number
  /** Injectable for tests / custom TLS setup. Defaults to global `fetch`. */
  fetch?: typeof fetch
}

interface AppRoleLoginResponse {
  auth?: {
    client_token?: string
    lease_duration?: number
    renewable?: boolean
  }
  errors?: string[]
}

/**
 * AppRole authentication. Logs in, tracks the token lease, renews it before
 * expiry and logs in again when renewal is no longer possible. Concurrent
 * callers share a single refresh.
 *
 * @example
 * ```ts
 * const auth = new AppRoleAuth({
 *   address: 'https://openbao.example.com:8200',
 *   roleId: process.env.OPENBAO_ROLE_ID!,
 *   secretIdFile: '/var/run/secrets/openbao/secret-id',
 * })
 * const client = new FetchOpenBaoClient({ address, token: () => auth.getToken() })
 * ```
 */
export class AppRoleAuth implements AuthProvider {
  readonly #address: string
  readonly #roleId: string
  readonly #mountPath: string
  readonly #namespace?: string
  readonly #timeoutMs: number
  readonly #renewBeforeMs: number
  readonly #fetch: typeof fetch
  readonly #secretIdFile: string | undefined

  #secretId: string | undefined
  #token: string | undefined
  #tokenExpiresAt = 0
  #renewable = true
  #refresh: Promise<string> | undefined

  /**
   * Create an AppRole token provider. No request is made until the first `getToken`.
   *
   * @param options Address, role id and secret id (or a file containing it).
   */
  public constructor(options: AppRoleAuthOptions) {
    this.#address = options.address.replace(/\/+$/, '')
    this.#roleId = options.roleId
    this.#secretId = options.secretId
    this.#secretIdFile = options.secretIdFile
    this.#mountPath = (options.mountPath ?? 'approle').replace(/^\/+|\/+$/g, '')
    if (options.namespace) this.#namespace = options.namespace
    this.#timeoutMs = options.timeoutMs ?? 10_000
    this.#renewBeforeMs = options.renewBeforeMs ?? 30_000
    this.#fetch = options.fetch ?? globalThis.fetch
  }

  /**
   * Replace the secret id, e.g. after it has been rotated at the OpenBao
   * server. The next `getToken` call logs in with the new credential.
   */
  public setSecretId(secretId: string): void {
    this.#secretId = secretId
    this.#token = undefined
    this.#tokenExpiresAt = 0
  }

  /** Return a currently valid token, logging in or renewing first when needed. */
  public async getToken(): Promise<string> {
    if (this.#token && Date.now() < this.#tokenExpiresAt - this.#renewBeforeMs) {
      return this.#token
    }

    // Coalesce concurrent refreshes so a burst of signing requests triggers
    // one login, not one per request.
    this.#refresh ??= this.#refreshToken().finally(() => {
      this.#refresh = undefined
    })
    return this.#refresh
  }

  /** Log in with the role id and secret id and return the new client token. */
  public async login(): Promise<string> {
    const secretId = await this.#resolveSecretId()
    const body: Record<string, string> = { role_id: this.#roleId }
    if (secretId) body.secret_id = secretId

    const response = await this.#request('POST', `auth/${this.#mountPath}/login`, body)
    return this.#applyToken(response)
  }

  /** Renew the current token, or log in again when it is not renewable. */
  public async renew(): Promise<string> {
    if (!this.#token || !this.#renewable) return this.login()
    try {
      const response = await this.#request('POST', 'auth/token/renew-self', {}, this.#token)
      return this.#applyToken(response)
    } catch {
      // The token may have been revoked or the max TTL reached. A fresh login
      // is the only recovery path.
      return this.login()
    }
  }

  async #refreshToken(): Promise<string> {
    if (!this.#token) return this.login()
    if (this.#renewable) return this.renew()
    return this.login()
  }

  #applyToken(response: AppRoleLoginResponse): string {
    const token = response.auth?.client_token
    if (!token) {
      throw new OpenBaoUnreachableError(this.#address, 'AppRole login returned no client token')
    }
    const leaseSeconds = response.auth?.lease_duration ?? 0
    this.#token = token
    this.#renewable = response.auth?.renewable ?? true
    // A zero lease means the token does not expire (root/periodic without TTL).
    this.#tokenExpiresAt = leaseSeconds > 0 ? Date.now() + leaseSeconds * 1000 : Number.MAX_SAFE_INTEGER
    return token
  }

  async #resolveSecretId(): Promise<string | undefined> {
    if (this.#secretId) return this.#secretId
    if (this.#secretIdFile) {
      this.#secretId = (await readFile(this.#secretIdFile, 'utf8')).trim()
      return this.#secretId
    }
    return undefined
  }

  async #request(
    method: string,
    path: string,
    body?: Record<string, unknown>,
    token?: string,
  ): Promise<AppRoleLoginResponse> {
    const headers: Record<string, string> = { accept: 'application/json' }
    if (this.#namespace) headers['X-Vault-Namespace'] = this.#namespace
    if (token) headers['X-Vault-Token'] = token
    if (body) headers['content-type'] = 'application/json'

    let response: Response
    try {
      response = await this.#fetch(`${this.#address}/v1/${path}`, {
        method,
        headers,
        ...(body ? { body: JSON.stringify(body) } : {}),
        signal: AbortSignal.timeout(this.#timeoutMs),
      })
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error)
      throw new OpenBaoUnreachableError(this.#address, reason, { cause: error })
    }

    const text = await response.text()
    let parsed: AppRoleLoginResponse = {}
    try {
      parsed = text.length > 0 ? (JSON.parse(text) as AppRoleLoginResponse) : {}
    } catch {
      throw new OpenBaoUnreachableError(this.#address, `authentication returned HTTP ${response.status}`)
    }

    const errors = parsed.errors ?? []
    if (response.status === 503 && errors.some((message) => /seal/i.test(message))) {
      throw new OpenBaoSealedError(method, path, errors)
    }
    if (!response.ok) {
      throw new OpenBaoUnreachableError(
        this.#address,
        `authentication failed with HTTP ${response.status}${errors.length ? `: ${errors.join('; ')}` : ''}`,
      )
    }
    return parsed
  }
}

/** A token that never changes, for local development and tests. */
export class StaticTokenAuth implements AuthProvider {
  readonly #token: string

  /**
   * Create a static token provider.
   *
   * @param token The OpenBao token to send with every request.
   */
  public constructor(token: string) {
    this.#token = token
  }

  /** Return the static token. */
  public async getToken(): Promise<string> {
    return this.#token
  }
}
