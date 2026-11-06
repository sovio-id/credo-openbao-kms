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

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { AppRoleAuth } from '../src/auth.js'
import { OpenBaoSealedError } from '../src/OpenBaoClient.js'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

describe('AppRole authentication', () => {
  it('logs in and caches the token for its lease', async () => {
    let calls = 0
    const auth = new AppRoleAuth({
      address: 'https://openbao.test:8200',
      roleId: 'role',
      secretId: 'secret',
      async fetch() {
        calls++
        return jsonResponse({ auth: { client_token: 'token-1', lease_duration: 3600, renewable: true } })
      },
    })

    assert.equal(await auth.getToken(), 'token-1')
    assert.equal(await auth.getToken(), 'token-1')
    assert.equal(calls, 1)
  })

  it('coalesces concurrent refreshes into one login', async () => {
    let calls = 0
    const auth = new AppRoleAuth({
      address: 'https://openbao.test:8200',
      roleId: 'role',
      secretId: 'secret',
      async fetch() {
        calls++
        return jsonResponse({ auth: { client_token: `token-${calls}`, lease_duration: 3600, renewable: true } })
      },
    })

    const [first, second] = await Promise.all([auth.getToken(), auth.getToken()])
    assert.equal(first, 'token-1')
    assert.equal(second, 'token-1')
    assert.equal(calls, 1)
  })

  it('renews before expiry and falls back to login', async () => {
    const paths: string[] = []
    const auth = new AppRoleAuth({
      address: 'https://openbao.test:8200',
      roleId: 'role',
      secretId: 'secret',
      // The 60-second lease is immediately inside the renewal window.
      renewBeforeMs: 70_000,
      async fetch(url) {
        const path = new URL(String(url)).pathname
        paths.push(path)
        if (path.endsWith('/login')) {
          return jsonResponse({ auth: { client_token: 'login-token', lease_duration: 60, renewable: true } })
        }
        return jsonResponse({ auth: { client_token: 'renewed-token', lease_duration: 60, renewable: true } })
      },
    })

    assert.equal(await auth.getToken(), 'login-token')
    assert.equal(await auth.getToken(), 'renewed-token')
    assert.deepEqual(paths, ['/v1/auth/approle/login', '/v1/auth/token/renew-self'])
  })

  it('maps a sealed node to OpenBaoSealedError', async () => {
    const auth = new AppRoleAuth({
      address: 'https://openbao.test:8200',
      roleId: 'role',
      secretId: 'secret',
      async fetch() {
        return jsonResponse({ errors: ['Vault is sealed'] }, 503)
      },
    })

    await assert.rejects(auth.getToken(), OpenBaoSealedError)
  })

  it('sets the X-Vault-Namespace header when configured', async () => {
    let namespace: string | null = null
    const auth = new AppRoleAuth({
      address: 'https://openbao.test:8200',
      roleId: 'role',
      secretId: 'secret',
      namespace: 'team-a',
      async fetch(_url, init) {
        namespace = new Headers(init?.headers).get('X-Vault-Namespace')
        return jsonResponse({ auth: { client_token: 'token', lease_duration: 3600, renewable: true } })
      },
    })

    await auth.getToken()
    assert.equal(namespace, 'team-a')
  })
})
