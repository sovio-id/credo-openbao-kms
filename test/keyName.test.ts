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
import { createHash } from 'node:crypto'
import { describe, it } from 'node:test'

import type { AgentContext } from '@credo-ts/core'

import type { OpenBaoClient, OpenBaoTransitKey } from '../src/OpenBaoClient.js'
import { OpenBaoKeyManagementService } from '../src/OpenBaoKeyManagementService.js'

// keyName() is pure, so the client is only a placeholder.
const client = {} as OpenBaoClient

function context(correlationId: string): AgentContext {
  return { contextCorrelationId: correlationId } as AgentContext
}

function scopeHash(scope: string): string {
  return createHash('sha256').update(scope, 'utf8').digest('hex').slice(0, 16)
}

function expectedName(scope: string, keyId: string, prefix = 'ac'): string {
  return `${prefix}_${scopeHash(scope)}_${Buffer.from(keyId, 'utf8').toString('base64url')}`
}

describe('key id to Transit key name', () => {
  it('scopes a key id by the agent context correlation id', () => {
    const service = new OpenBaoKeyManagementService({ client })
    const keyId = 'f2b0f2f4-6b1c-4f8e-9b7a-2f1d3c4e5a6b'

    assert.equal(service.keyName(context('default'), keyId), expectedName('default', keyId))
    assert.equal(service.keyName(context('tenant-a'), keyId), expectedName('tenant-a', keyId))
  })

  it('gives two tenants different names for the same key id', () => {
    const service = new OpenBaoKeyManagementService({ client })
    const keyId = 'same-key-id'

    assert.notEqual(service.keyName(context('tenant-a'), keyId), service.keyName(context('tenant-b'), keyId))
  })

  it('includes the deployment id when one is configured', () => {
    const service = new OpenBaoKeyManagementService({ client, deploymentId: 'wallet-1' })
    const keyId = 'same-key-id'

    assert.equal(service.keyName(context('tenant-a'), keyId), expectedName('wallet-1:tenant-a', keyId))
    assert.equal(service.scopeForCorrelationId('tenant-a'), 'wallet-1:tenant-a')
  })

  it('honours a custom name prefix', () => {
    const service = new OpenBaoKeyManagementService({ client, keyNamePrefix: 'credebl' })
    assert.equal(
      service.keyName(context('tenant-a'), 'did:example:123'),
      expectedName('tenant-a', 'did:example:123', 'credebl'),
    )
  })

  it('keeps names within the Transit limit', () => {
    const service = new OpenBaoKeyManagementService({ client })
    const name = service.keyName(context('tenant-a'), 'x'.repeat(400))

    assert.ok(name.length <= 128)
    assert.match(name, /^ac_[0-9a-f]{16}_[A-Za-z0-9_-]{32}$/)
  })

  it('supports the legacy single-argument form for the default context', () => {
    const service = new OpenBaoKeyManagementService({ client })
    const keyId = 'f2b0f2f4-6b1c-4f8e-9b7a-2f1d3c4e5a6b'

    assert.equal(service.keyName(keyId), expectedName('default', keyId))
  })
})

describe('key id namespacing', () => {
  function fakeClient(created: string[]): OpenBaoClient {
    const transitKey = (name: string): OpenBaoTransitKey => ({
      name,
      type: 'ed25519',
      latest_version: 1,
      keys: {
        '1': { public_key: Buffer.alloc(32, 1).toString('base64') },
      },
    })

    return {
      async getKey(name) {
        throw Object.assign(new Error(`not found: ${name}`), { name: 'OpenBaoNotFoundError' })
      },
      async createKey(name) {
        created.push(name)
        return transitKey(name)
      },
      async updateKeyConfig() {},
      async deleteKey() {},
      async listKeys() {
        return []
      },
      async sign() {
        return 'bao:v1:AA=='
      },
      async getWrappingKey() {
        return ''
      },
      async importKey() {},
      async getKv() {
        return null
      },
      async listKv() {
        return []
      },
      async putKv() {},
      async deleteKv() {},
      async health() {
        return { initialized: true, sealed: false, standby: false }
      },
      async assertHealthy() {},
    }
  }

  it('prefixes created key ids and names Transit keys by scope', async () => {
    const created: string[] = []
    const service = new OpenBaoKeyManagementService({ client: fakeClient(created) })

    const result = await service.createKey(context('tenant-a'), {
      type: { kty: 'OKP', crv: 'Ed25519' },
    })

    assert.ok(result.keyId.startsWith('ob_'))
    assert.equal(created.length, 1)
    assert.equal(created[0], expectedName('tenant-a', result.keyId))
  })

  it('does not create keys when writes are disabled', async () => {
    const created: string[] = []
    const service = new OpenBaoKeyManagementService({ client: fakeClient(created), writeEnabled: false })

    assert.equal(
      service.isOperationSupported(context('tenant-a'), {
        operation: 'createKey',
        type: { kty: 'OKP', crv: 'Ed25519' },
      }),
      false,
    )
    await assert.rejects(service.createKey(context('tenant-a'), { type: { kty: 'OKP', crv: 'Ed25519' } }), /read-only/)
    assert.equal(created.length, 0)
  })
})
