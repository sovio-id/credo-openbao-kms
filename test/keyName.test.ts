/**
 * Copyright 2026 AyanWorks Technology Solutions Pvt. Ltd.
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

import type { OpenBaoClient } from '../src/OpenBaoClient.js'
import { OpenBaoKeyManagementService } from '../src/OpenBaoKeyManagementService.js'

// keyName() is pure, so the client is only a placeholder.
const client = {} as OpenBaoClient

describe('key id to Transit key name', () => {
  it('uses a UUID key id directly', () => {
    const service = new OpenBaoKeyManagementService({ client })
    const keyId = 'f2b0f2f4-6b1c-4f8e-9b7a-2f1d3c4e5a6b'
    assert.equal(service.keyName(keyId), keyId)
  })

  it('encodes ids that are not valid Transit names', () => {
    const service = new OpenBaoKeyManagementService({ client })
    assert.equal(service.keyName('did:example:123'), `credo-${Buffer.from('did:example:123').toString('base64url')}`)
  })

  it('honours a custom prefix', () => {
    const service = new OpenBaoKeyManagementService({ client, keyNamePrefix: 'tenant-a-' })
    assert.equal(service.keyName('did:example:123').startsWith('tenant-a-'), true)
  })

  it('always encodes when direct names are disabled', () => {
    const service = new OpenBaoKeyManagementService({ client, useDirectKeyNames: false })
    const keyId = 'f2b0f2f4-6b1c-4f8e-9b7a-2f1d3c4e5a6b'
    assert.notEqual(service.keyName(keyId), keyId)
    assert.equal(service.keyName(keyId), `credo-${Buffer.from(keyId).toString('base64url')}`)
  })
})
