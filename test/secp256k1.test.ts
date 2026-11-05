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
import { createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify, type KeyObject } from 'node:crypto'
import { describe, it } from 'node:test'

import { generateSecp256k1KeyPair, signSecp256k1, verifySecp256k1 } from '../src/secp256k1.js'

const data = new TextEncoder().encode('Hello from Credo')

describe('secp256k1 JWK helpers', () => {
  it('generates a public JWK that matches the private JWK', () => {
    const { privateJwk, publicJwk } = generateSecp256k1KeyPair('key-1')

    assert.equal(privateJwk.kty, 'EC')
    assert.equal(privateJwk.crv, 'secp256k1')
    assert.equal(publicJwk.kty, 'EC')
    assert.equal(publicJwk.crv, 'secp256k1')
    assert.equal(publicJwk.x, privateJwk.x)
    assert.equal(publicJwk.y, privateJwk.y)
    assert.equal(publicJwk.kid, 'key-1')
    assert.equal(typeof privateJwk.d, 'string')
    assert.equal((privateJwk.d as string).length, 43)
  })

  it('produces compact r || s signatures that verify', () => {
    const { privateJwk, publicJwk } = generateSecp256k1KeyPair('key-1')
    const signature = signSecp256k1(privateJwk, data)

    assert.equal(signature.length, 64)
    assert.equal(verifySecp256k1(publicJwk, data, signature), true)
    assert.equal(verifySecp256k1(publicJwk, new TextEncoder().encode('tampered'), signature), false)

    const tamperedSignature = new Uint8Array(signature)
    tamperedSignature[0] = (tamperedSignature[0] ?? 0) ^ 0xff
    assert.equal(verifySecp256k1(publicJwk, data, tamperedSignature), false)
  })

  it('rejects malformed public keys and signatures', () => {
    const { publicJwk } = generateSecp256k1KeyPair('key-1')

    assert.equal(verifySecp256k1({ ...publicJwk, x: 'not-base64url!' }, data, new Uint8Array(64)), false)
    assert.equal(verifySecp256k1(publicJwk, data, new Uint8Array(3)), false)
  })

  it('interoperates with node:crypto where the runtime supports secp256k1', () => {
    const { privateJwk, publicJwk } = generateSecp256k1KeyPair('key-1')

    let nodePrivateKey: KeyObject
    let nodePublicKey: KeyObject
    try {
      nodePrivateKey = createPrivateKey({ key: privateJwk as never, format: 'jwk' })
      nodePublicKey = createPublicKey({ key: publicJwk as never, format: 'jwk' })
    } catch {
      // Bun's OpenSSL build, for example, has no secp256k1 support.
      return
    }

    // A signature from @noble/curves must verify with node:crypto.
    const nobleSignature = signSecp256k1(privateJwk, data)
    assert.equal(nodeVerify('sha256', data, { key: nodePublicKey, dsaEncoding: 'ieee-p1363' }, nobleSignature), true)

    // And a signature from node:crypto must verify with @noble/curves.
    const nodeSignature = nodeSign('sha256', data, {
      key: nodePrivateKey,
      dsaEncoding: 'ieee-p1363',
    })
    assert.equal(verifySecp256k1(publicJwk, data, new Uint8Array(nodeSignature)), true)
  })
})
