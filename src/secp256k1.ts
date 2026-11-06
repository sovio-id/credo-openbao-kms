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

import { secp256k1 } from '@noble/curves/secp256k1.js'

/**
 * Minimal JWK-level helpers for secp256k1.
 *
 * Transit cannot represent secp256k1, so the KV fallback has to create, sign,
 * and verify these keys in-process. `node:crypto` supports secp256k1 on Node.js
 * but not in every runtime (Bun's OpenSSL build, for example, rejects the
 * curve), so the pure-JS `@noble/curves` implementation is used instead. That
 * keeps the backend portable and gives the same compact `r || s` signatures
 * JWA requires.
 */

export interface Secp256k1KeyPairJwk {
  privateJwk: Record<string, unknown>
  publicJwk: Record<string, unknown>
}

function encodeBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url')
}

function decodeBase64Url(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'base64url'))
}

export function generateSecp256k1KeyPair(keyId: string): Secp256k1KeyPairJwk {
  const privateKey = secp256k1.utils.randomSecretKey()
  const publicKey = secp256k1.getPublicKey(privateKey, false)

  const x = encodeBase64Url(publicKey.subarray(1, 33))
  const y = encodeBase64Url(publicKey.subarray(33, 65))

  return {
    privateJwk: {
      kty: 'EC',
      crv: 'secp256k1',
      x,
      y,
      d: encodeBase64Url(privateKey),
    },
    publicJwk: {
      kty: 'EC',
      crv: 'secp256k1',
      x,
      y,
      kid: keyId,
    },
  }
}

/**
 * Sign data with ES256K. `@noble/curves` hashes the message with SHA-256 by
 * default (`prehash: true`) and returns the compact 64-byte `r || s` form.
 */
export function signSecp256k1(privateJwk: Record<string, unknown>, data: Uint8Array): Uint8Array {
  const d = privateJwk.d
  if (typeof d !== 'string') {
    throw new Error("The secp256k1 private JWK does not contain a 'd' parameter")
  }

  const signature = secp256k1.sign(data, decodeBase64Url(d))
  return new Uint8Array(signature)
}

/**
 * Verify an ES256K signature against a secp256k1 public JWK.
 *
 * `lowS: false` accepts signatures produced by OpenSSL/node:crypto as well as
 * the normalized low-S signatures this backend produces.
 */
export function verifySecp256k1(publicJwk: Record<string, unknown>, data: Uint8Array, signature: Uint8Array): boolean {
  const { x, y } = publicJwk
  if (typeof x !== 'string' || typeof y !== 'string') return false

  try {
    const publicKey = new Uint8Array(65)
    publicKey[0] = 0x04
    publicKey.set(decodeBase64Url(x), 1)
    publicKey.set(decodeBase64Url(y), 33)

    return secp256k1.verify(signature, data, publicKey, { lowS: false })
  } catch {
    // Malformed signatures and points throw; treat them as invalid.
    return false
  }
}
