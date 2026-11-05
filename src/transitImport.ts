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

/**
 * Helpers for OpenBao Transit's BYOK (bring your own key) import.
 *
 * Transit never receives plaintext key material: the private key is encoded as
 * PKCS#8 DER, wrapped with a one-time AES-256 key using RFC 5649, and that AES
 * key is wrapped with the server's RSA-4096 wrapping key using RSA-OAEP. The
 * wire format is:
 *
 *     base64( RSA-OAEP(ephemeralAesKey) || AES-KWP(pkcs8) )
 *
 * with the RSA-OAEP part always exactly 512 bytes (`EncryptedKeyBytes` in
 * OpenBao's `path_import.go`).
 */

import { constants, createPrivateKey, createPublicKey, publicEncrypt, randomBytes } from 'node:crypto'

import {
  KeyManagementError,
  type KmsJwkPrivate,
  type KmsJwkPrivateEc,
  type KmsJwkPrivateOkp,
  type KmsJwkPrivateRsa,
  type KmsJwkPublic,
} from '@credo-ts/core/kms'

import { aesKeyWrapPad } from './aesKeyWrap.js'

type PrivateJwkForNode =
  | { kty: 'EC'; crv: string; x: string; y: string; d: string }
  | { kty: 'OKP'; crv: string; x: string; d: string }
  | {
      kty: 'RSA'
      n: string
      e: string
      d: string
      p: string
      q: string
      dp: string
      dq: string
      qi: string
    }

function minimalPrivateJwk(jwk: KmsJwkPrivateEc | KmsJwkPrivateOkp | KmsJwkPrivateRsa): PrivateJwkForNode {
  switch (jwk.kty) {
    case 'EC':
      return { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d }
    case 'OKP':
      return { kty: 'OKP', crv: jwk.crv, x: jwk.x, d: jwk.d }
    case 'RSA':
      return {
        kty: 'RSA',
        n: jwk.n,
        e: jwk.e,
        d: jwk.d,
        p: jwk.p,
        q: jwk.q,
        dp: jwk.dp,
        dq: jwk.dq,
        qi: jwk.qi,
      }
  }
}

/**
 * Encode a private JWK as PKCS#8 DER, which is the format Transit expects for
 * imported asymmetric keys.
 */
export function privateJwkToPkcs8(jwk: KmsJwkPrivate): Buffer {
  if (jwk.kty === 'oct') {
    throw new KeyManagementError('Symmetric keys cannot be imported into the OpenBao backend')
  }

  const minimal = minimalPrivateJwk(jwk)
  return createPrivateKey({ key: minimal as never, format: 'jwk' }).export({
    type: 'pkcs8',
    format: 'der',
  })
}

/** Derive the public JWK (with a `kid`) from a private JWK. */
export function publicJwkFromPrivateJwk(jwk: KmsJwkPrivate, keyId: string): KmsJwkPublic {
  switch (jwk.kty) {
    case 'EC':
      return { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y, kid: keyId } as KmsJwkPublic
    case 'OKP':
      return { kty: 'OKP', crv: jwk.crv, x: jwk.x, kid: keyId } as KmsJwkPublic
    case 'RSA':
      return { kty: 'RSA', n: jwk.n, e: jwk.e, kid: keyId } as KmsJwkPublic
    case 'oct':
      throw new KeyManagementError('Symmetric keys cannot be imported into the OpenBao backend')
  }
}

/** RSA modulus length in bits, as required to choose `rsa-2048/3072/4096`. */
export function rsaModulusLengthFromPrivateJwk(jwk: KmsJwkPrivateRsa): number {
  const publicKey = createPublicKey({
    key: { kty: 'RSA', n: jwk.n, e: jwk.e } as never,
    format: 'jwk',
  })
  const modulusLength = publicKey.asymmetricKeyDetails?.modulusLength
  if (!modulusLength) throw new KeyManagementError('Unable to determine the RSA modulus length')
  return modulusLength
}

/**
 * Wrap PKCS#8 key material for `POST /transit/keys/:name/import`.
 * Returns the base64 string to send as `ciphertext`.
 */
export function wrapPrivateKeyForTransitImport(pkcs8: Uint8Array, wrappingKeyPem: string): string {
  const ephemeralKey = randomBytes(32)

  const wrappedEphemeralKey = publicEncrypt(
    {
      key: wrappingKeyPem,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    ephemeralKey,
  )

  const wrappedKey = aesKeyWrapPad(ephemeralKey, pkcs8)
  return Buffer.concat([wrappedEphemeralKey, wrappedKey]).toString('base64')
}
