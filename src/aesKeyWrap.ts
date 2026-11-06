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
 * AES Key Wrap with Padding (RFC 5649).
 *
 * OpenBao's Transit BYOK import expects key material wrapped this way, but
 * Node's OpenSSL binding rejects the IV that `id-aes256-wrap-pad` requires, so
 * the algorithm is implemented on top of AES-ECB. That keeps the package
 * dependency-free and works on every Node version.
 */

import { createCipheriv, createDecipheriv } from 'node:crypto'

const AIV_PREFIX = 0xa65959a6

function aesEcbEncryptBlock(key: Buffer, block: Buffer): Buffer {
  const cipher = createCipheriv(`aes-${key.length * 8}-ecb`, key, null)
  cipher.setAutoPadding(false)
  return Buffer.concat([cipher.update(block), cipher.final()])
}

function aesEcbDecryptBlock(key: Buffer, block: Buffer): Buffer {
  const decipher = createDecipheriv(`aes-${key.length * 8}-ecb`, key, null)
  decipher.setAutoPadding(false)
  return Buffer.concat([decipher.update(block), decipher.final()])
}

function xorWithRound(a: Buffer, round: number): Buffer {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(round))
  const result = Buffer.alloc(8)
  for (let i = 0; i < 8; i++) result.writeUInt8(a.readUInt8(i) ^ counter.readUInt8(i), i)
  return result
}

/**
 * Wrap `plaintext` with the RFC 5649 AES Key Wrap with Padding algorithm.
 * The KEK must be a 128, 192 or 256 bit AES key.
 */
export function aesKeyWrapPad(kek: Uint8Array, plaintext: Uint8Array): Buffer {
  const key = Buffer.from(kek)
  const data = Buffer.from(plaintext)
  if (data.length === 0) throw new Error('AES-KWP cannot wrap empty data')
  if (data.length > 0xffff_ffff) throw new Error('AES-KWP input is too large')

  // Pad to a multiple of 8 bytes. A plaintext that already is a multiple of 8
  // gets no padding; the message length in the AIV distinguishes the cases.
  const padded = Buffer.concat([data, Buffer.alloc((8 - (data.length % 8)) % 8)])
  const blockCount = padded.length / 8

  let a: Buffer = Buffer.alloc(8)
  a.writeUInt32BE(AIV_PREFIX, 0)
  a.writeUInt32BE(data.length, 4)

  const blocks: Buffer[] = []
  for (let i = 0; i < blockCount; i++) blocks.push(Buffer.from(padded.subarray(i * 8, i * 8 + 8)))

  // RFC 5649 §4.1: a single block is encrypted as one AES block, without the
  // six-round Feistel transform used for two or more blocks.
  if (blockCount === 1) {
    const onlyBlock = blocks[0]
    if (!onlyBlock) throw new Error('AES-KWP internal error')
    return aesEcbEncryptBlock(key, Buffer.concat([a, onlyBlock]))
  }

  for (let round = 0; round < 6; round++) {
    for (let i = 0; i < blockCount; i++) {
      const block = blocks[i]
      if (!block) throw new Error('AES-KWP internal error')
      const encrypted = aesEcbEncryptBlock(key, Buffer.concat([a, block]))
      a = xorWithRound(encrypted.subarray(0, 8), round * blockCount + i + 1)
      blocks[i] = Buffer.from(encrypted.subarray(8, 16))
    }
  }

  return Buffer.concat([a, ...blocks])
}

/**
 * Unwrap data produced by {@link aesKeyWrapPad}. Used by the RFC 5649 test
 * vectors and useful for debugging imported key material.
 */
export function aesKeyUnwrapPad(kek: Uint8Array, wrapped: Uint8Array): Buffer {
  const key = Buffer.from(kek)
  const data = Buffer.from(wrapped)
  if (data.length % 8 !== 0 || data.length < 16) throw new Error('Invalid AES-KWP ciphertext length')

  const blockCount = data.length / 8 - 1
  let a: Buffer = Buffer.from(data.subarray(0, 8))
  const blocks: Buffer[] = []
  for (let i = 0; i < blockCount; i++) {
    blocks.push(Buffer.from(data.subarray(8 + i * 8, 16 + i * 8)))
  }

  if (blockCount === 1) {
    const onlyBlock = blocks[0]
    if (!onlyBlock) throw new Error('AES-KWP internal error')
    const decrypted = aesEcbDecryptBlock(key, Buffer.concat([a, onlyBlock]))
    a = Buffer.from(decrypted.subarray(0, 8))
    blocks[0] = Buffer.from(decrypted.subarray(8, 16))
  } else {
    for (let round = 5; round >= 0; round--) {
      for (let i = blockCount - 1; i >= 0; i--) {
        const block = blocks[i]
        if (!block) throw new Error('AES-KWP internal error')
        const decrypted = aesEcbDecryptBlock(key, Buffer.concat([xorWithRound(a, round * blockCount + i + 1), block]))
        a = Buffer.from(decrypted.subarray(0, 8))
        blocks[i] = Buffer.from(decrypted.subarray(8, 16))
      }
    }
  }

  if (a.readUInt32BE(0) !== AIV_PREFIX) throw new Error('Invalid AES-KWP AIV')

  const messageLength = a.readUInt32BE(4)
  if (messageLength > 8 * blockCount || messageLength <= 8 * (blockCount - 1)) {
    throw new Error('Invalid AES-KWP message length')
  }

  const padded = Buffer.concat(blocks)
  for (let i = messageLength; i < padded.length; i++) {
    if (padded.readUInt8(i) !== 0) throw new Error('Invalid AES-KWP padding')
  }

  return Buffer.from(padded.subarray(0, messageLength))
}
