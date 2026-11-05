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

import { aesKeyUnwrapPad, aesKeyWrapPad } from '../src/aesKeyWrap.js'

// The two examples from RFC 5649 §6, which also exercise the single-block and
// multi-block branches.
const KEK = Buffer.from('5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8', 'hex')

describe('AES Key Wrap with Padding (RFC 5649)', () => {
  it('matches the 20-byte test vector from §6.1', () => {
    const keyData = Buffer.from('c37b7e6492584340bed12207808941155068f738', 'hex')
    const expected = '138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a'

    const wrapped = aesKeyWrapPad(KEK, keyData)
    assert.equal(wrapped.toString('hex'), expected)
    assert.deepEqual(aesKeyUnwrapPad(KEK, wrapped), keyData)
  })

  it('matches the 7-byte test vector from §6.2', () => {
    const keyData = Buffer.from('466f7250617369', 'hex')
    const expected = 'afbeb0f07dfbf5419200f2ccb50bb24f'

    const wrapped = aesKeyWrapPad(KEK, keyData)
    assert.equal(wrapped.toString('hex'), expected)
    assert.deepEqual(aesKeyUnwrapPad(KEK, wrapped), keyData)
  })

  it('round-trips and pads keys of arbitrary length', () => {
    for (let length = 1; length <= 64; length++) {
      const keyData = Buffer.alloc(length, length)
      const wrapped = aesKeyWrapPad(KEK, keyData)
      assert.deepEqual(aesKeyUnwrapPad(KEK, wrapped), keyData, `length ${length}`)
    }
  })

  it('rejects corrupted ciphertext', () => {
    const wrapped = aesKeyWrapPad(KEK, Buffer.alloc(32, 7))
    wrapped[wrapped.length - 1] ^= 0xff
    assert.throws(() => aesKeyUnwrapPad(KEK, wrapped))
  })
})
