// SPDX-License-Identifier: Apache-2.0. Copyright 2026 Stefanos Flokos.
import './setup.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { canon, same, lines, firstSentence, short, plural, upper } from '../lib.js';

test('the same value in another order of keys is the same value', () => {
  assert.equal(same({ b: 1, a: { d: [1, 2], c: 3 } }, { a: { c: 3, d: [1, 2] }, b: 1 }), true);
  assert.equal(same({ a: [1, 2] }, { a: [2, 1] }), false, 'the order of a list matters');
  assert.deepEqual(Object.keys(canon({ b: 1, a: 2 })), ['a', 'b']);
});

test('lines, sentences and words', () => {
  assert.deepEqual(lines(' a \n\n b\n'), ['a', 'b']);
  assert.equal(firstSentence('It does this. And that.'), 'It does this.');
  assert.equal(firstSentence('no full stop'), 'no full stop');
  assert.equal(short('sha256:0123456789abcdef'), '0123456789ab');
  assert.equal(plural(1, 'step'), '1 step');
  assert.equal(plural(2, 'step'), '2 steps');
  assert.equal(upper('threat'), 'Threat');
});
