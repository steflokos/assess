// SPDX-License-Identifier: Apache-2.0. Copyright 2026 Stefanos Flokos.
import './setup.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { S, load, drafts } from '../data.js';
import { inSchemaOrder, labelOf, hasValue, readOnly, madeFor } from '../form.js';

await load();

test('a block comes back in the order of the format, as people write it', () => {
  const potential = { equipment: 'Eq1', expertise: 'SE1', knowledge: 'KoIC1', time: 'ET1', window: 'WoO1' }; // sorted, as export gives it
  const def = (name) => S.kinds.step.attributes.find((a) => a.name === name);
  assert.deepEqual(Object.keys(inSchemaOrder('step', def('potential'), potential)), ['time', 'expertise', 'knowledge', 'window', 'equipment']);
  assert.deepEqual(inSchemaOrder('step', def('name'), 'Text'), 'Text', 'a text is as it is');
  const notes = { b: '1', a: '2' };
  assert.deepEqual(Object.keys(inSchemaOrder('step', def('notes'), notes)), ['b', 'a'], 'notes are the person\'s, in the order they wrote them');
});

test('names that are one word in the files read as words', () => {
  assert.equal(labelOf('preparedby'), 'Prepared by');
  assert.equal(labelOf('roaduser'), 'Road user');
  assert.equal(labelOf('name'), 'Name');
});

test('what is empty and what assess writes', () => {
  for (const empty of [undefined, null, '', [], {}]) assert.equal(hasValue(empty), false);
  for (const full of [0, false, 'a', ['a'], { a: 1 }]) assert.equal(hasValue(full), true);
  assert.equal(readOnly('risk', { name: 'base', doc: '' }), true);
  assert.equal(readOnly('risk', { name: 'treatment', doc: 'Your decision.' }), false);
});

test('a list of blocks comes back in the order of the format too', () => {
  const flow = { name: 'flow', type: 'blocks', attributes: [{ name: 'from', type: 'text' }, { name: 'to', type: 'text' }] };
  const out = inSchemaOrder('function', flow, [{ to: 'b', from: 'a' }]);
  assert.deepEqual(Object.keys(out[0]), ['from', 'to']);
});

test('a record made on the way is written with the form only while the form still names it', () => {
  drafts.set('step:fresh-step', { kind: 'step', id: 'fresh-step', attributes: { name: 'Fresh step', scalability: 'Fleet-Wide' } });
  drafts.set('step:dropped-step', { kind: 'step', id: 'dropped-step', attributes: { name: 'Dropped step' } });
  try {
    const attrs = { steps: { and: ['modify-package-in-transit', { or: ['fresh-step', 'other'] }] }, name: 'dropped-step is only text in a name' };
    assert.deepEqual(madeFor(attrs), [{ op: 'put', kind: 'step', id: 'fresh-step', attributes: { name: 'Fresh step', scalability: 'Fleet-Wide' }, new: true }]);
    assert.deepEqual(madeFor({ steps: 'fresh-step' }).map((c) => c.id), ['fresh-step'], 'a path of one step is the id');
    assert.deepEqual(madeFor({ name: 'Other' }), [], 'a step that the path no longer holds is not made');
  } finally { drafts.clear(); }
});
