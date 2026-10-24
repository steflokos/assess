// SPDX-License-Identifier: Apache-2.0. Copyright 2026 Stefanos Flokos.
import './setup.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { S, load, resolveAttr, workflow, recordAt, candidates, kindOfId, nameOf, drafts, freeId, newOpen } from '../data.js';
import { pagesFor } from '../palette.js';

await load();

test('the records are indexed by kind and by id', () => {
  assert.equal(S.fatal, '');
  assert.equal((S.of.threat || []).length, 4, 'the test project has four threat scenarios');
  assert.ok(S.byKey.has('risk:update-package-tampering'));
  assert.ok(S.threats.get('update-package-tampering').risk, 'the results are there');
  assert.ok(S.points.time && S.points.time.ET1 !== undefined, 'the points of the policy are there');
});

test('what a record uses and what uses it is worked out from the ids in its attributes', () => {
  const uses = (kind, id) => (S.uses.get(kind + ':' + id) || []).map((r) => r.kind + ':' + r.id);
  const usedBy = (kind, id) => (S.usedBy.get(kind + ':' + id) || []).map((r) => r.kind + ':' + r.id);
  assert.ok(uses('threat', 'update-package-tampering').includes('asset:update-package'), 'a threat scenario is written <asset>-<stride>');
  assert.ok(uses('risk', 'update-package-tampering').includes('threat:update-package-tampering'), 'a risk has the id of its threat scenario');
  assert.ok(usedBy('asset', 'update-package').includes('threat:update-package-tampering'));
  assert.ok(uses('step', 'modify-package-in-transit').includes('control:signed-packages'), 'a step names the controls that mitigate it');
  assert.ok(usedBy('control', 'signed-packages').includes('step:modify-package-in-transit'));
  assert.ok(uses('interface', 'api-interface').includes('component:backend'), 'an interface is written inside a component');
});

test('a block that is written like another one is resolved', () => {
  const impact = S.kinds.damage.attributes.find((a) => a.name === 'impact');
  const oem = impact.attributes.find((a) => a.name === 'oem');
  assert.ok(!oem.attributes, 'describe gives sameAs and no attributes for it');
  const resolved = resolveAttr('damage', oem);
  assert.equal(resolved.name, 'oem');
  assert.ok(resolved.attributes.length > 0, 'the attributes of the road user stand in for it');
});

test('a place in a file belongs to the record that starts at or before it', () => {
  const r = S.byKey.get('step:modify-package-in-transit');
  assert.equal(recordAt(r.file, r.line + 1).id, 'modify-package-in-transit');
  assert.equal(recordAt('nowhere.yaml', 1), null);
});

test('candidates are found by name and by the kinds that an attribute may point at', () => {
  const names = candidates(['component']).map((c) => c.name);
  assert.deepEqual(names, [...names].sort((a, b) => a.localeCompare(b)));
  assert.equal(kindOfId('update-package', ['component', 'asset']), 'asset');
  assert.equal(kindOfId('nobody', ['asset']), undefined);
});

test('the path of the work has seven steps and one of them is next', () => {
  const path = workflow();
  assert.equal(path.length, 7);
  assert.deepEqual(path.slice(0, 4).map((s) => s.state), ['done', 'done', 'done', 'done']);
  assert.ok(path.filter((s) => s.state === 'now').length <= 1, 'only the first step that is not done is the next one');
  for (const s of path) assert.ok(['done', 'now', 'todo'].includes(s.state));
});

test('a search for a word finds the list, the way to make one and the page, whether it is written as one or many', () => {
  const titles = (q) => pagesFor(q).map((p) => p.title);
  assert.ok(titles('attack steps').includes('Attack steps'), 'the list of a kind');
  assert.ok(titles('attack steps').includes('New attack step'), 'making a record of it');
  assert.ok(titles('step').includes('Attack steps'), 'one word finds the many');
  assert.ok(titles('report').includes('Report'), 'a page');
  assert.deepEqual(titles('nothing like this'), []);
});

test('a project reads the same twice, and a change is seen', async () => {
  await load();
  assert.equal(S.changed, false, 'the same answer is no change');
  assert.equal(S.view, 'v', 'the token of the report is kept');
});

test('an id is made from a name, with a number when it is taken, and nothing when the name has no letters', () => {
  assert.equal(freeId('step', 'Replace the package — in transit!'), 'replace-the-package-in-transit');
  assert.equal(freeId('step', 'Modify package in transit'), 'modify-package-in-transit-2', 'that step exists');
  assert.equal(freeId('step', '???'), '');
  drafts.set('step:fresh-step', { kind: 'step', id: 'fresh-step', attributes: { name: 'Fresh step' } });
  try {
    assert.equal(freeId('step', 'Fresh step'), 'fresh-step-2', 'a draft holds its id too');
  } finally { drafts.clear(); }
});

test('a record that a form made on the way is known to its pickers and its chips, and to nothing else', () => {
  drafts.set('step:fresh-step', { kind: 'step', id: 'fresh-step', attributes: { name: 'Fresh step' } });
  try {
    assert.ok(candidates(['step', 'threat']).some((c) => c.id === 'fresh-step' && c.draft));
    assert.equal(kindOfId('fresh-step', ['threat', 'step']), 'step');
    assert.equal(nameOf('step', 'fresh-step'), 'Fresh step');
    assert.ok(!(S.of.step || []).some((r) => r.id === 'fresh-step'), 'the lists show what is written');
  } finally { drafts.clear(); }
  assert.ok(!candidates(['step']).some((c) => c.id === 'fresh-step'));
  assert.equal(kindOfId('fresh-step', ['step']), undefined);
});

test('the open items that a change made are the ones that were not open before', () => {
  const item = (code, id, extra) => Object.assign({ code, kind: 'risk', id, text: 'x', where: 'Risks' }, extra);
  const before = [item('no-treatment', 'a'), item('rule-finding', 'b', { rule: 'r1' })];
  const after = [item('no-treatment', 'a', { text: 'other words' }), item('rule-finding', 'b', { rule: 'r1' }), item('rule-finding', 'b', { rule: 'r2' }), item('no-treatment', 'c')];
  assert.deepEqual(newOpen(before, after).map((o) => o.code + ':' + o.id + ':' + (o.rule || '')), ['rule-finding:b:r2', 'no-treatment:c:'],
    'the same record and code is the same item, whatever the text says. Another rule on the same record is another item');
  assert.deepEqual(newOpen(before, before), []);
  assert.deepEqual(newOpen(null, after), [], 'a project that had errors has no list to compare with');
  assert.deepEqual(newOpen(before, null), []);
});
