// SPDX-License-Identifier: Apache-2.0. Copyright 2026 Stefanos Flokos.
// Where the page keeps the token of the API. Each case loads lib.js anew, with a query that makes it a module of its own.
import './setup.js';
import test from 'node:test';
import assert from 'node:assert/strict';

// fresh loads lib.js in a browser whose address, tab storage and origin storage are as given, and says what the page took as its
// token and what it stored where.
async function fresh(name, { hostname = '127.0.0.1', hash = '', tab = null, origin = null }) {
  const stored = { tab: {}, origin: {} };
  globalThis.location = { hash, pathname: '/', protocol: 'http:', hostname, port: '1' };
  globalThis.sessionStorage = { getItem: () => tab, setItem: (k, v) => { stored.tab[k] = v; } };
  globalThis.localStorage = { getItem: () => origin, setItem: (k, v) => { stored.origin[k] = v; } };
  const lib = await import('../lib.js?' + name);
  return { token: lib.tokenValue(), stored };
}

test('the token of the address is kept for the tab and for a new tab of the same origin', async () => {
  const { token, stored } = await fresh('given', { hash: '#t=abc123' });
  assert.equal(token, 'abc123');
  assert.equal(stored.tab['assess-token'], 'abc123');
  assert.equal(stored.origin['assess-token'], 'abc123', 'a link opened in a new tab finds it');
});

test('a new tab, which has no token of its own, takes the one of the origin', async () => {
  const { token } = await fresh('newtab', { origin: 'abc123' });
  assert.equal(token, 'abc123');
});

test('the token of the tab wins over the one of the origin, which another run may have left', async () => {
  const { token } = await fresh('both', { tab: 'mine', origin: 'other' });
  assert.equal(token, 'mine');
});

test('at [::1] the report opens in a tab of this origin, so the token stays with the tab', async () => {
  const given = await fresh('ipv6given', { hostname: '[::1]', hash: '#t=abc123' });
  assert.equal(given.token, 'abc123');
  assert.equal(given.stored.origin['assess-token'], undefined, 'nothing is kept where the report could read it');
  const newTab = await fresh('ipv6newtab', { hostname: '[::1]', origin: 'abc123' });
  assert.equal(newTab.token, '', 'a new tab at [::1] needs the address');
});
