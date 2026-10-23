// SPDX-License-Identifier: Apache-2.0. Copyright 2026 Stefanos Flokos.
// The scripts of the page expect a browser. This gives them the little of it that they touch when they are loaded, so that the parts that
// work on data can be tested without one. Import it first.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

globalThis.location = { hash: '', pathname: '/', protocol: 'http:', hostname: '127.0.0.1', port: '1' };
globalThis.history = { replaceState() {} };
globalThis.sessionStorage = { getItem: () => 'token', setItem() {} };
globalThis.localStorage = { getItem: () => null, setItem() {} };

// fixtures are the answers of the real commands on the test project. The Go test that runs these tests writes them.
export const fixtures = process.env.ASSESS_FIXTURES || '';
export const fixture = (name) => JSON.parse(readFileSync(join(fixtures, name + '.json'), 'utf8'));

// fetch answers the routes of the server from the fixtures.
globalThis.fetch = async (path) => {
  const name = String(path).split('?')[0].replace('/api/', '');
  const body = JSON.stringify(name === 'stamp' ? { stamp: 'x' } : name === 'view' ? { view: 'v' } : fixture(name));
  return { status: 200, text: async () => body };
};
