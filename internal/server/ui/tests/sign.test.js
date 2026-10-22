// SPDX-License-Identifier: Apache-2.0. Copyright 2026 Stefanos Flokos.
import './setup.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, verify, createPublicKey } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { signIteration, parsePrivate, publicPEM } from '../sign.js';

const pair = () => generateKeyPairSync('ed25519', {
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' },
});

test('the page signs the text that assess checks, and gives the public key as openssl writes it', async () => {
  const { privateKey, publicKey } = pair();
  const hash = process.env.ASSESS_SIGN_HASH || 'sha256:' + 'ab'.repeat(32);
  const made = await signIteration(privateKey, 'assess-iteration-v1', hash);
  assert.equal(made.public, publicKey, 'the public key is the same PKIX PEM');
  assert.match(made.signature, /^[A-Za-z0-9+/]{86}==$/);
  const ok = verify(null, Buffer.from('assess-iteration-v1\n' + hash), createPublicKey(made.public), Buffer.from(made.signature, 'base64'));
  assert.equal(ok, true, 'the signature is a signature of the prefix, a line break and the hash');
  // Go checks the same signature with assess sign, in the test that runs this file
  if (process.env.ASSESS_FIXTURES) writeFileSync(join(process.env.ASSESS_FIXTURES, 'signed.json'), JSON.stringify(made));
});

test('a key that the page cannot use is refused with a reason', async () => {
  assert.throws(() => parsePrivate('-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----'), /passphrase/);
  assert.throws(() => parsePrivate('-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----'), /OpenSSH/);
  assert.throws(() => parsePrivate('hello'), /not a private key/);
  await assert.rejects(() => signIteration(pair().publicKey, 'p', 'h'), /not a private key/);
  assert.match(publicPEM(new Uint8Array(32)), /^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+-----END PUBLIC KEY-----\n$/);
});
