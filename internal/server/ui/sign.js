// SPDX-License-Identifier: Apache-2.0. Copyright 2026 Stefanos Flokos.
// Signing in the browser. The person gives the page the file of their private key. The page makes the signature itself with the
// WebCrypto of the browser and sends the server only the signature and the public key. The private key is read here, used here and
// forgotten here. It is never sent anywhere. assess checks the signature against the hash of the iteration before it writes it.

const b64 = (bytes) => { let s = ''; for (const b of bytes) s += String.fromCharCode(b); return btoa(s); };
const unb64 = (text) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
const unb64url = (text) => unb64(text.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((text.length + 3) % 4));

// the start of the DER of an ed25519 public key, in the form that openssl writes (PKIX): then come the 32 bytes of the key
const PKIX_PREFIX = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);

// parsePrivate reads the PEM of an ed25519 private key in PKCS#8 form, without a passphrase, as `openssl genpkey -algorithm ed25519` writes.
export function parsePrivate(text) {
  if (/BEGIN ENCRYPTED PRIVATE KEY/.test(text)) throw new Error('This key has a passphrase, and the page cannot read such keys. Use a key without one.');
  if (/BEGIN OPENSSH PRIVATE KEY/.test(text)) throw new Error('This is an OpenSSH key. Use a key in PKCS#8 form: openssl genpkey -algorithm ed25519 makes one.');
  const m = /-----BEGIN PRIVATE KEY-----([A-Za-z0-9+/=\s]+)-----END PRIVATE KEY-----/.exec(text);
  if (!m) throw new Error('This file is not a private key. The text must start with BEGIN PRIVATE KEY.');
  return unb64(m[1].replace(/\s+/g, ''));
}

// publicPEM writes the 32 bytes of a public key as PEM.
export function publicPEM(raw) {
  const der = new Uint8Array(PKIX_PREFIX.length + raw.length);
  der.set(PKIX_PREFIX);
  der.set(raw, PKIX_PREFIX.length);
  const body = b64(der).match(/.{1,64}/g).join('\n');
  return '-----BEGIN PUBLIC KEY-----\n' + body + '\n-----END PUBLIC KEY-----\n';
}

// signIteration makes the signature of an iteration. prefix is the start of the text that is signed, which describe gives, and
// hash is the hash of the iteration. It gives the signature in base64 and the public key as PEM.
export async function signIteration(keyText, prefix, hash) {
  if (!globalThis.crypto || !crypto.subtle) throw new Error('This browser cannot use cryptography here. Open the page at the address that assess serve printed, on this computer.');
  const der = parsePrivate(keyText);
  let key;
  try {
    key = await crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, true, ['sign']);
  } catch (e) {
    throw new Error(e && e.name === 'NotSupportedError'
      ? 'This browser cannot sign with ed25519. Use a current Chrome, Firefox or Safari, or sign on the command line with assess sign.'
      : 'The page cannot read this key. It has to be an ed25519 key in PKCS#8 form.');
  }
  const jwk = await crypto.subtle.exportKey('jwk', key);
  const signature = await crypto.subtle.sign({ name: 'Ed25519' }, key, new TextEncoder().encode(prefix + '\n' + hash));
  return { signature: b64(new Uint8Array(signature)), public: publicPEM(unb64url(jwk.x)) };
}
