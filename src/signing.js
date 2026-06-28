/**
 * signing.js — Ed25519 signing of entitlement records (Story 24)
 *
 * The activation server can sign the entitlement records it
 * returns. This lets clients verify that a record really came
 * from the activation server they think it came from (the
 * signed record + the server's public key is enough; no
 * central CA needed).
 *
 * The keypair is generated on first server start and stored
 * alongside the data directory. The private key is stored with
 * mode 0600.
 *
 * This is the creator's identity key for the activation server.
 * The same identity model as kdna-cli's `kdna identity init`
 * (Story 19) — but in a separate file because the server
 * identity is the SERVER's, not the deployer's CLI identity.
 *
 * Story 19 design contract:
 *   - Each actor generates their own key pair.
 *   - KDNA Inc. holds NO private keys.
 *   - No TUF, no registry, no central authority.
 *
 * Same rules apply here: the server generates its own key.
 * Clients verify against the server's public key (which the
 * server advertises at GET /v1/server/identity).
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const PRIVATE_KEY_PATH_DEFAULT = 'activation-server-ed25519.key';
const PUBLIC_KEY_PATH_DEFAULT = 'activation-server-ed25519.pub';

function keyPaths(dataDir) {
  return {
    priv: path.join(dataDir, PRIVATE_KEY_PATH_DEFAULT),
    pub: path.join(dataDir, PUBLIC_KEY_PATH_DEFAULT),
  };
}

function ensureKeyPair(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const { priv, pub } = keyPaths(dataDir);
  if (fs.existsSync(priv) && fs.existsSync(pub)) {
    return {
      privatePem: fs.readFileSync(priv, 'utf8'),
      publicPem: fs.readFileSync(pub, 'utf8'),
    };
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  fs.writeFileSync(priv, privateKey, { mode: 0o600 });
  fs.writeFileSync(pub, publicKey, { mode: 0o644 });
  return { privatePem: privateKey, publicPem: publicKey };
}

function publicKeyFingerprint(publicPem) {
  return crypto.createHash('sha256').update(publicPem).digest('hex').substring(0, 16);
}

function publicKeyRawHex(publicPem) {
  const obj = crypto.createPublicKey({ key: publicPem, format: 'pem', type: 'spki' });
  const der = obj.export({ type: 'spki', format: 'der' });
  return Buffer.from(der.subarray(der.length - 32)).toString('hex');
}

/**
 * Sign an entitlement record. The signature covers the
 * canonical JSON of the body (everything except
 * signature_base64). The signature is base64.
 */
function signEntitlement(record, privatePem) {
  const { signature_base64: _ignore, ...body } = record;
  const stable = stableStringify(body);
  const sig = crypto.sign(null, Buffer.from(stable, 'utf8'),
    crypto.createPrivateKey({ key: privatePem, format: 'pem', type: 'pkcs8' }));
  return { ...record, signature_base64: sig.toString('base64') };
}

function verifyEntitlementSignature(record, publicPem) {
  const { signature_base64, ...body } = record;
  if (!signature_base64) return { ok: false, reason: 'no signature' };
  const stable = stableStringify(body);
  const ok = crypto.verify(
    null,
    Buffer.from(stable, 'utf8'),
    crypto.createPublicKey({ key: publicPem, format: 'pem', type: 'spki' }),
    Buffer.from(signature_base64, 'base64'),
  );
  return { ok, reason: ok ? null : 'signature does not verify' };
}

function stableStringify(value) {
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

module.exports = {
  ensureKeyPair,
  keyPaths,
  publicKeyFingerprint,
  publicKeyRawHex,
  signEntitlement,
  verifyEntitlementSignature,
  stableStringify,
};
