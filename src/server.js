/**
 * server.js — activation server HTTP layer (Story 24)
 *
 * Implements the four endpoints from specs/kdna-entitlement-api.md:
 *
 *   POST /v1/entitlements/activate
 *     Body: { domain, license_key, machine_fingerprint?, ... }
 *     Response: activation record (status: "active")
 *     Errors: INVALID_LICENSE_KEY, LICENSE_REVOKED, ...
 *
 *   POST /v1/entitlements/sync
 *     Body: { domain, license_key, license_id? }
 *     Response: same as activation (refreshes last_checked_at)
 *
 *   POST /v1/entitlements/revoke
 *     Auth: Bearer <admin-token>
 *     Body: { license_id, domain, reason, revoked_by? }
 *     Response: { ok: true, license_id, status: "revoked", ... }
 *
 *   GET /v1/entitlements/status?domain=...&license_key=...
 *     Response: activation record
 *
 * Plus:
 *   GET /v1/server/identity
 *     Response: { public_key_pem, public_key_fingerprint,
 *                 public_key_hex, ... }
 *     Lets clients verify signed entitlement records.
 *
 *   GET /healthz
 *     Response: { ok: true, server, version }
 *
 * Layer isolation: the server returns the activation record's
 * fields verbatim. It does NOT add content-trust claims like
 * "official" or "trusted" — those would contradict the KDNA
 * layer-isolation rules (SPEC §13.1).
 */

'use strict';

const http = require('node:http');
const { URL } = require('node:url');
const crypto = require('node:crypto');
const { makeStore } = require('./store');
const {
  ensureKeyPair,
  publicKeyFingerprint,
  publicKeyRawHex,
  signEntitlement,
  verifyEntitlementSignature,
} = require('./signing');

const DEFAULT_PORT = 3001;

function makeRequestHandler(opts) {
  if (!opts.store) throw new Error('store is required');
  if (!opts.keys) throw new Error('keys is required');
  const { store, keys, adminToken } = opts;

  async function handle(req, res) {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    // Health check (always 200, no auth)
    if (req.method === 'GET' && url.pathname === '/healthz') {
      json(res, 200, {
        ok: true,
        server: '@aikdna/kdna-activation-server',
        version: require('../package.json').version,
        data_dir: store.dataDir,
      });
      return;
    }

    // Server identity — the public key clients use to verify
    // signed entitlement records. No auth (this is a public key).
    if (req.method === 'GET' && url.pathname === '/v1/server/identity') {
      const rawHex = publicKeyRawHex(keys.publicPem);
      json(res, 200, {
        server: '@aikdna/kdna-activation-server',
        version: require('../package.json').version,
        public_key_pem: keys.publicPem.trim(),
        public_key_fingerprint: publicKeyFingerprint(keys.publicPem),
        public_key_hex: rawHex,
        algorithm: 'ed25519',
        signature_version: '1.0',
      });
      return;
    }

    // Activation
    if (req.method === 'POST' && url.pathname === '/v1/entitlements/activate') {
      await readJson(req, res, async (body) => {
        const { domain, license_key } = body || {};
        if (!domain) return jsonError(res, 400, 'MISSING_DOMAIN', 'domain is required');
        if (!license_key) return jsonError(res, 400, 'MISSING_LICENSE_KEY', 'license_key is required');

        const rec = store.getByKey(license_key);
        if (!rec || rec.domain !== domain) {
          return jsonError(res, 404, 'INVALID_LICENSE_KEY',
            'license_key does not match the requested domain');
        }
        if (rec.revoked || rec.status === 'revoked') {
          return jsonError(res, 403, 'LICENSE_REVOKED',
            'license has been revoked',
            { license_id: rec.license_id, revoked_at: rec.revoked_at, revocation_reason: rec.revocation_reason });
        }
        if (rec.expires_at && new Date(rec.expires_at) < new Date()) {
          return jsonError(res, 403, 'LICENSE_EXPIRED',
            'license has expired',
            { license_id: rec.license_id, expires_at: rec.expires_at });
        }
        // Activate: refresh last_checked_at + offline_valid_until
        store.updateSync(rec.license_id);
        const fresh = store.get(rec.license_id);
        const signed = signEntitlement(stripForApi(fresh), keys.privatePem);
        return json(res, 200, signed);
      });
      return;
    }

    // Sync
    if (req.method === 'POST' && url.pathname === '/v1/entitlements/sync') {
      await readJson(req, res, async (body) => {
        const { domain, license_key, license_id } = body || {};
        let rec = null;
        if (license_id) rec = store.get(license_id);
        if (!rec && license_key) rec = store.getByKey(license_key);
        if (!rec || (domain && rec.domain !== domain)) {
          return jsonError(res, 404, 'INVALID_LICENSE_KEY',
            'no entitlement matches the provided identifiers');
        }
        if (rec.revoked || rec.status === 'revoked') {
          return jsonError(res, 403, 'LICENSE_REVOKED',
            'license has been revoked',
            { license_id: rec.license_id, revoked_at: rec.revoked_at, revocation_reason: rec.revocation_reason });
        }
        if (rec.expires_at && new Date(rec.expires_at) < new Date()) {
          return jsonError(res, 403, 'LICENSE_EXPIRED',
            'license has expired',
            { license_id: rec.license_id, expires_at: rec.expires_at });
        }
        store.updateSync(rec.license_id);
        const fresh = store.get(rec.license_id);
        const signed = signEntitlement(stripForApi(fresh), keys.privatePem);
        return json(res, 200, signed);
      });
      return;
    }

    // Status (introspection; lightweight)
    if (req.method === 'GET' && url.pathname === '/v1/entitlements/status') {
      const domain = url.searchParams.get('domain');
      const licenseKey = url.searchParams.get('license_key');
      const licenseId = url.searchParams.get('license_id');
      let rec = null;
      if (licenseId) rec = store.get(licenseId);
      if (!rec && licenseKey) rec = store.getByKey(licenseKey);
      if (!rec || (domain && rec.domain !== domain)) {
        return jsonError(res, 404, 'NOT_FOUND', 'no entitlement matches');
      }
      return json(res, 200, stripForStatus(rec));
    }

    // Revoke (admin-only, bearer token)
    if (req.method === 'POST' && url.pathname === '/v1/entitlements/revoke') {
      const auth = req.headers.authorization || '';
      if (!adminToken || !auth.startsWith('Bearer ') || auth.slice(7) !== adminToken) {
        return jsonError(res, 401, 'UNAUTHORIZED',
          'admin bearer token required');
      }
      await readJson(req, res, async (body) => {
        const { license_id, domain, reason, revoked_by } = body || {};
        if (!license_id) return jsonError(res, 400, 'MISSING_LICENSE_ID', 'license_id is required');
        const rec = store.get(license_id);
        if (!rec || (domain && rec.domain !== domain)) {
          return jsonError(res, 404, 'NOT_FOUND', 'no entitlement matches');
        }
        const updated = store.revoke(license_id, { reason, revoked_by });
        return json(res, 200, {
          ok: true,
          license_id,
          status: 'revoked',
          revoked: true,
          revoked_at: updated.revoked_at,
          reason: updated.revocation_reason,
          revoked_by: updated.revoked_by,
        });
      });
      return;
    }

    jsonError(res, 404, 'NOT_FOUND', `no handler for ${req.method} ${url.pathname}`);
  }

  return handle;
}

/**
 * Strip internal fields from the API response. The store keeps
 * `updated_at`, `revoked_by`, etc. for bookkeeping; these are
 * not part of the public entitlement record shape.
 */
function stripForApi(rec) {
  const out = { ...rec };
  delete out.revoked_by;
  return out;
}

function stripForStatus(rec) {
  const out = stripForApi(rec);
  delete out.license_key;
  return out;
}

function readJson(req, res, fn) {
  let body = '';
  req.on('data', (chunk) => {
    body += chunk;
    if (body.length > 64 * 1024) {
      req.destroy();
      jsonError(res, 413, 'REQUEST_TOO_LARGE', 'request body exceeds 64KB');
    }
  });
  req.on('end', async () => {
    let parsed;
    try {
      parsed = body.length === 0 ? {} : JSON.parse(body);
    } catch (e) {
      return jsonError(res, 400, 'INVALID_JSON', `not valid JSON: ${e.message}`);
    }
    try {
      await fn(parsed);
    } catch (e) {
      jsonError(res, 500, 'INTERNAL_ERROR', e.message);
    }
  });
}

function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(body, null, 2) + '\n');
}

function jsonError(res, status, code, message, extra) {
  json(res, status, { ok: false, error: { code, message, retryable: false, ...(extra || {}) } });
}

function startServer(opts = {}) {
  return new Promise((resolve, reject) => {
    const dataDir = opts.dataDir || require('./store').DEFAULT_DATA_DIR;
    const store = opts.store || makeStore(dataDir);
    const keys = opts.keys || ensureKeyPair(dataDir);
    const handler = makeRequestHandler({
      store,
      keys,
      adminToken: opts.adminToken || null,
    });
    const server = http.createServer(handler);
    server.on('error', reject);
    server.listen(typeof opts.port === 'number' ? opts.port : DEFAULT_PORT, opts.host || '127.0.0.1', () => {
      const addr = server.address();
      resolve({ server, port: addr.port, host: addr.address, store, keys, dataDir });
    });
  });
}

function stopServer(server) {
  return new Promise((resolve) => {
    if (!server) return resolve();
    server.close(() => resolve());
  });
}

module.exports = {
  makeRequestHandler,
  startServer,
  stopServer,
};
