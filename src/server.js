/**
 * server.js — activation server HTTP layer (Story 24)
 *
 * Implements the four endpoints from specs/kdna-entitlement-api.md:
 *
 *   POST /entitlements/activate
 *     Body: { domain, license_key, machine_fingerprint, ... }
 *     Response: activation record (status: "active")
 *     Errors: INVALID_LICENSE_KEY, LICENSE_REVOKED, ...
 *
 *   POST /entitlements/sync
 *     Body: { domain, license_key, license_id?, machine_fingerprint? }
 *     Response: same as activation (refreshes last_checked_at)
 *
 *   POST /entitlements/revoke
 *     Auth: Bearer <admin-token>
 *     Body: { license_id, domain, reason, revoked_by? }
 *     Response: { ok: true, license_id, status: "revoked", ... }
 *
 *   GET /entitlements/status?domain=...&license_id=...&machine_fingerprint=...
 *     Response: activation record
 *
 * Plus:
 *   GET /server/identity
 *     Response: { public_key_pem, public_key_fingerprint,
 *                 public_key_hex, ... }
 *     Lets clients verify signed entitlement records.
 *
 *   GET /healthz
 *     Response: { ok: true, server, version }
 *
 * Layer isolation: the server returns a signed public entitlement record
 * without the request-only license secret or internal binding digest. It does
 * NOT add content-trust claims like
 * "official" or "trusted" — those would contradict the KDNA
 * layer-isolation rules (SPEC §13.1).
 */

'use strict';

const http = require('node:http');
const { URL } = require('node:url');
const crypto = require('node:crypto');
const { ENTITLEMENT_ROUTES } = require('./contract');
const { isCanonicalDomain, makeStore } = require('./store');
const {
  ensureKeyPair,
  publicKeyFingerprint,
  publicKeyRawHex,
  signEntitlement,
  verifyEntitlementSignature,
} = require('./signing');

const DEFAULT_PORT = 3001;
const MAX_REQUEST_BODY_BYTES = 64 * 1024;
const REQUEST_BASE_URL = 'http://kdna.invalid';
const MACHINE_FINGERPRINT_RE = /^[0-9a-f]{64}$/;
const LICENSE_ID_RE = /^[A-Za-z0-9_\-:.]{1,128}$/;
const MACHINE_BINDING_KEY_SALT = Buffer.from(
  'kdna.activation.machine-binding.hkdf-salt',
  'utf8',
);
const MACHINE_BINDING_KEY_INFO = Buffer.from(
  'kdna.activation.machine-binding.hmac-key',
  'utf8',
);
const MACHINE_BINDING_RECORD_CONTEXT = 'kdna.activation.machine-binding.fingerprint\0';

function normalizeMachineFingerprint(value) {
  if (typeof value !== 'string' || !MACHINE_FINGERPRINT_RE.test(value)) return null;
  return value;
}

function deriveMachineBindingDigest(machineFingerprint, privatePem) {
  const bindingKey = Buffer.from(crypto.hkdfSync(
    'sha256',
    Buffer.from(privatePem, 'utf8'),
    MACHINE_BINDING_KEY_SALT,
    MACHINE_BINDING_KEY_INFO,
    32,
  ));
  return crypto
    .createHmac('sha256', bindingKey)
    .update(MACHINE_BINDING_RECORD_CONTEXT, 'utf8')
    .update(machineFingerprint, 'utf8')
    .digest('hex');
}

function makeRequestHandler(opts) {
  if (!opts.store) throw new Error('store is required');
  if (!opts.keys) throw new Error('keys is required');
  const { store, keys, adminToken } = opts;

  function resolveRecord({ domain, licenseKey, licenseId }) {
    let byKey;
    let byId;
    try {
      byKey = licenseKey ? store.getByKey(licenseKey, domain) : null;
      byId = licenseId ? store.get(licenseId) : null;
    } catch {
      return null;
    }

    if (licenseKey && !byKey) return null;
    if (licenseId && !byId) return null;
    if (byKey && byId && byKey.license_id !== byId.license_id) return null;

    const rec = byKey || byId;
    if (!rec || (domain && rec.domain !== domain)) return null;
    return rec;
  }

  function authorizeMachine(rec, suppliedFingerprint, { allowInitialBinding = false } = {}) {
    if (rec.require_machine_binding === false) {
      return { ok: true, record: rec, machineFingerprint: null };
    }

    if (suppliedFingerprint === undefined || suppliedFingerprint === null || suppliedFingerprint === '') {
      return {
        ok: false,
        status: 400,
        code: 'MISSING_MACHINE_FINGERPRINT',
        message: 'machine_fingerprint is required for this license',
      };
    }

    const machineFingerprint = normalizeMachineFingerprint(suppliedFingerprint);
    if (!machineFingerprint) {
      return {
        ok: false,
        status: 400,
        code: 'INVALID_MACHINE_FINGERPRINT',
        message: 'machine_fingerprint must be exactly 64 lowercase hexadecimal characters',
      };
    }

    const suppliedDigest = deriveMachineBindingDigest(machineFingerprint, keys.privatePem);
    const binding = store.compareAndBindMachine(rec.license_id, {
      bindingDigest: suppliedDigest,
      allowInitialBinding,
      deriveLegacyDigest(value) {
        const legacyFingerprint = normalizeMachineFingerprint(value);
        return legacyFingerprint
          ? deriveMachineBindingDigest(legacyFingerprint, keys.privatePem)
          : null;
      },
    });

    if (!binding.ok && binding.reason === 'missing') {
      return {
        ok: false,
        status: 404,
        code: 'INVALID_LICENSE_KEY',
        message: 'no entitlement matches the provided identifiers',
      };
    }
    if (!binding.ok) {
      return {
        ok: false,
        status: 403,
        code: 'MACHINE_MISMATCH',
        message: 'machine fingerprint does not match an active binding',
      };
    }
    return { ok: true, record: binding.record, machineFingerprint };
  }

  function sendMachineError(res, authorization) {
    return jsonError(
      res,
      authorization.status,
      authorization.code,
      authorization.message,
    );
  }

  async function handle(req, res) {
    let url;
    try {
      url = parseRequestUrl(req);
    } catch {
      jsonError(
        res,
        400,
        'INVALID_REQUEST_TARGET',
        'request target or Host header is invalid',
      );
      return;
    }

    // Health check (always 200, no auth)
    if (req.method === 'GET' && url.pathname === ENTITLEMENT_ROUTES.health) {
      json(res, 200, {
        ok: true,
        server: '@aikdna/kdna-activation-server',
        version: require('../package.json').version,
      });
      return;
    }

    // Server identity — the public key clients use to verify
    // signed entitlement records. No auth (this is a public key).
    if (req.method === 'GET' && url.pathname === ENTITLEMENT_ROUTES.identity) {
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
    if (req.method === 'POST' && url.pathname === ENTITLEMENT_ROUTES.activate) {
      await readJson(req, res, async (body) => {
        const { domain, license_key, machine_fingerprint } = body || {};
        const domainError = requestDomainError(domain);
        if (domainError) return jsonError(res, 400, domainError.code, domainError.message);
        if (license_key === undefined || license_key === null || license_key === '') {
          return jsonError(res, 400, 'MISSING_LICENSE_KEY', 'license_key is required');
        }
        if (typeof license_key !== 'string') {
          return jsonError(
            res,
            404,
            'INVALID_LICENSE_KEY',
            'no entitlement matches the provided identifiers',
          );
        }

        const rec = store.getByKey(license_key, domain);
        if (!rec) {
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
        const authorization = authorizeMachine(rec, machine_fingerprint, {
          allowInitialBinding: true,
        });
        if (!authorization.ok) return sendMachineError(res, authorization);
        // Activate: refresh last_checked_at + offline_valid_until
        store.updateSync(rec.license_id);
        const fresh = store.get(rec.license_id);
        const response = stripForApi(fresh);
        if (fresh.require_machine_binding !== false) {
          response.require_machine_binding = true;
          response.machine_fingerprint = authorization.machineFingerprint;
        }
        const signed = signEntitlement(response, keys.privatePem);
        return json(res, 200, signed);
      });
      return;
    }

    // Sync
    if (req.method === 'POST' && url.pathname === ENTITLEMENT_ROUTES.sync) {
      await readJson(req, res, async (body) => {
        const { domain, license_key, license_id, machine_fingerprint } = body || {};
        const domainError = requestDomainError(domain);
        if (domainError) return jsonError(res, 400, domainError.code, domainError.message);
        if (license_key === undefined || license_key === null || license_key === '') {
          return jsonError(res, 400, 'MISSING_LICENSE_KEY', 'license_key is required');
        }
        if (typeof license_key !== 'string') {
          return jsonError(
            res,
            404,
            'INVALID_LICENSE_KEY',
            'no entitlement matches the provided identifiers',
          );
        }
        const rec = resolveRecord({ domain, licenseKey: license_key, licenseId: license_id });
        if (!rec) {
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
        const authorization = authorizeMachine(rec, machine_fingerprint);
        if (!authorization.ok) return sendMachineError(res, authorization);
        store.updateSync(rec.license_id);
        const fresh = store.get(rec.license_id);
        const response = stripForApi(fresh);
        if (fresh.require_machine_binding !== false) {
          response.require_machine_binding = true;
          response.machine_fingerprint = authorization.machineFingerprint;
        }
        const signed = signEntitlement(response, keys.privatePem);
        return json(res, 200, signed);
      });
      return;
    }

    // Status (introspection; lightweight)
    if (req.method === 'GET' && url.pathname === ENTITLEMENT_ROUTES.status) {
      const statusNotFound = () => jsonError(res, 404, 'NOT_FOUND', 'no entitlement matches');
      const domains = url.searchParams.getAll('domain');
      const licenseIds = url.searchParams.getAll('license_id');
      const machineFingerprints = url.searchParams.getAll('machine_fingerprint');

      // Status uses public identifiers only. A secret license key must never be
      // accepted in a URL, where ordinary proxy and access logs may retain it.
      if (
        url.searchParams.has('license_key') ||
        domains.length !== 1 ||
        licenseIds.length !== 1 ||
        machineFingerprints.length > 1 ||
        !isCanonicalDomain(domains[0]) ||
        !LICENSE_ID_RE.test(licenseIds[0])
      ) {
        return statusNotFound();
      }

      const domain = url.searchParams.get('domain');
      const licenseId = url.searchParams.get('license_id');
      const machineFingerprint = url.searchParams.get('machine_fingerprint');
      const rec = resolveRecord({ domain, licenseId });
      if (!rec) {
        return statusNotFound();
      }
      const authorization = authorizeMachine(rec, machineFingerprint);
      // license_id is public audit metadata, so status must not turn machine
      // failures into a record-enumeration oracle. Missing, malformed, wrong,
      // and not-yet-bound machines are indistinguishable from no record.
      if (!authorization.ok) {
        return statusNotFound();
      }
      return json(res, 200, stripForStatus(authorization.record));
    }

    // Revoke (admin-only, bearer token)
    if (req.method === 'POST' && url.pathname === ENTITLEMENT_ROUTES.revoke) {
      const auth = req.headers.authorization || '';
      if (!validAdminBearer(auth, adminToken)) {
        return jsonError(res, 401, 'UNAUTHORIZED',
          'admin bearer token required');
      }
      await readJson(req, res, async (body) => {
        const { license_id, domain, reason, revoked_by } = body || {};
        if (!license_id) return jsonError(res, 400, 'MISSING_LICENSE_ID', 'license_id is required');
        const domainError = requestDomainError(domain);
        if (domainError) return jsonError(res, 400, domainError.code, domainError.message);
        if (!LICENSE_ID_RE.test(license_id)) {
          return jsonError(res, 404, 'NOT_FOUND', 'no entitlement matches');
        }
        const rec = store.get(license_id);
        if (!rec || rec.domain !== domain) {
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

    jsonError(res, 404, 'NOT_FOUND', 'no handler for this request');
  }

  return handle;
}

/**
 * Strip request secrets and server-only bookkeeping from API responses.
 * The signed public record keeps the machine fingerprint needed by the
 * remote-runtime binding contract, but never the stored keyed digest.
 */
function stripForApi(rec) {
  const out = { ...rec };
  delete out.license_key;
  delete out.revoked_by;
  delete out.machine_binding_digest;
  delete out.machine_fingerprint;
  return out;
}

function stripForStatus(rec) {
  return stripForApi(rec);
}

function readJson(req, res, fn) {
  let bodyBytes = 0;
  let bodyChunks = [];
  let tooLarge = false;
  req.on('data', (chunk) => {
    if (tooLarge) return;
    bodyBytes += chunk.length;
    if (bodyBytes > MAX_REQUEST_BODY_BYTES) {
      tooLarge = true;
      bodyChunks = [];
      jsonError(res, 413, 'REQUEST_TOO_LARGE', 'request body exceeds 64KB');
      return;
    }
    bodyChunks.push(Buffer.from(chunk));
  });
  req.on('end', async () => {
    if (tooLarge) return;
    let parsed;
    try {
      const body = new TextDecoder('utf-8', { fatal: true })
        .decode(Buffer.concat(bodyChunks, bodyBytes));
      parsed = body.length === 0 ? {} : JSON.parse(body);
    } catch {
      return jsonError(res, 400, 'INVALID_JSON', 'request body is not valid JSON');
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return jsonError(res, 400, 'INVALID_REQUEST_BODY', 'request body must be a JSON object');
    }
    try {
      await fn(parsed);
    } catch {
      if (!res.headersSent && !res.writableEnded) {
        jsonError(res, 500, 'INTERNAL_ERROR', 'request could not be processed');
      }
    }
  });
}

function json(res, status, body) {
  if (res.writableEnded) return;
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(body, null, 2) + '\n');
}

function jsonError(res, status, code, message, extra) {
  json(res, status, { ok: false, error: { code, message, retryable: false, ...(extra || {}) } });
}

function requestDomainError(domain) {
  if (domain === undefined || domain === null || domain === '') {
    return { code: 'MISSING_DOMAIN', message: 'domain is required' };
  }
  if (!isCanonicalDomain(domain)) {
    return {
      code: 'INVALID_DOMAIN',
      message: 'domain must be a canonical KDNA asset_id',
    };
  }
  return null;
}

function parseRequestUrl(req) {
  const hostValues = [];
  for (let index = 0; index < req.rawHeaders.length; index += 2) {
    if (String(req.rawHeaders[index]).toLowerCase() === 'host') {
      hostValues.push(req.rawHeaders[index + 1]);
    }
  }
  if (hostValues.length !== 1) throw new Error('exactly one Host header is required');
  assertValidHostHeader(hostValues[0]);
  if (
    typeof req.url !== 'string' ||
    !req.url.startsWith('/') ||
    req.url.startsWith('//') ||
    req.url.includes('#')
  ) {
    throw new Error('request target must use origin-form');
  }
  const url = new URL(req.url, REQUEST_BASE_URL);
  if (url.origin !== REQUEST_BASE_URL || url.hash) {
    throw new Error('request target must use origin-form');
  }
  return url;
}

function assertValidHostHeader(host) {
  if (
    typeof host !== 'string' ||
    host.length === 0 ||
    host.endsWith(':') ||
    /[\u0000-\u0020\u007f\\]/.test(host)
  ) {
    throw new Error('Host header is invalid');
  }
  const parsed = new URL(`http://${host}`);
  if (
    !parsed.hostname ||
    parsed.username ||
    parsed.password ||
    parsed.pathname !== '/' ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error('Host header is invalid');
  }
}

function validAdminBearer(authorization, adminToken) {
  const configured = typeof adminToken === 'string' && adminToken.length > 0;
  const exactScheme = typeof authorization === 'string' && authorization.startsWith('Bearer ');
  const supplied = exactScheme ? authorization.slice(7) : '';
  const expected = configured ? adminToken : '';
  const suppliedBytes = Buffer.from(supplied, 'utf8');
  const expectedBytes = Buffer.from(expected, 'utf8');
  const sameLength = suppliedBytes.length === expectedBytes.length;
  const suppliedDigest = crypto.createHash('sha256').update(suppliedBytes).digest();
  const expectedDigest = crypto.createHash('sha256').update(expectedBytes).digest();
  const sameDigest = crypto.timingSafeEqual(suppliedDigest, expectedDigest);
  return configured && exactScheme && sameLength && sameDigest;
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
    // Node 18 does not reap keep-alive connections as part of close(). Close
    // only idle sockets after initiating graceful shutdown so active requests
    // may still complete while the public stop API remains deterministic.
    server.closeIdleConnections?.();
  });
}

module.exports = {
  makeRequestHandler,
  startServer,
  stopServer,
};
