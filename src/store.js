/**
 * store.js — entitlement record storage (Story 24)
 *
 * Per docs/REMOTE_MODE.md and specs/kdna-entitlement-api.md,
 * the activation server stores entitlement records. The design
 * contract calls for SQLite ("zero external dependencies for the
 * simplest deployment path"). The v0.1.0 implementation uses a
 * single JSON file (one file per license_id) for the simplest
 * deployment path. A future version can swap in SQLite without
 * changing the public API.
 *
 * Each record has the shape documented in
 * specs/kdna-entitlement-api.md §10 (Local Activation File).
 * The activation server returns the same shape (plus optional
 * Ed25519 signature) on /activate and /sync endpoints.
 *
 * The store is the SOURCE OF TRUTH for entitlement state. The
 * CLI's local copy at ~/.kdna/licenses/<domain>.json is a
 * CLIENT cache, not the source of truth. If a client claims
 * "active" but the server says "revoked", the server wins.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const DEFAULT_DATA_DIR = path.join(
  process.env.HOME || process.env.USERPROFILE || '.',
  '.kdna',
  'activation-server',
);

function makeStore(dataDir) {
  if (!dataDir) dataDir = DEFAULT_DATA_DIR;
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });

  function recordPath(licenseId) {
    if (!licenseId || !/^[A-Za-z0-9_\-:.]{1,128}$/.test(licenseId)) {
      throw new Error(`invalid license_id: ${licenseId}`);
    }
    return path.join(dataDir, `${licenseId.replace(/[^A-Za-z0-9_\-]/g, '_')}.json`);
  }

  function get(licenseId) {
    const p = recordPath(licenseId);
    if (!fs.existsSync(p)) return null;
    try {
      return JSON.parse(fs.readFileSync(p, 'utf8'));
    } catch (e) {
      throw new Error(`failed to read ${p}: ${e.message}`);
    }
  }

  function getByKey(licenseKey) {
    // The store is keyed by license_id. The CLI sends both
    // domain + license_key. We index license_key by scanning
    // all records (acceptable for self-hosted single-creator
    // scale; a future version can use a secondary index).
    const files = fs.readdirSync(dataDir).filter((f) => f.endsWith('.json'));
    for (const f of files) {
      try {
        const rec = JSON.parse(fs.readFileSync(path.join(dataDir, f), 'utf8'));
        if (rec.license_key === licenseKey) return rec;
      } catch (_) {
        // ignore malformed files
      }
    }
    return null;
  }

  function put(record) {
    if (!record || !record.license_id) {
      throw new Error('record.license_id is required');
    }
    const p = recordPath(record.license_id);
    record.updated_at = new Date().toISOString();
    fs.writeFileSync(p, JSON.stringify(record, null, 2) + '\n', { mode: 0o600 });
    return record;
  }

  function list() {
    const out = [];
    const files = fs.readdirSync(dataDir).filter((f) => f.endsWith('.json'));
    for (const f of files) {
      try {
        out.push(JSON.parse(fs.readFileSync(path.join(dataDir, f), 'utf8')));
      } catch (_) {
        // ignore
      }
    }
    return out;
  }

  function create({ domain, license_key, license_id, issued_to, require_machine_binding, require_online_check, offline_grace_days, allowed_agents, ttl_days, issued_at }) {
    if (!domain) throw new Error('domain is required');
    if (!license_key) throw new Error('license_key is required');
    if (!license_id) license_id = `lic_${crypto.randomBytes(8).toString('hex')}`;

    const record = {
      version: '1.0',
      license_id,
      license_key,
      domain,
      issued_to: issued_to || null,
      issued_at: issued_at || new Date().toISOString(),
      expires_at: ttl_days
        ? new Date(Date.now() + ttl_days * 24 * 60 * 60 * 1000).toISOString()
        : null,
      status: 'active',
      revoked: false,
      revoked_at: null,
      revocation_reason: null,
      require_machine_binding: require_machine_binding !== false,
      require_online_check: require_online_check !== false,
      offline_grace_days: typeof offline_grace_days === 'number' ? offline_grace_days : 7,
      allowed_agents: Array.isArray(allowed_agents) ? allowed_agents : null,
    };
    return put(record);
  }

  function revoke(licenseId, { reason, revoked_by } = {}) {
    const rec = get(licenseId);
    if (!rec) return null;
    rec.status = 'revoked';
    rec.revoked = true;
    rec.revoked_at = new Date().toISOString();
    rec.revocation_reason = reason || null;
    rec.revoked_by = revoked_by || null;
    return put(rec);
  }

  function updateSync(licenseId) {
    const rec = get(licenseId);
    if (!rec) return null;
    rec.last_checked_at = new Date().toISOString();
    rec.offline_valid_until = new Date(
      Date.now() + (rec.offline_grace_days || 7) * 24 * 60 * 60 * 1000,
    ).toISOString();
    return put(rec);
  }

  return { get, getByKey, put, list, create, revoke, updateSync, dataDir };
}

module.exports = { makeStore, DEFAULT_DATA_DIR };
