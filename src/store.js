/**
 * store.js — entitlement record storage (Story 24)
 *
 * Per docs/REMOTE_MODE.md and specs/kdna-entitlement-api.md,
 * the activation server stores entitlement records. The design
 * contract calls for SQLite ("zero external dependencies for the
 * simplest deployment path"). The 0.1.0 implementation uses a
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
 * Machine-bound server records persist a purpose-separated keyed digest in
 * `machine_binding_digest`; raw `machine_fingerprint` values are accepted only
 * as legacy migration input and are removed after an exact successful match.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const MACHINE_BINDING_DIGEST_RE = /^[0-9a-f]{64}$/;

const DEFAULT_DATA_DIR = path.join(
  process.env.HOME || process.env.USERPROFILE || '.',
  '.kdna',
  'activation-server',
);

function makeStore(dataDir) {
  if (!dataDir) dataDir = DEFAULT_DATA_DIR;
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });

  function recordPath(licenseId) {
    validateLicenseId(licenseId);
    const encoded = encodeLicenseId(licenseId);
    return path.join(dataDir, `record~${encoded}.json`);
  }

  function legacyRecordPath(licenseId) {
    validateLicenseId(licenseId);
    return path.join(dataDir, `${licenseId.replace(/[^A-Za-z0-9_\-]/g, '_')}.json`);
  }

  function recordFiles() {
    return fs
      .readdirSync(dataDir)
      .filter((file) => file.endsWith('.json'))
      .sort((left, right) => {
        const leftCanonical = left.startsWith('record~') ? 1 : 0;
        const rightCanonical = right.startsWith('record~') ? 1 : 0;
        return rightCanonical - leftCanonical || left.localeCompare(right);
      });
  }

  function readRecordFile(filePath) {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  }

  function get(licenseId) {
    const canonicalPath = recordPath(licenseId);
    if (fs.existsSync(canonicalPath)) {
      try {
        const rec = readRecordFile(canonicalPath);
        if (rec.license_id !== licenseId) {
          throw new Error('canonical record identifier does not match its storage key');
        }
        return rec;
      } catch (e) {
        throw new Error(`failed to read ${canonicalPath}: ${e.message}`);
      }
    }

    const legacyPath = legacyRecordPath(licenseId);
    if (!fs.existsSync(legacyPath)) return null;
    try {
      const rec = readRecordFile(legacyPath);
      // Legacy filenames were not one-to-one: ':' and '.' both became '_'.
      // A colliding file for another identifier is not an alias.
      if (rec.license_id !== licenseId) return null;
      return rec;
    } catch (e) {
      throw new Error(`failed to read ${legacyPath}: ${e.message}`);
    }
  }

  function getByKey(licenseKey) {
    // The store is keyed by license_id. The CLI sends both
    // domain + license_key. We index license_key by scanning
    // all records (acceptable for self-hosted single-creator
    // scale; a future version can use a secondary index).
    const files = recordFiles();
    const seen = new Set();
    for (const f of files) {
      try {
        const rec = readRecordFile(path.join(dataDir, f));
        if (!rec.license_id || seen.has(rec.license_id)) continue;
        seen.add(rec.license_id);
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
    const tmp = `${p}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
    try {
      fs.writeFileSync(tmp, JSON.stringify(record, null, 2) + '\n', {
        mode: 0o600,
        flag: 'wx',
      });
      fs.renameSync(tmp, p);
      fs.chmodSync(p, 0o600);
    } finally {
      fs.rmSync(tmp, { force: true });
    }

    // Successful writes migrate an exact legacy record to the collision-free
    // filename. Never delete a colliding legacy file whose content belongs to
    // another identifier.
    const legacyPath = legacyRecordPath(record.license_id);
    if (legacyPath !== p && fs.existsSync(legacyPath)) {
      try {
        if (readRecordFile(legacyPath).license_id === record.license_id) {
          fs.rmSync(legacyPath, { force: true });
        }
      } catch (_) {
        // Leave malformed legacy state for operator recovery; the canonical
        // record has already been written safely.
      }
    }
    return record;
  }

  function compareAndBindMachine(licenseId, {
    bindingDigest,
    allowInitialBinding = false,
    deriveLegacyDigest,
  } = {}) {
    if (!MACHINE_BINDING_DIGEST_RE.test(bindingDigest || '')) {
      throw new Error('bindingDigest must be exactly 64 lowercase hexadecimal characters');
    }

    // All reads, comparisons, and writes are synchronous and kept inside this
    // store operation. That gives one running server a compare-and-bind
    // critical section: two first activations cannot both succeed.
    const rec = get(licenseId);
    if (!rec) return { ok: false, reason: 'missing', record: null };
    if (rec.require_machine_binding === false) {
      return { ok: true, reason: 'disabled', record: rec };
    }

    const hasStoredDigest = Object.prototype.hasOwnProperty.call(
      rec,
      'machine_binding_digest',
    );
    const hasLegacyFingerprint = Object.prototype.hasOwnProperty.call(
      rec,
      'machine_fingerprint',
    );
    let storedDigest = hasStoredDigest ? rec.machine_binding_digest : null;

    if (hasStoredDigest && !MACHINE_BINDING_DIGEST_RE.test(storedDigest || '')) {
      return { ok: false, reason: 'invalid', record: rec };
    }

    if (!storedDigest && hasLegacyFingerprint) {
      storedDigest = typeof deriveLegacyDigest === 'function'
        ? deriveLegacyDigest(rec.machine_fingerprint)
        : null;
      if (!MACHINE_BINDING_DIGEST_RE.test(storedDigest || '')) {
        return { ok: false, reason: 'invalid', record: rec };
      }
    }

    if (storedDigest && !equalBindingDigests(storedDigest, bindingDigest)) {
      return { ok: false, reason: 'mismatch', record: rec };
    }
    if (!storedDigest && !allowInitialBinding) {
      return { ok: false, reason: 'not_bound', record: rec };
    }
    if (storedDigest && !hasLegacyFingerprint && rec.require_machine_binding === true) {
      return { ok: true, reason: 'matched', record: rec };
    }

    const bound = {
      ...rec,
      require_machine_binding: true,
      machine_binding_digest: bindingDigest,
    };
    delete bound.machine_fingerprint;
    return {
      ok: true,
      reason: storedDigest ? 'migrated' : 'bound',
      record: put(bound),
    };
  }

  function list() {
    const out = [];
    const files = recordFiles();
    const seen = new Set();
    for (const f of files) {
      try {
        const rec = readRecordFile(path.join(dataDir, f));
        if (!rec.license_id || seen.has(rec.license_id)) continue;
        seen.add(rec.license_id);
        out.push(rec);
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

  return {
    get,
    getByKey,
    put,
    list,
    create,
    revoke,
    updateSync,
    compareAndBindMachine,
    dataDir,
  };
}

function validateLicenseId(licenseId) {
  if (!licenseId || !/^[A-Za-z0-9_\-:.]{1,128}$/.test(licenseId)) {
    throw new Error(`invalid license_id: ${licenseId}`);
  }
}

function encodeLicenseId(licenseId) {
  const alphabet = '0123456789abcdefghijklmnopqrstuv';
  const bytes = Buffer.from(licenseId, 'ascii');
  let encoded = '';
  let accumulator = 0;
  let bitCount = 0;

  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bitCount += 8;
    while (bitCount >= 5) {
      bitCount -= 5;
      encoded += alphabet[(accumulator >>> bitCount) & 31];
      accumulator &= (1 << bitCount) - 1;
    }
  }
  if (bitCount > 0) encoded += alphabet[(accumulator << (5 - bitCount)) & 31];
  return encoded;
}

function equalBindingDigests(left, right) {
  if (!MACHINE_BINDING_DIGEST_RE.test(left || '') || !MACHINE_BINDING_DIGEST_RE.test(right || '')) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

module.exports = { makeStore, DEFAULT_DATA_DIR };
