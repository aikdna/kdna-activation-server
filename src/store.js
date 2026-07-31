/**
 * store.js — entitlement record storage
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
 * The activation server signs a public projection of this shape on /activate
 * and /sync. Request secrets and server-only binding digests remain internal.
 *
 * The store is the SOURCE OF TRUTH for entitlement state. The
 * CLI's local copy at ~/.kdna/licenses/<domain>.json is a
 * CLIENT cache, not the source of truth. If a client claims
 * "active" but the server says "revoked", the server wins.
 * Machine-bound server records persist a purpose-separated keyed digest in
 * `machine_binding_digest`; raw `machine_fingerprint` values are accepted only
 * as legacy migration input and are removed after an exact successful match.
 * License request secrets are persisted only as bounded scrypt verifiers.
 * Legacy plaintext records migrate atomically only after the supplied secret
 * succeeds; failed verification leaves the original bytes untouched.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { ASSET_ID_RE, isCanonicalAssetId } = require('./contract');

const MACHINE_BINDING_DIGEST_RE = /^[0-9a-f]{64}$/;
const CANONICAL_DOMAIN_RE = ASSET_ID_RE;
const LICENSE_SECRET_PROFILE = 'scrypt';
const LICENSE_SECRET_VERSION = '1';
const LICENSE_SECRET_MAX_BYTES = 4096;
const LICENSE_SECRET_SALT_BYTES = 16;
const LICENSE_SECRET_KEY_BYTES = 32;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const LICENSE_SECRET_SCRYPT = Object.freeze({
  N: 16384,
  r: 8,
  p: 1,
  maxmem: 64 * 1024 * 1024,
});

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

  function authoritativeRecords() {
    const records = [];
    const seen = new Set();
    for (const file of recordFiles()) {
      try {
        // Scanned files can only suggest an identifier. The record returned to
        // callers must be re-read through get(), which alone understands the
        // canonical path, exact legacy path, and fail-closed precedence rules.
        const candidate = readRecordFile(path.join(dataDir, file));
        if (!candidate.license_id || seen.has(candidate.license_id)) continue;
        const authoritative = get(candidate.license_id);
        if (!authoritative || seen.has(authoritative.license_id)) continue;
        seen.add(authoritative.license_id);
        records.push(authoritative);
      } catch (_) {
        // Malformed, misplaced, or internally inconsistent files are not
        // records. In particular, get() never downgrades a bad canonical file
        // to legacy content.
      }
    }
    return records;
  }

  function get(licenseId) {
    const canonicalPath = recordPath(licenseId);
    if (fs.existsSync(canonicalPath)) {
      try {
        const rec = readRecordFile(canonicalPath);
        return validateStoredRecord(rec, licenseId);
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
      return validateStoredRecord(rec, licenseId);
    } catch (e) {
      throw new Error(`failed to read ${legacyPath}: ${e.message}`);
    }
  }

  function getByKey(licenseKey, domain) {
    // The store is keyed by license_id. The CLI sends both
    // domain + license_key. We index license_key by scanning
    // all records (acceptable for self-hosted single-creator
    // scale; a future version can use a secondary index).
    if (typeof licenseKey !== 'string' || licenseKey.length === 0) return null;
    if (!isCanonicalDomain(domain)) return null;
    for (const rec of authoritativeRecords()) {
      if (rec.domain !== domain) continue;
      if (
        rec.license_secret_verifier &&
        verifyLicenseSecret(licenseKey, rec.license_secret_verifier)
      ) {
        return rec;
      }
      if (rec.license_key && equalSecrets(rec.license_key, licenseKey)) {
        const migrated = {
          ...rec,
          license_secret_verifier: createLicenseSecretVerifier(licenseKey),
        };
        delete migrated.license_key;
        return put(migrated, { expectedLegacySecret: licenseKey });
      }
    }
    return null;
  }

  function put(record, { expectedLegacySecret } = {}) {
    if (!record || !record.license_id) {
      throw new Error('record.license_id is required');
    }
    validateLicenseId(record.license_id);
    validateDomain(record.domain);
    if (Object.prototype.hasOwnProperty.call(record, 'license_key')) {
      throw new Error('plaintext license_key cannot be written to entitlement storage');
    }
    validateLicenseSecretVerifier(record.license_secret_verifier);
    const p = recordPath(record.license_id);
    const next = { ...record, updated_at: new Date().toISOString() };
    const tmp = `${p}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
    const lock = `${p}.lock`;
    let lockFd;
    try {
      lockFd = fs.openSync(lock, 'wx', 0o600);
      if (expectedLegacySecret !== undefined) {
        const current = get(record.license_id);
        if (
          !current ||
          current.domain !== record.domain ||
          typeof current.license_key !== 'string' ||
          !equalSecrets(current.license_key, expectedLegacySecret)
        ) {
          throw new Error('legacy license secret changed before migration');
        }
      }
      fs.writeFileSync(tmp, JSON.stringify(next, null, 2) + '\n', {
        mode: 0o600,
        flag: 'wx',
      });
      fs.renameSync(tmp, p);
      fs.chmodSync(p, 0o600);
    } finally {
      if (lockFd !== undefined) fs.closeSync(lockFd);
      fs.rmSync(tmp, { force: true });
      if (lockFd !== undefined) fs.rmSync(lock, { force: true });
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
    return next;
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
    return authoritativeRecords();
  }

  function create({ domain, license_key, license_id, issued_to, require_machine_binding, require_online_check, offline_grace_days, allowed_agents, ttl_days, issued_at }) {
    validateDomain(domain);
    validateLicenseSecret(license_key);
    if (!license_id) license_id = `lic_${crypto.randomBytes(8).toString('hex')}`;

    const record = {
      version: '1.0',
      license_id,
      license_secret_verifier: createLicenseSecretVerifier(license_key),
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
    const stored = put(record);
    Object.defineProperty(stored, 'license_key', {
      value: license_key,
      enumerable: false,
      configurable: false,
      writable: false,
    });
    return stored;
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

function isCanonicalDomain(domain) {
  return isCanonicalAssetId(domain);
}

function validateDomain(domain) {
  if (domain === undefined || domain === null || domain === '') {
    throw new Error('domain is required');
  }
  if (!isCanonicalDomain(domain)) {
    throw new Error('domain must be a canonical KDNA asset_id');
  }
  return domain;
}

function validateLicenseSecret(licenseKey) {
  if (licenseKey === undefined || licenseKey === null || licenseKey === '') {
    throw new Error('license_key is required');
  }
  if (typeof licenseKey !== 'string') {
    throw new Error('license_key must be a non-empty string');
  }
  const bytes = Buffer.byteLength(licenseKey, 'utf8');
  if (bytes > LICENSE_SECRET_MAX_BYTES) {
    throw new Error(`license_key exceeds ${LICENSE_SECRET_MAX_BYTES} UTF-8 bytes`);
  }
  return licenseKey;
}

function validateStoredRecord(record, expectedLicenseId) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    throw new Error('stored entitlement record must be a JSON object');
  }
  validateLicenseId(record.license_id);
  if (record.license_id !== expectedLicenseId) {
    throw new Error('canonical record identifier does not match its storage key');
  }
  validateDomain(record.domain);
  const hasPlaintext = Object.prototype.hasOwnProperty.call(record, 'license_key');
  const hasVerifier = Object.prototype.hasOwnProperty.call(record, 'license_secret_verifier');
  if (hasPlaintext === hasVerifier) {
    throw new Error('stored entitlement must contain exactly one license secret authority');
  }
  if (hasPlaintext) validateLicenseSecret(record.license_key);
  else validateLicenseSecretVerifier(record.license_secret_verifier);
  return record;
}

function createLicenseSecretVerifier(licenseKey, salt = crypto.randomBytes(LICENSE_SECRET_SALT_BYTES)) {
  validateLicenseSecret(licenseKey);
  if (!Buffer.isBuffer(salt) || salt.length !== LICENSE_SECRET_SALT_BYTES) {
    throw new Error('license secret verifier salt is invalid');
  }
  const secretBytes = Buffer.from(licenseKey, 'utf8');
  let derived;
  try {
    derived = crypto.scryptSync(
      secretBytes,
      salt,
      LICENSE_SECRET_KEY_BYTES,
      LICENSE_SECRET_SCRYPT,
    );
    return {
      profile: LICENSE_SECRET_PROFILE,
      version: LICENSE_SECRET_VERSION,
      salt: salt.toString('base64url'),
      derived_key: derived.toString('base64url'),
      parameters: {
        N: LICENSE_SECRET_SCRYPT.N,
        r: LICENSE_SECRET_SCRYPT.r,
        p: LICENSE_SECRET_SCRYPT.p,
        key_length: LICENSE_SECRET_KEY_BYTES,
      },
    };
  } finally {
    secretBytes.fill(0);
    if (derived) derived.fill(0);
  }
}

function validateLicenseSecretVerifier(verifier) {
  if (!verifier || typeof verifier !== 'object' || Array.isArray(verifier)) {
    throw new Error('license secret verifier is required');
  }
  if (
    verifier.profile !== LICENSE_SECRET_PROFILE ||
    verifier.version !== LICENSE_SECRET_VERSION ||
    verifier.parameters?.N !== LICENSE_SECRET_SCRYPT.N ||
    verifier.parameters?.r !== LICENSE_SECRET_SCRYPT.r ||
    verifier.parameters?.p !== LICENSE_SECRET_SCRYPT.p ||
    verifier.parameters?.key_length !== LICENSE_SECRET_KEY_BYTES
  ) {
    throw new Error('license secret verifier parameters are invalid');
  }
  if (
    typeof verifier.salt !== 'string' ||
    typeof verifier.derived_key !== 'string' ||
    !BASE64URL_RE.test(verifier.salt) ||
    !BASE64URL_RE.test(verifier.derived_key)
  ) {
    throw new Error('license secret verifier encoding is invalid');
  }
  let salt;
  let derived;
  try {
    salt = Buffer.from(verifier.salt, 'base64url');
    derived = Buffer.from(verifier.derived_key, 'base64url');
  } catch {
    throw new Error('license secret verifier encoding is invalid');
  }
  if (salt.length !== LICENSE_SECRET_SALT_BYTES || derived.length !== LICENSE_SECRET_KEY_BYTES) {
    throw new Error('license secret verifier length is invalid');
  }
  if (
    salt.toString('base64url') !== verifier.salt ||
    derived.toString('base64url') !== verifier.derived_key
  ) {
    throw new Error('license secret verifier encoding is not canonical');
  }
  return verifier;
}

function verifyLicenseSecret(licenseKey, verifier) {
  let secretBytes;
  let expected;
  let actual;
  try {
    validateLicenseSecret(licenseKey);
    validateLicenseSecretVerifier(verifier);
    const salt = Buffer.from(verifier.salt, 'base64url');
    expected = Buffer.from(verifier.derived_key, 'base64url');
    secretBytes = Buffer.from(licenseKey, 'utf8');
    actual = crypto.scryptSync(
      secretBytes,
      salt,
      verifier.parameters.key_length,
      LICENSE_SECRET_SCRYPT,
    );
    return crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  } finally {
    if (secretBytes) secretBytes.fill(0);
    if (expected) expected.fill(0);
    if (actual) actual.fill(0);
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

function equalSecrets(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const leftBytes = Buffer.from(left, 'utf8');
  const rightBytes = Buffer.from(right, 'utf8');
  const sameLength = leftBytes.length === rightBytes.length;
  const leftDigest = crypto.createHash('sha256').update(leftBytes).digest();
  const rightDigest = crypto.createHash('sha256').update(rightBytes).digest();
  const sameDigest = crypto.timingSafeEqual(leftDigest, rightDigest);
  return sameLength && sameDigest;
}

module.exports = {
  CANONICAL_DOMAIN_RE,
  DEFAULT_DATA_DIR,
  LICENSE_SECRET_MAX_BYTES,
  createLicenseSecretVerifier,
  encodeLicenseId,
  isCanonicalDomain,
  makeStore,
  validateDomain,
  verifyLicenseSecret,
};
