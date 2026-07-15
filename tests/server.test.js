/**
 * server.test.js — kdna-activation-server tests (Story 24)
 *
 * Covers:
 *   1. /healthz returns 200
 *   2. /server/identity returns the server's Ed25519 public key
 *   3. /entitlements/activate returns a signed activation
 *      record for a valid (domain, license_key) pair
 *   4. /entitlements/activate rejects an unknown license_key
 *   5. /entitlements/activate rejects a license_key that
 *      does not match the requested domain
 *   6. /entitlements/sync refreshes last_checked_at and returns
 *      a signed record
 *   7. /activate and /sync reject expired licenses
 *   8. /entitlements/revoke requires the admin bearer token
 *   9. /entitlements/revoke with the admin token marks the
 *      license as revoked; subsequent activate returns 403
 *      LICENSE_REVOKED
 *  10. /entitlements/status returns public metadata without license_key
 *  11. Signed records verify against the server's public key
 *      (Ed25519 round-trip)
 *  12. Server does not call back to any KDNA Inc. URL during
 *      normal operation (no external network calls)
 *  13. CLI one-shot commands work: --create-license, --list,
 *      --revoke
 *
 * Run: node --test tests/
 */

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');

const { startServer, stopServer, makeStore, ensureKeyPair, verifyEntitlementSignature, publicKeyFingerprint } = require('../src/index');

const CLI = path.resolve(__dirname, '..', 'bin', 'kdna-activation-server.js');

function makeDataDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'kdna-s24-'));
}

async function withServer(opts, fn) {
  const dataDir = makeDataDir();
  const store = makeStore(dataDir);
  const keys = ensureKeyPair(dataDir);
  const ctx = await startServer({ dataDir, store, keys, port: 0, ...opts });
  try {
    return await fn(ctx, dataDir, store, keys);
  } finally {
    await stopServer(ctx.server);
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
}

function httpJson(ctx, method, path, body, headers) {
  return fetch(`http://127.0.0.1:${ctx.port}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(headers || {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
}

test('Story 24: /healthz returns 200 with server metadata', async () => {
  await withServer({}, async (ctx) => {
    const res = await httpJson(ctx, 'GET', '/healthz');
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.equal(body.server, '@aikdna/kdna-activation-server');
  });
});

test('Story 24: /server/identity returns the server public key', async () => {
  await withServer({}, async (ctx) => {
    const res = await httpJson(ctx, 'GET', '/server/identity');
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.match(body.public_key_pem, /-----BEGIN PUBLIC KEY-----/);
    assert.equal(body.algorithm, 'ed25519');
    assert.equal(body.public_key_fingerprint.length, 16);
    assert.equal(body.public_key_hex.length, 64);
  });
});

test('Story 24: /entitlements/activate returns a signed record for valid key', async () => {
  await withServer({}, async (ctx, dataDir, store) => {
    store.create({ domain: '@x/y', license_key: 'KDNA-LIC-test' });
    const res = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: '@x/y',
      license_key: 'KDNA-LIC-test',
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'active');
    assert.equal(body.domain, '@x/y');
    assert.match(body.signature_base64, /^[A-Za-z0-9+/=]+$/);
  });
});

test('Story 24: /activate rejects an unknown license_key with INVALID_LICENSE_KEY', async () => {
  await withServer({}, async (ctx) => {
    const res = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: '@x/y',
      license_key: 'KDNA-LIC-DOES-NOT-EXIST',
    });
    assert.equal(res.status, 404);
    const body = await res.json();
    assert.equal(body.error.code, 'INVALID_LICENSE_KEY');
  });
});

test('Story 24: /activate rejects a license_key that does not match the domain', async () => {
  await withServer({}, async (ctx, dataDir, store) => {
    store.create({ domain: '@x/y', license_key: 'KDNA-LIC-test' });
    const res = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: '@x/different-domain',
      license_key: 'KDNA-LIC-test',
    });
    assert.equal(res.status, 404);
    const body = await res.json();
    assert.equal(body.error.code, 'INVALID_LICENSE_KEY');
  });
});

test('Story 24: /sync refreshes last_checked_at and returns a signed record', async () => {
  await withServer({}, async (ctx, dataDir, store) => {
    store.create({ domain: '@x/y', license_key: 'KDNA-LIC-test' });
    const res = await httpJson(ctx, 'POST', '/entitlements/sync', {
      domain: '@x/y',
      license_key: 'KDNA-LIC-test',
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'active');
    assert.ok(body.last_checked_at, 'last_checked_at should be set after sync');
    assert.ok(body.offline_valid_until, 'offline_valid_until should be set after sync');
  });
});

test('Story 24: /activate and /sync reject expired licenses', async () => {
  await withServer({}, async (ctx, dataDir, store) => {
    const expired = store.create({
      domain: '@x/y',
      license_key: 'KDNA-LIC-expired',
      issued_at: '2026-01-01T00:00:00.000Z',
    });
    store.put({
      ...expired,
      expires_at: '2026-01-02T00:00:00.000Z',
    });

    const activate = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: '@x/y',
      license_key: 'KDNA-LIC-expired',
    });
    assert.equal(activate.status, 403);
    const activateBody = await activate.json();
    assert.equal(activateBody.error.code, 'LICENSE_EXPIRED');

    const sync = await httpJson(ctx, 'POST', '/entitlements/sync', {
      domain: '@x/y',
      license_key: 'KDNA-LIC-expired',
    });
    assert.equal(sync.status, 403);
    const syncBody = await sync.json();
    assert.equal(syncBody.error.code, 'LICENSE_EXPIRED');
  });
});

test('Story 24: /revoke without admin token returns 401 UNAUTHORIZED', async () => {
  await withServer({ adminToken: 'secret-admin-token' }, async (ctx, dataDir, store) => {
    store.create({ domain: '@x/y', license_key: 'KDNA-LIC-test' });
    const res = await httpJson(ctx, 'POST', '/entitlements/revoke', {
      license_id: '...', domain: '@x/y', reason: 'test',
    });
    assert.equal(res.status, 401);
  });
});

test('Story 24: /revoke with admin token marks license as revoked; activate returns 403', async () => {
  await withServer({ adminToken: 'secret-admin-token' }, async (ctx, dataDir, store) => {
    const rec = store.create({ domain: '@x/y', license_key: 'KDNA-LIC-test' });
    // Revoke
    const rev = await httpJson(ctx, 'POST', '/entitlements/revoke', {
      license_id: rec.license_id, domain: '@x/y', reason: 'payment_failed',
    }, { Authorization: 'Bearer secret-admin-token' });
    assert.equal(rev.status, 200);
    const revBody = await rev.json();
    assert.equal(revBody.ok, true);
    assert.equal(revBody.status, 'revoked');
    // Activate should now fail with LICENSE_REVOKED
    const act = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: '@x/y', license_key: 'KDNA-LIC-test',
    });
    assert.equal(act.status, 403);
    const actBody = await act.json();
    assert.equal(actBody.error.code, 'LICENSE_REVOKED');
  });
});

test('Story 24: /entitlements/status returns public metadata without license_key', async () => {
  await withServer({}, async (ctx, dataDir, store) => {
    const rec = store.create({ domain: '@x/y', license_key: 'KDNA-LIC-test' });
    const qs = new URLSearchParams({ domain: '@x/y', license_id: rec.license_id }).toString();
    const res = await httpJson(ctx, 'GET', '/entitlements/status?' + qs);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'active');
    assert.equal(body.domain, '@x/y');
    assert.equal(body.license_id, rec.license_id);
    assert.equal(body.license_key, undefined);
  });
});

test('Story 24: signed records verify against the server public key (Ed25519 round-trip)', async () => {
  await withServer({}, async (ctx, dataDir, store, keys) => {
    store.create({ domain: '@x/y', license_key: 'KDNA-LIC-test' });
    const res = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: '@x/y', license_key: 'KDNA-LIC-test',
    });
    const body = await res.json();
    const verify = verifyEntitlementSignature(body, keys.publicPem);
    assert.equal(verify.ok, true, `signature must verify: ${verify.reason}`);
    // Tamper with the record
    const tampered = { ...body, status: 'revoked' };
    const tamperedVerify = verifyEntitlementSignature(tampered, keys.publicPem);
    assert.equal(tamperedVerify.ok, false, 'tampered record must fail verification');
  });
});

test('Story 24: server does not make outbound network calls (no KDNA Inc. URL hardcoded)', async () => {
  // We can't easily prove a negative, but we can prove that the
  // server's source code contains no outbound URLs and the test
  // passes with no DNS / network access.
  await withServer({}, async (ctx) => {
    // The server should respond to /healthz without any outbound call.
    const t0 = Date.now();
    const res = await httpJson(ctx, 'GET', '/healthz');
    assert.equal(res.status, 200);
    const elapsed = Date.now() - t0;
    assert.ok(elapsed < 1000, `healthz took ${elapsed}ms — suspiciously slow for an isolated server`);
    // And the source must not contain any KDNA Inc. URL pattern.
    const src = fs.readFileSync(path.resolve(__dirname, '..', 'src', 'server.js'), 'utf8');
    assert.doesNotMatch(src, /aikdna\.com/);
    assert.doesNotMatch(src, /kdna\.dev/);
    assert.doesNotMatch(src, /license\.aikdna\.com/);
  });
});

test('Story 24: CLI --create-license creates a record, --list lists it, --revoke revokes it', async () => {
  const dataDir = makeDataDir();
  try {
    const create = spawnSync(process.execPath, [CLI,
      '--create-license',
      '{"domain":"@cli/test","license_key":"KDNA-LIC-cli","issued_to":"cli@example.com","ttl_days":30}',
      '--data-dir', dataDir,
    ], { encoding: 'utf8' });
    assert.equal(create.status, 0, `create failed: ${create.stderr}`);
    assert.match(create.stdout, /Created license:/);
    assert.match(create.stdout, /KDNA-LIC-cli/);

    const list = spawnSync(process.execPath, [CLI, '--list', '--data-dir', dataDir], { encoding: 'utf8' });
    assert.equal(list.status, 0);
    assert.match(list.stdout, /@cli\/test/);

    // Find the license_id from the create output
    const created = JSON.parse(create.stdout.split('Created license:\n  ')[1]);
    const revoke = spawnSync(process.execPath, [CLI,
      '--revoke', created.license_id,
      '--reason', 'CLI test',
      '--data-dir', dataDir,
    ], { encoding: 'utf8' });
    assert.equal(revoke.status, 0, `revoke failed: ${revoke.stderr}`);
    assert.match(revoke.stdout, /Revoked:/);
    assert.match(revoke.stdout, /CLI test/);
  } finally {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('removed generation-shaped routes return 404 without aliases', async () => {
  await withServer({}, async (ctx) => {
    for (const [method, route] of [
      ['GET', '/v1/server/identity'],
      ['POST', '/v1/entitlements/activate'],
      ['POST', '/v1/entitlements/sync'],
      ['GET', '/v1/entitlements/status'],
      ['POST', '/v1/entitlements/revoke'],
    ]) {
      const res = await httpJson(ctx, method, route, method === 'POST' ? {} : undefined);
      assert.equal(res.status, 404, `${method} ${route}`);
      assert.equal((await res.json()).error.code, 'NOT_FOUND');
    }
  });
});
