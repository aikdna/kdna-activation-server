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
const MACHINE_A = 'a'.repeat(64);
const MACHINE_B = 'b'.repeat(64);

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
      machine_fingerprint: MACHINE_A,
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'active');
    assert.equal(body.domain, '@x/y');
    assert.equal(body.machine_fingerprint, MACHINE_A);
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
    const rec = store.create({ domain: '@x/y', license_key: 'KDNA-LIC-test' });
    const res = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: '@x/different-domain',
      license_key: 'KDNA-LIC-test',
      machine_fingerprint: MACHINE_A,
    });
    assert.equal(res.status, 404);
    const body = await res.json();
    assert.equal(body.error.code, 'INVALID_LICENSE_KEY');
    assert.equal(store.get(rec.license_id).machine_binding_digest, undefined);
  });
});

test('Story 24: /sync refreshes last_checked_at and returns a signed record', async () => {
  await withServer({}, async (ctx, dataDir, store) => {
    store.create({ domain: '@x/y', license_key: 'KDNA-LIC-test' });
    const activate = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: '@x/y',
      license_key: 'KDNA-LIC-test',
      machine_fingerprint: MACHINE_A,
    });
    assert.equal(activate.status, 200);
    const res = await httpJson(ctx, 'POST', '/entitlements/sync', {
      domain: '@x/y',
      license_key: 'KDNA-LIC-test',
      machine_fingerprint: MACHINE_A,
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
    const activate = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: '@x/y',
      license_key: 'KDNA-LIC-test',
      machine_fingerprint: MACHINE_A,
    });
    assert.equal(activate.status, 200);
    const qs = new URLSearchParams({
      domain: '@x/y',
      license_id: rec.license_id,
      machine_fingerprint: MACHINE_A,
    }).toString();
    const res = await httpJson(ctx, 'GET', '/entitlements/status?' + qs);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'active');
    assert.equal(body.domain, '@x/y');
    assert.equal(body.license_id, rec.license_id);
    assert.equal(body.license_key, undefined);
    assert.equal(body.machine_binding_digest, undefined);
    assert.equal(body.machine_fingerprint, undefined);
  });
});

test('machine-bound activation requires one canonical SHA-256 fingerprint', async () => {
  await withServer({}, async (ctx, dataDir, store) => {
    const rec = store.create({ domain: '@x/y', license_key: 'KDNA-LIC-bound' });

    const missing = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: '@x/y', license_key: 'KDNA-LIC-bound',
    });
    assert.equal(missing.status, 400);
    assert.equal((await missing.json()).error.code, 'MISSING_MACHINE_FINGERPRINT');

    for (const machine_fingerprint of [
      MACHINE_A.toUpperCase(),
      ` ${MACHINE_A}`,
      `${MACHINE_A} `,
      'ａ'.repeat(64),
      'a'.repeat(63),
      'a'.repeat(65),
      `sha256:${MACHINE_A}`,
      1234,
      {},
    ]) {
      const malformed = await httpJson(ctx, 'POST', '/entitlements/activate', {
        domain: '@x/y', license_key: 'KDNA-LIC-bound', machine_fingerprint,
      });
      assert.equal(malformed.status, 400, JSON.stringify(machine_fingerprint));
      const body = await malformed.json();
      assert.equal(body.error.code, 'INVALID_MACHINE_FINGERPRINT');
      assert.equal(JSON.stringify(body).includes('license_id'), false);
      assert.equal(JSON.stringify(body).includes('machine_binding_digest'), false);
    }

    const syncCannotCreateBinding = await httpJson(ctx, 'POST', '/entitlements/sync', {
      domain: rec.domain,
      license_key: rec.license_key,
      machine_fingerprint: MACHINE_A,
    });
    assert.equal(syncCannotCreateBinding.status, 403);
    assert.equal((await syncCannotCreateBinding.json()).error.code, 'MACHINE_MISMATCH');
    assert.equal(store.get(rec.license_id).machine_binding_digest, undefined);
  });
});

test('first activation stores only a keyed binding digest and is idempotent for that machine', async () => {
  await withServer({}, async (ctx, dataDir, store, keys) => {
    const rec = store.create({ domain: '@x/y', license_key: 'KDNA-LIC-private' });

    for (let attempt = 0; attempt < 2; attempt++) {
      const activate = await httpJson(ctx, 'POST', '/entitlements/activate', {
        domain: '@x/y',
        license_key: 'KDNA-LIC-private',
        machine_fingerprint: MACHINE_A,
      });
      assert.equal(activate.status, 200);
      const body = await activate.json();
      assert.equal(body.machine_fingerprint, MACHINE_A);
      assert.equal(body.machine_binding_digest, undefined);
      assert.equal(verifyEntitlementSignature(body, keys.publicPem).ok, true);
      assert.equal(verifyEntitlementSignature({
        ...body,
        machine_fingerprint: MACHINE_B,
      }, keys.publicPem).ok, false);
    }

    const stored = store.get(rec.license_id);
    assert.equal(stored.machine_fingerprint, undefined);
    assert.match(stored.machine_binding_digest, /^[0-9a-f]{64}$/);
    assert.notEqual(stored.machine_binding_digest, MACHINE_A);
    const disk = fs.readFileSync(path.join(dataDir, `${rec.license_id}.json`), 'utf8');
    assert.equal(disk.includes(MACHINE_A), false);

    const wrongMachine = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: '@x/y',
      license_key: 'KDNA-LIC-private',
      machine_fingerprint: MACHINE_B,
    });
    assert.equal(wrongMachine.status, 403);
    const denied = await wrongMachine.json();
    assert.equal(denied.error.code, 'MACHINE_MISMATCH');
    assert.deepEqual(Object.keys(denied), ['ok', 'error']);
    assert.equal(JSON.stringify(denied).includes(rec.license_id), false);
    assert.equal(store.get(rec.license_id).machine_binding_digest, stored.machine_binding_digest);
  });
});

test('simultaneous first activations bind exactly one machine and preserve the winner', async () => {
  await withServer({}, async (ctx, dataDir, store) => {
    const rec = store.create({ domain: '@x/race', license_key: 'KDNA-LIC-race' });
    const request = (machine_fingerprint) => httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: '@x/race', license_key: 'KDNA-LIC-race', machine_fingerprint,
    });

    const responses = await Promise.all([request(MACHINE_A), request(MACHINE_B)]);
    const statuses = responses.map((response) => response.status).sort();
    assert.deepEqual(statuses, [200, 403]);
    const bodies = await Promise.all(responses.map((response) => response.json()));
    const winner = bodies.find((body) => body.signature_base64).machine_fingerprint;
    const loser = winner === MACHINE_A ? MACHINE_B : MACHINE_A;

    const retryWinner = await request(winner);
    assert.equal(retryWinner.status, 200);
    const retryLoser = await request(loser);
    assert.equal(retryLoser.status, 403);
    assert.equal((await retryLoser.json()).error.code, 'MACHINE_MISMATCH');
    assert.equal(store.get(rec.license_id).machine_fingerprint, undefined);
  });
});

test('sync requires matching domain, secret key, optional id, and bound machine', async () => {
  await withServer({}, async (ctx, dataDir, store) => {
    const first = store.create({
      domain: '@x/first', license_key: 'KDNA-LIC-first', license_id: 'lic_first',
    });
    const second = store.create({
      domain: '@x/second', license_key: 'KDNA-LIC-second', license_id: 'lic_second',
      require_machine_binding: false,
    });
    const activate = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: first.domain,
      license_key: first.license_key,
      machine_fingerprint: MACHINE_A,
    });
    assert.equal(activate.status, 200);

    for (const [request, expectedStatus, expectedCode] of [
      [{ license_key: first.license_key, machine_fingerprint: MACHINE_A }, 400, 'MISSING_DOMAIN'],
      [{ domain: first.domain, license_id: first.license_id, machine_fingerprint: MACHINE_A }, 400, 'MISSING_LICENSE_KEY'],
      [{ domain: second.domain, license_key: first.license_key, machine_fingerprint: MACHINE_A }, 404, 'INVALID_LICENSE_KEY'],
      [{ domain: first.domain, license_key: first.license_key, license_id: second.license_id, machine_fingerprint: MACHINE_A }, 404, 'INVALID_LICENSE_KEY'],
      [{ domain: first.domain, license_key: first.license_key }, 400, 'MISSING_MACHINE_FINGERPRINT'],
      [{ domain: first.domain, license_key: first.license_key, machine_fingerprint: MACHINE_B }, 403, 'MACHINE_MISMATCH'],
    ]) {
      const response = await httpJson(ctx, 'POST', '/entitlements/sync', request);
      assert.equal(response.status, expectedStatus, JSON.stringify(request));
      const body = await response.json();
      assert.equal(body.error.code, expectedCode);
      assert.equal(JSON.stringify(body).includes(first.license_id), false);
      assert.equal(JSON.stringify(body).includes(first.license_key), false);
    }
  });
});

test('status fails closed for a missing or wrong bound machine without exposing the record', async () => {
  await withServer({}, async (ctx, dataDir, store) => {
    const rec = store.create({ domain: '@x/y', license_key: 'KDNA-LIC-status' });

    const beforeActivation = new URLSearchParams({
      domain: rec.domain, license_id: rec.license_id, machine_fingerprint: MACHINE_A,
    });
    const before = await httpJson(ctx, 'GET', `/entitlements/status?${beforeActivation}`);
    assert.equal(before.status, 404);
    const notFoundBody = await before.json();
    assert.equal(notFoundBody.error.code, 'NOT_FOUND');

    const activated = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: rec.domain,
      license_key: rec.license_key,
      machine_fingerprint: MACHINE_A,
    });
    assert.equal(activated.status, 200);

    for (const query of [
      { domain: rec.domain, license_id: rec.license_id },
      { domain: rec.domain, license_id: rec.license_id, machine_fingerprint: MACHINE_B },
      { domain: rec.domain, license_id: rec.license_id, machine_fingerprint: 'not-canonical' },
      { domain: rec.domain, license_id: 'lic_unknown', machine_fingerprint: MACHINE_A },
      { domain: rec.domain, license_id: '../../escape', machine_fingerprint: MACHINE_A },
    ]) {
      const response = await httpJson(
        ctx,
        'GET',
        `/entitlements/status?${new URLSearchParams(query)}`,
      );
      assert.equal(response.status, 404);
      const body = await response.json();
      assert.deepEqual(body, notFoundBody);
      assert.equal(JSON.stringify(body).includes(rec.license_id), false);
      assert.equal(JSON.stringify(body).includes(rec.license_key), false);
      assert.equal(JSON.stringify(body).includes('machine_binding_digest'), false);
    }
  });
});

test('unbound licenses keep no-binding activation, sync, and status semantics', async () => {
  await withServer({}, async (ctx, dataDir, store) => {
    const rec = store.create({
      domain: '@x/unbound',
      license_key: 'KDNA-LIC-unbound',
      require_machine_binding: false,
    });
    const activate = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: rec.domain,
      license_key: rec.license_key,
      machine_fingerprint: 'not-a-fingerprint',
    });
    assert.equal(activate.status, 200);
    assert.equal((await activate.json()).machine_fingerprint, undefined);

    const sync = await httpJson(ctx, 'POST', '/entitlements/sync', {
      domain: rec.domain, license_key: rec.license_key,
    });
    assert.equal(sync.status, 200);
    assert.equal((await sync.json()).machine_fingerprint, undefined);

    const status = await httpJson(
      ctx,
      'GET',
      `/entitlements/status?${new URLSearchParams({ domain: rec.domain, license_id: rec.license_id })}`,
    );
    assert.equal(status.status, 200);
    assert.equal(store.get(rec.license_id).machine_binding_digest, undefined);
  });
});

test('a legacy raw binding migrates only after an exact machine match', async () => {
  await withServer({}, async (ctx, dataDir, store) => {
    const rec = store.create({ domain: '@x/legacy', license_key: 'KDNA-LIC-legacy' });
    store.put({ ...rec, machine_fingerprint: MACHINE_A });

    const mismatch = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: rec.domain, license_key: rec.license_key, machine_fingerprint: MACHINE_B,
    });
    assert.equal(mismatch.status, 403);
    assert.equal(store.get(rec.license_id).machine_fingerprint, MACHINE_A);

    const matching = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: rec.domain, license_key: rec.license_key, machine_fingerprint: MACHINE_A,
    });
    assert.equal(matching.status, 200);
    const stored = store.get(rec.license_id);
    assert.equal(stored.machine_fingerprint, undefined);
    assert.match(stored.machine_binding_digest, /^[0-9a-f]{64}$/);
  });
});

test('a malformed legacy raw binding cannot be claimed by a new machine', async () => {
  await withServer({}, async (ctx, dataDir, store) => {
    const rec = store.create({ domain: '@x/legacy', license_key: 'KDNA-LIC-bad-legacy' });
    store.put({ ...rec, machine_fingerprint: 'legacy-device-name' });
    const response = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: rec.domain, license_key: rec.license_key, machine_fingerprint: MACHINE_A,
    });
    assert.equal(response.status, 403);
    assert.equal((await response.json()).error.code, 'MACHINE_MISMATCH');
    assert.equal(store.get(rec.license_id).machine_binding_digest, undefined);
  });
});

test('a legacy record with no binding flag inherits the fail-closed default', async () => {
  await withServer({}, async (ctx, dataDir, store) => {
    const rec = store.create({ domain: '@x/default', license_key: 'KDNA-LIC-default' });
    const legacy = { ...rec };
    delete legacy.require_machine_binding;
    store.put(legacy);

    const missing = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: rec.domain, license_key: rec.license_key,
    });
    assert.equal(missing.status, 400);
    assert.equal((await missing.json()).error.code, 'MISSING_MACHINE_FINGERPRINT');

    const activate = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: rec.domain, license_key: rec.license_key, machine_fingerprint: MACHINE_A,
    });
    assert.equal(activate.status, 200);
    const response = await activate.json();
    assert.equal(response.require_machine_binding, true);
    assert.equal(response.machine_fingerprint, MACHINE_A);
    assert.equal(store.get(rec.license_id).require_machine_binding, true);
  });
});

test('the keyed machine binding survives a clean server restart', async () => {
  const dataDir = makeDataDir();
  let first;
  let second;
  try {
    first = await startServer({ dataDir, port: 0 });
    const rec = first.store.create({
      domain: '@x/restart',
      license_key: 'KDNA-LIC-restart',
    });
    const activate = await httpJson(first, 'POST', '/entitlements/activate', {
      domain: rec.domain,
      license_key: rec.license_key,
      machine_fingerprint: MACHINE_A,
    });
    assert.equal(activate.status, 200);
    const beforeRestart = first.store.get(rec.license_id).machine_binding_digest;
    await stopServer(first.server);
    first = null;

    second = await startServer({ dataDir, port: 0 });
    const sync = await httpJson(second, 'POST', '/entitlements/sync', {
      domain: rec.domain,
      license_key: rec.license_key,
      machine_fingerprint: MACHINE_A,
    });
    assert.equal(sync.status, 200);
    assert.equal(second.store.get(rec.license_id).machine_binding_digest, beforeRestart);

    const wrongMachine = await httpJson(second, 'POST', '/entitlements/sync', {
      domain: rec.domain,
      license_key: rec.license_key,
      machine_fingerprint: MACHINE_B,
    });
    assert.equal(wrongMachine.status, 403);
  } finally {
    if (first) await stopServer(first.server);
    if (second) await stopServer(second.server);
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('Story 24: signed records verify against the server public key (Ed25519 round-trip)', async () => {
  await withServer({}, async (ctx, dataDir, store, keys) => {
    store.create({ domain: '@x/y', license_key: 'KDNA-LIC-test' });
    const res = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: '@x/y', license_key: 'KDNA-LIC-test', machine_fingerprint: MACHINE_A,
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
