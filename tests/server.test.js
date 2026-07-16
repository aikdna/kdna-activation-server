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
const net = require('node:net');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');

const { startServer, stopServer, makeStore, ensureKeyPair, verifyEntitlementSignature, publicKeyFingerprint } = require('../src/index');

const CLI = path.resolve(__dirname, '..', 'bin', 'kdna-activation-server.js');
const MACHINE_A = 'a'.repeat(64);
const MACHINE_B = 'b'.repeat(64);
const MAX_REQUEST_BODY_BYTES = 64 * 1024;

function makeDataDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'kdna-s24-'));
}

function recordJsonFiles(dataDir) {
  return fs.readdirSync(dataDir)
    .filter((name) => name.endsWith('.json'))
    .map((name) => path.join(dataDir, name));
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

function rawHttp(port, request) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port });
    const chunks = [];
    socket.setTimeout(5000, () => socket.destroy(new Error('raw HTTP request timed out')));
    socket.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
    socket.on('error', reject);
    socket.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    socket.on('connect', () => socket.end(request));
  });
}

test('Story 24: /healthz returns 200 with server metadata', async () => {
  await withServer({}, async (ctx) => {
    const res = await httpJson(ctx, 'GET', '/healthz');
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.equal(body.server, '@aikdna/kdna-activation-server');
    assert.equal(body.data_dir, undefined);
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
    store.create({ domain: 'kdna:x:y', license_key: 'KDNA-LIC-test' });
    const res = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: 'kdna:x:y',
      license_key: 'KDNA-LIC-test',
      machine_fingerprint: MACHINE_A,
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'active');
    assert.equal(body.domain, 'kdna:x:y');
    assert.equal(body.license_key, undefined);
    assert.doesNotMatch(JSON.stringify(body), /KDNA-LIC-test/);
    assert.equal(body.machine_fingerprint, MACHINE_A);
    assert.match(body.signature_base64, /^[A-Za-z0-9+/=]+$/);
  });
});

test('Story 24: /activate rejects an unknown license_key with INVALID_LICENSE_KEY', async () => {
  await withServer({}, async (ctx) => {
    const res = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: 'kdna:x:y',
      license_key: 'KDNA-LIC-DOES-NOT-EXIST',
    });
    assert.equal(res.status, 404);
    const body = await res.json();
    assert.equal(body.error.code, 'INVALID_LICENSE_KEY');
  });
});

test('Story 24: /activate rejects a license_key that does not match the domain', async () => {
  await withServer({}, async (ctx, dataDir, store) => {
    const rec = store.create({ domain: 'kdna:x:y', license_key: 'KDNA-LIC-test' });
    const res = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: 'kdna:x:different-domain',
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
    store.create({ domain: 'kdna:x:y', license_key: 'KDNA-LIC-test' });
    const activate = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: 'kdna:x:y',
      license_key: 'KDNA-LIC-test',
      machine_fingerprint: MACHINE_A,
    });
    assert.equal(activate.status, 200);
    const res = await httpJson(ctx, 'POST', '/entitlements/sync', {
      domain: 'kdna:x:y',
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
      domain: 'kdna:x:y',
      license_key: 'KDNA-LIC-expired',
      issued_at: '2026-01-01T00:00:00.000Z',
    });
    store.put({
      ...expired,
      expires_at: '2026-01-02T00:00:00.000Z',
    });

    const activate = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: 'kdna:x:y',
      license_key: 'KDNA-LIC-expired',
    });
    assert.equal(activate.status, 403);
    const activateBody = await activate.json();
    assert.equal(activateBody.error.code, 'LICENSE_EXPIRED');

    const sync = await httpJson(ctx, 'POST', '/entitlements/sync', {
      domain: 'kdna:x:y',
      license_key: 'KDNA-LIC-expired',
    });
    assert.equal(sync.status, 403);
    const syncBody = await sync.json();
    assert.equal(syncBody.error.code, 'LICENSE_EXPIRED');
  });
});

test('Story 24: /revoke without admin token returns 401 UNAUTHORIZED', async () => {
  await withServer({ adminToken: 'secret-admin-token' }, async (ctx, dataDir, store) => {
    store.create({ domain: 'kdna:x:y', license_key: 'KDNA-LIC-test' });
    const res = await httpJson(ctx, 'POST', '/entitlements/revoke', {
      license_id: '...', domain: 'kdna:x:y', reason: 'test',
    });
    assert.equal(res.status, 401);
  });
});

test('Story 24: /revoke with admin token marks license as revoked; activate returns 403', async () => {
  await withServer({ adminToken: 'secret-admin-token' }, async (ctx, dataDir, store) => {
    const rec = store.create({ domain: 'kdna:x:y', license_key: 'KDNA-LIC-test' });
    // Revoke
    const rev = await httpJson(ctx, 'POST', '/entitlements/revoke', {
      license_id: rec.license_id, domain: 'kdna:x:y', reason: 'payment_failed',
    }, { Authorization: 'Bearer secret-admin-token' });
    assert.equal(rev.status, 200);
    const revBody = await rev.json();
    assert.equal(revBody.ok, true);
    assert.equal(revBody.status, 'revoked');
    // Activate should now fail with LICENSE_REVOKED
    const act = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: 'kdna:x:y', license_key: 'KDNA-LIC-test',
    });
    assert.equal(act.status, 403);
    const actBody = await act.json();
    assert.equal(actBody.error.code, 'LICENSE_REVOKED');
  });
});

test('Story 24: /entitlements/status returns public metadata without license_key', async () => {
  await withServer({}, async (ctx, dataDir, store) => {
    const rec = store.create({ domain: 'kdna:x:y', license_key: 'KDNA-LIC-test' });
    const activate = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: 'kdna:x:y',
      license_key: 'KDNA-LIC-test',
      machine_fingerprint: MACHINE_A,
    });
    assert.equal(activate.status, 200);
    const qs = new URLSearchParams({
      domain: 'kdna:x:y',
      license_id: rec.license_id,
      machine_fingerprint: MACHINE_A,
    }).toString();
    const res = await httpJson(ctx, 'GET', '/entitlements/status?' + qs);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, 'active');
    assert.equal(body.domain, 'kdna:x:y');
    assert.equal(body.license_id, rec.license_id);
    assert.equal(body.license_key, undefined);
    assert.equal(body.machine_binding_digest, undefined);
    assert.equal(body.machine_fingerprint, undefined);
  });
});

test('machine-bound activation requires one canonical SHA-256 fingerprint', async () => {
  await withServer({}, async (ctx, dataDir, store) => {
    const rec = store.create({ domain: 'kdna:x:y', license_key: 'KDNA-LIC-bound' });

    const missing = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: 'kdna:x:y', license_key: 'KDNA-LIC-bound',
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
        domain: 'kdna:x:y', license_key: 'KDNA-LIC-bound', machine_fingerprint,
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
    const rec = store.create({ domain: 'kdna:x:y', license_key: 'KDNA-LIC-private' });

    for (let attempt = 0; attempt < 2; attempt++) {
      const activate = await httpJson(ctx, 'POST', '/entitlements/activate', {
        domain: 'kdna:x:y',
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
    const disk = recordJsonFiles(dataDir)
      .map((file) => fs.readFileSync(file, 'utf8'))
      .join('\n');
    assert.equal(disk.includes(MACHINE_A), false);

    const wrongMachine = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: 'kdna:x:y',
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
    const rec = store.create({ domain: 'kdna:x:race', license_key: 'KDNA-LIC-race' });
    const request = (machine_fingerprint) => httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: 'kdna:x:race', license_key: 'KDNA-LIC-race', machine_fingerprint,
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
      domain: 'kdna:x:first', license_key: 'KDNA-LIC-first', license_id: 'lic_first',
    });
    const second = store.create({
      domain: 'kdna:x:second', license_key: 'KDNA-LIC-second', license_id: 'lic_second',
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
    const rec = store.create({ domain: 'kdna:x:y', license_key: 'KDNA-LIC-status' });

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
      { license_id: rec.license_id, machine_fingerprint: MACHINE_A },
      { domain: rec.domain, machine_fingerprint: MACHINE_A },
      { domain: rec.domain, license_key: rec.license_key, machine_fingerprint: MACHINE_A },
      { domain: rec.domain, license_id: rec.license_id, license_key: rec.license_key, machine_fingerprint: MACHINE_A },
      { domain: rec.domain, license_id: rec.license_id },
      { domain: rec.domain, license_id: rec.license_id, machine_fingerprint: MACHINE_B },
      { domain: rec.domain, license_id: rec.license_id, machine_fingerprint: 'not-canonical' },
      { domain: '@X/y', license_id: rec.license_id, machine_fingerprint: MACHINE_A },
      { domain: 'kdna:x:wrong', license_id: rec.license_id, machine_fingerprint: MACHINE_A },
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

    for (const query of [
      `domain=${encodeURIComponent(rec.domain)}&domain=${encodeURIComponent(rec.domain)}&license_id=${encodeURIComponent(rec.license_id)}&machine_fingerprint=${MACHINE_A}`,
      `domain=${encodeURIComponent(rec.domain)}&license_id=${encodeURIComponent(rec.license_id)}&license_id=${encodeURIComponent(rec.license_id)}&machine_fingerprint=${MACHINE_A}`,
      `domain=${encodeURIComponent(rec.domain)}&license_id=${encodeURIComponent(rec.license_id)}&machine_fingerprint=${MACHINE_A}&machine_fingerprint=${MACHINE_A}`,
    ]) {
      const response = await httpJson(ctx, 'GET', `/entitlements/status?${query}`);
      assert.equal(response.status, 404);
      assert.deepEqual(await response.json(), notFoundBody);
    }
  });
});

test('unbound licenses keep no-binding activation, sync, and status semantics', async () => {
  await withServer({}, async (ctx, dataDir, store) => {
    const rec = store.create({
      domain: 'kdna:x:unbound',
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
    const rec = store.create({ domain: 'kdna:x:legacy', license_key: 'KDNA-LIC-legacy' });
    for (const file of recordJsonFiles(dataDir)) fs.rmSync(file);
    const legacyPath = path.join(
      dataDir,
      `${rec.license_id.replace(/[^A-Za-z0-9_\-]/g, '_')}.json`,
    );
    fs.writeFileSync(
      legacyPath,
      JSON.stringify({ ...rec, machine_fingerprint: MACHINE_A }, null, 2) + '\n',
      { mode: 0o600 },
    );

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
    assert.equal(fs.existsSync(legacyPath), false);
    assert.equal(recordJsonFiles(dataDir).length, 1);
  });
});

test('license identifiers have collision-free storage and exact lookup semantics', async () => {
  await withServer({}, async (ctx, dataDir, store) => {
    const colon = store.create({
      domain: 'kdna:x:colon',
      license_key: 'KDNA-LIC-colon',
      license_id: 'lic:alias',
    });
    const legacyCollisionPath = path.join(dataDir, 'lic_alias.json');
    fs.renameSync(recordJsonFiles(dataDir)[0], legacyCollisionPath);
    const dot = store.create({
      domain: 'kdna:x:dot',
      license_key: 'KDNA-LIC-dot',
      license_id: 'lic.alias',
      require_machine_binding: false,
    });
    const upper = store.create({
      domain: 'kdna:x:upper',
      license_key: 'KDNA-LIC-upper',
      license_id: 'LIC:ALIAS',
      require_machine_binding: false,
    });
    assert.equal(recordJsonFiles(dataDir).length, 3);
    assert.equal(store.get(colon.license_id).license_key, colon.license_key);
    assert.equal(store.get(dot.license_id).license_key, dot.license_key);
    assert.equal(store.get(upper.license_id).license_key, upper.license_key);
    assert.deepEqual(store.list().map((record) => record.license_id).sort(), [
      'LIC:ALIAS',
      'lic.alias',
      'lic:alias',
    ]);
    assert.equal(fs.existsSync(legacyCollisionPath), true);

    const activate = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: colon.domain,
      license_key: colon.license_key,
      machine_fingerprint: MACHINE_A,
    });
    assert.equal(activate.status, 200);
    assert.equal(fs.existsSync(legacyCollisionPath), false);
    assert.equal(recordJsonFiles(dataDir).length, 3);

    const wrongStatus = await httpJson(
      ctx,
      'GET',
      `/entitlements/status?${new URLSearchParams({
        domain: colon.domain,
        license_id: dot.license_id,
        machine_fingerprint: MACHINE_A,
      })}`,
    );
    assert.equal(wrongStatus.status, 404);
    assert.equal((await wrongStatus.json()).error.code, 'NOT_FOUND');

    const wrongSync = await httpJson(ctx, 'POST', '/entitlements/sync', {
      domain: colon.domain,
      license_key: colon.license_key,
      license_id: dot.license_id,
      machine_fingerprint: MACHINE_A,
    });
    assert.equal(wrongSync.status, 404);
    assert.equal((await wrongSync.json()).error.code, 'INVALID_LICENSE_KEY');
  });
});

test('canonical records are authoritative and never fall back after corruption', () => {
  const dataDir = makeDataDir();
  try {
    const store = makeStore(dataDir);
    const rec = store.create({
      domain: 'kdna:x:canonical',
      license_key: 'KDNA-LIC-canonical',
      license_id: 'lic_canonical',
    });
    const canonicalPath = recordJsonFiles(dataDir)[0];
    const legacyPath = path.join(dataDir, `${rec.license_id}.json`);
    fs.writeFileSync(
      legacyPath,
      JSON.stringify({ ...rec, license_key: 'KDNA-LIC-stale' }, null, 2) + '\n',
      { mode: 0o600 },
    );

    assert.equal(store.get(rec.license_id).license_key, rec.license_key);
    assert.equal(store.getByKey('KDNA-LIC-stale', rec.domain), null);
    assert.equal(store.list().length, 1);
    assert.equal(store.list()[0].license_key, rec.license_key);

    fs.writeFileSync(
      canonicalPath,
      JSON.stringify({ ...rec, license_id: 'lic_other' }, null, 2) + '\n',
      { mode: 0o600 },
    );
    assert.throws(
      () => store.get(rec.license_id),
      /canonical record identifier does not match its storage key/,
    );
    assert.equal(store.getByKey(rec.license_key, rec.domain), null);
    assert.deepEqual(store.list(), []);
  } finally {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('misplaced JSON is never an entitlement authority, including for unbound licenses', async () => {
  await withServer({}, async (ctx, dataDir, store) => {
    const rec = store.create({
      domain: 'kdna:x:misplaced',
      license_key: 'KDNA-LIC-misplaced',
      license_id: 'lic_misplaced',
      require_machine_binding: false,
    });
    const authoritative = JSON.parse(fs.readFileSync(recordJsonFiles(dataDir)[0], 'utf8'));
    for (const file of recordJsonFiles(dataDir)) fs.rmSync(file);
    fs.writeFileSync(
      path.join(dataDir, 'arbitrary.json'),
      JSON.stringify(authoritative, null, 2) + '\n',
      { mode: 0o600 },
    );

    assert.equal(store.get(rec.license_id), null);
    assert.equal(store.getByKey(rec.license_key, rec.domain), null);
    assert.deepEqual(store.list(), []);

    const activate = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: rec.domain,
      license_key: rec.license_key,
    });
    assert.equal(activate.status, 404);
    assert.equal((await activate.json()).error.code, 'INVALID_LICENSE_KEY');

    const sync = await httpJson(ctx, 'POST', '/entitlements/sync', {
      domain: rec.domain,
      license_key: rec.license_key,
    });
    assert.equal(sync.status, 404);
    assert.equal((await sync.json()).error.code, 'INVALID_LICENSE_KEY');
  });
});

test('malformed canonical state cannot downgrade to an exact legacy record', async () => {
  await withServer({}, async (ctx, dataDir, store) => {
    const rec = store.create({
      domain: 'kdna:x:no-downgrade',
      license_key: 'KDNA-LIC-no-downgrade',
      license_id: 'lic_no_downgrade',
      require_machine_binding: false,
    });
    const canonicalPath = recordJsonFiles(dataDir)[0];
    const legacyPath = path.join(dataDir, `${rec.license_id}.json`);
    fs.writeFileSync(legacyPath, JSON.stringify(rec, null, 2) + '\n', { mode: 0o600 });
    fs.writeFileSync(canonicalPath, '{ malformed', { mode: 0o600 });

    assert.throws(() => store.get(rec.license_id), /failed to read/);
    assert.equal(store.getByKey(rec.license_key, rec.domain), null);
    assert.deepEqual(store.list(), []);

    const activate = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: rec.domain,
      license_key: rec.license_key,
    });
    assert.equal(activate.status, 404);
    assert.equal((await activate.json()).error.code, 'INVALID_LICENSE_KEY');

    const sync = await httpJson(ctx, 'POST', '/entitlements/sync', {
      domain: rec.domain,
      license_key: rec.license_key,
    });
    assert.equal(sync.status, 404);
    assert.equal((await sync.json()).error.code, 'INVALID_LICENSE_KEY');
  });
});

test('a malformed legacy raw binding cannot be claimed by a new machine', async () => {
  await withServer({}, async (ctx, dataDir, store) => {
    const rec = store.create({ domain: 'kdna:x:legacy', license_key: 'KDNA-LIC-bad-legacy' });
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
    const rec = store.create({ domain: 'kdna:x:default', license_key: 'KDNA-LIC-default' });
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
      domain: 'kdna:x:restart',
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
    store.create({ domain: 'kdna:x:y', license_key: 'KDNA-LIC-test' });
    const res = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: 'kdna:x:y', license_key: 'KDNA-LIC-test', machine_fingerprint: MACHINE_A,
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

test('domain is one canonical Core asset identity across storage and every HTTP operation', async () => {
  await withServer({ adminToken: 'admin-secret' }, async (ctx, dataDir, store) => {
    for (const domain of [
      'kdna:creator:asset',
      'KDNA:Creator_1:asset.name-2',
      'a_b:c.d-e',
    ]) {
      const rec = store.create({
        domain,
        license_key: `secret-${domain}`,
        require_machine_binding: false,
      });
      assert.equal(store.get(rec.license_id).domain, domain);
      assert.equal(store.getByKey(rec.license_key, domain).license_id, rec.license_id);
    }

    const invalidDomains = [
      '@scope/name',
      'kdna',
      '1kdna:asset',
      'kdna:',
      'kdna:asset/name',
      'kdna:asset name',
      '知识:资产',
      42,
      {},
    ];
    for (const domain of invalidDomains) {
      assert.throws(
        () => store.create({ domain, license_key: 'secret-invalid-domain' }),
        /canonical KDNA asset_id/,
        JSON.stringify(domain),
      );
      assert.throws(
        () => store.put({
          license_id: 'lic_invalid_domain',
          domain,
          license_key: 'secret-invalid-domain',
        }),
        /canonical KDNA asset_id/,
        JSON.stringify(domain),
      );

      for (const [pathName, body, headers] of [
        [
          '/entitlements/activate',
          { domain, license_key: 'secret-invalid-domain' },
          undefined,
        ],
        [
          '/entitlements/sync',
          { domain, license_key: 'secret-invalid-domain' },
          undefined,
        ],
        [
          '/entitlements/revoke',
          { domain, license_id: 'lic_unknown' },
          { Authorization: 'Bearer admin-secret' },
        ],
      ]) {
        const response = await httpJson(ctx, 'POST', pathName, body, headers);
        assert.equal(response.status, 400, `${pathName} ${JSON.stringify(domain)}`);
        const responseBody = await response.json();
        assert.equal(responseBody.error.code, 'INVALID_DOMAIN');
        assert.doesNotMatch(JSON.stringify(responseBody), /secret-invalid-domain|@scope\/name/);
      }

      const status = await httpJson(
        ctx,
        'GET',
        `/entitlements/status?${new URLSearchParams({
          domain: String(domain),
          license_id: 'lic_unknown',
        })}`,
      );
      assert.equal(status.status, 404);
      assert.deepEqual(await status.json(), {
        ok: false,
        error: { code: 'NOT_FOUND', message: 'no entitlement matches', retryable: false },
      });
    }

    for (const [pathName, body, headers] of [
      ['/entitlements/activate', { license_key: 'secret-missing-domain' }, undefined],
      ['/entitlements/sync', { license_key: 'secret-missing-domain' }, undefined],
      [
        '/entitlements/revoke',
        { license_id: 'lic_unknown' },
        { Authorization: 'Bearer admin-secret' },
      ],
    ]) {
      const response = await httpJson(ctx, 'POST', pathName, body, headers);
      assert.equal(response.status, 400);
      const responseBody = await response.json();
      assert.equal(responseBody.error.code, 'MISSING_DOMAIN');
      assert.doesNotMatch(JSON.stringify(responseBody), /secret-missing-domain/);
    }

    for (const license_key of [42, {}, [], true]) {
      assert.throws(
        () => store.create({ domain: 'kdna:invalid:secret', license_key }),
        /non-empty string/,
      );
      assert.throws(
        () => store.put({
          license_id: 'lic_invalid_secret',
          domain: 'kdna:invalid:secret',
          license_key,
        }),
        /non-empty string/,
      );
    }

    const legacy = store.create({
      domain: 'kdna:legacy:asset',
      license_key: 'secret-legacy-domain',
      license_id: 'lic_legacy_domain',
      require_machine_binding: false,
    });
    const legacyPath = recordJsonFiles(dataDir)
      .find((file) => JSON.parse(fs.readFileSync(file, 'utf8')).license_id === legacy.license_id);
    fs.writeFileSync(
      legacyPath,
      JSON.stringify({ ...legacy, domain: '@legacy/asset' }, null, 2) + '\n',
      { mode: 0o600 },
    );
    assert.throws(() => store.get(legacy.license_id), /canonical KDNA asset_id/);
    assert.equal(store.getByKey(legacy.license_key, 'kdna:legacy:asset'), null);
    assert.equal(store.list().some((record) => record.license_id === legacy.license_id), false);
  });
});

test('license secrets stay request-only across signed records, errors, routes, and command examples', async () => {
  const licenseSecret = 'request-only-secret-7f48';
  await withServer({}, async (ctx, dataDir, store, keys) => {
    const rec = store.create({
      domain: 'kdna:privacy:asset',
      license_key: licenseSecret,
      require_machine_binding: false,
    });
    for (const route of ['/entitlements/activate', '/entitlements/sync']) {
      const response = await httpJson(ctx, 'POST', route, {
        domain: rec.domain,
        license_key: licenseSecret,
      });
      assert.equal(response.status, 200);
      const body = await response.json();
      assert.equal(body.license_key, undefined);
      assert.doesNotMatch(JSON.stringify(body), new RegExp(licenseSecret));
      assert.equal(verifyEntitlementSignature(body, keys.publicPem).ok, true);
    }

    const unknown = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: rec.domain,
      license_key: `${licenseSecret}-unknown`,
    });
    assert.equal(unknown.status, 404);
    assert.doesNotMatch(await unknown.text(), new RegExp(licenseSecret));

    const reflectedRoute = await httpJson(
      ctx,
      'GET',
      `/not-found/${encodeURIComponent(licenseSecret)}`,
    );
    assert.equal(reflectedRoute.status, 404);
    assert.doesNotMatch(await reflectedRoute.text(), new RegExp(licenseSecret));
  });

  const readme = fs.readFileSync(path.resolve(__dirname, '..', 'README.md'), 'utf8');
  const cli = fs.readFileSync(CLI, 'utf8');
  assert.doesNotMatch(readme, /KDNA-LIC-|echoes it\s+back/);
  assert.doesNotMatch(cli, /KDNA-LIC-/);
});

test('admin bearer comparison is exact and record absence is not exposed by revoke errors', async () => {
  const adminToken = 'admin-secret-exact';
  await withServer({ adminToken }, async (ctx, dataDir, store) => {
    const rec = store.create({
      domain: 'kdna:admin:asset',
      license_key: 'request-secret-admin',
      require_machine_binding: false,
    });
    let unauthorizedBody;
    for (const authorization of [
      undefined,
      `bearer ${adminToken}`,
      `Bearer ${adminToken} x`,
      `Bearer ${adminToken.slice(0, -1)}`,
      `Bearer x${adminToken}`,
    ]) {
      const headers = authorization ? { Authorization: authorization } : undefined;
      const response = await httpJson(ctx, 'POST', '/entitlements/revoke', {
        license_id: rec.license_id,
        domain: rec.domain,
      }, headers);
      assert.equal(response.status, 401, String(authorization));
      const body = await response.json();
      unauthorizedBody ||= body;
      assert.deepEqual(body, unauthorizedBody);
      assert.doesNotMatch(JSON.stringify(body), new RegExp(`${rec.license_id}|${adminToken}`));
    }

    const wrongDomain = await httpJson(ctx, 'POST', '/entitlements/revoke', {
      license_id: rec.license_id,
      domain: 'kdna:admin:other',
    }, { Authorization: `Bearer ${adminToken}` });
    const unknownId = await httpJson(ctx, 'POST', '/entitlements/revoke', {
      license_id: 'lic_unknown',
      domain: rec.domain,
    }, { Authorization: `Bearer ${adminToken}` });
    assert.equal(wrongDomain.status, 404);
    assert.equal(unknownId.status, 404);
    assert.deepEqual(await wrongDomain.json(), await unknownId.json());

    const exact = await httpJson(ctx, 'POST', '/entitlements/revoke', {
      license_id: rec.license_id,
      domain: rec.domain,
      reason: 'operator request',
    }, { Authorization: `Bearer ${adminToken}` });
    assert.equal(exact.status, 200);
  });

  const source = fs.readFileSync(path.resolve(__dirname, '..', 'src', 'server.js'), 'utf8');
  assert.match(source, /timingSafeEqual/);
  assert.doesNotMatch(source, /auth\.slice\(7\)\s*!==\s*adminToken/);
});

test('origin-form routing rejects malformed targets and hostile Host components', async () => {
  await withServer({}, async (ctx) => {
    const hostileRequests = [
      'GET /healthz HTTP/1.1\r\nHost: [invalid\r\nConnection: close\r\n\r\n',
      'GET http://attacker.invalid/healthz HTTP/1.1\r\nHost: safe.invalid\r\nConnection: close\r\n\r\n',
      'GET //attacker.invalid/healthz HTTP/1.1\r\nHost: safe.invalid\r\nConnection: close\r\n\r\n',
      'GET /healthz#fragment HTTP/1.1\r\nHost: safe.invalid\r\nConnection: close\r\n\r\n',
      'GET /healthz HTTP/1.1\r\nHost: user@safe.invalid\r\nConnection: close\r\n\r\n',
      'GET /healthz HTTP/1.1\r\nHost: safe.invalid/path\r\nConnection: close\r\n\r\n',
      'GET /healthz HTTP/1.1\r\nHost: safe.invalid?query\r\nConnection: close\r\n\r\n',
      'GET /healthz HTTP/1.1\r\nHost: safe.invalid#fragment\r\nConnection: close\r\n\r\n',
      'GET /healthz HTTP/1.1\r\nHost: safe.invalid\r\nHost: duplicate.invalid\r\nConnection: close\r\n\r\n',
    ];
    for (const request of hostileRequests) {
      const response = await rawHttp(ctx.port, request);
      assert.match(response, /^HTTP\/1\.1 400 /, request);
      if (response.includes('{')) assert.match(response, /INVALID_REQUEST_TARGET/);
    }

    const hostIndependent = await rawHttp(
      ctx.port,
      'GET /healthz HTTP/1.1\r\nHost: attacker.invalid:80\r\nConnection: close\r\n\r\n',
    );
    assert.match(hostIndependent, /^HTTP\/1\.1 200 /);
    assert.match(hostIndependent, /@aikdna\/kdna-activation-server/);
    assert.equal((await httpJson(ctx, 'GET', '/healthz')).status, 200);
  });
});

test('JSON body handling enforces raw-byte limits, fatal UTF-8, and one stable response', async () => {
  await withServer({}, async (ctx, dataDir, store) => {
    const rec = store.create({
      domain: 'kdna:body:boundary',
      license_key: 'request-secret-boundary',
      require_machine_binding: false,
    });
    const base = {
      domain: rec.domain,
      license_key: rec.license_key,
      padding: '',
    };
    const baseBytes = Buffer.byteLength(JSON.stringify(base), 'utf8');
    base.padding = 'x'.repeat(MAX_REQUEST_BODY_BYTES - baseBytes);
    const exactBody = JSON.stringify(base);
    assert.equal(Buffer.byteLength(exactBody, 'utf8'), MAX_REQUEST_BODY_BYTES);
    const exact = await fetch(`http://127.0.0.1:${ctx.port}/entitlements/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: exactBody,
    });
    assert.equal(exact.status, 200);
    assert.doesNotMatch(await exact.text(), /request-secret-boundary/);

    const multibyteBody = JSON.stringify({
      domain: rec.domain,
      license_key: rec.license_key,
      padding: '界'.repeat(Math.ceil(MAX_REQUEST_BODY_BYTES / 3)),
    });
    assert.ok(multibyteBody.length < MAX_REQUEST_BODY_BYTES);
    assert.ok(Buffer.byteLength(multibyteBody, 'utf8') > MAX_REQUEST_BODY_BYTES);
    const multibyte = await fetch(`http://127.0.0.1:${ctx.port}/entitlements/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: multibyteBody,
    });
    assert.equal(multibyte.status, 413);
    const multibyteResponse = await multibyte.text();
    assert.equal((multibyteResponse.match(/REQUEST_TOO_LARGE/g) || []).length, 1);

    const oversizedBytes = Buffer.alloc(MAX_REQUEST_BODY_BYTES + 1, 0x78);
    const oversizedRequest = Buffer.concat([
      Buffer.from(
        `POST /entitlements/activate HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: ${oversizedBytes.length}\r\nConnection: close\r\n\r\n`,
      ),
      oversizedBytes,
    ]);
    const oversized = await rawHttp(ctx.port, oversizedRequest);
    assert.match(oversized, /^HTTP\/1\.1 413 /);
    assert.equal((oversized.match(/HTTP\/1\.1/g) || []).length, 1);
    assert.equal((oversized.match(/REQUEST_TOO_LARGE/g) || []).length, 1);

    const invalidUtf8 = await rawHttp(
      ctx.port,
      Buffer.concat([
        Buffer.from(
          'POST /entitlements/activate HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 1\r\nConnection: close\r\n\r\n',
        ),
        Buffer.from([0xc3]),
      ]),
    );
    assert.match(invalidUtf8, /^HTTP\/1\.1 400 /);
    assert.equal((invalidUtf8.match(/INVALID_JSON/g) || []).length, 1);
    assert.doesNotMatch(invalidUtf8, /decoder|offset|position|fatal|encoded data/i);

    const malformed = await fetch(`http://127.0.0.1:${ctx.port}/entitlements/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"license_key":',
    });
    assert.equal(malformed.status, 400);
    assert.deepEqual(await malformed.json(), {
      ok: false,
      error: {
        code: 'INVALID_JSON',
        message: 'request body is not valid JSON',
        retryable: false,
      },
    });
    assert.equal((await httpJson(ctx, 'GET', '/healthz')).status, 200);
  });
});

test('handler exceptions return one generic error without internal or request secrets', async () => {
  const internalSecret = 'internal-storage-detail-should-not-escape';
  const requestSecret = 'request-secret-should-not-escape';
  await withServer({
    store: {
      getByKey() {
        throw new Error(internalSecret);
      },
    },
  }, async (ctx) => {
    const response = await httpJson(ctx, 'POST', '/entitlements/activate', {
      domain: 'kdna:errors:asset',
      license_key: requestSecret,
    });
    assert.equal(response.status, 500);
    const raw = await response.text();
    assert.equal((raw.match(/INTERNAL_ERROR/g) || []).length, 1);
    assert.doesNotMatch(raw, new RegExp(`${internalSecret}|${requestSecret}`));
    assert.deepEqual(JSON.parse(raw), {
      ok: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'request could not be processed',
        retryable: false,
      },
    });
    assert.equal((await httpJson(ctx, 'GET', '/healthz')).status, 200);
  });
});

test('Story 24: CLI --create-license creates a record, --list lists it, --revoke revokes it', async () => {
  const dataDir = makeDataDir();
  try {
    const create = spawnSync(process.execPath, [CLI,
      '--create-license',
      '{"domain":"kdna:cli:test","license_key":"KDNA-LIC-cli","issued_to":"cli@example.com","ttl_days":30}',
      '--data-dir', dataDir,
    ], { encoding: 'utf8' });
    assert.equal(create.status, 0, `create failed: ${create.stderr}`);
    assert.match(create.stdout, /Created license:/);
    assert.doesNotMatch(create.stdout, /KDNA-LIC-cli|license_key/);

    const list = spawnSync(process.execPath, [CLI, '--list', '--data-dir', dataDir], { encoding: 'utf8' });
    assert.equal(list.status, 0);
    assert.match(list.stdout, /kdna:cli:test/);
    assert.doesNotMatch(list.stdout, /KDNA-LIC-cli|license_key/);

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
    assert.doesNotMatch(revoke.stdout, /KDNA-LIC-cli|license_key/);
  } finally {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});
