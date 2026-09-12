import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { once } from 'node:events';
import { randomUUID } from 'node:crypto';
import { createActivationObserver, makeStore, createLicenseSecretVerifier, verifyLicenseSecret } from '@aikdna/kdna-activation-server';
import { admitNode } from '@aikdna/kdna-core/node';
import { inspectSnapshot } from '@aikdna/kdna-core/read-boundary';
import { admitReadTransportResponse } from '@aikdna/kdna-read/transport';
import { createRemoteReadHandler } from '@aikdna/kdna-remote-server';
import { fixture, readRequest, tuple, asset } from './current-fixture.mjs';
const TEST_ROOT = process.env.KDNA_TEST_DIR;
assert.ok(TEST_ROOT && path.isAbsolute(TEST_ROOT), 'Set an explicit absolute KDNA_TEST_DIR.');
fs.mkdirSync(TEST_ROOT, { recursive: true, mode: 0o700 });
const SECRET = 'SYNTHETIC-ONLY-BEARER';
const bytes = fixture();
const admitted = await admitNode(bytes);
assert.equal(admitted.status, 'accepted');
const snapshot = admitted.snapshot, view = inspectSnapshot(snapshot);
const alternate = (await admitNode(fixture(1, p => { p.judgments[0].label = 'Different admitted asset bytes'; }))).snapshot;
function setup(overrides = {}) {
  const dir = fs.mkdtempSync(path.join(TEST_ROOT, 'observer-'));
  const store = makeStore(dir);
  const created = store.create({ domain: 'kdna:synthetic:legacy', license_id: 'license:synthetic', license_key: SECRET,
    ttl_days: 1, require_machine_binding: false });
  const filename = path.join(dir, fs.readdirSync(dir).find(x => x.endsWith('.json')));
  let now = Date.now() + 1000;
  const initial = store.get(created.license_id);
  const binding = { licenseId: created.license_id, legacyDomain: initial.domain, snapshot,
    scope: view.ir.nodes.map(n => n.id), epoch: 'epoch:synthetic', policyId: 'policy:synthetic' };
  let currentBinding = binding;
  const options = { store, binding, readBinding: () => currentBinding, clock: () => now, ...overrides };
  const observer = createActivationObserver(options);
  const patch = patch => fs.writeFileSync(filename, JSON.stringify({ ...JSON.parse(fs.readFileSync(filename)), ...patch }), { mode: 0o600 });
  return { dir, store, observer, binding, filename, initial, patch,
    setNow: value => { now = value; }, getNow: () => now, setBinding: value => { currentBinding = value; } };
}
async function withSetup(fn, overrides) { const x = setup(overrides); try { await fn(x); } finally { x.observer.dispose(); } }
async function policy(x, context) { return x.observer.observePolicy({ context, snapshot: view }); }

test('AR05 real verifier, exact store lookup and bearer-only opaque context', async () => withSetup(async x => {
  assert.equal(verifyLicenseSecret(SECRET, x.initial.license_secret_verifier), true);
  assert.equal(verifyLicenseSecret('wrong', x.initial.license_secret_verifier), false);
  assert.equal(fs.readFileSync(x.filename, 'utf8').includes(SECRET), false);
  for (const invalid of [undefined, null, '', 'wrong', x.binding.licenseId, {}, 'x'.repeat(4097)]) assert.equal(await x.observer.authenticate(invalid), null);
  const context = await x.observer.authenticate(SECRET);
  assert.ok(context); assert.equal(JSON.stringify(context), '{}'); assert.ok(Object.isFrozen(context));
  assert.equal(await x.observer.verifyContext(context), true);
  assert.equal(await x.observer.verifyContext(JSON.parse(JSON.stringify(context))), false);
  assert.equal((await policy(x, context)).decision, 'allow');
  assert.equal((await policy(x, { account: 'owner', machine_id: 'device', token: SECRET })).decision, 'deny');
}));
test('AR06 explicitly configured admitted identity/scope is mandatory', () => {
  const x = setup(); try {
    for (const patch of [{ snapshot: {} }, { snapshot: view }, { legacyDomain: 'opaque unsupported' }, { scope: [] },
      { scope: ['unknown'] }, { scope: [x.binding.scope[0], x.binding.scope[0]] }, { epoch: '' }, { licenseId: '../file' }, { trustSource: 'request' }]) {
      assert.throws(() => createActivationObserver({ store: x.store, binding: { ...x.binding, ...patch }, readBinding: () => x.binding }));
    }
    assert.throws(() => makeStore()); assert.throws(() => makeStore('relative'));
  } finally { x.observer.dispose(); }
});
for (const [name, patch] of Object.entries({ revoked: { revoked: true }, suspended: { status: 'suspended' }, trial: { status: 'trial' }, missing_issue: { issued_at: undefined }, missing_update: { updated_at: undefined }, numeric_expiry: { expires_at: 123 }, unknown: { status: 'unknown' },
  missing_status: { status: null }, missing_revoked: { revoked: null }, revocation_time: { revoked_at: new Date().toISOString() },
  revocation_reason: { revocation_reason: 'synthetic revoked' }, unbounded_expiry: { expires_at: null }, invalid_expiry: { expires_at: 'NaN' },
  future_issue: { issued_at: '2099-01-01T00:00:00.000Z' }, future_update: { updated_at: '2099-01-01T00:00:00.000Z' },
  expired: { expires_at: '2020-01-01T00:00:00.000Z' }, unsupported_device: { require_machine_binding: true },
  unsupported_agents: { allowed_agents: ['agent:synthetic'] }, offline: { require_online_check: false },
  wrong_domain: { domain: 'kdna:different:domain' }, wrong_license: { license_id: 'license:different' } })) {
  test(`AR07/08/14 current record refuses ${name} and latches`, async () => withSetup(async x => {
    const context = await x.observer.authenticate(SECRET); assert.ok(context);
    x.patch(patch); assert.equal(await x.observer.verifyContext(context), false);
    fs.writeFileSync(x.filename, JSON.stringify(x.initial));
    assert.equal(await x.observer.authenticate(SECRET), null);
    assert.equal((await policy(x, context)).decision, 'deny');
  }));
}
test('AR08 actual store revoke invalidates existing context and rejects replay', async () => withSetup(async x => {
  const context = await x.observer.authenticate(SECRET);
  x.store.revoke(x.binding.licenseId, { reason: 'synthetic test' });
  assert.equal((await policy(x, context)).decision, 'deny');
  fs.writeFileSync(x.filename, JSON.stringify(x.initial));
  assert.equal(await x.observer.authenticate(SECRET), null);
}));
test('AR07 observed updated_at rollback and trusted clock rollback close', async () => {
  await withSetup(async x => { const c = await x.observer.authenticate(SECRET);
    x.patch({ updated_at: new Date(Date.parse(x.initial.updated_at) - 1).toISOString() });
    assert.equal(await x.observer.verifyContext(c), false); });
  await withSetup(async x => { const c = await x.observer.authenticate(SECRET); x.setNow(x.getNow() - 1);
    assert.equal(await x.observer.verifyContext(c), false); });
  await withSetup(async x => { const c = await x.observer.authenticate(SECRET); x.setNow(NaN);
    assert.equal(await x.observer.verifyContext(c), false); });
});
test('AR07 context and record expiry do not renew from previous active', async () => {
  await withSetup(async x => { const c = await x.observer.authenticate(SECRET); x.setNow(x.getNow() + 50);
    assert.equal(await x.observer.verifyContext(c), false); }, { contextTtlMs: 50 });
  await withSetup(async x => { const c = await x.observer.authenticate(SECRET); x.setNow(Date.parse(x.initial.expires_at));
    assert.equal((await policy(x, c)).decision, 'deny'); });
});
for (const [name, change] of Object.entries({ epoch: { epoch: 'epoch:changed' }, scope: { scope: [view.ir.nodes[0].id] },
  asset_bytes: { snapshot: alternate }, domain: { legacyDomain: 'kdna:changed:domain' }, license: { licenseId: 'license:changed' },
  policy: { policyId: 'policy:changed' } })) test(`AR10/14 current mapping change refuses ${name}`, async () => withSetup(async x => {
  const c = await x.observer.authenticate(SECRET); x.setBinding({ ...x.binding, ...change });
  assert.equal((await policy(x, c)).decision, 'deny'); x.setBinding(x.binding);
  assert.equal(await x.observer.verifyContext(c), false);
}));
test('AR06/11 observed different asset and cross-observer context refuse', async () => {
  const x = setup(), y = setup(); try { const c = await x.observer.authenticate(SECRET);
    assert.equal(await y.observer.verifyContext(c), false);
    assert.equal((await x.observer.observePolicy({ context: c, snapshot: inspectSnapshot(alternate) })).decision, 'deny');
  } finally { x.observer.dispose(); y.observer.dispose(); }
});
test('AR05 plaintext legacy secret is refused without migration', async () => withSetup(async x => {
  const raw = { ...x.initial, license_key: SECRET }; delete raw.license_secret_verifier;
  fs.writeFileSync(x.filename, JSON.stringify(raw)); const before = fs.readFileSync(x.filename);
  assert.equal(await x.observer.authenticate(SECRET), null); assert.deepEqual(fs.readFileSync(x.filename), before);
}));
test('AR08 secret rotation and malformed actual file close', async () => {
  await withSetup(async x => { const c = await x.observer.authenticate(SECRET);
    x.patch({ license_secret_verifier: createLicenseSecretVerifier('SYNTHETIC-ROTATED') });
    assert.equal(await x.observer.verifyContext(c), false); });
  await withSetup(async x => { const c = await x.observer.authenticate(SECRET); fs.writeFileSync(x.filename, '{broken');
    assert.equal(await x.observer.verifyContext(c), false); });
});
test('AR09 current store/config failure and asynchronous timeout close', async () => {
  for (const target of ['store', 'readBinding']) {
    const x = setup(); let resolveLate;
    const observer = createActivationObserver({ store: x.store, binding: x.binding, readBinding: () => x.binding,
      timeoutMs: 10, ...(target === 'store' ? { store: { get: () => new Promise(r => { resolveLate = r; }) } }
        : { readBinding: () => new Promise(r => { resolveLate = r; }) }) });
    try { assert.equal(await observer.authenticate(SECRET), null); resolveLate(target === 'store' ? x.initial : x.binding);
      assert.equal(await observer.authenticate(SECRET), null); } finally { observer.dispose(); x.observer.dispose(); }
  }
  await withSetup(async x => { fs.unlinkSync(x.filename); assert.equal(await x.observer.authenticate(SECRET), null); });
});

async function serve(x, fn, customize = {}) {
  const results = []; const pending = new Set();
  const handler = createRemoteReadHandler({ assetBytes: bytes, bindingId: 'binding:synthetic', authorizationDomainId: 'domain:synthetic',
    clock: x.getNow, resolveContext: req => x.observer.authenticate(req.headers.authorization === `Bearer ${SECRET}` ? SECRET : null),
    verifyContext: x.observer.verifyContext, observePolicy: x.observer.observePolicy, ...customize.options });
  const server = http.createServer((req, res) => { customize.response?.(res);
    const p = handler(req, res).then(r => { results.push(r); }).finally(() => pending.delete(p)); pending.add(p); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const url = `http://127.0.0.1:${server.address().port}/read`;
  const post = (body, auth = SECRET) => fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${auth}` }, body: JSON.stringify(body) });
  try { await fn({ url, post, results, handler, settle: () => Promise.all([...pending]) }); }
  finally { handler.dispose(); server.closeAllConnections(); await new Promise(r => server.close(r)); await Promise.all([...pending]); }
}
test('AR11/15/20 packed Remote real HTTP, public Read admission, current revoke recheck', async () => withSetup(async x => {
  await serve(x, async ({ url, post, results, settle }) => {
    const request = readRequest(); const response = await post(request); const body = await response.clone().json();
    assert.equal(response.status, 200); await settle(); assert.equal(results[0].envelope.status, 'ready');
    assert.equal(body.request_id, request.request_id); assert.equal(body.states.action_authorization, 'not_evaluated');
    assert.ok(Number(body.budget.actual_bytes) <= request.budget_bytes);
    const remote = await admitReadTransportResponse(response, { association_id: randomUUID(), endpoint_id: 'endpoint:synthetic',
      session_id: 'session:synthetic', endpoint_url: url, issued_at_ms: Date.now(), expires_at_ms: Date.now() + 5000,
      outbound_request_json: JSON.stringify(request), correlation: { state: 'validated', request_id: request.request_id },
      expected_tuple: tuple, expected_asset: asset, expected_digests: Object.fromEntries(['A', 'C', 'E'].map(k => [k, body.digests[k].observed])),
      expected_snapshot_id: null, max_response_bytes: 1000000, max_read_ms: 1000, admission_response_limit_bytes: 4096 });
    assert.equal(remote.status, 'accepted'); assert.equal(remote.origin, 'remote');
    assert.equal(remote.proof_limits.current_remote_revocation, 'NOT_PROVEN'); assert.ok(Object.values(remote.capabilities).every(v => v === false));
    const serialized = JSON.stringify(remote); assert.ok(serialized.includes('NOT_PROVEN')); assert.ok(serialized.includes('remote'));
    assert.equal(serialized.includes(SECRET), false); assert.equal(JSON.stringify(body).includes('license_secret'), false);
    x.store.revoke(x.binding.licenseId, { reason: 'synthetic test' });
    const denied = await post(readRequest({ request_id: 'request:after-revoke' }));
    assert.notEqual(denied.status, 200); assert.equal((await denied.text()).includes('RESULT_SENTINEL'), false);
  });
}));
test('AR11 real HTTP insufficient scope and wrong bearer disclose no result', async () => {
  await withSetup(async x => { x.observer.dispose();
    const binding = { ...x.binding, scope: [view.ir.nodes.find(n => n.type === 'actor')?.id ?? view.ir.nodes[0].id] };
    x.observer = createActivationObserver({ store: x.store, binding, readBinding: () => binding, clock: x.getNow });
    await serve(x, async ({ post }) => { const res = await post(readRequest()); const body = await res.text();
      assert.notEqual(res.status, 200); assert.equal(body.includes('RESULT_SENTINEL'), false); }); });
  await withSetup(async x => serve(x, async ({ post }) => { const res = await post(readRequest(), 'WRONG');
    assert.notEqual(res.status, 200); assert.equal((await res.text()).includes('RESULT_SENTINEL'), false); }));
});
test('AR15 real HTTP delivery interruption closes Host and publishes no handles', async () => withSetup(async x => {
  await serve(x, async ({ post, results, handler, settle }) => {
    await assert.rejects(post(readRequest())); await settle();
    assert.equal(results[0].channel, 'transport_failure'); assert.equal(results[0].transport_failure.delivery, 'not_confirmed');
    assert.equal(handler.retentionState().issued_handle_records, 0); assert.equal(handler.retentionState().state, 'closed');
  }, { response: res => { res.end = () => { res.destroy(); return res; }; } });
}));
test('AR08/16 revocation during actual HTTP sink is rechecked after physical finish', async () => withSetup(async x => {
  await serve(x, async ({ post, results, handler, settle }) => {
    const response = await post(readRequest()); await response.arrayBuffer(); await settle();
    assert.equal(results[0].channel, 'transport_failure'); assert.equal(handler.retentionState().state, 'closed');
    assert.equal(await x.observer.authenticate(SECRET), null);
  }, { response: res => { const end = res.end.bind(res); res.end = (...args) => {
    x.store.revoke(x.binding.licenseId, { reason: 'synthetic sink change' }); return end(...args); }; } });
}));
test('AR09 store/config exceptions and bounded context registry refuse', async () => {
  for (const target of ['store', 'readBinding']) {
    const x = setup(); const observer = createActivationObserver({ store: x.store, binding: x.binding, readBinding: () => x.binding,
      ...(target === 'store' ? { store: { get() { throw new Error('synthetic private store path'); } } }
        : { readBinding() { throw new Error('synthetic private config path'); } }) });
    try { assert.equal(await observer.authenticate(SECRET), null); assert.equal(await observer.verifyContext({}), false); }
    finally { observer.dispose(); x.observer.dispose(); }
  }
  await withSetup(async x => { const c = await x.observer.authenticate(SECRET); assert.ok(c);
    assert.equal(await x.observer.authenticate(SECRET), null); assert.equal(await x.observer.verifyContext(c), true); }, { maxContexts: 1 });
});
test('AR14/16/22 actual HTTP budget, legacy operation and request replay refuse', async () => {
  await withSetup(async x => serve(x, async ({ post }) => { const res = await post(readRequest({ budget_bytes: 1 }));
    assert.equal(res.status, 413); assert.equal((await res.text()).length, 0); }));
  await withSetup(async x => serve(x, async ({ post }) => { const res = await post({ task: 'old task', axiom: 'old axiom' });
    assert.equal(res.status, 501); assert.equal((await res.json()).error.code, 'REMOTE_LEGACY_TASK_UNSUPPORTED'); }));
  await withSetup(async x => serve(x, async ({ post, settle, handler }) => {
    assert.equal((await post(readRequest())).status, 200); await settle();
    const replay = await post(readRequest()); assert.notEqual(replay.status, 200);
    assert.equal((await replay.text()).includes('RESULT_SENTINEL'), false); assert.equal(handler.retentionState().consumed_request_ids, 1);
  }));
});
test('AR08 revoke after first current policy observation prevents disclosure', async () => withSetup(async x => {
  let observations = 0;
  await serve(x, async ({ post, settle, handler }) => { const response = await post(readRequest());
    assert.notEqual(response.status, 200); assert.equal((await response.text()).includes('RESULT_SENTINEL'), false);
    await settle(); assert.equal(handler.retentionState().state, 'closed');
  }, { options: { observePolicy: async observation => { const p = await x.observer.observePolicy(observation);
    if (++observations === 1) x.store.revoke(x.binding.licenseId, { reason: 'synthetic preparation revoke' }); return p; } } });
}));
test('AR16 real current authorization permits fresh handle expansion then refuses after revoke', async () => withSetup(async x => {
  const optional = fixture(3, p => { p.dependencies = [1, 2].map(i => ({ id: `dependency:${i}`,
    producer: { kind: 'judgment_result', judgment_ref: `judgment:${i}`, result_contract_ref: `contract:${i}` },
    consumer_judgment_ref: 'judgment:0', input_role: 'support', data_type: { term: 'result.type.text' },
    required: false, purpose: 'Synthetic optional support' })); });
  const a = await admitNode(optional); assert.equal(a.status, 'accepted'); const v = inspectSnapshot(a.snapshot);
  const binding = { ...x.binding, snapshot: a.snapshot, scope: v.ir.nodes.map(n => n.id) };
  x.observer.dispose(); x.observer = createActivationObserver({ store: x.store, binding, readBinding: () => binding, clock: x.getNow });
  let handle;
  await serve(x, async ({ post, settle }) => {
    const first = await post(readRequest()); assert.equal(first.status, 200); const body = await first.json(); await settle();
    handle = body.content.expansion_handles[0]; assert.ok(handle);
    const next = await post(readRequest({ request_id: 'request:expansion', mode: 'expand', handle }));
    assert.equal(next.status, 200); assert.ok((await next.text()).includes('RESULT_SENTINEL_1')); await settle();
    x.store.revoke(x.binding.licenseId, { reason: 'synthetic expansion revoke' });
    const denied = await post(readRequest({ request_id: 'request:revoked-expansion', mode: 'expand', handle }));
    assert.notEqual(denied.status, 200); assert.equal((await denied.text()).includes('RESULT_SENTINEL'), false);
  }, { options: { assetBytes: optional } });
}));
test('AR20 actual HTTP action endpoints and caller action flag never grant action', async () => {
  await withSetup(async x => serve(x, async ({ url }) => {
    for (const route of ['activate', 'load', 'execute']) {
      const res = await fetch(url.replace('/read', `/${route}`), { method: 'POST' });
      assert.equal(res.status, 501); assert.equal((await res.json()).error.code, 'REMOTE_CAPABILITY_UNAVAILABLE');
    }
  }));
  await withSetup(async x => serve(x, async ({ post }) => {
    const res = await post({ ...readRequest(), action_authorized: true }); assert.notEqual(res.status, 200);
    assert.equal((await res.text()).includes('RESULT_SENTINEL'), false);
  }));
});
