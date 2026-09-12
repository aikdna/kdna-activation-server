'use strict';
const { performance } = require('node:perf_hooks');
const { inspectSnapshot } = require('@aikdna/kdna-core/read-boundary');
const { isCanonicalDomain, verifyLicenseSecret, LICENSE_SECRET_MAX_BYTES } = require('./store');
const OPTIONS = new Set(['store', 'binding', 'readBinding', 'clock', 'timeoutMs', 'contextTtlMs', 'maxContexts']);
const BINDING = new Set(['licenseId', 'legacyDomain', 'snapshot', 'scope', 'epoch', 'policyId']);
function bounded(value, fallback, maximum) {
  const n = value ?? fallback;
  if (!Number.isSafeInteger(n) || n < 1 || n > maximum) throw new TypeError('Invalid observer limit.');
  return n;
}
function configuredLabel(value) {
  // A deployment subset only; Host remains responsible for its public grammar.
  return typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= 256;
}
function normalizeBinding(value) {
  if (!value || typeof value !== 'object' || Object.keys(value).some(k => !BINDING.has(k))
    || typeof value.licenseId !== 'string' || !/^[A-Za-z0-9_\-:.]{1,128}$/.test(value.licenseId)
    || !isCanonicalDomain(value.legacyDomain) || !configuredLabel(value.epoch) || !configuredLabel(value.policyId)) {
    throw new TypeError('Invalid server-owned Activation binding.');
  }
  const view = inspectSnapshot(value.snapshot);
  if (!view || !Array.isArray(value.scope) || !value.scope.length) throw new TypeError('An admitted asset and explicit scope are required.');
  const ids = new Set(view.ir.nodes.map(n => n.id));
  if (value.scope.some(id => typeof id !== 'string' || !ids.has(id)) || new Set(value.scope).size !== value.scope.length) {
    throw new TypeError('Scope must be a unique explicit subset of the admitted IR.');
  }
  const identity = { asset: view.asset, digests: Object.fromEntries(['A', 'C', 'E'].map(k => [k, view.digests[k].observed])) };
  return Object.freeze({ licenseId: value.licenseId, legacyDomain: value.legacyDomain,
    identity: JSON.stringify(identity), scope: Object.freeze([...value.scope].sort()), epoch: value.epoch, policyId: value.policyId });
}
function timestamp(value) {
  if (typeof value !== 'string' || value.length !== 24) return null;
  const n = Date.parse(value);
  return Number.isSafeInteger(n) && n >= 0 && new Date(n).toISOString() === value ? n : null;
}
/** Co-located current-store observer; produces no portable credential or Host brand. */
function createActivationObserver(options) {
  if (!options || typeof options !== 'object' || Object.keys(options).some(k => !OPTIONS.has(k))
    || !options.store || typeof options.store.get !== 'function' || typeof options.readBinding !== 'function'
    || (options.clock !== undefined && typeof options.clock !== 'function')) throw new TypeError('Invalid server-owned observer configuration.');
  const binding = normalizeBinding(options.binding), bindingKey = JSON.stringify(binding);
  const store = options.store, readBinding = options.readBinding, clock = options.clock ?? Date.now;
  const timeoutMs = bounded(options.timeoutMs, 1000, 30000);
  const contextTtlMs = bounded(options.contextTtlMs, 30000, 300000);
  const maxContexts = bounded(options.maxContexts, 16, 1024);
  const contexts = new Map();
  let closed = false, lastClock = -1, lastUpdated = -1, pending = 0;
  function close() { closed = true; contexts.clear(); }
  function current() {
    if (closed) throw new Error('Observer unavailable.');
    const now = clock();
    if (!Number.isSafeInteger(now) || now < 0 || now < lastClock) { close(); throw new Error('Observer unavailable.'); }
    lastClock = now;
    for (const [context, record] of contexts) if (now >= record.expiresAt) contexts.delete(context);
    return now;
  }
  async function external(call, deadline) {
    const remaining = deadline - performance.now();
    if (remaining <= 0) throw new Error('Observer timeout.');
    let timer;
    const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Observer timeout.')), remaining); });
    try {
      const result = await Promise.race([Promise.resolve().then(call), timeout]);
      if (closed || performance.now() >= deadline) throw new Error('Observer timeout.');
      return result;
    } finally { clearTimeout(timer); }
  }
  async function currentBinding(deadline) {
    const value = await external(readBinding, deadline);
    if (JSON.stringify(normalizeBinding(value)) !== bindingKey) throw new Error('Binding changed.');
  }
  async function check(secret, invalidateSecret = false) {
    if (closed || pending >= maxContexts || typeof secret !== 'string' || !secret.length
      || Buffer.byteLength(secret) > LICENSE_SECRET_MAX_BYTES) return null;
    pending++;
    try {
      current(); const deadline = performance.now() + timeoutMs;
      await currentBinding(deadline);
      const record = await external(() => store.get(binding.licenseId), deadline);
      if (!record || record.license_id !== binding.licenseId || record.domain !== binding.legacyDomain
        || Object.hasOwn(record, 'license_key') || !record.license_secret_verifier) throw new Error('Current record unavailable.');
      if (!verifyLicenseSecret(secret, record.license_secret_verifier)) {
        if (invalidateSecret) close();
        return null;
      }
      const now = current(), issued = timestamp(record.issued_at), expires = timestamp(record.expires_at), updated = timestamp(record.updated_at);
      if (performance.now() >= deadline || issued === null || expires === null || updated === null
        || issued > updated || updated > now || issued >= expires || now >= expires || updated < lastUpdated
        || record.status !== 'active' || record.revoked !== false || record.revoked_at !== null
        || record.revocation_reason !== null || record.require_machine_binding !== false
        || record.require_online_check !== true || record.allowed_agents !== null) throw new Error('Current record denied.');
      await currentBinding(deadline);
      const finalNow = current();
      if (finalNow >= expires) throw new Error('Current record expired.');
      lastUpdated = Math.max(lastUpdated, updated);
      return { now: finalNow, expires };
    } catch { close(); return null; }
    finally { pending--; }
  }
  function deny() {
    const now = Number.isSafeInteger(lastClock) && lastClock >= 0 ? lastClock : 0;
    return Object.freeze({ decision: 'deny', scope: Object.freeze([]), epoch: binding.epoch, policyId: binding.policyId,
      issuedAt: now, expiresAt: now + 1, revoked: true });
  }
  async function authenticate(secret) {
    const result = await check(secret);
    if (!result || closed || contexts.size >= maxContexts) return null;
    const expiresAt = Math.min(result.expires, result.now + contextTtlMs);
    if (!Number.isSafeInteger(expiresAt)) { close(); return null; }
    const context = Object.freeze(Object.create(null));
    contexts.set(context, { secret, expiresAt });
    return context;
  }
  async function verifyContext(context) {
    const credential = contexts.get(context);
    if (!credential || closed) return false;
    const result = await check(credential.secret, true);
    return Boolean(result && !closed && contexts.has(context) && result.now < credential.expiresAt);
  }
  async function observePolicy(observation) {
    const credential = contexts.get(observation?.context);
    if (!credential || closed) return deny();
    const result = await check(credential.secret, true);
    if (!result || closed || !contexts.has(observation.context) || result.now >= credential.expiresAt) return deny();
    try {
      const view = observation.snapshot;
      const identity = { asset: view.asset, digests: Object.fromEntries(['A', 'C', 'E'].map(k => [k, view.digests[k].observed])) };
      const ids = new Set(view.ir.nodes.map(n => n.id));
      if (JSON.stringify(identity) !== binding.identity || binding.scope.some(id => !ids.has(id))) { close(); return deny(); }
      return Object.freeze({ decision: 'allow', scope: binding.scope, epoch: binding.epoch, policyId: binding.policyId,
        issuedAt: result.now, expiresAt: Math.min(result.expires, credential.expiresAt), revoked: false });
    } catch { close(); return deny(); }
  }
  return Object.freeze({ authenticate, verifyContext, observePolicy, dispose: close });
}
module.exports = { createActivationObserver };
