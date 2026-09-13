# KDNA Activation current-store observer

`@aikdna/kdna-activation-server@0.4.0-rc.component-semantics.1` is a co-located reference authorization observer for the public KDNA reference Host. It observes an authoritative entitlement store before disclosure and maps that observation to the existing HostPolicy. This release candidate has no standalone HTTP server or CLI, portable credential, issuer-signature claim, account/device identity, or action grant.

## Exact supported boundary

The trusted deployment supplies one `licenseId`, one supported historical `legacyDomain`, a genuine Core-admitted `snapshot`, an explicit nonempty IR-node `scope`, and `epoch` / `policyId`. It supplies `readBinding()` to obtain that mapping again at every check. A difference in license, domain, admitted asset ID/version/A/C/E, scope, epoch or policy ID closes this observer. The legacy domain grammar is an explicitly named historical Activation subset, not a replacement for Core's current Identifier grammar.

The current record must match the exact configured license and domain, contain the existing bounded scrypt verifier, and have canonical UTC millisecond ISO `issued_at`, `updated_at`, and `expires_at`. It must satisfy `issued_at <= updated_at <= now < expires_at`, with no observed update rollback. Only `status: "active"`, `revoked: false`, `revoked_at: null`, `revocation_reason: null`, `require_machine_binding: false`, `require_online_check: true`, and `allowed_agents: null` are supported. Missing/unknown values, perpetual expiry, unsupported device/agent restrictions and plaintext legacy secrets are refused. When machine binding is explicitly disabled, legacy machine digest/fingerprint metadata is ignored and supplies no device authority. The observer never scans by secret, migrates records, or writes an offline lease.

`authenticate(secret)` performs real current secret verification and returns an opaque process-local object or `null`. `verifyContext(context)` and `observePolicy({ context, snapshot })` repeat current store, binding and clock checks. The Host supplies the public snapshot view to `observePolicy`. A copied JSON context has no authority. Possession of this context proves only the supplied bearer matched the configured current record; it does not prove who owns that bearer. Store/configuration failure, timeout, invalid/future timestamps, clock rollback, revocation, secret rotation, identity mismatch or mapping change clears contexts and closes the observer. Recreating the observer requires fresh server-owned configuration; the existing Host denial latch must also remain intact.

## Embedding

Use `createActivationObserver`, `makeStore`, `createLicenseSecretVerifier` and `verifyLicenseSecret` from the package root. Runtime Core is exactly `0.24.0-rc.component-semantics.2`; the Host interface is exactly `0.5.0-rc.component-semantics.1`. The reference HTTP tests consume Remote `0.6.0-rc.component-semantics.1` and Read `0.3.0-rc.component-semantics.2` through public exports.

```js
const { createActivationObserver, makeStore } = require('@aikdna/kdna-activation-server');
// These values belong to the trusted deployment, never to a request body.
const observer = createActivationObserver({
  store: makeStore(deployment.dataDirectory), // explicit absolute private directory
  binding: deployment.currentBinding,
  readBinding: deployment.readCurrentBinding,
  clock: deployment.trustedClock,
});
// In the trusted Remote embedding:
// resolveContext: request => observer.authenticate(readBoundedBearer(request))
// verifyContext: observer.verifyContext
// observePolicy: observer.observePolicy
// On shutdown: remoteHandler.dispose(); observer.dispose();
```

Do not log bearer values, returned records, verifier fields or internal contexts. The store's administration methods remain server-only; older machine-binding/signing/server files are historical repository material and excluded from the package. `makeStore` no longer chooses a home-directory fallback. Server data-directory permissions and deployment store/configuration integrity remain the operator's responsibility.

Limits are positive safe integers: `timeoutMs` defaults to 1000 (maximum 30000), `contextTtlMs` to 30000 (maximum 300000), and `maxContexts` to 16 (maximum 1024). Context expiry never exceeds record expiry. A full registry refuses new contexts and retains existing unexpired contexts. Store/config callbacks are deadline-bounded on return and asynchronous waits time out. JavaScript cannot forcibly interrupt synchronous disk I/O/scrypt or a non-cooperative callback; timed-out observers remain closed even if that operation later completes. Disposal drops retained bearer references; JavaScript strings cannot be reliably zeroed.

## Proof and delivery limits

This boundary trusts a current co-located authoritative store and trusted clock. It introduces no cryptography and proves no cross-host/store-replica freshness, issuer identity, network replay resistance or portable signature coverage. An unobserved malicious rollback of the authoritative source cannot be detected as such. The remote consumer retains `origin: remote`, `NOT_PROVEN` remote identity/authorization/revocation and all local capabilities false. HTTP 200 does not substitute for formal Read admission, request correlation, budget accounting or Host delivery checks.

Host rechecks policy through its existing preparation and delivery lifecycle. If the store changes after bytes enter the actual HTTP sink, local post-delivery checks can close the session and withhold retained handles, but cannot recall bytes already sent or prove client receipt. A new request always rechecks current state.

## Development

The repository preserves the old source/tests and changelog as history. Current commands explicitly select current tests; old CLI execution refuses, and the old server/signing modules are not public exports or tar members. `vendor/provenance.json` records exact development tar hashes and repack provenance; local repacks are not asserted to be original registry tarballs.

```
npm ci --ignore-scripts --omit=optional --no-audit --no-fund
npm test
npm run lint
npm run check:public-surface
npm pack --ignore-scripts --json
```

`npm test` uses a temporary private store directory (or an explicit absolute `KDNA_TEST_DIR`), synthetic secrets and localhost OS-assigned ports, then closes its own connections. Publishing is explicitly blocked pending a separate release decision. This repository contains a reference candidate, not a production identity deployment.

## Current component graph

This candidate binds the current public Core, Read and reference Host. Taxonomy, candidate-set and discriminator-set content is carried in the public Read projection; this package adds no component interpreter or action permission. Exact versions, artifact hashes and scope limits are recorded in `public-contract-binding.json`.
