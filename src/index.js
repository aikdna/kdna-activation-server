/**
 * index.js — public API for @aikdna/kdna-activation-server (Story 24)
 */

'use strict';

const server = require('./server');
const store = require('./store');
const signing = require('./signing');
const contract = require('./contract');

module.exports = {
  ASSET_ID_RE: contract.ASSET_ID_RE,
  CORE_CONFORMANCE_VERSION: contract.CORE_CONFORMANCE_VERSION,
  ENTITLEMENT_ROUTES: contract.ENTITLEMENT_ROUTES,
  isCanonicalAssetId: contract.isCanonicalAssetId,
  startServer: server.startServer,
  stopServer: server.stopServer,
  makeRequestHandler: server.makeRequestHandler,
  makeStore: store.makeStore,
  ensureKeyPair: signing.ensureKeyPair,
  publicKeyFingerprint: signing.publicKeyFingerprint,
  signEntitlement: signing.signEntitlement,
  verifyEntitlementSignature: signing.verifyEntitlementSignature,
};
