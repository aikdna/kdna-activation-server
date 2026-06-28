/**
 * index.js — public API for @aikdna/kdna-activation-server (Story 24)
 */

'use strict';

const server = require('./server');
const store = require('./store');
const signing = require('./signing');

module.exports = {
  startServer: server.startServer,
  stopServer: server.stopServer,
  makeRequestHandler: server.makeRequestHandler,
  makeStore: store.makeStore,
  ensureKeyPair: signing.ensureKeyPair,
  publicKeyFingerprint: signing.publicKeyFingerprint,
  signEntitlement: signing.signEntitlement,
  verifyEntitlementSignature: signing.verifyEntitlementSignature,
};
