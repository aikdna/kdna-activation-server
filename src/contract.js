'use strict';
// Historical Activation domain subset only; not current Core Identifier grammar.
const LEGACY_DOMAIN_PROFILE = 'activation-legacy-domain-subset';
const ENTITLEMENT_ROUTES = Object.freeze({
  health: '/healthz',
  identity: '/server/identity',
  activate: '/entitlements/activate',
  sync: '/entitlements/sync',
  status: '/entitlements/status',
  revoke: '/entitlements/revoke',
});

const ASSET_ID_RE = /^[a-zA-Z][a-zA-Z0-9_-]*(:[a-zA-Z0-9_.-]+)+$/u;
function isCanonicalAssetId(value) { return typeof value === 'string' && ASSET_ID_RE.test(value); }
module.exports = { ASSET_ID_RE, LEGACY_DOMAIN_PROFILE, ENTITLEMENT_ROUTES, isCanonicalAssetId };
