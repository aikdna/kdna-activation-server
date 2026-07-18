/**
 * Canonical public contract shared by the Activation HTTP layer and clients.
 *
 * `domain` is not a second identifier namespace. It is the exact `asset_id`
 * from the KDNA Core manifest, so its grammar is derived from the published
 * Core schema instead of being copied into this package.
 */

'use strict';

const corePackage = require('@aikdna/kdna-core/package.json');
const manifestSchema = require('@aikdna/kdna-core/schema/manifest.schema.json');

const CORE_CONFORMANCE_VERSION = '0.20.0';
const ENTITLEMENT_ROUTES = Object.freeze({
  health: '/healthz',
  identity: '/server/identity',
  activate: '/entitlements/activate',
  sync: '/entitlements/sync',
  status: '/entitlements/status',
  revoke: '/entitlements/revoke',
});

const assetIdPattern = manifestSchema?.properties?.asset_id?.pattern;
if (corePackage.version !== CORE_CONFORMANCE_VERSION) {
  throw new Error(
    `Activation requires the exact KDNA Core ${CORE_CONFORMANCE_VERSION} conformance contract`,
  );
}
if (typeof assetIdPattern !== 'string' || assetIdPattern.length === 0) {
  throw new Error('KDNA Core manifest schema does not expose the asset_id grammar');
}

const ASSET_ID_RE = new RegExp(assetIdPattern, 'u');

function isCanonicalAssetId(value) {
  return typeof value === 'string' && ASSET_ID_RE.test(value);
}

module.exports = {
  ASSET_ID_RE,
  CORE_CONFORMANCE_VERSION,
  ENTITLEMENT_ROUTES,
  isCanonicalAssetId,
};
