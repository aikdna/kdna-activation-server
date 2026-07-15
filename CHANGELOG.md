# Changelog

## 0.2.0 (2026-07-16)

- Enforce the default machine-binding policy during activation, sync, and
  status checks; persist only a purpose-separated keyed digest and migrate
  valid legacy raw fingerprints after an exact match.
- Require sync identifiers to resolve to one domain and license, preventing a
  public license identifier from being used to retrieve a signed secret-bearing
  entitlement record.
- Require status lookups to use canonical public domain and license identifiers,
  and reject secret license keys in query strings.
- Replace collision-prone sanitized license filenames with an exact encoded
  mapping, retaining fail-closed reads and on-write migration for legacy files;
  scanned JSON is never trusted without an authoritative-path re-read.
- Replace generation-shaped HTTP paths with responsibility routes for server
  identity and entitlement activation, synchronization, status, and
  revocation.
- Remove the former paths instead of retaining compatibility aliases; hostile
  integration coverage verifies that every removed path returns 404.
- Present package versions as natural SemVer coordinates without a
  generation-style prefix.

## 0.1.2 (2026-07-13)

- Publish a versioned, reproducible package after the unused `0.1.1` release tag was
  found to still contain package version 0.1.0.
- Clarify that this repository is the legacy self-hosted license-key/receipt
  reference server. It is not an RFC-0019 account/device grant issuer and does
  not represent an AIKDNA-hosted authorization service.
- Add test-gated npm publishing and normalized repository metadata.

## 0.1.0

- Initial experimental self-hosted activation, sync, and revocation server.
