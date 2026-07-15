# @aikdna/kdna-activation-server

**Experimental self-hostable HTTP activation server for KDNA `licensed` assets.**

KDNA makes judgment portable across models and runtimes. This repository is an
experimental entitlement reference implementation, not a marketplace, billing
service, or AIKDNA-hosted activation platform.

This package implements the legacy license-key and signed-receipt profile. It
is not an RFC-0019 account/device external-key-grant issuer. Implementations
must not present one profile as the other.

This server answers one question:

> Is this user / device / organisation currently entitled to use this
> asset?

It implements the four endpoints in
[`specs/kdna-entitlement-api.md`][1] and the self-hosting invariant
from [`docs/REMOTE_MODE.md`][2].

[1]: https://github.com/aikdna/kdna/blob/main/specs/kdna-entitlement-api.md
[2]: https://github.com/aikdna/kdna/blob/main/docs/REMOTE_MODE.md

---

## Self-hosting is the default

> The KDNA protocol MUST NOT assume a single official KDNA
> server. Any asset creator can run their own activation server.
> No AIKDNA-hosted activation service is part of the current public baseline.

This server is the deployer's own. The protocol does not
hardcode any KDNA Inc. URL. The admin token is deployer-
controlled. License records are deployer-controlled. The
server's signing keypair is generated on first start and
stored locally.

---

## Quick start (self-hosting)

```bash
# 1. Install (any Node 18+ server)
npm install -g @aikdna/kdna-activation-server

# 2. Create your first license
kdna-activation-server --create-license '{
  "domain": "@yourname/your-asset",
  "license_key": "KDNA-LIC-customer-1",
  "issued_to": "customer@example.com",
  "ttl_days": 365
}'

# 3. Start the server
kdna-activation-server --port 3001 --admin-token "your-secret"

# 4. Test
curl http://localhost:3001/healthz
curl -X POST http://localhost:3001/entitlements/activate \
  -H 'Content-Type: application/json' \
  -d '{"domain":"@yourname/your-asset","license_key":"KDNA-LIC-customer-1","machine_fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
```

That's it. No registration, no phone-home, no KDNA Inc. URL.

---

## HTTP API

### `GET /healthz`

Health check. Returns 200 with server metadata.

### `GET /server/identity`

Returns the server's Ed25519 public key (PEM, hex, and
fingerprint). Clients use this to verify that an entitlement
record was really signed by this server.

### `POST /entitlements/activate`

Activates a license. Returns a signed entitlement record
(cryptographically verifiable against `/server/identity`).

Request body:

```json
{
  "domain": "@yourname/your-asset",
  "license_key": "KDNA-LIC-customer-1",
  "machine_fingerprint": "<sha256>"
}
```

Optional: `client`, `client_version`, `agent`, `account_id`,
`device_label`.

`machine_fingerprint` is required when the license was created with
`require_machine_binding: true` (the default). Its canonical wire format is
exactly 64 lowercase hexadecimal characters: the SHA-256 digest produced by
the client. Uppercase, prefixed, whitespace-padded, non-ASCII, short, and long
forms are rejected rather than normalized into aliases.

Response (200): the signed entitlement record (see
`specs/kdna-entitlement-api.md` §5).

Errors:
- `INVALID_LICENSE_KEY` (404) — key does not match the domain
- `LICENSE_REVOKED` (403) — license has been revoked
- `LICENSE_EXPIRED` (403) — `expires_at` is in the past
- `MISSING_MACHINE_FINGERPRINT` (400) — a bound license omitted its fingerprint
- `INVALID_MACHINE_FINGERPRINT` (400) — the fingerprint is not canonical
- `MACHINE_MISMATCH` (403) — the license is bound to another machine or has
  not yet been activated on this machine

### `POST /entitlements/sync`

Refreshes the entitlement state (updates `last_checked_at` and
`offline_valid_until`). `domain` and `license_key` are required;
`license_id` is optional but, when present, must identify that same license.
Machine-bound licenses must already have been activated and must send the same
canonical `machine_fingerprint`. Returns the signed record. Same errors as
`/activate`.

### `POST /entitlements/revoke` (admin)

Revokes a license. Requires an `Authorization: Bearer
<admin-token>` header. The admin token is set at server
startup.

Request body:

```json
{
  "license_id": "lic_abc123",
  "domain": "@yourname/your-asset",
  "reason": "payment_failed",
  "revoked_by": "billing-system"
}
```

### `GET /entitlements/status?domain=...&license_id=...&machine_fingerprint=...`

Introspection. Returns public entitlement metadata (unsigned,
for introspection only) and does not include `license_key`.
Use `license_id` for status checks so the secret `license_key`
does not appear in URLs or access logs. The server still accepts
`license_key` for compatibility, but consumers should use
`/activate` or `/sync` for signed entitlement records.
For machine-bound licenses, status requires the already-bound canonical
fingerprint and never creates a first binding. Error responses do not include
license metadata, the submitted fingerprint, or the stored binding digest.
Missing, malformed, mismatched, and not-yet-bound machine authorization all
return the same `NOT_FOUND` response as an unknown record, so public
`license_id` values cannot be used as a binding-enumeration oracle.

---

## CLI

```bash
# Create a license (one-shot)
kdna-activation-server --create-license '{"domain":"@x/y","license_key":"KDNA-LIC-1"}'

# List all licenses
kdna-activation-server --list

# Revoke
kdna-activation-server --revoke lic_abc123 --reason "payment_failed"

# Start the server
kdna-activation-server --port 3001 --admin-token "your-secret"
```

The server keypair is auto-generated on first start and
stored at `~/.kdna/activation-server/`. The private key is
mode 0600.

---

## Security properties

- **No KDNA Inc. URL is hardcoded.** The server has zero
  outbound network calls during normal operation.
- **The server keypair is local.** The private key never
  leaves the deployer's machine.
- **The admin token is deployer-controlled.** Set it at
  startup or omit it to disable `/revoke` over HTTP.
- **The license_key is the secret.** The server echoes it
  back in the activation record (per spec). Clients MUST
  NOT log or persist it beyond the local activation file.
- **Records are signed.** Every `/activate` and `/sync`
  response is signed with the server's Ed25519 key. Clients
  can verify against `/server/identity`.
- **Raw machine fingerprints are not stored by new activations.** The server
  derives a purpose-separated HMAC key from its local private key and stores
  only the keyed binding digest. A matching request migrates an older raw
  fingerprint record in place; malformed legacy bindings fail closed.

---

## Local development

```bash
git clone https://github.com/aikdna/kdna-activation-server
cd kdna-activation-server
npm test
```

The tests spin up the server on an OS-assigned port. No
external services are required.

---

## License

Apache 2.0. See [LICENSE](./LICENSE).

This server is a license-management reference implementation.
Trust is the consumer's decision, not the server's claim.
