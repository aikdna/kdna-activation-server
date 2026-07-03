# @aikdna/kdna-activation-server

**Self-hostable HTTP activation server for KDNA `licensed`-mode assets.**

This server answers one question:

> Is this user / device / organisation currently entitled to use this
> asset?

It implements the four endpoints in
[`specs/kdna-entitlement-api.md`][1] and the self-hosting invariant
from [`docs/REMOTE_MODE.md`][2]. Reference implementation of
roadmap-2026.md Story 24.

[1]: https://github.com/aikdna/kdna/blob/main/specs/kdna-entitlement-api.md
[2]: https://github.com/aikdna/kdna/blob/main/docs/REMOTE_MODE.md

---

## Self-hosting is the default

> The KDNA protocol MUST NOT assume a single official KDNA
> server. Any asset creator can run their own activation server.
> Official KDNA hosting is one deployment option, not the
> protocol requirement.

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
curl -X POST http://localhost:3001/v1/entitlements/activate \
  -H 'Content-Type: application/json' \
  -d '{"domain":"@yourname/your-asset","license_key":"KDNA-LIC-customer-1"}'
```

That's it. No registration, no phone-home, no KDNA Inc. URL.

---

## HTTP API

### `GET /healthz`

Health check. Returns 200 with server metadata.

### `GET /v1/server/identity`

Returns the server's Ed25519 public key (PEM, hex, and
fingerprint). Clients use this to verify that an entitlement
record was really signed by this server.

### `POST /v1/entitlements/activate`

Activates a license. Returns a signed entitlement record
(cryptographically verifiable against `/v1/server/identity`).

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

Response (200): the signed entitlement record (see
`specs/kdna-entitlement-api.md` §5).

Errors:
- `INVALID_LICENSE_KEY` (404) — key does not match the domain
- `LICENSE_REVOKED` (403) — license has been revoked
- `LICENSE_EXPIRED` (403) — `expires_at` is in the past

### `POST /v1/entitlements/sync`

Refreshes the entitlement state (updates `last_checked_at` and
`offline_valid_until`). Returns the signed record. Same
errors as `/activate`.

### `POST /v1/entitlements/revoke` (admin)

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

### `GET /v1/entitlements/status?domain=...&license_key=...`

Introspection. Returns public entitlement metadata (unsigned,
for introspection only) and does not include `license_key`.
Consumers should use `/activate` or `/sync` for the signed
record.

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
  can verify against `/v1/server/identity`.

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
