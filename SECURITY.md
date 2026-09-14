# Security Policy

## Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues.

Instead, use one of these private channels:

- **GitHub Private Vulnerability Reporting**: Go to the [Security Advisories](https://github.com/aikdna/kdna-activation-server/security/advisories/new) page
- **Email**: security@aikdna.com

We aim to respond within 72 hours and provide a timeline for resolution within 1 week.
Please do not disclose the vulnerability publicly until we have had a chance to address it.

## Supported Versions

`kdna-activation-server` provides a co-located entitlement store observer for
the public reference Host. Until the first stable release, security support
tracks the latest mainline pre-release and the canonical KDNA protocol/runtime
surfaces.

| Component | Supported Versions |
|-----------|-------------------|
| KDNA Protocol | Latest tagged release |
| kdna-cli | Latest minor release |
| kdna-activation-server | Latest mainline pre-release |

Older pre-release versions may receive critical security patches on a
case-by-case basis.

## Security Model

The current source package is `0.4.0-rc.component-semantics.1`, bound to Core
`0.24.0-rc.component-semantics.2`, Read `0.3.0-rc.component-semantics.2`,
Host `0.5.0-rc.component-semantics.1`, and integration-tested with Remote
`0.6.0-rc.component-semantics.1`. These source coordinates do not establish
registry publication or change the supported-version policy above.

The observer authenticates a license secret against an authoritative local
entitlement store and supplies the reference Host with process-local context
and policy observations. The deployment supplies the license identifier,
historical domain binding, Core-admitted snapshot, non-empty IR scope, epoch,
policy identifier, and a `readBinding()` callback that returns the current
mapping. These bindings are checked again when the Host verifies context and
observes policy. Revocation, secret rotation, invalid
bindings, expired observations, and detected clock rollback close access.

Store administration remains server-side. Pass an explicit absolute path to a
private writable store directory and protect its integrity and access permissions.
Do not put license secrets, stored verifiers, entitlement records, or process
contexts in browser code or logs. Secret verification uses bounded scrypt;
JavaScript strings cannot be reliably erased. Synchronous store operations cannot
be preempted by a timeout, so the deployment must control local storage latency.

This package provides no HTTP server, command-line interface, issuer service,
portable identity credential, or action authorization. It does not establish
protocol validity, perform Core admission itself, or grant capabilities from
asset text. Co-location is an assumption: network replay protection,
cross-replica freshness, and remote identity proof require separate deployment
controls. An HTTP success or completed response is not an authorization proof.

For the KDNA Protocol security architecture, see
[GOVERNANCE.md](https://github.com/aikdna/kdna/blob/main/docs/GOVERNANCE.md)
in the main protocol repository.
