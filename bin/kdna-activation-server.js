#!/usr/bin/env node
/**
 * kdna-activation-server — CLI entry
 *
 * Self-hostable HTTP activation server. See README.md for
 * self-hosting instructions.
 *
 * Usage:
 *   kdna-activation-server [--port 3001] [--data-dir <path>]
 *                          [--admin-token-stdin|--admin-token-file <path>]
 *                          [--create-license-stdin|--create-license-file <path>]
 *                          [--list]
 *                          [--revoke <license-id> --reason "..."]
 *
 * The server is the deployer's own. The protocol does not
 * hardcode any KDNA Inc. URL. The admin token is deployer-
 * controlled. License records are deployer-controlled.
 */

'use strict';

const path = require('node:path');
const fs = require('node:fs');
const { startServer, stopServer } = require('../src/server');
const { makeStore, DEFAULT_DATA_DIR } = require('../src/store');
const {
  MAX_ADMIN_TOKEN_BYTES,
  MAX_LICENSE_REQUEST_BYTES,
  readPrivateFile,
  readPrivateStdin,
} = require('../src/private-input');
const pkg = require('../package.json');

function rejectSecretArguments(argv) {
  for (const argument of argv) {
    if (
      argument === '--admin-token' ||
      argument.startsWith('--admin-token=') ||
      argument === '--create-license' ||
      argument.startsWith('--create-license=')
    ) {
      throw new Error(
        'Secrets are not accepted in process arguments. Use the matching --stdin or --file option.',
      );
    }
  }
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const eq = key.indexOf('=');
      if (eq >= 0) {
        out[key.slice(0, eq)] = key.slice(eq + 1);
      } else if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) {
        out[key] = argv[i + 1];
        i++;
      } else {
        out[key] = true;
      }
    }
  }
  return out;
}

function help() {
  return `kdna-activation-server ${pkg.version} — self-hostable activation server

Usage:
  kdna-activation-server [serve options]
  kdna-activation-server --create-license-stdin [--data-dir <path>]
  kdna-activation-server --create-license-file <path> [--data-dir <path>]
  kdna-activation-server --list [--data-dir <path>]
  kdna-activation-server --revoke <license-id> --reason "..." [--data-dir <path>]

Server options:
  --port <n>             Port to listen on. Default 3001.
  --host <addr>          Host to bind. Default 127.0.0.1.
  --data-dir <path>      Where to store entitlement records +
                         server keypair. Default
                         ~/.kdna/activation-server.
  --admin-token-stdin    Read the revoke bearer token from bounded strict
                         UTF-8 stdin before starting the server.
  --admin-token-file <path>
                         Read it from a regular private file that is
                         inaccessible to group/other users.

One-shot commands (do not start the server):
  --create-license-stdin
                        Read one bounded strict UTF-8 JSON request from stdin.
  --create-license-file <path>
                        Read the request from a regular private file.
                        The JSON
                        must contain: domain, license_key. Domain
                        must use canonical asset_id syntax such as
                        kdna:creator:asset.
                        Optional: issued_to, ttl_days,
                        require_machine_binding (default true),
                        require_online_check (default true),
                        offline_grace_days (default 7),
                        allowed_agents (array).
  --list                 List all license records.
  --revoke <id>          Revoke a license by id. Requires --reason.
  --reason "..."         Reason for revocation (audit log).

Self-hosting:
  Run this on any Node 18+ server. There is no registration
  with KDNA Inc. The license records, the admin token, and
  the server keypair are all deployer-controlled.
`;
}

async function main() {
  const argv = process.argv.slice(2);
  rejectSecretArguments(argv);
  const args = parseArgs(argv);
  if (args.help || args.h) {
    process.stdout.write(help());
    return;
  }

  const dataDir = args['data-dir'] || DEFAULT_DATA_DIR;
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const store = makeStore(dataDir);

  // One-shot commands
  const createSources = [
    args['create-license-stdin'] ? 'stdin' : null,
    args['create-license-file'] ? 'file' : null,
  ].filter(Boolean);
  if (createSources.length > 1) {
    throw new Error('Choose exactly one create-license private input source.');
  }
  if (createSources.length === 1) {
    let body;
    try {
      const text =
        createSources[0] === 'stdin'
          ? readPrivateStdin({
              label: 'License creation request',
              maximum: MAX_LICENSE_REQUEST_BYTES,
            })
          : readPrivateFile(args['create-license-file'], {
              label: 'License creation request',
              maximum: MAX_LICENSE_REQUEST_BYTES,
            });
      body = JSON.parse(text);
    } catch {
      throw new Error('License creation input is not valid private JSON.');
    }
    if (!body.domain || !body.license_key) {
      throw new Error('License creation JSON must include domain and license_key.');
    }
    const rec = store.create(body);
    process.stdout.write(`Created license:\n  ${JSON.stringify(stripLicenseSecret(rec), null, 2)}\n`);
    return;
  }
  if (args.list) {
    const recs = store.list();
    process.stdout.write(`${recs.length} license record(s):\n`);
    for (const r of recs) {
      process.stdout.write(`  ${r.license_id}  ${r.domain}  status=${r.status}  revoked=${r.revoked}\n`);
    }
    return;
  }
  if (args.revoke) {
    if (!args.reason) {
      process.stderr.write(`Error: --revoke requires --reason\n`);
      process.exit(1);
    }
    const updated = store.revoke(args.revoke, { reason: args.reason, revoked_by: 'cli' });
    if (!updated) {
      process.stderr.write(`Error: no license found with id ${args.revoke}\n`);
      process.exit(1);
    }
    process.stdout.write(`Revoked:\n  ${JSON.stringify(stripLicenseSecret(updated), null, 2)}\n`);
    return;
  }

  // Start the server
  const port = args.port ? parseInt(args.port, 10) : 3001;
  const host = args.host || '127.0.0.1';
  if (isNaN(port)) {
    process.stderr.write(`Error: invalid port: ${args.port}\n`);
    process.exit(1);
  }

  const adminSources = [
    args['admin-token-stdin'] ? 'stdin' : null,
    args['admin-token-file'] ? 'file' : null,
  ].filter(Boolean);
  if (adminSources.length > 1) {
    throw new Error('Choose exactly one admin-token private input source.');
  }
  const adminToken =
    adminSources.length === 0
      ? null
      : adminSources[0] === 'stdin'
        ? readPrivateStdin({ label: 'Admin token', maximum: MAX_ADMIN_TOKEN_BYTES })
        : readPrivateFile(args['admin-token-file'], {
            label: 'Admin token',
            maximum: MAX_ADMIN_TOKEN_BYTES,
          });

  const { server, port: actualPort, keys, dataDir: dd } = await startServer({
    dataDir,
    port,
    host,
    adminToken,
  });

  process.stdout.write(
    `kdna-activation-server ${pkg.version} listening on http://${host}:${actualPort}\n` +
      `  data_dir:     ${dd}\n` +
      `  admin_token:  ${adminToken ? '(configured from private input)' : '(NOT set — /revoke returns 401)'}\n` +
      `  public_key:   ${keys.publicPem.length} bytes (PEM, ed25519)\n` +
      `\n` +
      `Try:\n` +
      `  curl http://${host}:${actualPort}/healthz\n` +
      `  curl http://${host}:${actualPort}/server/identity\n` +
      `  Send activation JSON through stdin or a private request-body file; never place secrets in argv.\n` +
      `\n` +
      `Create a license from private stdin:\n` +
      `  kdna-activation-server --create-license-stdin\n`,
  );

  const shutdown = (signal) => {
    process.stdout.write(`\nReceived ${signal}, shutting down...\n`);
    stopServer(server).then(() => process.exit(0));
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

function stripLicenseSecret(record) {
  const out = { ...record };
  delete out.license_key;
  delete out.license_secret_verifier;
  return out;
}

main().catch((e) => {
  process.stderr.write(`Error: ${e.message}\n`);
  process.exit(1);
});
