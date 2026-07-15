#!/usr/bin/env node
/**
 * kdna-activation-server — CLI entry (Story 24)
 *
 * Self-hostable HTTP activation server. See README.md for
 * self-hosting instructions.
 *
 * Usage:
 *   kdna-activation-server [--port 3001] [--data-dir <path>]
 *                          [--admin-token <secret>]
 *                          [--create-license <json>]
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
const pkg = require('../package.json');

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
  kdna-activation-server --create-license '<json>' [--data-dir <path>]
  kdna-activation-server --list [--data-dir <path>]
  kdna-activation-server --revoke <license-id> --reason "..." [--data-dir <path>]

Server options:
  --port <n>             Port to listen on. Default 3001.
  --host <addr>          Host to bind. Default 127.0.0.1.
  --data-dir <path>      Where to store entitlement records +
                         server keypair. Default
                         ~/.kdna/activation-server.
  --admin-token <secret> Bearer token for the /entitlements/revoke
                         endpoint. If unset, /revoke returns 401.
                         Set this if you want to be able to revoke
                         licenses via HTTP.

One-shot commands (do not start the server):
  --create-license '<json>'
                        Create a new license record. The JSON
                        must contain: domain, license_key.
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
  const args = parseArgs(process.argv.slice(2));
  if (args.help || args.h) {
    process.stdout.write(help());
    return;
  }

  const dataDir = args['data-dir'] || DEFAULT_DATA_DIR;
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const store = makeStore(dataDir);

  // One-shot commands
  if (args['create-license']) {
    let body;
    try {
      body = JSON.parse(args['create-license']);
    } catch (e) {
      process.stderr.write(`Error: --create-license value is not valid JSON: ${e.message}\n`);
      process.exit(1);
    }
    if (!body.domain || !body.license_key) {
      process.stderr.write(`Error: --create-license JSON must include domain and license_key\n`);
      process.exit(1);
    }
    const rec = store.create(body);
    process.stdout.write(`Created license:\n  ${JSON.stringify(rec, null, 2)}\n`);
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
    process.stdout.write(`Revoked:\n  ${JSON.stringify(updated, null, 2)}\n`);
    return;
  }

  // Start the server
  const port = args.port ? parseInt(args.port, 10) : 3001;
  const host = args.host || '127.0.0.1';
  if (isNaN(port)) {
    process.stderr.write(`Error: invalid port: ${args.port}\n`);
    process.exit(1);
  }

  const { server, port: actualPort, keys, dataDir: dd } = await startServer({
    dataDir,
    port,
    host,
    adminToken: args['admin-token'] || null,
  });

  process.stdout.write(
    `kdna-activation-server ${pkg.version} listening on http://${host}:${actualPort}\n` +
      `  data_dir:     ${dd}\n` +
      `  admin_token:  ${args['admin-token'] ? '(configured)' : '(NOT set — /revoke returns 401)'}\n` +
      `  public_key:   ${keys.publicPem.length} bytes (PEM, ed25519)\n` +
      `\n` +
      `Try:\n` +
      `  curl http://${host}:${actualPort}/healthz\n` +
      `  curl http://${host}:${actualPort}/server/identity\n` +
      `  curl -X POST http://${host}:${actualPort}/entitlements/activate \\\n` +
      `    -H 'Content-Type: application/json' \\\n` +
      `    -d '{"domain":"@yourname/your-asset","license_key":"KDNA-LIC-...","machine_fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'\n` +
      `\n` +
      `Create a license:\n` +
      `  kdna-activation-server --create-license '{"domain":"@yourname/your-asset","license_key":"KDNA-LIC-test1"}'\n`,
  );

  const shutdown = (signal) => {
    process.stdout.write(`\nReceived ${signal}, shutting down...\n`);
    stopServer(server).then(() => process.exit(0));
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((e) => {
  process.stderr.write(`Error: ${e.message}\n`);
  process.exit(1);
});
