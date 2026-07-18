#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const excluded = new Set(['.git', 'node_modules']);
const textExtensions = new Set(['.js', '.json', '.md', '.yml', '.yaml', '.txt']);
const retired = [
  ['retired manifest discriminator', /kdna_version/],
  ['retired judgment profile', /judgment-profile-v1/i],
  ['retired Capsule discriminator', /kdna\.context\.capsule/i],
  ['generation-shaped entitlement route', /\/v1\/entitlements\/(?:activate|sync|status|revoke)/i],
  ['generation-style integer label', /(?:^|[^A-Za-z0-9.])[Vv][0-9]+(?![0-9.])/],
  ['generation suffix on a KDNA-owned name', /\bkdna[a-z0-9_.:-]*[-_.]v[0-9]+(?![0-9.])/i],
];
const findings = [];

function isRemovedRouteEvidence(relative, line) {
  return relative === 'tests/server.test.js' &&
    /['"]\/v1\/entitlements\/(?:activate|sync|status|revoke)['"]/.test(line);
}

function visit(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (excluded.has(entry.name)) continue;
    const absolute = path.join(directory, entry.name);
    const relative = path.relative(root, absolute).split(path.sep).join('/');
    if (entry.isDirectory()) {
      visit(absolute);
      continue;
    }
    if (!entry.isFile() || !textExtensions.has(path.extname(entry.name))) continue;
    if (relative === 'scripts/check-protocol-names.js') continue;
    const bytes = fs.readFileSync(absolute);
    if (bytes.length > 1_000_000 || bytes.includes(0)) continue;
    const lines = bytes.toString('utf8').split(/\r?\n/);
    lines.forEach((rawLine, index) => {
      const line = rawLine.replace(/("integrity"\s*:\s*")[^"]+(")/g, '$1<opaque digest>$2');
      for (const [rule, pattern] of retired) {
        pattern.lastIndex = 0;
        if (!pattern.test(line)) continue;
        if (rule === 'generation-shaped entitlement route' && isRemovedRouteEvidence(relative, line)) {
          continue;
        }
        findings.push(`${relative}:${index + 1}: ${rule}`);
      }
    });
  }
}

visit(root);
if (findings.length) {
  for (const finding of findings) console.error(finding);
  throw new Error(`protocol naming gate found ${findings.length} issue(s)`);
}
console.log('Protocol naming gate passed.');
