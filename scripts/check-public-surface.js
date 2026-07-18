#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const excluded = new Set(['.git', 'node_modules']);
const textExtensions = new Set(['.js', '.json', '.md', '.yml', '.yaml', '.txt']);
const findings = [];

function visit(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (excluded.has(entry.name)) continue;
    const absolute = path.join(directory, entry.name);
    const relative = path.relative(root, absolute).split(path.sep).join('/');
    if (entry.isSymbolicLink()) {
      findings.push(`${relative}: repository contains a symlink`);
      continue;
    }
    if (entry.isDirectory()) {
      visit(absolute);
      continue;
    }
    if (!entry.isFile() || (!textExtensions.has(path.extname(entry.name)) && entry.name !== 'NOTICE')) {
      continue;
    }
    const bytes = fs.readFileSync(absolute);
    if (bytes.length > 1_000_000 || bytes.includes(0)) continue;
    const text = bytes.toString('utf8');
    if (/\/Users\/(?!<user>\/|you\/|username\/)[^/\s]+\//.test(text)) {
      findings.push(`${relative}: machine-specific filesystem path`);
    }
    const privateLicensePrefix = `${['KDNA', 'LIC'].join('-')}-`;
    if (text.includes(privateLicensePrefix)) {
      findings.push(`${relative}: credential prefix or token-shaped example`);
    }
    if (/(?:^|\/)(?:AGENTS|WORKLOG)\.md$/i.test(relative)) {
      findings.push(`${relative}: private coordination file`);
    }
  }
}

visit(root);
if (findings.length) {
  for (const finding of findings) console.error(finding);
  throw new Error(`public-surface check found ${findings.length} issue(s)`);
}
console.log('Public-surface check passed.');
