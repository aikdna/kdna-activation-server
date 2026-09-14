'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');

function verifyVendorProvenance(root = path.resolve(__dirname, '..')) {
  const vendor = path.join(root, 'vendor');
  assert.ok(fs.lstatSync(vendor).isDirectory(), 'vendor must be a real directory');
  const rows = JSON.parse(fs.readFileSync(path.join(vendor, 'provenance.json'), 'utf8'));
  assert.ok(Array.isArray(rows) && rows.length > 0, 'provenance must be a nonempty array');
  const files = fs.readdirSync(vendor).filter(name => name.endsWith('.tgz')).map(name => `vendor/${name}`).sort();
  const names = new Set();
  const byTar = new Map();
  for (const row of rows) {
    assert.ok(row && typeof row === 'object' && !Array.isArray(row), 'invalid provenance row');
    assert.match(row.tar || '', /^vendor\/[A-Za-z0-9][A-Za-z0-9._-]*\.tgz$/, 'unsafe archive path');
    assert.ok(!byTar.has(row.tar), 'duplicate archive record');
    assert.equal(typeof row.name, 'string', 'package name must be a string');
    assert.equal(typeof row.version, 'string', 'package version must be a string');
    assert.ok(row.name.length && row.version.length, 'package coordinates must not be empty');
    assert.ok(!names.has(row.name), 'duplicate package record');
    names.add(row.name);
    assert.ok(fs.lstatSync(path.join(root, row.tar)).isFile(), 'archive must be a regular file');
    const bytes = fs.readFileSync(path.join(root, row.tar));
    assert.equal(row.bytes, bytes.length, 'archive byte count differs');
    assert.equal(row.sha256, createHash('sha256').update(bytes).digest('hex'), 'archive SHA-256 differs');
    assert.equal(row.sha512, `sha512-${createHash('sha512').update(bytes).digest('base64')}`, 'archive integrity differs');
    byTar.set(row.tar, row);
  }
  assert.deepEqual([...byTar.keys()].sort(), files, 'archive inventory differs');
  const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
  assert.ok(lock.packages && typeof lock.packages === 'object', 'lock packages must exist');
  for (const [location, entry] of Object.entries(lock.packages)) {
    if (!entry.resolved?.startsWith('file:')) continue;
    const row = byTar.get(entry.resolved.slice(5));
    assert.ok(row, 'local lock archive has no provenance');
    assert.equal(entry.integrity, row.sha512, 'lock integrity differs');
    assert.equal(entry.version, row.version, 'lock package version differs');
    assert.ok(location.endsWith(`node_modules/${row.name}`), 'lock package name differs');
  }
  return rows.length;
}

if (require.main === module) {
  console.log(`Verified ${verifyVendorProvenance()} exact vendor provenance records.`);
}
module.exports = { verifyVendorProvenance };
