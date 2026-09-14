'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { verifyVendorProvenance } = require('../scripts/check-vendor-provenance.cjs');
const source = path.resolve(__dirname, '..');

function fixture(fn) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'activation-provenance-'));
  try {
    fs.cpSync(path.join(source, 'vendor'), path.join(root, 'vendor'), { recursive: true });
    fs.copyFileSync(path.join(source, 'package-lock.json'), path.join(root, 'package-lock.json'));
    fn(root);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
function editRows(root, edit) {
  const file = path.join(root, 'vendor/provenance.json');
  const rows = JSON.parse(fs.readFileSync(file, 'utf8'));
  edit(rows);
  fs.writeFileSync(file, JSON.stringify(rows));
}
function editLock(root, edit) {
  const file = path.join(root, 'package-lock.json');
  const lock = JSON.parse(fs.readFileSync(file, 'utf8'));
  const entry = Object.values(lock.packages).find(x => x.resolved?.startsWith('file:'));
  edit(entry);
  fs.writeFileSync(file, JSON.stringify(lock));
}

test('current archives have complete exact provenance and matching local locks', () => {
  assert.equal(verifyVendorProvenance(), fs.readdirSync(path.join(source, 'vendor')).filter(x => x.endsWith('.tgz')).length);
});
const mutations = [
  ['stale absent record', root => editRows(root, rows => rows.push({ ...rows[0], name: 'stale-package', tar: 'vendor/stale-package.tgz' }))],
  ['unrecorded archive', root => fs.copyFileSync(path.join(root, 'vendor', fs.readdirSync(path.join(root, 'vendor')).find(x => x.endsWith('.tgz'))), path.join(root, 'vendor/unrecorded.tgz'))],
  ['missing archive', root => editRows(root, rows => fs.unlinkSync(path.join(root, rows[0].tar)))],
  ['duplicate record', root => editRows(root, rows => rows.push(rows[0]))],
  ['wrong byte count', root => editRows(root, rows => rows[0].bytes++)],
  ['wrong SHA-256', root => editRows(root, rows => rows[0].sha256 = '0'.repeat(64))],
  ['wrong integrity', root => editRows(root, rows => rows[0].sha512 += 'x')],
  ['changed archive bytes', root => editRows(root, rows => fs.appendFileSync(path.join(root, rows[0].tar), 'changed'))],
  ['path traversal', root => editRows(root, rows => rows[0].tar = 'vendor/../package-lock.json.tgz')],
  ['absolute path', root => editRows(root, rows => rows[0].tar = path.join(root, rows[0].tar))],
  ['symlink archive', root => editRows(root, rows => { const file = path.join(root, rows[0].tar); fs.unlinkSync(file); fs.symlinkSync('provenance.json', file); })],
  ['directory archive', root => editRows(root, rows => { const file = path.join(root, rows[0].tar); fs.unlinkSync(file); fs.mkdirSync(file); })],
  ['local lock missing provenance', root => editLock(root, entry => entry.resolved = 'file:vendor/absent.tgz')],
  ['local lock wrong integrity', root => editLock(root, entry => entry.integrity += 'x')],
  ['local lock wrong version', root => editLock(root, entry => entry.version = '0.0.0')],
  ['local lock wrong package name', root => editRows(root, rows => rows.find(x => x.name === '@aikdna/kdna-core').name = 'wrong-package')],
];
for (const [name, mutate] of mutations) {
  test(`rejects ${name}`, () => fixture(root => {
    verifyVendorProvenance(root);
    mutate(root);
    assert.throws(() => verifyVendorProvenance(root));
  }));
}
