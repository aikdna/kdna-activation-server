'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');
const pkg = require('../package.json');
const expected = ['src/index.js', 'src/index.d.ts', 'src/observer.js', 'src/store.js', 'src/contract.js', 'README.md', 'CHANGELOG.md', 'LICENSE', 'NOTICE', 'public-contract-binding.json'];
assert.deepEqual(pkg.files, expected);
assert.deepEqual(Object.keys(pkg.exports), ['.']);
assert.equal(pkg.bin, undefined);
for (const file of expected) assert.ok(fs.statSync(file).isFile(), file);
const api = require('..');
assert.deepEqual(Object.keys(api).sort(), ['createActivationObserver', 'createLicenseSecretVerifier', 'makeStore', 'verifyLicenseSecret'].sort());
for (const file of expected.filter(x => x.endsWith('.js'))) {
  const source = fs.readFileSync(file, 'utf8');
  assert.ok(!source.includes('@aikdna/kdna-core/schema'), file);
  assert.ok(!source.includes('@aikdna/kdna-core/package.json'), file);
}
const cli = spawnSync(process.execPath, ['bin/kdna-activation-server.js'], { encoding: 'utf8' });
assert.equal(cli.status, 1); assert.ok(cli.stderr.includes('ACTIVATION_LEGACY_CLI_UNAVAILABLE'));
console.log('current public surface and explicit legacy CLI refusal verified');
