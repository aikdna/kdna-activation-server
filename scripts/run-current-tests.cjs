'use strict';
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const supplied = process.env.KDNA_TEST_DIR;
if (supplied && !path.isAbsolute(supplied)) throw new Error('KDNA_TEST_DIR must be absolute.');
const root = supplied || fs.mkdtempSync(path.join(os.tmpdir(), 'kdna-activation-tests-'));
try {
  const check = spawnSync(process.execPath, ['scripts/check-current-surface.cjs'], { stdio: 'inherit' });
  if (check.status !== 0) process.exitCode = check.status ?? 1;
  else {
    const result = spawnSync(process.execPath, ['--unhandled-rejections=strict', '--test', '--test-timeout=30000', 'tests/current-observer.test.mjs', 'tests/vendor-provenance.test.cjs'],
      { stdio: 'inherit', env: { ...process.env, KDNA_TEST_DIR: root } });
    process.exitCode = result.status ?? 1;
    if (process.exitCode === 0) {
      const components = spawnSync(process.execPath, ['tests/components/current-components.mjs', 'activation'], { stdio: 'inherit', env: { ...process.env, KDNA_TEST_DIR: root } });
      process.exitCode = components.status ?? 1;
    }
  }
} finally { if (!supplied) fs.rmSync(root, { recursive: true, force: true }); }
