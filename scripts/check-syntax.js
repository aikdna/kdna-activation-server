'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const SOURCE_DIRECTORIES = ['bin', 'scripts', 'src', 'tests'];
const JAVASCRIPT_EXTENSIONS = new Set(['.cjs', '.js', '.mjs']);

function sourceFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) => {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) return sourceFiles(absolute);
      return JAVASCRIPT_EXTENSIONS.has(path.extname(entry.name)) ? [absolute] : [];
    })
    .sort();
}

for (const file of SOURCE_DIRECTORIES.flatMap((directory) => sourceFiles(path.join(ROOT, directory)))) {
  const result = spawnSync(process.execPath, ['--check', file], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  if (result.status !== 0) {
    process.stderr.write(result.stderr || 'JavaScript syntax check failed.\n');
    process.exit(1);
  }
}

process.stdout.write('JavaScript syntax check passed.\n');
