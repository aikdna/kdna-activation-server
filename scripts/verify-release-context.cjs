#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const NATURAL_SEMVER_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function headingCoordinate(line) {
  if (!line.startsWith('## ')) return null;
  const body = line.slice(3);
  const separator = body.indexOf(' ');
  return separator === -1 ? body : body.slice(0, separator);
}

function isExactReleaseHeading(line, version) {
  const bare = `## ${version}`;
  if (line === bare) return true;
  const datedPrefix = `${bare} (`;
  if (!line.startsWith(datedPrefix) || !line.endsWith(')')) return false;
  return ISO_DATE_RE.test(line.slice(datedPrefix.length, -1));
}

function verifyReleaseContext({ packageJson, changelog, releaseTag }) {
  const version = packageJson?.version;
  assert(
    typeof version === 'string' && NATURAL_SEMVER_RE.test(version),
    'package version must be an exact natural SemVer coordinate',
  );
  assert(
    typeof releaseTag === 'string' && NATURAL_SEMVER_RE.test(releaseTag),
    'release tag must be an exact natural SemVer coordinate',
  );
  assert(releaseTag === version, `release tag must be exactly ${version}`);

  const headings = String(changelog)
    .split(/\r?\n/)
    .filter((line) => line.startsWith('## '));
  assert(headings.length > 0, 'CHANGELOG has no release headings');
  assert(
    isExactReleaseHeading(headings[0], version),
    `first CHANGELOG release heading must be exactly ## ${version} or ## ${version} (YYYY-MM-DD)`,
  );
  const matchingHeadings = headings.filter((line) => headingCoordinate(line) === version);
  assert(matchingHeadings.length === 1, `CHANGELOG must contain exactly one heading for ${version}`);

  return { version, releaseTag, changelogHeading: headings[0] };
}

function main() {
  const root = path.resolve(__dirname, '..');
  const packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const changelog = fs.readFileSync(path.join(root, 'CHANGELOG.md'), 'utf8');
  try {
    const context = verifyReleaseContext({
      packageJson,
      changelog,
      releaseTag: process.env.RELEASE_TAG,
    });
    console.log(
      `Release context verified: ${packageJson.name}@${context.version} tag=${context.releaseTag}`,
    );
  } catch (error) {
    console.error(`Release context rejected: ${error.message}`);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = {
  isExactReleaseHeading,
  verifyReleaseContext,
};
