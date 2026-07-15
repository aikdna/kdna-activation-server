#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const NATURAL_SEMVER_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const RELEASE_HEADING_RE =
  /^## ((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))(?: \((\d{4}-\d{2}-\d{2})\))?$/;
const FORBIDDEN_CHANGELOG_CONTROL_RE =
  /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u0084\u0086-\u009f]/u;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function parseReleaseHeading(line) {
  const match = RELEASE_HEADING_RE.exec(line);
  if (!match || (match[2] !== undefined && !ISO_DATE_RE.test(match[2]))) return null;
  return { line, version: match[1] };
}

function isExactReleaseHeading(line, version) {
  const heading = parseReleaseHeading(line);
  return heading !== null && heading.version === version;
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

  const changelogText = String(changelog);
  assert(
    !FORBIDDEN_CHANGELOG_CONTROL_RE.test(changelogText),
    'CHANGELOG contains an unsupported control separator',
  );
  const lines = changelogText.split(/\r\n|[\n\r\u0085\u2028\u2029]/);
  const hasSetextH2 = lines.some(
    (line, index) => index > 0 && /^-+$/.test(line.trim()) && lines[index - 1].trim() !== '',
  );
  assert(
    !hasSetextH2,
    'CHANGELOG release headings must not use Setext H2; use the exact ## x.y.z syntax',
  );
  const headings = lines.filter((line) => /^\s*##(?!#)/u.test(line));
  assert(headings.length > 0, 'CHANGELOG has no release headings');
  const parsedHeadings = headings.map(parseReleaseHeading);
  assert(
    parsedHeadings.every((heading) => heading !== null),
    'every CHANGELOG H2 release heading must be exactly ## x.y.z or ## x.y.z (YYYY-MM-DD)',
  );
  assert(
    isExactReleaseHeading(headings[0], version),
    `first CHANGELOG release heading must be exactly ## ${version} or ## ${version} (YYYY-MM-DD)`,
  );
  const matchingHeadings = parsedHeadings.filter((heading) => heading.version === version);
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
