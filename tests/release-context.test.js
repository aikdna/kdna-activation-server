'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const {
  verifyReleaseContext,
  verifyReleaseEvent,
  verifyRuntimeDependency,
} = require('../scripts/verify-release-context.cjs');

const ROOT = path.resolve(__dirname, '..');
const PACKAGE_JSON = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const PACKAGE_LOCK = JSON.parse(fs.readFileSync(path.join(ROOT, 'package-lock.json'), 'utf8'));
const WORKFLOW = fs.readFileSync(path.join(ROOT, '.github/workflows/publish.yml'), 'utf8');
const SCRIPT = path.join(ROOT, 'scripts/verify-release-context.cjs');

function changelogFor(heading, extra = '') {
  return `# Changelog

${heading}

- Release notes.
${extra}`;
}

test('release context accepts the exact natural SemVer tag and literal top CHANGELOG heading', () => {
  const version = PACKAGE_JSON.version;
  assert.equal(
    verifyReleaseContext({
      packageJson: PACKAGE_JSON,
      changelog: changelogFor(`## ${version}`),
      releaseTag: version,
    }).changelogHeading,
    `## ${version}`,
  );
  assert.deepEqual(
    verifyReleaseContext({
      packageJson: PACKAGE_JSON,
      changelog: changelogFor(`## ${version} (2026-07-16)`),
      releaseTag: version,
    }),
    {
      version,
      releaseTag: version,
      changelogHeading: `## ${version} (2026-07-16)`,
    },
  );

  const result = spawnSync(process.execPath, [SCRIPT], {
    cwd: ROOT,
    encoding: 'utf8',
    env: {
      ...process.env,
      RELEASE_EVENT_ACTION: 'published',
      RELEASE_IS_DRAFT: 'false',
      RELEASE_IS_PRERELEASE: 'false',
      RELEASE_TAG: version,
    },
  });
  assert.equal(result.status, 0, result.stderr);
});
test('release context rejects version drift and generation-shaped tag forms', () => {
  const version = PACKAGE_JSON.version;
  for (const releaseTag of [
    '9.9.9',
    `0${version}`,
    `${version}-preview`,
    `${version}+build`,
  ]) {
    assert.throws(
      () => verifyReleaseContext({
        packageJson: PACKAGE_JSON,
        changelog: changelogFor(`## ${version} (2026-07-16)`),
        releaseTag,
      }),
      /natural SemVer|release tag must be exactly/,
      releaseTag,
    );
  }
  for (const packageVersion of [
    `0${version}`,
    `v${version}`,
    `${version}-preview`,
    `${version}+build`,
  ]) {
    assert.throws(
      () => verifyReleaseContext({
        packageJson: { ...PACKAGE_JSON, version: packageVersion },
        changelog: changelogFor(`## ${version}`),
        releaseTag: version,
      }),
      /package version must be an exact natural SemVer coordinate/,
      packageVersion,
    );
  }
});

test('release event and exact Core dependency fail closed', () => {
  assert.deepEqual(
    verifyReleaseEvent({ action: 'published', isDraft: 'false', isPrerelease: 'false' }),
    { action: 'published', isDraft: 'false', isPrerelease: 'false' },
  );
  for (const event of [
    { action: 'created', isDraft: 'false', isPrerelease: 'false' },
    { action: 'published', isDraft: 'true', isPrerelease: 'false' },
    { action: 'published', isDraft: 'false', isPrerelease: 'true' },
  ]) {
    assert.throws(() => verifyReleaseEvent(event), /release|draft|prerelease/);
  }
  assert.doesNotThrow(() => verifyRuntimeDependency(PACKAGE_JSON, PACKAGE_LOCK));
  assert.throws(
    () => verifyRuntimeDependency(
      { ...PACKAGE_JSON, dependencies: { '@aikdna/kdna-core': '^0.20.0' } },
      PACKAGE_LOCK,
    ),
    /exact @aikdna\/kdna-core/,
  );
});

test('a command-injection-shaped legal Git tag is data, never shell source', () => {
  const version = PACKAGE_JSON.version;
  const maliciousTag = `${version}';printf\${IFS}TAG_INTERPOLATION_EXECUTED;#`;
  const git = spawnSync('git', ['check-ref-format', `refs/tags/${maliciousTag}`]);
  assert.equal(git.status, 0, 'hostile fixture must remain a Git-legal tag');

  const result = spawnSync(process.execPath, [SCRIPT], {
    cwd: ROOT,
    encoding: 'utf8',
    env: {
      ...process.env,
      RELEASE_EVENT_ACTION: 'published',
      RELEASE_IS_DRAFT: 'false',
      RELEASE_IS_PRERELEASE: 'false',
      RELEASE_TAG: maliciousTag,
    },
  });
  assert.notEqual(result.status, 0);
  assert.doesNotMatch(`${result.stdout}${result.stderr}`, /TAG_INTERPOLATION_EXECUTED/);
  assert.match(result.stderr, /exact natural SemVer/);
});

test('near-match, stale, and duplicate CHANGELOG headings fail closed', () => {
  const version = PACKAGE_JSON.version;
  const approximateHeadings = [
    `## ${version}.1 (2026-07-16)`,
    `## ${version}1 (2026-07-16)`,
    `### ${version} (2026-07-16)`,
    `## ${version}-preview (2026-07-16)`,
    `## ${version} notes`,
    `## ${version}\t(2026-07-16)`,
    `## ${version}\v(2026-07-16)`,
    `## ${version}: duplicate`,
    `## ${version}  (2026-07-16)`,
    `## ${version}\u00a0(2026-07-16)`,
    `##\t${version}`,
    ` ## ${version}`,
    '## 01.2.3',
    '## 1.2.3-preview',
    '## 1.2.3+build',
  ];
  for (const heading of approximateHeadings) {
    assert.throws(
      () => verifyReleaseContext({
        packageJson: PACKAGE_JSON,
        changelog: changelogFor(heading),
        releaseTag: version,
      }),
      /CHANGELOG/,
      heading,
    );
  }

  assert.throws(
    () => verifyReleaseContext({
      packageJson: PACKAGE_JSON,
      changelog: changelogFor(
        '## 9.9.9 (2026-07-16)',
        `
## ${version} (2026-07-15)
`,
      ),
      releaseTag: version,
    }),
    /first CHANGELOG release heading/,
  );
  assert.throws(
    () => verifyReleaseContext({
      packageJson: PACKAGE_JSON,
      changelog: changelogFor(
        `## ${version} (2026-07-16)`,
        `
## ${version}
`,
      ),
      releaseTag: version,
    }),
    /exactly one heading/,
  );

  const approximateDuplicates = [
    `## ${version}\t(2026-07-15)`,
    `## ${version}\v(2026-07-15)`,
    `## ${version}: duplicate`,
    `## ${version}  (2026-07-15)`,
    `## ${version}\u2003(2026-07-15)`,
  ];
  for (const duplicate of approximateDuplicates) {
    assert.throws(
      () => verifyReleaseContext({
        packageJson: PACKAGE_JSON,
        changelog: changelogFor(
          `## ${version} (2026-07-16)`,
          `\n${duplicate}\n`,
        ),
        releaseTag: version,
      }),
      /CHANGELOG/,
      duplicate,
    );
  }

  assert.throws(
    () => verifyReleaseContext({
      packageJson: PACKAGE_JSON,
      changelog: changelogFor(
        `## ${version} (2026-07-16)`,
        `\u2028## ${version}\u2029`,
      ),
      releaseTag: version,
    }),
    /exactly one heading/,
  );

  assert.throws(
    () => verifyReleaseContext({
      packageJson: PACKAGE_JSON,
      changelog: changelogFor(
        `## ${version} (2026-07-16)`,
        `\u0085## ${version}\u0085`,
      ),
      releaseTag: version,
    }),
    /exactly one heading/,
  );

  for (const changelog of [
    changelogFor(`## ${version}`, `\n${version}\n---\n`),
    `# Changelog\n\n9.9.9\n---\n\n## ${version}\n`,
  ]) {
    assert.throws(
      () => verifyReleaseContext({ packageJson: PACKAGE_JSON, changelog, releaseTag: version }),
      /Setext H2/,
    );
  }
});

test('publish workflow is release-only and passes the tag only through env', () => {
  assert.match(WORKFLOW, /release:\s*\n\s+types: \[published\]/);
  assert.doesNotMatch(WORKFLOW, /workflow_dispatch/);
  assert.match(WORKFLOW, /run: node scripts\/verify-release-context\.cjs/);
  assert.match(WORKFLOW, /actions\/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0/);
  assert.match(WORKFLOW, /actions\/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38/);
  assert.doesNotMatch(WORKFLOW, /actions\/(?:checkout|setup-node)@v\d+/);
  assert.match(WORKFLOW, /RELEASE_EVENT_ACTION: \$\{\{ github\.event\.action \}\}/);
  assert.match(WORKFLOW, /RELEASE_IS_DRAFT: \$\{\{ github\.event\.release\.draft \}\}/);
  assert.match(WORKFLOW, /RELEASE_IS_PRERELEASE: \$\{\{ github\.event\.release\.prerelease \}\}/);

  const expression = '$' + '{{ github.event.release.tag_name }}';
  const expressionLines = WORKFLOW
    .split(/\r?\n/)
    .filter((line) => line.includes(expression))
    .map((line) => line.trim());
  assert.equal(expressionLines.includes(`RELEASE_TAG: ${expression}`), true);
  assert.equal(expressionLines.includes(`ref: ${expression}`), true);
});
