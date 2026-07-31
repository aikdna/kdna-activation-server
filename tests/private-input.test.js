'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  PrivateInputError,
  decodePrivateBytes,
  readPrivateFile,
} = require('../src/private-input');
const { unsafeSecretExamples } = require('../scripts/public-secret-example-policy');

function privateDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'kdna-activation-private-input-'));
}

test('private input preserves whitespace and removes at most one transport line ending', () => {
  const options = { label: 'Secret', maximum: 64 };
  assert.equal(decodePrivateBytes(Buffer.from(' leading and trailing '), options), ' leading and trailing ');
  assert.equal(decodePrivateBytes(Buffer.from('no-newline'), options), 'no-newline');
  assert.equal(decodePrivateBytes(Buffer.from('crlf value \r\n'), options), 'crlf value ');
  assert.equal(decodePrivateBytes(Buffer.from('embedded\nnewline\n'), options), 'embedded\nnewline');
  assert.equal(decodePrivateBytes(Buffer.from('two\n\n'), options), 'two\n');
});

test('private input rejects empty, oversized, and invalid UTF-8 without echoing bytes', () => {
  const cases = [
    [Buffer.alloc(0), 'PRIVATE_INPUT_EMPTY'],
    [Buffer.from('12345'), 'PRIVATE_INPUT_TOO_LARGE'],
    [Buffer.from([0xc3, 0x28]), 'PRIVATE_INPUT_ENCODING'],
  ];
  for (const [bytes, code] of cases) {
    const original = Buffer.from(bytes);
    assert.throws(
      () => decodePrivateBytes(bytes, { label: 'Secret', maximum: 4 }),
      (error) =>
        error instanceof PrivateInputError &&
        error.code === code &&
        (original.length === 0 || !error.message.includes(original.toString('hex'))),
    );
    assert.equal(bytes.every((byte) => byte === 0), true);
  }
});

test('private files require one stable mode-0600 regular file and reject symlinks', () => {
  const directory = privateDirectory();
  try {
    const safe = path.join(directory, 'safe');
    fs.writeFileSync(safe, ' exact file value \n', { mode: 0o600 });
    assert.equal(
      readPrivateFile(safe, { label: 'Secret', maximum: 64 }),
      ' exact file value ',
    );

    fs.chmodSync(safe, 0o640);
    assert.throws(
      () => readPrivateFile(safe, { label: 'Secret', maximum: 64 }),
      (error) => error.code === 'PRIVATE_INPUT_PERMISSIONS',
    );
    fs.chmodSync(safe, 0o600);

    const link = path.join(directory, 'link');
    fs.symlinkSync(safe, link);
    assert.throws(
      () => readPrivateFile(link, { label: 'Secret', maximum: 64 }),
      (error) => error.code === 'PRIVATE_INPUT_FILE',
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('public example policy rejects secret argv and inline curl bodies but permits private sources', () => {
  const unsafe = [
    ['admin', '--admin', '-token'].join(''),
    ['create', '--create', '-license'].join(''),
  ];
  const hostile = [
    `\`\`\`bash\nserver ${unsafe[0]} "real-secret"\n\`\`\``,
    `\`\`\`bash\nserver ${unsafe[1]} '{"license_key":"real-secret"}'\n\`\`\``,
    `\`\`\`bash\ncurl -d '{"license_key":"real-secret"}' https://example.invalid\n\`\`\``,
  ];
  for (const markdown of hostile) assert.equal(unsafeSecretExamples(markdown).length, 1);

  const safe = [
    '```bash\nserver --admin-token-file ./token\n```',
    '```bash\nserver --create-license-stdin < ./request.json\n```',
    "```bash\ncurl --data-binary @./private-request.json https://example.invalid\n```",
  ];
  for (const markdown of safe) assert.deepEqual(unsafeSecretExamples(markdown), []);
});
