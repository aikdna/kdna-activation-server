'use strict';

function fencedCodeBlocks(markdown) {
  const blocks = [];
  const pattern = /```[^\n]*\n([\s\S]*?)```/gu;
  let match;
  while ((match = pattern.exec(markdown)) !== null) blocks.push(match[1]);
  return blocks;
}

function unsafeSecretExamples(markdown) {
  const findings = [];
  for (const block of fencedCodeBlocks(markdown)) {
    if (/--admin-token(?!-(?:stdin|file)\b)(?:=|\s+)/u.test(block)) {
      findings.push('raw --admin-token command example');
    }
    if (/--create-license(?!-(?:stdin|file)\b)(?:=|\s+)/u.test(block)) {
      findings.push('raw --create-license command example');
    }
    if (
      /\bcurl\b[\s\S]{0,1200}(?:\s-d\b|\s--data(?:-raw)?\b)[\s\S]{0,600}(?:license_key|admin[_-]?token|password|secret)/iu.test(
        block,
      )
    ) {
      findings.push('secret-bearing inline curl body');
    }
  }
  return findings;
}

module.exports = {
  fencedCodeBlocks,
  unsafeSecretExamples,
};
