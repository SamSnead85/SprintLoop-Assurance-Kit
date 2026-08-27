import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const sourceScanner = path.resolve(import.meta.dirname, '../scripts/scan-sensitive.mjs');

test('sensitive scan detects expanded key/token families inside text and binary files', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'assurance-sensitive-scan-'));
  try {
    await mkdir(path.join(root, 'scripts'));
    await copyFile(sourceScanner, path.join(root, 'scripts/scan-sensitive.mjs'));
    const privateKey = ['-----BEGIN RSA ', 'PRIVATE', ' KEY-----'].join('');
    const githubToken = ['gh', 'o_', 'A'.repeat(36)].join('');
    const additionalTokens = [
      ['sk-', 'proj-', 'A'.repeat(24)].join(''),
      ['sk-', 'ant-', 'B'.repeat(24)].join(''),
      ['AI', 'za', 'C'.repeat(35)].join(''),
      ['n', 'pm_', 'D'.repeat(36)].join(''),
      ['py', 'pi-', 'E'.repeat(36)].join(''),
      ['h', 'f_', 'F'.repeat(36)].join(''),
      ['sk_', 'live_', 'G'.repeat(24)].join(''),
    ];
    await writeFile(path.join(root, 'unsafe.txt'), `${privateKey}\n`);
    await writeFile(path.join(root, 'unsafe.bin'), Buffer.concat([
      Buffer.from([0, 1, 2]),
      Buffer.from(githubToken, 'ascii'),
      Buffer.from([0, 3]),
    ]));
    await writeFile(path.join(root, 'more-unsafe.txt'), `${additionalTokens.join('\n')}\n`);

    const result = runScanner(root);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /unsafe\.txt: private-key/);
    assert.match(result.stderr, /unsafe\.bin: github-token/);
    for (const label of [
      'openai-token',
      'anthropic-token',
      'google-api-key',
      'npm-token',
      'pypi-token',
      'huggingface-token',
      'stripe-live-key',
    ]) assert.match(result.stderr, new RegExp(`more-unsafe\\.txt: ${label}`));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('sensitive scan accepts a clean source fixture', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'assurance-sensitive-clean-'));
  try {
    await mkdir(path.join(root, 'scripts'));
    await copyFile(sourceScanner, path.join(root, 'scripts/scan-sensitive.mjs'));
    await writeFile(path.join(root, 'README.md'), 'Synthetic public fixture with no credentials.\n');
    const result = runScanner(root);
    assert.equal(result.status, 0, result.stderr);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

function runScanner(root) {
  return spawnSync(process.execPath, ['scripts/scan-sensitive.mjs'], {
    cwd: root,
    encoding: 'utf8',
  });
}
