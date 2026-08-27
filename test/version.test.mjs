import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { KIT_VERSION } from '../src/version.mjs';

const root = path.resolve(import.meta.dirname, '..');
const executable = path.join(root, 'bin/sprintloop-assure.mjs');

test('version identity is exact across the package and CLI', async () => {
  const packageJson = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  assert.equal(KIT_VERSION, packageJson.version);

  for (const args of [['version'], ['--version'], ['-V']]) {
    const result = spawnSync(process.execPath, [executable, ...args], { cwd: root, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, `SprintLoop Assurance Kit ${KIT_VERSION}\n`);
    assert.equal(result.stderr, '');
  }

  const json = spawnSync(process.execPath, [executable, 'version', '--json'], { cwd: root, encoding: 'utf8' });
  assert.equal(json.status, 0, json.stderr);
  assert.deepEqual(JSON.parse(json.stdout), { name: '@sprintloop/assurance-kit', version: KIT_VERSION });
});

test('standard help forms are successful and write only to stdout', () => {
  for (const argument of ['help', '--help', '-h']) {
    const result = spawnSync(process.execPath, [executable, argument], { cwd: root, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Commands:\n  version \[--json\]/);
    assert.match(result.stdout, /Help flags \(top-level or after a command\): --help, -h/);
    assert.match(result.stdout, /Top-level version flags: --version, -V/);
    assert.equal(result.stderr, '');
  }
});

test('help and version scope is explicit and fail-closed', () => {
  for (const args of [['demo', '-h'], ['demo', '--help'], ['mcp', '-h'], ['mcp', '--help']]) {
    const result = spawnSync(process.execPath, [executable, ...args], { cwd: root, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, '');
  }
  for (const args of [['demo', '--version'], ['demo', '-V'], ['mcp', '--version'], ['mcp', '-V']]) {
    const result = spawnSync(process.execPath, [executable, ...args], { cwd: root, encoding: 'utf8' });
    assert.equal(result.status, 2);
    assert.equal(result.stdout, '');
  }
});
