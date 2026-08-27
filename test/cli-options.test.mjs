import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const root = path.resolve(import.meta.dirname, '..');
const executable = path.join(root, 'bin/sprintloop-assure.mjs');

function run(...args) {
  return spawnSync(process.execPath, [executable, ...args], { cwd: root, encoding: 'utf8' });
}

test('unknown, duplicate, positional, and valued boolean options fail closed', () => {
  const cases = [
    { args: ['demo', '--bogus-option', 'ignored'], message: /Unknown option: --bogus-option/ },
    { args: ['demo', 'unexpected'], message: /Unexpected positional argument: unexpected/ },
    { args: ['demo', '--out', 'one', '--out', 'two'], message: /Duplicate --out/ },
    { args: ['version', '--json=false'], message: /--json does not accept a value/ },
  ];

  for (const entry of cases) {
    const result = run(...entry.args);
    assert.equal(result.status, 2, `${entry.args.join(' ')} unexpectedly succeeded`);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, entry.message);
  }
});

test('option parsing preserves equals signs and rejects noncanonical aliases', () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'assurance-cli-option-'));
  try {
    const file = path.join(directory, 'package=lock.json');
    writeFileSync(file, '{}\n');
    const exact = run('digest', `--file=${file}`);
    assert.equal(exact.status, 0, exact.stderr);
    assert.match(exact.stdout, /^sha256:[0-9a-f]{64}\n$/);

    for (const args of [
      ['demo', '--tree_digest', '0'.repeat(40)],
      ['demo', '--Tree-Digest', '0'.repeat(40)],
      ['demo', '--', 'value'],
      ['demo', '--help=unexpected'],
      ['demo', '-h', '--out', 'elsewhere'],
    ]) {
      const result = run(...args);
      assert.equal(result.status, 2, `${args.join(' ')} unexpectedly succeeded`);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('documented boolean flags remain exact presence-only flags', () => {
  const version = run('version', '--json');
  assert.equal(version.status, 0, version.stderr);
  assert.equal(JSON.parse(version.stdout).version, '0.3.0');

  const help = run('demo', '--help');
  assert.equal(help.status, 0, help.stderr);
  assert.match(help.stdout, /SprintLoop Assurance Kit/);

  const shortHelp = run('demo', '-h');
  assert.equal(shortHelp.status, 0, shortHelp.stderr);
  assert.match(shortHelp.stdout, /SprintLoop Assurance Kit/);
});
