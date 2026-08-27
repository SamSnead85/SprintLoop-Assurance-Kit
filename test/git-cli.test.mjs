import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createExampleBundle, writeExampleBundle } from '../src/example.mjs';

const kitRoot = path.resolve(import.meta.dirname, '..');

test('CLI check binds required candidate to actual Git HEAD, tree, and clean tracked state', async () => {
  const fixtureRoot = await mkdtemp(path.join(os.tmpdir(), 'assurance-git-check-'));
  const repositoryRoot = path.join(fixtureRoot, 'candidate');
  try {
    await mkdir(repositoryRoot, { recursive: true });
    await writeFile(path.join(repositoryRoot, 'service.txt'), 'candidate bytes\n');
    git(repositoryRoot, ['init', '--quiet']);
    git(repositoryRoot, ['add', 'service.txt']);
    git(repositoryRoot, ['-c', 'user.name=fixture', '-c', 'user.email=fixture@invalid', 'commit', '--quiet', '-m', 'fixture']);
    const head = git(repositoryRoot, ['rev-parse', 'HEAD']).trim();
    const tree = git(repositoryRoot, ['rev-parse', 'HEAD^{tree}']).trim();
    const repository = 'https://example.invalid/engineering/git-bound';
    const bundle = createExampleBundle(new Date('2030-01-01T12:00:00.000Z'), {
      candidate: `git:sha1:${head}`,
      treeDigest: `git-tree:sha1:${tree}`,
      repository,
      environment: 'shadow',
    });
    const input = path.join(fixtureRoot, 'assurance-input');
    await writeExampleBundle(input, bundle);

    const common = [
      'src/cli.mjs', 'check',
      '--candidate', head,
      '--git-root', repositoryRoot,
      '--evidence-root', input,
      '--manifest', path.join(input, 'manifest.json'),
      '--receipt', path.join(input, 'verifier-receipt.json'),
      '--authorization', path.join(input, 'authorization.json'),
      '--policy', path.join(input, 'policy.json'),
      '--trust', path.join(input, 'trust.json'),
      '--expected-policy-digest', bundle.receiverContext.expectedPolicyDigest,
      '--expected-trust-digest', bundle.receiverContext.expectedTrustStoreDigest,
      '--expected-repository', repository,
      '--expected-environment', 'shadow',
      '--at', bundle.at,
    ];
    const passingDossier = path.join(input, 'passing-dossier.json');
    const passing = spawnSync(process.execPath, [...common, '--dossier', passingDossier], { cwd: kitRoot, encoding: 'utf8' });
    assert.equal(passing.status, 0, `${passing.stdout}\n${passing.stderr}`);
    assert.equal(JSON.parse(await readFile(passingDossier, 'utf8')).decision.conclusion, 'PASS');

    await writeFile(path.join(repositoryRoot, 'service.txt'), 'tracked tree changed\n');
    const blockedDossier = path.join(input, 'blocked-dossier.json');
    const blocked = spawnSync(process.execPath, [...common, '--dossier', blockedDossier], { cwd: kitRoot, encoding: 'utf8' });
    assert.equal(blocked.status, 20, `${blocked.stdout}\n${blocked.stderr}`);
    const decision = JSON.parse(await readFile(blockedDossier, 'utf8')).decision;
    assert.equal(decision.conclusion, 'BLOCK');
    assert.ok(decision.reasons.some((entry) => entry.code === 'candidate.tracked_tree_dirty'));
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
});

test('CLI check rejects omission of the exact candidate before reading inputs', () => {
  const result = spawnSync(process.execPath, ['src/cli.mjs', 'check'], { cwd: kitRoot, encoding: 'utf8' });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Missing --candidate/);
});

function git(root, args) {
  return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8' });
}
