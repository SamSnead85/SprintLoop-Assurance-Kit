import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const root = path.resolve(import.meta.dirname, '..');
const ACTION_REVISION = 'd5307358ce6a39d12de025748cb0676acbe461bf';

test('CLI demo is a no-secret PASS golden path', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'assurance-kit-cli-'));
  try {
    const result = spawnSync(process.execPath, ['src/cli.mjs', 'demo', '--out', directory], {
      cwd: root,
      encoding: 'utf8',
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Decision: PASS/);
    assert.match(result.stdout, /Integrity: VALID/);
    const dossier = JSON.parse(await readFile(path.join(directory, 'dossier.json'), 'utf8'));
    assert.equal(dossier.decision.conclusion, 'PASS');
    const allFiles = spawnSync('find', [directory, '-type', 'f', '-maxdepth', '3', '-print'], { encoding: 'utf8' });
    for (const file of allFiles.stdout.trim().split('\n').filter(Boolean)) {
      assert.doesNotMatch(await readFile(file, 'utf8'), new RegExp(`BEGIN ${'PRIVATE'} KEY`));
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('CLI uses documented exit codes', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'assurance-kit-cli-'));
  try {
    const demo = spawnSync(process.execPath, ['src/cli.mjs', 'demo', '--out', directory], { cwd: root, encoding: 'utf8' });
    assert.equal(demo.status, 0, demo.stderr);
    const dossierPath = path.join(directory, 'dossier.json');
    const trustPath = path.join(directory, 'trust.json');
    const dossier = JSON.parse(await readFile(dossierPath, 'utf8'));
    const receiver = dossier.receiverContext;
    const current = spawnSync(process.execPath, [
      'src/cli.mjs', 'verify-dossier',
      '--dossier', dossierPath,
      '--trust', trustPath,
      '--candidate', receiver.actualCandidateDigest,
      '--tree-digest', receiver.actualTreeDigest,
      '--working-tree-clean', 'true',
      '--expected-policy-digest', receiver.expectedPolicyDigest,
      '--expected-trust-digest', receiver.expectedTrustStoreDigest,
      '--expected-repository', receiver.expectedRepository,
      '--expected-environment', receiver.expectedEnvironment,
    ], {
      cwd: root,
      encoding: 'utf8',
    });
    assert.equal(current.status, 0, current.stderr);

    const requiredContext = [
      'src/cli.mjs', 'verify-dossier',
      '--dossier', dossierPath,
      '--trust', trustPath,
      '--candidate', receiver.actualCandidateDigest,
      '--expected-policy-digest', receiver.expectedPolicyDigest,
      '--expected-trust-digest', receiver.expectedTrustStoreDigest,
      '--expected-repository', receiver.expectedRepository,
      '--expected-environment', receiver.expectedEnvironment,
    ];
    const missingTree = spawnSync(process.execPath, requiredContext, { cwd: root, encoding: 'utf8' });
    assert.equal(missingTree.status, 2);
    assert.match(missingTree.stderr, /Missing --tree-digest/);
    const missingClean = spawnSync(process.execPath, [
      ...requiredContext,
      '--tree-digest', receiver.actualTreeDigest,
    ], { cwd: root, encoding: 'utf8' });
    assert.equal(missingClean.status, 2);
    assert.match(missingClean.stderr, /Missing --working-tree-clean/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('CLI init emits fork-safe candidate and receiver-owned protected checkouts', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'assurance-kit-init-'));
  try {
    const result = spawnSync(process.execPath, ['src/cli.mjs', 'init', '--directory', directory], {
      cwd: root,
      encoding: 'utf8',
    });
    assert.equal(result.status, 0, result.stderr);
    const workflow = await readFile(path.join(directory, '.github/workflows/assurance.yml'), 'utf8');
    assert.match(workflow, /repository: \$\{\{ github\.event\.pull_request\.head\.repo\.full_name \}\}/);
    assert.match(workflow, /ref: \$\{\{ github\.event\.pull_request\.head\.sha \}\}/);
    assert.match(workflow, /repository: \$\{\{ github\.repository \}\}/);
    assert.match(workflow, /ref: \$\{\{ github\.event\.pull_request\.base\.sha \}\}/);
    assert.match(workflow, /sparse-checkout-cone-mode: false/);
    assert.equal((workflow.match(/persist-credentials: false/g) ?? []).length, 2);
    assert.match(workflow, /expected-policy-digest: \$\{\{ vars\.ASSURANCE_POLICY_DIGEST \}\}/);
    assert.match(workflow, /expected-trust-digest: \$\{\{ vars\.ASSURANCE_TRUST_DIGEST \}\}/);
    assert.match(workflow, /expected-environment: \$\{\{ vars\.ASSURANCE_ENVIRONMENT \}\}/);
    const pins = [...workflow.matchAll(/SprintLoop-Assurance-Kit(?:\/materialize-bundle)?@([0-9a-f]{40})/g)]
      .map((match) => match[1]);
    assert.deepEqual(pins, [ACTION_REVISION, ACTION_REVISION]);
    assert.match(workflow, /source: \$\{\{ runner\.temp \}\}\/assurance-provider-inbox/);
    assert.match(workflow, /manifest: \$\{\{ steps\.bundle\.outputs\.manifest \}\}/);
    assert.doesNotMatch(workflow, /candidate\/\.assurance\/(?:manifest|verifier-receipt|authorization)/);
    assert.doesNotMatch(workflow, /evidence-root: candidate(?:\s|$)/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
