import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { documentDigest } from '../src/canonical.mjs';
import { createExampleBundle, writeExampleBundle } from '../src/example.mjs';
import { writeJsonAtomic } from '../src/io.mjs';
import { materializeExternalBundle } from '../src/materialize-bundle.mjs';

const kitRoot = path.resolve(import.meta.dirname, '..');

test('external bundle materializes outside the exact candidate and protected receiver configuration', async () => {
  await withExternalBundle(async (fixture) => {
    const output = await materializeExternalBundle(fixture.options);
    assert.equal(output.bundleRoot, await realpath(fixture.destination));
    assert.equal(JSON.parse(await readFile(output.manifest, 'utf8')).candidate.digest, fixture.bundle.candidate);
    assert.equal(await readFile(path.join(output.evidenceRoot, 'evidence/test-report.json'), 'utf8'), await readFile(path.join(fixture.inbox, 'evidence/test-report.json'), 'utf8'));
    assert.equal(inside(fixture.candidateRoot, output.bundleRoot), false);
    assert.equal(inside(fixture.candidateRoot, output.evidenceRoot), false);
    const dossier = path.join(fixture.root, 'evaluated-dossier.json');
    const checked = spawnSync(process.execPath, [
      'src/cli.mjs', 'check',
      '--candidate', fixture.bundle.candidate,
      '--git-root', fixture.candidateRoot,
      '--evidence-root', output.evidenceRoot,
      '--manifest', output.manifest,
      '--receipt', output.receipt,
      '--authorization', output.authorization,
      '--policy', fixture.policyPath,
      '--trust', fixture.trustPath,
      '--expected-policy-digest', fixture.options.expectedPolicyDigest,
      '--expected-trust-digest', fixture.options.expectedTrustStoreDigest,
      '--expected-repository', fixture.options.expectedRepository,
      '--expected-environment', fixture.options.expectedEnvironment,
      '--dossier', dossier,
      '--at', fixture.bundle.at,
    ], { cwd: path.resolve(import.meta.dirname, '..'), encoding: 'utf8' });
    assert.equal(checked.status, 0, `${checked.stdout}\n${checked.stderr}`);
    assert.equal(JSON.parse(await readFile(dossier, 'utf8')).decision.conclusion, 'PASS');
  });
});

test('external bundle preflight fails closed on missing, candidate-local, and excessive inputs', async () => {
  await withExternalBundle(async (fixture) => {
    await assert.rejects(
      materializeExternalBundle({ ...fixture.options, source: path.join(fixture.root, 'missing-inbox') }),
      /External bundle source is unavailable/,
    );

    const candidateLocal = path.join(fixture.candidateRoot, 'provider-inbox');
    await writeExampleBundle(candidateLocal, fixture.bundle);
    await assert.rejects(
      materializeExternalBundle({ ...fixture.options, source: candidateLocal }),
      /outside the candidate checkout/,
    );

    const candidateDestination = path.join(fixture.candidateRoot, 'new', 'bundle');
    await assert.rejects(
      materializeExternalBundle({ ...fixture.options, destination: candidateDestination }),
      /outside the candidate checkout/,
    );
    await assert.rejects(lstat(path.dirname(candidateDestination)), { code: 'ENOENT' });

    const sourceDestination = path.join(fixture.inbox, 'materialized');
    await assert.rejects(
      materializeExternalBundle({ ...fixture.options, destination: sourceDestination }),
      /must not overlap/,
    );
    await assert.rejects(lstat(sourceDestination), { code: 'ENOENT' });
    await assert.rejects(
      materializeExternalBundle({ ...fixture.options, policyPath: path.join(fixture.inbox, 'manifest.json') }),
      /Protected policy must be outside/,
    );

    await rm(path.join(fixture.inbox, 'authorization.json'));
    await assert.rejects(materializeExternalBundle(fixture.options), /ENOENT/);
    await writeProviderBundle(fixture.inbox, fixture.bundle);

    await writeFile(path.join(fixture.inbox, 'unexpected.txt'), 'not in the contract\n');
    await assert.rejects(materializeExternalBundle(fixture.options), /unexpected file/);
    await rm(path.join(fixture.inbox, 'unexpected.txt'));

    const evidencePath = path.join(fixture.inbox, 'evidence/test-report.json');
    await writeFile(evidencePath, 'tampered evidence\n');
    await assert.rejects(materializeExternalBundle(fixture.options), /evidence digest mismatch/);
    assert.equal((await readdir(fixture.root)).some((name) => name.startsWith('.assurance-bundle-')), false);
    await writeProviderBundle(fixture.inbox, fixture.bundle);

    await rm(evidencePath);
    await symlink(path.join(fixture.inbox, 'manifest.json'), evidencePath);
    await assert.rejects(materializeExternalBundle(fixture.options), /symlinks are prohibited/);
    await rm(evidencePath);
    await writeProviderBundle(fixture.inbox, fixture.bundle);

    fixture.bundle.policy.maxEvidenceBytes = 1;
    rebindPolicy(fixture.bundle);
    await writeProviderBundle(fixture.inbox, fixture.bundle);
    await writeJsonAtomic(fixture.policyPath, fixture.bundle.policy);
    await assert.rejects(
      materializeExternalBundle({ ...fixture.options, expectedPolicyDigest: documentDigest(fixture.bundle.policy) }),
      /exceeds its receiver-owned byte limit/,
    );

    fixture.bundle.policy.maxEvidenceBytes = 5_242_880;
    fixture.bundle.policy.maxEvidenceItems = 1;
    rebindPolicy(fixture.bundle);
    const policyDigest = documentDigest(fixture.bundle.policy);
    await writeProviderBundle(fixture.inbox, fixture.bundle);
    await writeJsonAtomic(fixture.policyPath, fixture.bundle.policy);
    await assert.rejects(
      materializeExternalBundle({
        ...fixture.options,
        expectedPolicyDigest: policyDigest,
      }),
      /evidence count exceeds/,
    );
  });
});

test('materializer wrapper escapes hostile provider filenames before writing GitHub logs', async () => {
  await withExternalBundle(async (fixture) => {
    const hostileName = 'forged\n::error title=attacker::owned.txt';
    await writeFile(path.join(fixture.inbox, hostileName), 'undeclared\n');
    const result = spawnSync(process.execPath, ['src/materialize-bundle.mjs'], {
      cwd: kitRoot,
      encoding: 'utf8',
      env: {
        ...process.env,
        ASSURANCE_BUNDLE_SOURCE: fixture.options.source,
        ASSURANCE_BUNDLE_DESTINATION: fixture.options.destination,
        ASSURANCE_CANDIDATE_ROOT: fixture.options.candidateRoot,
        ASSURANCE_CANDIDATE: fixture.options.candidate,
        ASSURANCE_POLICY: fixture.options.policyPath,
        ASSURANCE_TRUST: fixture.options.trustPath,
        ASSURANCE_EXPECTED_POLICY: fixture.options.expectedPolicyDigest,
        ASSURANCE_EXPECTED_TRUST: fixture.options.expectedTrustStoreDigest,
        ASSURANCE_EXPECTED_REPOSITORY: fixture.options.expectedRepository,
        ASSURANCE_EXPECTED_ENVIRONMENT: fixture.options.expectedEnvironment,
      },
    });
    assert.equal(result.status, 2);
    assert.equal((result.stderr.match(/\n/g) ?? []).length, 1, result.stderr);
    assert.doesNotMatch(result.stderr, /::(?:error|warning|notice|debug|group|endgroup|add-mask|stop-commands)/i);
    assert.doesNotMatch(result.stderr.slice(0, -1), /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u);
  });
});

async function withExternalBundle(callback) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'assurance-external-bundle-'));
  const candidateRoot = path.join(root, 'candidate');
  const inbox = path.join(root, 'provider-inbox');
  const receiver = path.join(root, 'receiver');
  const destination = path.join(root, 'materialized-bundle');
  try {
    await mkdir(candidateRoot, { recursive: true });
    await writeFile(path.join(candidateRoot, 'service.txt'), 'exact candidate bytes\n');
    git(candidateRoot, ['init', '--quiet']);
    git(candidateRoot, ['add', 'service.txt']);
    git(candidateRoot, ['-c', 'user.name=fixture', '-c', 'user.email=fixture@invalid', 'commit', '--quiet', '-m', 'candidate']);
    const head = git(candidateRoot, ['rev-parse', 'HEAD']).trim();
    const tree = git(candidateRoot, ['rev-parse', 'HEAD^{tree}']).trim();
    const repository = 'https://example.invalid/engineering/external-bundle';
    const environment = 'shadow';
    const bundle = createExampleBundle(new Date('2030-01-01T12:00:00.000Z'), {
      candidate: `git:sha1:${head}`,
      treeDigest: `git-tree:sha1:${tree}`,
      repository,
      environment,
    });
    await writeProviderBundle(inbox, bundle);
    const policyPath = path.join(receiver, 'policy.json');
    const trustPath = path.join(receiver, 'trust.json');
    await writeJsonAtomic(policyPath, bundle.policy);
    await writeJsonAtomic(trustPath, bundle.trustStore);
    await callback({
      root,
      candidateRoot,
      inbox,
      destination,
      receiver,
      bundle,
      policyPath,
      trustPath,
      options: {
        source: inbox,
        destination,
        candidateRoot,
        candidate: head,
        policyPath,
        trustPath,
        expectedPolicyDigest: bundle.receiverContext.expectedPolicyDigest,
        expectedTrustStoreDigest: bundle.receiverContext.expectedTrustStoreDigest,
        expectedRepository: repository,
        expectedEnvironment: environment,
      },
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function removeReceiverFiles(directory) {
  await Promise.all([
    rm(path.join(directory, 'policy.json'), { force: true }),
    rm(path.join(directory, 'trust.json'), { force: true }),
  ]);
}

async function writeProviderBundle(directory, bundle) {
  await writeExampleBundle(directory, bundle);
  await removeReceiverFiles(directory);
}

function rebindPolicy(bundle) {
  const policyDigest = documentDigest(bundle.policy);
  bundle.receipt.policyDigest = policyDigest;
  bundle.authorization.policyDigest = policyDigest;
  bundle.authorization.receiptDigest = documentDigest(bundle.receipt);
}

function git(root, args) {
  return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8' });
}

function inside(root, candidate) {
  return candidate === root || candidate.startsWith(`${root}${path.sep}`);
}
