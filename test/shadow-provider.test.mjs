import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { canonicalize, documentDigest } from '../src/canonical.mjs';
import { createExampleBundle } from '../src/example.mjs';
import { writeJsonAtomic } from '../src/io.mjs';
import { prepareShadowBundle } from '../src/prepare-shadow-bundle.mjs';
import { validateManifest } from '../src/validate.mjs';

const kitRoot = path.resolve(import.meta.dirname, '..');

test('shadow provider deterministically captures exact-candidate evidence and can emit only partial HOLD', async () => {
  await withShadowFixture(async (fixture) => {
    const result = await prepareShadowBundle(fixture.options);
    assert.equal(result.disposition, 'HOLD');
    assert.equal(result.completeness, 'partial');
    assert.equal(result.enforcementEligible, false);
    assert.deepEqual(result.missingEvidenceTypes, []);
    assert.equal(result.candidateDigest, fixture.bundle.candidate);
    assert.equal(result.treeDigest, fixture.bundle.treeDigest);
    assert.equal(result.policyDigest, fixture.bundle.receiverContext.expectedPolicyDigest);
    assert.equal(result.trustStoreDigest, fixture.bundle.receiverContext.expectedTrustStoreDigest);

    const manifestText = await readFile(result.manifest, 'utf8');
    const manifest = JSON.parse(manifestText);
    assert.deepEqual(validateManifest(manifest), []);
    assert.equal(manifestText, `${canonicalize(manifest)}\n`);
    assert.equal(result.manifestDigest, documentDigest(manifest));
    assert.deepEqual(manifest.evidence.map((item) => item.id), [
      'evidence:shadow-sbom',
      'evidence:shadow-tests',
    ]);
    assert.ok(manifest.evidence.every((item) => item.subjectDigest === fixture.bundle.candidate));
    assert.equal(manifest.candidate.repository, fixture.options.expectedRepository);
    assert.equal(manifest.candidate.environment, fixture.options.expectedEnvironment);
    assert.deepEqual(manifest.candidate.producer, {
      principalId: fixture.options.producerPrincipalId,
      ownerId: fixture.options.producerOwnerId,
      controlDomain: fixture.options.producerControlDomain,
    });

    assert.deepEqual(await inventory(result.bundleRoot), [
      'evidence',
      'evidence/sbom.spdx.json',
      'evidence/test-result.json',
      'manifest.json',
    ]);
    for (const prohibited of ['verifier-receipt.json', 'authorization.json', 'dossier.json', 'policy.json', 'trust.json']) {
      await assert.rejects(lstat(path.join(result.bundleRoot, prohibited)), { code: 'ENOENT' });
    }

    const second = await prepareShadowBundle({ ...fixture.options, destination: path.join(fixture.runnerTemp, 'shadow-output-2') });
    assert.equal(await readFile(second.manifest, 'utf8'), manifestText);
    assert.equal(second.manifestDigest, result.manifestDigest);
  });
});

test('shadow provider rejects dirty candidates, ambiguous inventory, symlinks, duplicates, drift, and unprotected roots', async () => {
  await withShadowFixture(async (fixture) => {
    const untracked = path.join(fixture.candidateRoot, 'untracked.txt');
    await writeFile(untracked, 'not sealed\n');
    await assert.rejects(
      prepareShadowBundle(fixture.optionsFor('dirty-untracked')),
      /tracked or non-ignored untracked files/,
    );
    await rm(untracked);

    const tracked = path.join(fixture.candidateRoot, 'service.txt');
    await writeFile(tracked, 'changed candidate\n');
    await assert.rejects(
      prepareShadowBundle(fixture.optionsFor('dirty-tracked')),
      /worktree is not clean/,
    );
    await writeFile(tracked, 'sealed candidate\n');

    await writeFile(path.join(fixture.evidenceRoot, 'undeclared.txt'), 'ambiguous\n');
    await assert.rejects(
      prepareShadowBundle(fixture.optionsFor('extra-inventory')),
      /undeclared file/,
    );
    await rm(path.join(fixture.evidenceRoot, 'undeclared.txt'));

    const evidenceFile = path.join(fixture.evidenceRoot, 'evidence/test-result.json');
    await rm(evidenceFile);
    await symlink(path.join(fixture.evidenceRoot, 'evidence/sbom.spdx.json'), evidenceFile);
    await assert.rejects(
      prepareShadowBundle(fixture.optionsFor('symlink')),
      /symlinks are prohibited/,
    );
    await rm(evidenceFile);
    await writeFile(evidenceFile, fixture.testResult);

    const duplicateType = JSON.stringify([
      { id: 'evidence:first', type: 'test-report', path: 'evidence/test-result.json', mediaType: 'application/json' },
      { id: 'evidence:second', type: 'test-report', path: 'evidence/sbom.spdx.json', mediaType: 'application/spdx+json' },
    ]);
    await assert.rejects(
      prepareShadowBundle({ ...fixture.optionsFor('duplicate'), evidenceDeclaration: duplicateType }),
      /duplicates type/,
    );

    await assert.rejects(
      prepareShadowBundle({
        ...fixture.optionsFor('policy-drift'),
        expectedPolicyDigest: `sha256:${'f'.repeat(64)}`,
      }),
      /Protected policy digest does not match/,
    );

    const outsideEvidence = path.join(fixture.root, 'outside-evidence');
    await mkdir(outsideEvidence);
    await assert.rejects(
      prepareShadowBundle({ ...fixture.optionsFor('outside'), evidenceRoot: outsideEvidence }),
      /inside the runner temporary root/,
    );

    await assert.rejects(
      prepareShadowBundle({ ...fixture.optionsFor('wrong-candidate'), candidate: '0'.repeat(40) }),
      /Checked-out candidate does not match/,
    );

    const occupied = path.join(fixture.runnerTemp, 'shadow-occupied');
    await mkdir(occupied);
    await writeFile(path.join(occupied, 'owner-marker.txt'), 'must survive\n');
    await assert.rejects(
      prepareShadowBundle({ ...fixture.options, destination: occupied }),
      /destination already exists/,
    );
    assert.equal(await readFile(path.join(occupied, 'owner-marker.txt'), 'utf8'), 'must survive\n');
  });
});

test('GitHub wrapper binds the candidate before execution, permits only advisory events, and publishes no enforcement output', async () => {
  await withShadowFixture(async (fixture) => {
    const [example, guide] = await Promise.all([
      readFile(path.join(kitRoot, 'examples/github/shadow-provider.yml'), 'utf8'),
      readFile(path.join(kitRoot, 'docs/SHADOW-PROVIDER.md'), 'utf8'),
    ]);
    for (const workflow of [example, guide]) {
      const bind = workflow.indexOf('name: Bind resolved candidate before execution');
      const execute = workflow.indexOf('name: Produce bounded candidate evidence without secrets');
      const action = workflow.indexOf('name: Prepare partial shadow evidence');
      assert.ok(bind > -1 && bind < execute && execute < action, 'candidate must be bound before candidate code executes');
      assert.match(workflow, /candidate: \$\{\{ steps\.candidate\.outputs\.sha \}\}/);
    }

    const denied = spawnSync(process.execPath, ['src/prepare-shadow-bundle.mjs'], {
      cwd: kitRoot,
      encoding: 'utf8',
      env: { ...process.env, GITHUB_ACTIONS: 'true', GITHUB_EVENT_NAME: 'pull_request' },
    });
    assert.equal(denied.status, 2);
    assert.match(denied.stderr, /permits only workflow_dispatch or schedule/);

    const outputFile = path.join(fixture.runnerTemp, 'github-output.txt');
    const wrapperEnvironment = {
      ...process.env,
      GITHUB_ACTIONS: 'true',
      GITHUB_EVENT_NAME: 'workflow_dispatch',
      GITHUB_OUTPUT: outputFile,
      RUNNER_TEMP: fixture.runnerTemp,
      ASSURANCE_CANDIDATE_ROOT: fixture.options.candidateRoot,
      ASSURANCE_CANDIDATE: fixture.options.candidate,
      ASSURANCE_EVIDENCE_ROOT: fixture.options.evidenceRoot,
      ASSURANCE_EVIDENCE_DECLARATION: fixture.options.evidenceDeclaration,
      ASSURANCE_SHADOW_DESTINATION: path.join(fixture.runnerTemp, 'wrapper-output'),
      ASSURANCE_POLICY: fixture.options.policyPath,
      ASSURANCE_TRUST: fixture.options.trustPath,
      ASSURANCE_EXPECTED_POLICY: fixture.options.expectedPolicyDigest,
      ASSURANCE_EXPECTED_TRUST: fixture.options.expectedTrustStoreDigest,
      ASSURANCE_EXPECTED_REPOSITORY: fixture.options.expectedRepository,
      ASSURANCE_EXPECTED_ENVIRONMENT: fixture.options.expectedEnvironment,
      ASSURANCE_CHANGE_ID: fixture.options.changeId,
      ASSURANCE_INTENT_ID: fixture.options.intentId,
      ASSURANCE_INTENT_DIGEST: fixture.options.intentDigest,
      ASSURANCE_PRODUCER_PRINCIPAL: fixture.options.producerPrincipalId,
      ASSURANCE_PRODUCER_OWNER: fixture.options.producerOwnerId,
      ASSURANCE_PRODUCER_CONTROL_DOMAIN: fixture.options.producerControlDomain,
    };

    if (process.platform !== 'win32') {
      const hostileName = 'forged\n::error title=attacker::owned.txt';
      await writeFile(path.join(fixture.evidenceRoot, hostileName), 'undeclared\n');
      const hostile = spawnSync(process.execPath, ['src/prepare-shadow-bundle.mjs'], {
        cwd: kitRoot,
        encoding: 'utf8',
        env: { ...wrapperEnvironment, ASSURANCE_SHADOW_DESTINATION: path.join(fixture.runnerTemp, 'hostile-output') },
      });
      assert.equal(hostile.status, 2);
      assert.equal((hostile.stderr.match(/\n/g) ?? []).length, 1, hostile.stderr);
      assert.doesNotMatch(hostile.stderr, /::(?:error|warning|notice|debug|group|endgroup|add-mask|stop-commands)/i);
      assert.doesNotMatch(hostile.stderr.slice(0, -1), /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u);
      await rm(path.join(fixture.evidenceRoot, hostileName));
    }

    const allowed = spawnSync(process.execPath, ['src/prepare-shadow-bundle.mjs'], {
      cwd: kitRoot,
      encoding: 'utf8',
      env: wrapperEnvironment,
    });
    assert.equal(allowed.status, 0, `${allowed.stdout}\n${allowed.stderr}`);
    assert.match(allowed.stdout, /HOLD — partial unsigned evidence manifest/);
    const outputs = await readFile(outputFile, 'utf8');
    assert.match(outputs, /^disposition=HOLD$/m);
    assert.match(outputs, /^completeness=partial$/m);
    assert.match(outputs, /^enforcement_eligible=false$/m);
    assert.doesNotMatch(outputs, /PASS|ALLOW/);
  });
});

test('shadow composite contract has no network, signing, authorization, or enforcement surface', async () => {
  const [action, implementation, documentation] = await Promise.all([
    readFile(path.join(kitRoot, 'prepare-shadow-bundle/action.yml'), 'utf8'),
    readFile(path.join(kitRoot, 'src/prepare-shadow-bundle.mjs'), 'utf8'),
    readFile(path.join(kitRoot, 'docs/SHADOW-PROVIDER.md'), 'utf8'),
  ]);
  for (const input of [
    'candidate-root',
    'candidate',
    'evidence-root',
    'evidence',
    'destination',
    'policy',
    'trust',
    'expected-policy-digest',
    'expected-trust-digest',
    'expected-repository',
    'expected-environment',
    'change-id',
    'intent-id',
    'intent-digest',
    'producer-principal-id',
    'producer-owner-id',
    'producer-control-domain',
  ]) {
    assert.match(action, new RegExp(`  ${input}:\\n(?:.*\\n){0,4}    required: true`));
  }
  assert.match(action, /Always HOLD/);
  assert.match(action, /Always false/);
  assert.match(implementation, /SAFE_GITHUB_EVENTS = new Set\(\['schedule', 'workflow_dispatch'\]\)/);
  assert.match(implementation, /inspectReceiverGitState/);
  assert.match(implementation, /manifest\.json` is the commit marker/);
  assert.match(implementation, /mkdir\(destination, \{ recursive: false/);
  assert.doesNotMatch(implementation, /\b(?:fetch|https?\.request|curl|wget|gh|aws|gcloud|az)\s*\(/);
  assert.doesNotMatch(action, /\b(?:curl|wget|gh|aws|gcloud|az)\b/);
  assert.doesNotMatch(action, /private-key|credential|token:/i);
  assert.match(documentation, /must not be a required check/i);
  assert.match(documentation, /receipt, authorization, dossier, policy, trust store, credential, private key, or generated key/);
});

async function withShadowFixture(callback) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'assurance-shadow-provider-')));
  const runnerTemp = path.join(root, 'runner-temp');
  const candidateRoot = path.join(root, 'candidate');
  const evidenceRoot = path.join(runnerTemp, 'incoming-evidence');
  const receiverRoot = path.join(runnerTemp, 'receiver');
  const destination = path.join(runnerTemp, 'shadow-output');
  try {
    await mkdir(path.join(evidenceRoot, 'evidence'), { recursive: true });
    await mkdir(receiverRoot, { recursive: true });
    await mkdir(candidateRoot, { recursive: true });
    await writeFile(path.join(candidateRoot, 'service.txt'), 'sealed candidate\n');
    git(candidateRoot, ['init', '--quiet']);
    git(candidateRoot, ['add', 'service.txt']);
    git(candidateRoot, ['-c', 'user.name=fixture', '-c', 'user.email=fixture@invalid', 'commit', '--quiet', '-m', 'candidate']);
    const head = git(candidateRoot, ['rev-parse', 'HEAD']).trim();
    const tree = git(candidateRoot, ['rev-parse', 'HEAD^{tree}']).trim();
    const repository = 'https://example.invalid/engineering/shadow-service';
    const environment = 'shadow';
    const bundle = createExampleBundle(new Date('2030-01-01T12:00:00.000Z'), {
      candidate: `git:sha1:${head}`,
      treeDigest: `git-tree:sha1:${tree}`,
      repository,
      environment,
    });
    const testResult = Buffer.from('{"schemaVersion":"shadow.test/v1","exitCode":0}\n');
    const sbom = Buffer.from('{"spdxVersion":"SPDX-2.3","packages":[]}\n');
    await writeFile(path.join(evidenceRoot, 'evidence/test-result.json'), testResult);
    await writeFile(path.join(evidenceRoot, 'evidence/sbom.spdx.json'), sbom);
    const policyPath = path.join(receiverRoot, 'policy.json');
    const trustPath = path.join(receiverRoot, 'trust.json');
    await writeJsonAtomic(policyPath, bundle.policy);
    await writeJsonAtomic(trustPath, bundle.trustStore);
    const evidenceDeclaration = JSON.stringify([
      { id: 'evidence:shadow-tests', type: 'test-report', path: 'evidence/test-result.json', mediaType: 'application/json' },
      { id: 'evidence:shadow-sbom', type: 'sbom', path: 'evidence/sbom.spdx.json', mediaType: 'application/spdx+json' },
    ]);
    const options = {
      runnerTemp,
      candidateRoot,
      candidate: head,
      evidenceRoot,
      evidenceDeclaration,
      destination,
      policyPath,
      trustPath,
      expectedPolicyDigest: bundle.receiverContext.expectedPolicyDigest,
      expectedTrustStoreDigest: bundle.receiverContext.expectedTrustStoreDigest,
      expectedRepository: repository,
      expectedEnvironment: environment,
      changeId: 'change:shadow-pilot-001',
      intentId: 'intent:shadow-pilot-001',
      intentDigest: `sha256:${'a'.repeat(64)}`,
      producerPrincipalId: 'agent:candidate-builder',
      producerOwnerId: 'team:delivery',
      producerControlDomain: 'candidate-production',
    };
    await callback({
      root,
      runnerTemp,
      candidateRoot,
      evidenceRoot,
      receiverRoot,
      destination,
      bundle,
      testResult,
      options,
      optionsFor(name) {
        return { ...options, destination: path.join(runnerTemp, `shadow-${name}`) };
      },
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function inventory(root) {
  const result = [];
  await walk(root);
  return result.sort();

  async function walk(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      result.push(path.relative(root, absolute).split(path.sep).join('/'));
      if (entry.isDirectory()) await walk(absolute);
    }
  }
}

function git(root, args) {
  return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8' });
}
