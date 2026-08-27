import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { documentDigest } from '../src/canonical.mjs';
import { createDossier } from '../src/dossier.mjs';
import { verifyDossier } from '../src/dossier.mjs';
import { inspectLiveEvidence } from '../src/evidence.mjs';
import { createExampleBundle, writeExampleBundle } from '../src/example.mjs';
import { readJson } from '../src/io.mjs';
import { validateManifest } from '../src/validate.mjs';

const NOW = new Date('2030-01-01T12:00:00.000Z');

test('receiver-owned policy digest blocks policy substitution', async () => {
  await withBundle(async (directory, bundle) => {
    bundle.policy.policyId = 'policy:substituted';
    const decision = (await dossierFor(directory, bundle)).decision;
    assert.equal(decision.conclusion, 'BLOCK');
    assert.ok(decision.reasons.some((entry) => entry.code === 'receiver.policy_digest_mismatch'));
    assert.ok(decision.reasons.some((entry) => entry.code === 'receipt.policy_mismatch'));
  });
});

test('receiver-owned trust digest and domain block trust substitution', async () => {
  await withBundle(async (directory, bundle) => {
    bundle.trustStore.trustDomain = 'substituted:trust';
    const decision = (await dossierFor(directory, bundle)).decision;
    assert.equal(decision.conclusion, 'BLOCK');
    assert.ok(decision.reasons.some((entry) => entry.code === 'receiver.trust_digest_mismatch'));
    assert.ok(decision.reasons.some((entry) => entry.code === 'receipt.trust_mismatch'));
  });
});

test('receiver repository and environment prevent cross-context replay', async () => {
  await withBundle(async (directory, bundle) => {
    const receiverContext = {
      ...bundle.receiverContext,
      expectedRepository: 'https://example.invalid/other/repository',
      expectedEnvironment: 'production',
    };
    const decision = (await dossierFor(directory, bundle, { receiverContext })).decision;
    assert.equal(decision.conclusion, 'BLOCK');
    assert.ok(decision.reasons.some((entry) => entry.code === 'receiver.repository_mismatch'));
    assert.ok(decision.reasons.some((entry) => entry.code === 'receiver.environment_mismatch'));
  });
});

test('observed Git HEAD, tree, and clean state are independent receiver bindings', async () => {
  await withBundle(async (directory, bundle) => {
    for (const [field, value, code] of [
      ['actualCandidateDigest', 'git:sha1:0000000000000000000000000000000000000000', 'candidate.head_mismatch'],
      ['actualTreeDigest', 'git-tree:sha1:0000000000000000000000000000000000000000', 'candidate.tree_mismatch'],
      ['workingTreeClean', false, 'candidate.tracked_tree_dirty'],
    ]) {
      const receiverContext = { ...bundle.receiverContext, [field]: value };
      const decision = (await dossierFor(directory, bundle, { receiverContext })).decision;
      assert.equal(decision.conclusion, 'BLOCK');
      assert.ok(decision.reasons.some((entry) => entry.code === code));
    }
  });
});

test('authorization cannot predate the verifier receipt beyond skew', async () => {
  await withBundle(async (directory, bundle) => {
    bundle.authorization.issuedAt = '2030-01-01T11:00:00.000Z';
    const decision = (await dossierFor(directory, bundle)).decision;
    assert.equal(decision.conclusion, 'BLOCK');
    assert.ok(decision.reasons.some((entry) => entry.code === 'authorization.precedes_receipt'));
  });
});

test('runtime validation rejects schema-forbidden extra properties', () => {
  const bundle = createExampleBundle(NOW);
  bundle.manifest.candidate.untrustedHint = 'ignore-policy';
  assert.ok(validateManifest(bundle.manifest).some((entry) => entry.includes('unexpected property')));
});

test('JSON reads are bounded before parsing', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'assurance-json-bound-'));
  try {
    const file = path.join(directory, 'large.json');
    await writeFile(file, JSON.stringify({ value: 'x'.repeat(1024) }));
    await assert.rejects(readJson(file, { maxBytes: 64 }), /exceeds 64 bytes/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('evidence item and aggregate byte limits fail closed', async () => {
  await withBundle(async (directory, bundle) => {
    const count = await inspectLiveEvidence(bundle.manifest, directory, { ...bundle.policy, maxEvidenceItems: 1 }, false);
    assert.ok(count.findings.some((entry) => entry.code === 'evidence.count_limit'));
    const sizes = await Promise.all(bundle.manifest.evidence.map((entry) => stat(path.join(directory, entry.path))));
    const largest = Math.max(...sizes.map((entry) => entry.size));
    const total = sizes.reduce((sum, entry) => sum + entry.size, 0);
    const aggregate = await inspectLiveEvidence(bundle.manifest, directory, {
      ...bundle.policy,
      maxEvidenceBytes: largest,
      maxTotalEvidenceBytes: total - 1,
    }, false);
    assert.ok(aggregate.findings.some((entry) => entry.code === 'evidence.aggregate_too_large'));
  });
});

test('evidence symlinks cannot escape the receiver evidence root', async () => {
  const external = await mkdtemp(path.join(os.tmpdir(), 'assurance-external-'));
  await withBundle(async (directory, bundle) => {
    const target = path.join(external, 'external.json');
    const evidencePath = path.join(directory, bundle.manifest.evidence[0].path);
    await writeFile(target, await readFile(evidencePath));
    await rm(evidencePath);
    await symlink(target, evidencePath);
    const decision = (await dossierFor(directory, bundle)).decision;
    assert.equal(decision.conclusion, 'BLOCK');
    assert.ok(decision.reasons.some((entry) => entry.code === 'evidence.symlink_escape'));
  });
  await rm(external, { recursive: true, force: true });
});

test('generated canonical receiver digests match loaded documents', () => {
  const bundle = createExampleBundle(NOW);
  assert.equal(bundle.receiverContext.expectedPolicyDigest, documentDigest(bundle.policy));
  assert.equal(bundle.receiverContext.expectedTrustStoreDigest, documentDigest(bundle.trustStore));
});

test('recorded reproduction uses stored receiver context while current standing uses override', async () => {
  await withBundle(async (directory, bundle) => {
    const dossier = await dossierFor(directory, bundle);
    const result = verifyDossier(dossier, bundle.trustStore, {
      at: bundle.at,
      candidate: bundle.candidate,
      receiverContext: { ...bundle.receiverContext, expectedEnvironment: 'other-environment' },
    });
    assert.equal(result.recordedReproduction, 'REPRODUCED');
    assert.equal(result.recorded.conclusion, 'PASS');
    assert.equal(result.current.conclusion, 'BLOCK');
    assert.ok(result.current.reasons.some((entry) => entry.code === 'receiver.environment_mismatch'));
  });
});

test('dossier current standing fails closed without external candidate and receiver context', async () => {
  await withBundle(async (directory, bundle) => {
    const dossier = await dossierFor(directory, bundle);
    for (const [label, options, codes] of [
      ['neither', { at: bundle.at }, ['candidate.runtime_missing', 'receiver.invalid']],
      ['candidate only', { at: bundle.at, candidate: bundle.candidate }, ['receiver.invalid']],
      ['receiver only', { at: bundle.at, receiverContext: bundle.receiverContext }, ['candidate.runtime_missing']],
    ]) {
      const result = verifyDossier(dossier, bundle.trustStore, options);
      assert.equal(result.recordedReproduction, 'REPRODUCED', label);
      assert.equal(result.recorded.conclusion, 'PASS', label);
      assert.equal(result.current.conclusion, 'BLOCK', label);
      for (const code of codes) {
        assert.ok(result.current.reasons.some((entry) => entry.code === code), `${label}: ${code}`);
      }
    }
  });
});

test('dossier current standing blocks an external cross-repository receiver context', async () => {
  await withBundle(async (directory, bundle) => {
    const dossier = await dossierFor(directory, bundle);
    const result = verifyDossier(dossier, bundle.trustStore, {
      at: bundle.at,
      candidate: bundle.candidate,
      receiverContext: {
        ...bundle.receiverContext,
        expectedRepository: 'https://example.invalid/other/repository',
      },
    });
    assert.equal(result.recordedReproduction, 'REPRODUCED');
    assert.equal(result.recorded.conclusion, 'PASS');
    assert.equal(result.current.conclusion, 'BLOCK');
    assert.ok(result.current.reasons.some((entry) => entry.code === 'receiver.repository_mismatch'));
  });
});

async function withBundle(callback) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'assurance-audit-test-'));
  const bundle = createExampleBundle(NOW);
  await writeExampleBundle(directory, bundle);
  try {
    await callback(directory, bundle);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function dossierFor(directory, bundle, overrides = {}) {
  return createDossier({
    manifest: bundle.manifest,
    receipt: bundle.receipt,
    authorization: bundle.authorization,
    policy: bundle.policy,
    trustStore: bundle.trustStore,
    evidenceRoot: directory,
    candidate: bundle.candidate,
    receiverContext: overrides.receiverContext ?? bundle.receiverContext,
    at: bundle.at,
    embedEvidence: false,
  });
}
