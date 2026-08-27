import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { canonicalize, documentDigest } from '../src/canonical.mjs';
import { createDossier, verifyDossier } from '../src/dossier.mjs';
import { evaluateAssurance } from '../src/evaluate.mjs';
import { createExampleBundle, writeExampleBundle } from '../src/example.mjs';
import { validateJsonSchema } from '../src/schema-check.mjs';

const NOW = new Date('2030-01-01T12:00:00.000Z');

test('canonical JSON sorts object keys and preserves array order', () => {
  assert.equal(canonicalize({ z: 1, a: ['b', 'a'] }), '{"a":["b","a"],"z":1}');
  assert.equal(documentDigest({ b: 2, a: 1 }), documentDigest({ a: 1, b: 2 }));
  assert.throws(() => canonicalize({ value: 1.25 }), /safe integers/);
});

test('canonical JSON preserves prototype-named keys without digest collisions', () => {
  const hostile = JSON.parse('{"x":1,"__proto__":{"polluted":true},"constructor":{"nested":{"__proto__":"value"}}}');
  assert.equal(
    canonicalize(hostile),
    '{"__proto__":{"polluted":true},"constructor":{"nested":{"__proto__":"value"}},"x":1}',
  );
  assert.notEqual(documentDigest(hostile), documentDigest({ x: 1 }));
  assert.equal(Object.prototype.polluted, undefined);
});

test('canonical JSON rejects sparse arrays instead of aliasing them to null', () => {
  assert.throws(() => canonicalize(Array(1)), /dense|sparse/);
  const withExtra = [null];
  withExtra.extra = true;
  assert.throws(() => canonicalize(withExtra), /extra enumerable/);
  assert.equal(canonicalize([null]), '[null]');
});

test('internal schema validation enforces oneOf, property bounds, and ref siblings', () => {
  assert.ok(validateJsonSchema({ oneOf: [{ type: 'string' }, { type: 'null' }] }, 42).length > 0);
  assert.ok(validateJsonSchema({ type: 'object', maxProperties: 0 }, { x: 1 }).length > 0);
  assert.ok(validateJsonSchema({
    $defs: { text: { type: 'string' } },
    $ref: '#/$defs/text',
    minLength: 3,
  }, 'x').length > 0);
  assert.ok(validateJsonSchema({ oneOf: [{ type: 'number' }, { type: 'integer' }] }, 1).length > 0);
});

test('golden path creates a PASS dossier and verifies it offline', async () => {
  await withBundle(async (directory, bundle) => {
    const dossier = await dossierFor(directory, bundle, { embedEvidence: true });
    assert.equal(dossier.decision.conclusion, 'PASS');
    assert.equal(dossier.decision.verificationLevel, 'FULL');
    const verified = verifyDossier(dossier, bundle.trustStore, {
      at: bundle.at,
      candidate: bundle.candidate,
      receiverContext: bundle.receiverContext,
    });
    assert.equal(verified.integrity, 'VALID');
    assert.equal(verified.recorded.conclusion, 'PASS');
    assert.equal(verified.current.conclusion, 'PASS');
    assert.equal(verified.verificationLevel, 'FULL');
  });
});

test('digest-only dossiers honestly report envelope-only offline verification', async () => {
  await withBundle(async (directory, bundle) => {
    const dossier = await dossierFor(directory, bundle, { embedEvidence: false });
    const verified = verifyDossier(dossier, bundle.trustStore, {
      at: bundle.at,
      candidate: bundle.candidate,
      receiverContext: bundle.receiverContext,
    });
    assert.equal(verified.integrity, 'VALID');
    assert.equal(verified.verificationLevel, 'ENVELOPE_ONLY');
    assert.equal(verified.current.conclusion, 'PASS');
  });
});

test('runtime candidate substitution blocks an otherwise valid release', async () => {
  await withBundle(async (directory, bundle) => {
    const dossier = await dossierFor(directory, bundle, {
      candidate: 'git:sha1:0000000000000000000000000000000000000000',
    });
    assert.equal(dossier.decision.conclusion, 'BLOCK');
    assert.ok(dossier.decision.reasons.some((entry) => entry.code === 'candidate.runtime_mismatch'));
  });
});

test('tampered evidence blocks the release', async () => {
  await withBundle(async (directory, bundle) => {
    await writeFile(path.join(directory, 'evidence/test-report.json'), '{"tampered":true}\n');
    const dossier = await dossierFor(directory, bundle);
    assert.equal(dossier.decision.conclusion, 'BLOCK');
    assert.ok(dossier.decision.reasons.some((entry) => entry.code === 'evidence.digest_mismatch'));
  });
});

test('missing evidence holds rather than inventing a pass', async () => {
  await withBundle(async (directory, bundle) => {
    await rm(path.join(directory, 'evidence/test-report.json'));
    const dossier = await dossierFor(directory, bundle);
    assert.equal(dossier.decision.conclusion, 'HOLD');
    assert.ok(dossier.decision.reasons.some((entry) => entry.code === 'evidence.missing'));
  });
});

test('expired receipt and authorization make current standing HOLD', async () => {
  await withBundle(async (directory, bundle) => {
    const dossier = await dossierFor(directory, bundle, { at: '2030-01-02T13:00:00.000Z' });
    assert.equal(dossier.decision.conclusion, 'HOLD');
    assert.ok(dossier.decision.reasons.some((entry) => entry.code === 'receipt.expired'));
    assert.ok(dossier.decision.reasons.some((entry) => entry.code === 'authorization.expired'));
  });
});

test('missing verification and authorization produce HOLD', () => {
  const bundle = createExampleBundle(NOW);
  const decision = evaluateAssurance({
    manifest: bundle.manifest,
    receipt: null,
    authorization: null,
    policy: bundle.policy,
    trustStore: bundle.trustStore,
    at: bundle.at,
    candidate: bundle.candidate,
    receiverContext: bundle.receiverContext,
  });
  assert.equal(decision.conclusion, 'HOLD');
  assert.deepEqual(decision.reasons.map((entry) => entry.code), ['authorization.missing', 'receipt.missing']);
});

test('forged signed content blocks on signature verification', async () => {
  await withBundle(async (directory, bundle) => {
    bundle.receipt.verdict = 'BLOCK';
    const dossier = await dossierFor(directory, bundle);
    assert.equal(dossier.decision.conclusion, 'BLOCK');
    assert.ok(dossier.decision.reasons.some((entry) => entry.code === 'receipt.invalid_signature'));
  });
});

test('revoked verifier trust root blocks current standing', async () => {
  await withBundle(async (directory, bundle) => {
    bundle.trustStore.keys[0].revokedAt = '2030-01-01T11:59:30.000Z';
    const dossier = await dossierFor(directory, bundle);
    assert.equal(dossier.decision.conclusion, 'BLOCK');
    assert.ok(dossier.decision.reasons.some((entry) => entry.code === 'receipt.key_revoked'));
  });
});

test('a different verifier model cannot compensate for a shared owner', async () => {
  await withBundle(async (directory, bundle) => {
    bundle.receipt.verifier.ownerId = bundle.manifest.candidate.producer.ownerId;
    bundle.receipt.verifier.model = 'different-model-name';
    const dossier = await dossierFor(directory, bundle);
    assert.equal(dossier.decision.conclusion, 'BLOCK');
    assert.ok(dossier.decision.reasons.some((entry) => entry.code === 'separation.producer_verifier'));
  });
});

test('tampering with a portable dossier invalidates recorded integrity', async () => {
  await withBundle(async (directory, bundle) => {
    const dossier = await dossierFor(directory, bundle, { embedEvidence: true });
    dossier.inputs.authorization.scope.environment = 'production';
    const verified = verifyDossier(dossier, bundle.trustStore, {
      at: bundle.at,
      candidate: bundle.candidate,
      receiverContext: bundle.receiverContext,
    });
    assert.equal(verified.integrity, 'INVALID');
    assert.equal(verified.current.conclusion, 'BLOCK');
  });
});

async function withBundle(callback) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'assurance-kit-test-'));
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
    candidate: overrides.candidate ?? bundle.candidate,
    receiverContext: overrides.receiverContext ?? bundle.receiverContext,
    at: overrides.at ?? bundle.at,
    embedEvidence: overrides.embedEvidence ?? false,
  });
}
