import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { collectEvidence } from '../src/collect-evidence.mjs';
import { validateJsonSchema } from '../src/schema-check.mjs';

const kitRoot = path.resolve(import.meta.dirname, '..');
const corpusRoot = path.join(kitRoot, 'fixtures/collector-producers');
const inputs = [
  { id: 'producer:pytest-junit', path: 'producer-output/pytest-9.0.2-junit.xml', format: 'junit' },
  { id: 'producer:github-codeql-sarif', path: 'producer-output/github-codeql-action-6f530319-sarif-2.1.0.json', format: 'sarif' },
  { id: 'producer:syft-spdx', path: 'producer-output/syft-1.31.0-spdx.json', format: 'spdx' },
  { id: 'producer:syft-cyclonedx', path: 'producer-output/syft-1.31.0-cyclonedx.json', format: 'cyclonedx' },
  { id: 'producer:github-slsa-provenance', path: 'producer-output/github-cli-attestation-21158102-slsa-v1.json', format: 'in-toto' },
  { id: 'producer:cosign-sigstore-bundle', path: 'producer-output/cosign-3.1.3-sigstore-bundle.json', format: 'sigstore' },
  { id: 'producer:github-artifact-attestation-bundle', path: 'producer-output/github-cli-attestation-21158102-sigstore-bundle.json', format: 'sigstore' },
];

const [schema, expected] = await Promise.all([
  readJson(path.join(kitRoot, 'schemas/evidence-collection.v1.schema.json')),
  readJson(path.join(corpusRoot, 'expected-collection.json')),
]);

test('real producer fixtures remain compatible with the collector and public schema', async () => {
  const actual = await collectEvidence(inputs, { root: corpusRoot });

  assert.deepEqual(validateJsonSchema(schema, actual), []);
  assert.deepEqual(actual, expected);
  assert.deepEqual(new Set(actual.evidence.map(({ format }) => format)), new Set([
    'junit',
    'sarif',
    'spdx',
    'cyclonedx',
    'in-toto',
    'sigstore',
  ]));
  assert.ok(actual.evidence.every(({ claimsVerified }) => claimsVerified === false));
  assert.equal(actual.evidence.filter(({ format }) => format === 'sigstore').length, 2);
});

async function readJson(file) {
  return JSON.parse(await readFile(file, 'utf8'));
}
