import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { canonicalize, documentDigest } from '../src/canonical.mjs';

const subject = {
  schemaVersion: 'assurance.sprintloop.dev/release-subject/v1',
  repository: 'https://github.com/acme/payments-api',
  environment: 'production',
  operation: 'release',
  commitDigest: 'git:sha1:0123456789abcdef0123456789abcdef01234567',
  treeDigest: 'git-tree:sha1:89abcdef0123456789abcdef0123456789abcdef',
};

test('canonical release subject v1 matches the cross-product golden vector', async () => {
  assert.equal(
    canonicalize(subject),
    '{"commitDigest":"git:sha1:0123456789abcdef0123456789abcdef01234567","environment":"production","operation":"release","repository":"https://github.com/acme/payments-api","schemaVersion":"assurance.sprintloop.dev/release-subject/v1","treeDigest":"git-tree:sha1:89abcdef0123456789abcdef0123456789abcdef"}',
  );
  assert.equal(
    documentDigest(subject),
    'sha256:0a6d1440b68b3ae8a27bee767b0fdd533f633aed587152ca2cf22a63b4e1716c',
  );
  const schema = JSON.parse(await readFile(
    path.resolve(import.meta.dirname, '../schemas/release-subject.v1.schema.json'),
    'utf8',
  ));
  assert.equal(schema.properties.schemaVersion.const, subject.schemaVersion);
  assert.deepEqual(schema.required, Object.keys(subject));
});
