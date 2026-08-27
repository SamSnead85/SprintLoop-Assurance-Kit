import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { documentDigest } from '../src/canonical.mjs';
import { createExampleBundle } from '../src/example.mjs';

const kitRoot = path.resolve(import.meta.dirname, '..');
const executable = path.join(kitRoot, 'bin/sprintloop-assure.mjs');

test('doctor CLI returns path-free warning and fully pinned pass contracts', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'assurance-doctor-cli-'));
  try {
    const bundle = createExampleBundle(new Date('2030-01-01T12:00:00.000Z'));
    await mkdir(path.join(root, '.assurance'));
    await writeJson(path.join(root, '.assurance/policy.json'), bundle.policy);
    await writeJson(path.join(root, '.assurance/trust.json'), bundle.trustStore);
    git(root, ['init', '-q']);
    git(root, ['config', 'user.name', 'Assurance Test']);
    git(root, ['config', 'user.email', 'fixture@invalid']);
    git(root, ['add', '.']);
    git(root, ['commit', '-qm', 'receiver fixture']);
    const head = git(root, ['rev-parse', 'HEAD']).trim();
    const tree = git(root, ['rev-parse', 'HEAD^{tree}']).trim();

    const warning = invoke(['doctor', '--root', root, '--json']);
    assert.equal(warning.status, 10, warning.stderr);
    assert.equal(JSON.parse(warning.stdout).status, 'warn');
    assert.doesNotMatch(warning.stdout, new RegExp(escapeRegex(root)));

    const passing = invoke([
      'doctor', '--root', root,
      '--expected-head', head,
      '--expected-tree', tree,
      '--expected-policy-digest', documentDigest(bundle.policy),
      '--expected-trust-digest', documentDigest(bundle.trustStore),
      '--json',
    ]);
    assert.equal(passing.status, 0, passing.stderr);
    const report = JSON.parse(passing.stdout);
    assert.equal(report.status, 'pass');
    assert.equal(report.mode, 'READ_ONLY_OFFLINE');
    assert.equal(report.securityBoundary.networkAccess, false);
    assert.equal(report.securityBoundary.filesystemWrites, false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('collect-evidence CLI emits deterministic machine output and fails closed on malformed input', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'assurance-collector-cli-'));
  try {
    await mkdir(path.join(root, 'ci'));
    await writeFile(path.join(root, 'ci/junit.xml'), '<testsuite><testcase/></testsuite>\n');
    await writeJson(path.join(root, 'inputs.json'), [
      { id: 'tests', path: 'ci/junit.xml', format: 'junit' },
    ]);
    const subjectDigest = `git:sha1:${'a'.repeat(40)}`;
    const result = invoke([
      'collect-evidence', '--input', path.join(root, 'inputs.json'), '--root', root,
      '--path-base', 'evidence', '--subject-digest', subjectDigest,
    ]);
    assert.equal(result.status, 0, result.stderr);
    const collection = JSON.parse(result.stdout);
    assert.equal(collection.schemaVersion, 'assurance.sprintloop.dev/evidence-collection/v1');
    assert.equal(collection.evidence[0].inspectionLevel, 'STRUCTURE_FULL');
    assert.equal(collection.evidence[0].claimsVerified, false);
    assert.equal(collection.pathBase, 'evidence');
    assert.deepEqual(collection.manifestEvidence, [{
      id: 'tests',
      type: 'test-report',
      path: 'evidence/ci/junit.xml',
      mediaType: 'application/junit+xml',
      digest: collection.evidence[0].digest,
      subjectDigest,
    }]);

    await writeFile(path.join(root, 'ci/junit.xml'), '<testsuite name="bad<value"/>');
    const malformed = invoke(['collect-evidence', '--input', path.join(root, 'inputs.json'), '--root', root]);
    assert.equal(malformed.status, 2);
    assert.equal(malformed.stdout, '');
    assert.match(malformed.stderr, /Evidence collection failed \(EMALFORMED\)/);
    assert.doesNotMatch(malformed.stderr, new RegExp(escapeRegex(root)));

    const confidential = path.join(root, 'TOP_SECRET_CUSTOMER', 'evidence-inputs.json');
    const missing = invoke(['collect-evidence', '--input', confidential, '--root', root]);
    assert.equal(missing.status, 2);
    assert.equal(missing.stdout, '');
    assert.match(missing.stderr, /Evidence descriptor input failed validation \(EINPUT\)/);
    assert.doesNotMatch(missing.stderr, /TOP_SECRET_CUSTOMER|evidence-inputs|assurance-collector-cli/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

function invoke(args) {
  return spawnSync(process.execPath, [executable, ...args], {
    cwd: kitRoot,
    encoding: 'utf8',
  });
}

function git(root, args) {
  return execFileSync('git', args, { cwd: root, encoding: 'utf8' });
}

async function writeJson(file, value) {
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
