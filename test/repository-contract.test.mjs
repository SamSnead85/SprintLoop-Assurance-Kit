import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

const root = path.resolve(import.meta.dirname, '..');
const ACTION_REVISION = '0d3f6f0a27f7244d0ec0eb6d924df191b6180a0a';

test('repository text is checked out with deterministic LF line endings', async () => {
  const attributes = await readFile(path.join(root, '.gitattributes'), 'utf8');
  assert.equal(attributes, '* text=auto eol=lf\n');
});

test('composite Action requires the complete protected receiver context', async () => {
  const action = await readFile(path.join(root, 'action.yml'), 'utf8');
  for (const input of [
    'candidate',
    'candidate-root',
    'evidence-root',
    'manifest',
    'receipt',
    'authorization',
    'policy',
    'trust',
    'dossier',
    'expected-policy-digest',
    'expected-trust-digest',
    'expected-repository',
    'expected-environment',
  ]) {
    assert.match(action, new RegExp(`  ${input}:\\n(?:.*\\n){0,3}    required: true`));
  }
  assert.match(action, /--git-root/);
  assert.match(action, /--evidence-root/);
  assert.match(action, /Node >=22\.23\.2 <23 or >=24\.20\.0 <25/);
  assert.match(action, /id: assure/);
  assert.match(action, /node "\$\{\{ github\.action_path \}\}\/src\/cli\.mjs"/);
  assert.doesNotMatch(action, /default: \.assurance/);
  assert.doesNotMatch(action, /^\s*default: \.$/m);
});

test('bundle materializer is an explicit no-fetch fail-closed provider stub', async () => {
  const action = await readFile(path.join(root, 'materialize-bundle/action.yml'), 'utf8');
  for (const input of [
    'source',
    'destination',
    'candidate-root',
    'candidate',
    'policy',
    'trust',
    'expected-policy-digest',
    'expected-trust-digest',
    'expected-repository',
    'expected-environment',
  ]) {
    assert.match(action, new RegExp(`  ${input}:\\n(?:.*\\n){0,3}    required: true`));
  }
  assert.doesNotMatch(action, /\b(?:curl|wget|gh|aws|gcloud|az)\b/);
  const implementation = await readFile(path.join(root, 'src/materialize-bundle.mjs'), 'utf8');
  assert.match(implementation, /requireExactSourceInventory/);
  assert.match(implementation, /maxEvidenceItems/);
  assert.match(implementation, /rejectOverlap/);
  assert.match(implementation, /inspectReceiverGitState/);
});

test('all exact-candidate entry points use receiver-owned Git observation', async () => {
  const [cli, materializer, shadow, gitState] = await Promise.all([
    readFile(path.join(root, 'src/cli.mjs'), 'utf8'),
    readFile(path.join(root, 'src/materialize-bundle.mjs'), 'utf8'),
    readFile(path.join(root, 'src/prepare-shadow-bundle.mjs'), 'utf8'),
    readFile(path.join(root, 'src/git-state.mjs'), 'utf8'),
  ]);
  for (const source of [cli, materializer, shadow]) assert.match(source, /inspectReceiverGitState/);
  assert.match(gitState, /GIT_NO_REPLACE_OBJECTS: '1'/);
  assert.match(gitState, /GIT_INDEX_FILE: receiverIndex/);
  assert.match(gitState, /read-tree/);
  assert.match(gitState, /ls-tree/);
  assert.match(gitState, /gitBlobDigest/);
  assert.match(gitState, /createReadStream/);
});

test('self-dogfood invokes the local composite action for positive and adversarial contexts', async () => {
  const workflow = await readFile(path.join(root, '.github/workflows/self-dogfood.yml'), 'utf8');
  assert.equal((workflow.match(/^\s*uses: \.\/$/gm) ?? []).length, 2);
  assert.equal((workflow.match(/^\s*uses: \.\/materialize-bundle$/gm) ?? []).length, 1);
  assert.match(workflow, /name: golden-path/);
  assert.match(workflow, /runner\.temp.*assurance-provider-inbox/);
  assert.match(workflow, /runner\.temp.*assurance-bundle/);
  assert.doesNotMatch(workflow, /artifacts\/action-input/);
  assert.match(workflow, /expected-repository: https:\/\/example\.invalid\/substituted-repository/);
  assert.match(workflow, /decision\.conclusion!=='BLOCK'/);
});

test('all workflow checkouts disable credential persistence and runners are fixed', async () => {
  for (const relative of [
    '.github/workflows/ci.yml',
    '.github/workflows/remote-action-smoke.yml',
    '.github/workflows/self-dogfood.yml',
    '.github/workflows/release-candidate.yml',
    'examples/github/assurance.yml',
    'examples/github/shadow-provider.yml',
  ]) {
    const workflow = await readFile(path.join(root, relative), 'utf8');
    assert.doesNotMatch(workflow, /ubuntu-latest/);
    const checkouts = workflow.match(/uses: actions\/checkout@[^\n]+/g) ?? [];
    assert.ok(checkouts.length > 0, `${relative} has no checkout`);
    assert.equal((workflow.match(/persist-credentials: false/g) ?? []).length, checkouts.length, relative);
  }
  const ci = await readFile(path.join(root, '.github/workflows/ci.yml'), 'utf8');
  assert.match(ci, /os: \[ubuntu-24\.04, macos-14, windows-2022\]/);
  assert.match(ci, /node: \[22\.23\.2, 24\.20\.0\]/);
  assert.match(ci, /actions\/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e/);
  assert.match(ci, /package-manager-cache: false/);
  assert.match(ci, /token: ''/);
  assert.match(ci, /mirror-token: ''/);
  assert.match(ci, /git --no-lazy-fetch --version/);
  assert.match(ci, /npm run lint && npm test && npm run fixtures:check && npm run package:smoke/);
  for (const relative of [
    '.github/workflows/remote-action-smoke.yml',
    '.github/workflows/self-dogfood.yml',
    '.github/workflows/release-candidate.yml',
  ]) {
    const workflow = await readFile(path.join(root, relative), 'utf8');
    assert.match(workflow, /actions\/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e/);
    assert.match(workflow, /node-version: 24\.20\.0/);
    assert.match(workflow, /package-manager-cache: false/);
    assert.match(workflow, /token: ''/);
    assert.match(workflow, /mirror-token: ''/);
    assert.match(workflow, /process\.versions\.node!==['"]24\.20\.0['"]/);
    assert.doesNotMatch(workflow, /major<20|major===20|major>=25/);
  }
  const example = await readFile(path.join(root, 'examples/github/assurance.yml'), 'utf8');
  assert.match(example, /repository: \$\{\{ github\.event\.pull_request\.head\.repo\.full_name \}\}/);
  assert.match(example, /repository: \$\{\{ github\.repository \}\}/);
  assert.match(example, /sparse-checkout:\s*\|\s*\.assurance\/policy\.json\s*\.assurance\/trust\.json/);
  assert.match(example, /sparse-checkout-cone-mode: false/);
  const pins = [...example.matchAll(/SprintLoop-Assurance-Kit(?:\/materialize-bundle)?@([0-9a-f]{40})/g)]
    .map((match) => match[1]);
  assert.deepEqual(pins, [ACTION_REVISION, ACTION_REVISION]);
  assert.match(example, /source: \$\{\{ runner\.temp \}\}\/assurance-provider-inbox/);
  assert.match(example, /manifest: \$\{\{ steps\.bundle\.outputs\.manifest \}\}/);
  assert.doesNotMatch(example, /candidate\/\.assurance\/(?:manifest|verifier-receipt|authorization)/);
  assert.doesNotMatch(example, /evidence-root: candidate(?:\s|$)/);

  const shadowExample = await readFile(path.join(root, 'examples/github/shadow-provider.yml'), 'utf8');
  const shadowPins = [...shadowExample.matchAll(/SprintLoop-Assurance-Kit\/prepare-shadow-bundle@([0-9a-f]{40})/g)]
    .map((match) => match[1]);
  assert.deepEqual(shadowPins, [ACTION_REVISION]);

  const remoteSmoke = await readFile(path.join(root, '.github/workflows/remote-action-smoke.yml'), 'utf8');
  const remotePins = [...remoteSmoke.matchAll(/SprintLoop-Assurance-Kit(?:\/(?:materialize-bundle|prepare-shadow-bundle))?@([0-9a-f]{40})/g)]
    .map((match) => match[1]);
  assert.deepEqual(remotePins, [ACTION_REVISION, ACTION_REVISION, ACTION_REVISION]);
  assert.match(remoteSmoke, /runner\.temp.*assurance-provider-inbox/);
  assert.match(remoteSmoke, /runner\.temp.*assurance-bundle/);
});

test('GitHub-only package and clean-room inventory are structural release requirements', async () => {
  const packageJson = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  assert.equal(packageJson.private, true);
  assert.equal(packageJson.license, 'MIT');
  assert.ok(packageJson.files.includes('materialize-bundle/'));
  assert.ok(packageJson.files.includes('prepare-shadow-bundle/'));
  const release = await readFile(path.join(root, 'scripts/release-dry-run.mjs'), 'utf8');
  assert.match(release, /SOURCE-INVENTORY\.md/);
  assert.match(release, /npmPublished: false/);
  assert.match(release, /status.*--porcelain/);
  assert.match(release, /artifacts\/SHA256SUMS/);
  assert.match(release, /rm\(path\.join\(root, 'artifacts'\)/);
  assert.match(release, /Release artifact inventory is not exact/);
  assert.match(release, /actionRevision/);
  assert.match(release, /eight identical full immutable Action revisions/);
  assert.match(release, /examples\/github\/shadow-provider\.yml/);
  assert.match(release, /remote-action-smoke\.yml/);
  assert.match(release, /src\/cli\.mjs/);
  assert.match(release, /shadow-provider guide to use the reviewed Action revision/);
  assert.match(release, /assurance\.sprintloop\.dev\/package-release\/v1/);
  assert.doesNotMatch(release, /assurance\.sprintloop\.dev\/release-subject\/v1/);
  assert.match(release, /git.*grep/);
});
