import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { documentDigest } from '../src/canonical.mjs';
import {
  DOCTOR_EXIT_CODES,
  DOCTOR_MODE,
  DOCTOR_SCHEMA_VERSION,
  diagnoseSetup,
  doctorExitCode,
  formatDoctorHuman,
  formatDoctorJson,
  nodeVersionCheck,
} from '../src/doctor.mjs';
import { createExampleBundle } from '../src/example.mjs';
import { KIT_VERSION } from '../src/version.mjs';
import { validateJsonSchema } from '../src/schema-check.mjs';

const kitRoot = path.resolve(import.meta.dirname, '..');

const CHECK_IDS = [
  'runtime.node',
  'runtime.git',
  'repository.exactness',
  'policy.document',
  'policy.digest',
  'trust.document',
  'trust.digest',
  'mcp.configuration',
];

test('maintained Node checks reject prerelease and custom-suffixed runtimes', () => {
  assert.equal(nodeVersionCheck('v22.23.2').code, 'NODE_SUPPORTED');
  assert.equal(nodeVersionCheck('v24.20.0').code, 'NODE_SUPPORTED');
  assert.equal(nodeVersionCheck('v24.20.1-nightly.20260827').code, 'NODE_VERSION_UNRECOGNIZED');
  assert.equal(nodeVersionCheck('v22.23.2+custom').code, 'NODE_VERSION_UNRECOGNIZED');
  assert.equal(nodeVersionCheck('v23.99.0').code, 'NODE_UNSUPPORTED');
});

test('fully pinned receiver and MCP roots produce a stable, path-free PASS result', async () => {
  await withFixture(async (fixture) => {
    const result = await diagnoseSetup(fixture.options({ mcp: true }));

    assert.equal(result.schemaVersion, DOCTOR_SCHEMA_VERSION);
    assert.equal(result.kitVersion, KIT_VERSION);
    assert.equal(result.mode, DOCTOR_MODE);
    assert.equal(result.status, 'pass', formatDoctorJson(result));
    assert.deepEqual(result.summary, { pass: 8, warn: 0, error: 0, total: 8 });
    assert.deepEqual(result.checks.map((entry) => entry.id), CHECK_IDS);
    assert.ok(result.checks.every((entry) => entry.status === 'pass'));
    assert.deepEqual(result.securityBoundary, {
      networkAccess: false,
      credentialAccess: false,
      filesystemWrites: false,
      sourceControlWrites: false,
    });

    const repository = byId(result, 'repository.exactness');
    assert.equal(repository.data.head, fixture.head);
    assert.equal(repository.data.tree, fixture.tree);
    assert.equal(repository.data.exactnessScope, 'TRACKED_HEAD');
    assert.equal(repository.data.expectedHeadMatch, true);
    assert.equal(repository.data.expectedTreeMatch, true);
    assert.equal(byId(result, 'policy.document').data.canonicalDigest, fixture.policyDigest);
    assert.equal(byId(result, 'trust.document').data.canonicalDigest, fixture.trustDigest);
    assert.deepEqual(byId(result, 'mcp.configuration').data, {
      configured: true,
      rootCount: 3,
      rootKinds: ['bundle', 'dossier', 'receiver'],
    });

    const json = formatDoctorJson(result);
    assert.ok(json.endsWith('\n'));
    assert.deepEqual(JSON.parse(json), result);
    assert.equal(formatDoctorJson(result), json);
    assert.doesNotMatch(json, new RegExp(escapeRegex(fixture.root)));
    assert.doesNotMatch(json, /publicKeyPem|PRIVATE KEY|BEGIN PUBLIC KEY/i);

    const human = formatDoctorHuman(result);
    assert.match(human, new RegExp(`^SprintLoop Assurance doctor ${escapeRegex(KIT_VERSION)}: PASS`));
    assert.match(human, /\[PASS\] repository\.exactness REPOSITORY_EXACT/);
    assert.match(human, new RegExp(`digest=${escapeRegex(fixture.policyDigest)}`));
    assert.doesNotMatch(human, new RegExp(escapeRegex(fixture.root)));
    assert.equal(doctorExitCode(result), DOCTOR_EXIT_CODES.pass);
  });
});

test('unpinned expectations warn without claiming immutable receiver binding', async () => {
  await withFixture(async (fixture) => {
    await writeFile(path.join(fixture.root, 'ignored-local-output.txt'), 'not part of the tracked candidate\n');
    const indexBefore = await lstat(path.join(fixture.root, '.git/index'));
    const inventoryBefore = await inventory(fixture.root);

    const result = await diagnoseSetup({ root: fixture.root });

    const indexAfter = await lstat(path.join(fixture.root, '.git/index'));
    const inventoryAfter = await inventory(fixture.root);
    assert.equal(result.status, 'warn', formatDoctorJson(result));
    assert.equal(byId(result, 'repository.exactness').code, 'REPOSITORY_IDENTITY_UNPINNED');
    assert.equal(byId(result, 'repository.exactness').data.exactnessScope, 'TRACKED_HEAD');
    assert.equal(byId(result, 'policy.digest').code, 'POLICY_DIGEST_UNPINNED');
    assert.equal(byId(result, 'trust.digest').code, 'TRUST_DIGEST_UNPINNED');
    assert.equal(byId(result, 'mcp.configuration').code, 'MCP_NOT_REQUESTED');
    assert.equal(doctorExitCode(result), DOCTOR_EXIT_CODES.warn);
    assert.deepEqual(inventoryAfter, inventoryBefore);
    assert.equal(indexAfter.size, indexBefore.size);
    assert.equal(indexAfter.mtimeMs, indexBefore.mtimeMs);
  });
});

test('hardened repository observation catches bytes hidden by assume-unchanged', async () => {
  await withFixture(async (fixture) => {
    git(fixture.root, ['update-index', '--assume-unchanged', 'app.txt']);
    await writeFile(path.join(fixture.root, 'app.txt'), 'candidate bytes hidden from ordinary status\n');
    assert.equal(git(fixture.root, ['status', '--porcelain=v1', '--untracked-files=no']), '');

    const result = await diagnoseSetup(fixture.options());
    assert.equal(result.status, 'error');
    assert.equal(byId(result, 'repository.exactness').code, 'WORKTREE_NOT_EXACT');
    assert.equal(byId(result, 'repository.exactness').data.workingTreeClean, false);
    assert.equal(doctorExitCode(result), DOCTOR_EXIT_CODES.error);
  });
});

test('immutable identity and canonical digest mismatches fail closed', async () => {
  await withFixture(async (fixture) => {
    const result = await diagnoseSetup({
      ...fixture.options(),
      expectedHead: 'f'.repeat(40),
      expectedPolicyDigest: `sha256:${'e'.repeat(64)}`,
      expectedTrustStoreDigest: `sha256:${'d'.repeat(64)}`,
    });
    const schema = JSON.parse(await readFile(path.join(kitRoot, 'schemas/doctor-result.v1.schema.json'), 'utf8'));
    assert.deepEqual(validateJsonSchema(schema, result), []);
    assert.equal(result.status, 'error');
    assert.equal(byId(result, 'repository.exactness').code, 'REPOSITORY_IDENTITY_MISMATCH');
    assert.equal(byId(result, 'policy.digest').code, 'POLICY_DIGEST_MISMATCH');
    assert.equal(byId(result, 'trust.digest').code, 'TRUST_DIGEST_MISMATCH');
    assert.equal(byId(result, 'policy.digest').data.match, false);
    assert.equal(byId(result, 'trust.digest').data.match, false);
  });
});

test('valid but untracked receiver documents are never treated as protected inputs', async () => {
  await withFixture(async (fixture) => {
    git(fixture.root, ['rm', '--quiet', '.assurance/policy.json', '.assurance/trust.json']);
    git(fixture.root, ['-c', 'user.name=fixture', '-c', 'user.email=fixture@invalid', 'commit', '--quiet', '-m', 'remove protected inputs']);
    await mkdir(path.join(fixture.root, '.assurance'));
    await writeJson(path.join(fixture.root, '.assurance/policy.json'), fixture.bundle.policy);
    await writeJson(path.join(fixture.root, '.assurance/trust.json'), fixture.bundle.trustStore);
    const head = git(fixture.root, ['rev-parse', 'HEAD']).trim();
    const tree = git(fixture.root, ['rev-parse', 'HEAD^{tree}']).trim();

    const result = await diagnoseSetup({
      ...fixture.options(),
      expectedHead: head,
      expectedTree: tree,
    });
    assert.equal(byId(result, 'repository.exactness').status, 'pass');
    assert.equal(byId(result, 'policy.document').code, 'POLICY_NOT_PROTECTED');
    assert.equal(byId(result, 'trust.document').code, 'TRUST_NOT_PROTECTED');
    assert.equal(byId(result, 'policy.digest').code, 'POLICY_DIGEST_UNAVAILABLE');
    assert.equal(result.status, 'error');
  });
});

test('symlinked protected ancestors are rejected without exposing either path', async () => {
  const outside = await mkdtemp(path.join(os.tmpdir(), 'assurance-doctor-outside-'));
  try {
    await withFixture(async (fixture) => {
      await writeJson(path.join(outside, 'policy.json'), fixture.bundle.policy);
      await writeJson(path.join(outside, 'trust.json'), fixture.bundle.trustStore);
      await rm(path.join(fixture.root, '.assurance'), { recursive: true });
      await symlink(outside, path.join(fixture.root, '.assurance'), 'dir');

      const result = await diagnoseSetup(fixture.options());
      assert.equal(result.status, 'error');
      assert.equal(byId(result, 'policy.document').code, 'POLICY_PATH_UNSAFE');
      assert.equal(byId(result, 'trust.document').code, 'TRUST_PATH_UNSAFE');
      const serialized = formatDoctorJson(result);
      assert.doesNotMatch(serialized, new RegExp(escapeRegex(outside)));
      assert.doesNotMatch(serialized, new RegExp(escapeRegex(fixture.root)));
    });
  } finally {
    await rm(outside, { recursive: true, force: true });
  }
});

test('bounded document reads and structural complexity checks return sanitized errors', async () => {
  await withFixture(async (fixture) => {
    const padded = `${JSON.stringify(fixture.bundle.policy, null, 2)}${' '.repeat(2_000)}\n`;
    await writeFile(path.join(fixture.root, '.assurance/policy.json'), padded);
    commitAll(fixture.root, 'large policy');
    let result = await diagnoseSetup({
      ...fixture.currentOptions(),
      maxDocumentBytes: 1_024,
    });
    assert.equal(byId(result, 'policy.document').code, 'POLICY_TOO_LARGE');
    assert.equal(byId(result, 'policy.document').data.canonicalDigest, null);

    const nested = `${'{"nested":'.repeat(70)}null${'}'.repeat(70)}`;
    await writeFile(path.join(fixture.root, '.assurance/policy.json'), nested);
    commitAll(fixture.root, 'deep policy');
    result = await diagnoseSetup(fixture.currentOptions());
    assert.equal(byId(result, 'policy.document').code, 'POLICY_COMPLEXITY_EXCEEDED');
    assert.doesNotMatch(formatDoctorJson(result), /nested/);
  });
});

test('duplicate protected JSON keys are rejected before semantic validation', async () => {
  await withFixture(async (fixture) => {
    const duplicate = `{${[
      `${JSON.stringify('policyId')}:${JSON.stringify('attacker-shadow')}`,
      ...Object.entries(fixture.bundle.policy)
        .map(([key, value]) => `${JSON.stringify(key)}:${JSON.stringify(value)}`),
    ].join(',')}}`;
    await writeFile(path.join(fixture.root, '.assurance/policy.json'), duplicate);
    commitAll(fixture.root, 'duplicate policy key');

    const result = await diagnoseSetup(fixture.currentOptions());
    assert.equal(byId(result, 'policy.document').code, 'POLICY_JSON_INVALID');
    assert.equal(byId(result, 'policy.digest').code, 'POLICY_DIGEST_UNAVAILABLE');
    assert.equal(result.status, 'error');
  });
});

test('executable protected documents and invalid MCP grants are setup errors', async (context) => {
  if (process.platform === 'win32') return context.skip('executable mode is not represented by the Windows worktree');
  await withFixture(async (fixture) => {
    await chmod(path.join(fixture.root, '.assurance/policy.json'), 0o755);
    commitAll(fixture.root, 'executable policy');
    await writeJson(fixture.mcpConfigPath, {
      schemaVersion: 'assurance.sprintloop.dev/mcp-server-config/v1',
      roots: [{ id: 'bad', kind: 'receiver', path: 'relative/root' }],
    });

    const result = await diagnoseSetup(fixture.currentOptions({ mcp: true }));
    assert.equal(byId(result, 'policy.document').code, 'POLICY_MODE_INVALID');
    assert.equal(byId(result, 'mcp.configuration').code, 'MCP_CONFIG_INVALID');
    assert.doesNotMatch(formatDoctorJson(result), /relative\/root/);
  });
});

test('invalid and hostile option values are bounded before filesystem or subprocess inspection', async () => {
  const secret = 'do-not-echo-this-value';
  for (const options of [
    { policyPath: `../${secret}.json` },
    { root: `/tmp/project\n${secret}` },
    { expectedHead: secret },
    { expectedPolicyDigest: `sha256:${'A'.repeat(64)}` },
    { mcpConfigPath: 'relative-config.json' },
    { timeoutMs: 31_000 },
    { unexpected: secret },
  ]) {
    const result = await diagnoseSetup(options);
    assert.equal(result.status, 'error');
    assert.deepEqual(result.checks.map((entry) => entry.id), ['doctor.input']);
    assert.equal(byId(result, 'doctor.input').code, 'INPUT_INVALID');
    assert.doesNotMatch(formatDoctorJson(result), new RegExp(secret));
    assert.doesNotMatch(formatDoctorHuman(result), new RegExp(secret));
  }

  const rendered = formatDoctorHuman({
    kitVersion: `0.3.0\n${secret}`,
    status: `pass\n${secret}`,
    checks: [{ id: `runtime.node\n${secret}`, status: 'pass', code: 'OK', message: `unsafe\n${secret}`, data: {} }],
    summary: { pass: 1, warn: 0, error: 0, total: 1 },
  });
  assert.doesNotMatch(rendered, new RegExp(secret));
  assert.match(rendered, /^SprintLoop Assurance doctor unknown: ERROR/);
  assert.match(rendered, /doctor\.unknown OK: Diagnostic result is unavailable\./);
});

test('doctor reports an older Git precisely before attempting repository inspection', async (context) => {
  if (process.platform === 'win32') return context.skip('fixture uses a POSIX executable shim');
  const root = await mkdtemp(path.join(os.tmpdir(), 'assurance-doctor-old-git-'));
  try {
    const gitPath = path.join(root, 'git');
    await writeFile(gitPath, '#!/bin/sh\nprintf "git version 2.44.0\\n"\n');
    await chmod(gitPath, 0o755);
    const result = spawnSync(process.execPath, [
      path.join(kitRoot, 'src/cli.mjs'),
      'doctor', '--root', root, '--json',
    ], {
      encoding: 'utf8',
      env: { ...process.env, PATH: root },
      timeout: 2_000,
    });
    assert.equal(result.status, DOCTOR_EXIT_CODES.error, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(byId(report, 'runtime.git').code, 'GIT_UNSUPPORTED');
    assert.equal(byId(report, 'runtime.git').data.version, '2.44.0');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('doctor hard deadline aborts a non-settling Git process', async (context) => {
  if (process.platform === 'win32') return context.skip('fixture uses a POSIX executable shim');
  const root = await mkdtemp(path.join(os.tmpdir(), 'assurance-doctor-timeout-'));
  try {
    const gitPath = path.join(root, 'git');
    await writeFile(gitPath, '#!/bin/sh\nexec sleep 5\n');
    await chmod(gitPath, 0o755);
    const started = performance.now();
    const result = spawnSync(process.execPath, [
      path.join(kitRoot, 'src/cli.mjs'),
      'doctor', '--root', root, '--timeout-ms', '250', '--json',
    ], {
      encoding: 'utf8',
      env: { ...process.env, PATH: `${root}:/bin:/usr/bin` },
      timeout: 2_000,
    });
    const elapsed = performance.now() - started;
    assert.equal(result.status, DOCTOR_EXIT_CODES.error, result.stderr);
    assert.ok(elapsed < 1_500, `doctor took ${elapsed}ms after its hard deadline`);
    const report = JSON.parse(result.stdout);
    assert.equal(byId(report, 'runtime.git').code, 'GIT_CHECK_TIMEOUT');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('doctor repeatedly classifies an exhausted Git/repository deadline as a repository timeout', async (context) => {
  if (process.platform === 'win32') return context.skip('fixture uses a POSIX executable shim');
  const root = await mkdtemp(path.join(os.tmpdir(), 'assurance-doctor-repository-timeout-'));
  try {
    const gitPath = path.join(root, 'git');
    await writeFile(gitPath, [
      '#!/bin/sh',
      'if [ "$1" = "--version" ] || { [ "$1" = "--no-lazy-fetch" ] && [ "$2" = "--version" ]; }; then',
      '  printf "git version 2.50.1\\n"',
      '  exit 0',
      'fi',
      'exec sleep 5',
      '',
    ].join('\n'));
    await chmod(gitPath, 0o755);
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const started = performance.now();
      const result = spawnSync(process.execPath, [
        path.join(kitRoot, 'src/cli.mjs'),
        'doctor', '--root', root, '--timeout-ms', '250', '--json',
      ], {
        encoding: 'utf8',
        env: { ...process.env, PATH: `${root}:/bin:/usr/bin` },
        timeout: 1_500,
      });
      const elapsed = performance.now() - started;
      assert.equal(result.status, DOCTOR_EXIT_CODES.error, result.stderr);
      assert.ok(elapsed < 1_000, `attempt ${attempt} took ${elapsed}ms after its reporting deadline`);
      const report = JSON.parse(result.stdout);
      assert.equal(byId(report, 'repository.exactness').code, 'REPOSITORY_CHECK_TIMEOUT');
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('doctor preserves a Git capability timeout for the dependent repository check', async (context) => {
  if (process.platform === 'win32') return context.skip('fixture uses a POSIX executable shim');
  const root = await mkdtemp(path.join(os.tmpdir(), 'assurance-doctor-git-capability-timeout-'));
  try {
    const gitPath = path.join(root, 'git');
    await writeFile(gitPath, [
      '#!/bin/sh',
      'if [ "$1" = "--version" ]; then',
      '  printf "git version 2.50.1\\n"',
      '  exit 0',
      'fi',
      'exec sleep 5',
      '',
    ].join('\n'));
    await chmod(gitPath, 0o755);
    const started = performance.now();
    const result = spawnSync(process.execPath, [
      path.join(kitRoot, 'src/cli.mjs'),
      'doctor', '--root', root, '--timeout-ms', '250', '--json',
    ], {
      encoding: 'utf8',
      env: { ...process.env, PATH: `${root}:/bin:/usr/bin` },
      timeout: 1_500,
    });
    const elapsed = performance.now() - started;
    assert.equal(result.status, DOCTOR_EXIT_CODES.error, result.stderr);
    assert.ok(elapsed < 1_000, `doctor took ${elapsed}ms after its reporting deadline`);
    const report = JSON.parse(result.stdout);
    assert.equal(byId(report, 'runtime.git').code, 'GIT_CHECK_TIMEOUT');
    assert.equal(byId(report, 'repository.exactness').code, 'REPOSITORY_CHECK_TIMEOUT');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('doctor source has no network, credential, shell, or write-capable implementation surface', async () => {
  const source = await readFile(new URL('../src/doctor.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /node:(?:http|https|http2|net|tls|dns|dgram)/);
  assert.doesNotMatch(source, /\b(?:fetch|WebSocket|request|connect)\s*\(/);
  assert.doesNotMatch(source, /\b(?:writeFile|appendFile|mkdir|mkdtemp|rename|copyFile|unlink|rm)\b/);
  assert.doesNotMatch(source, /import\s*\{[^}]*\b(?:spawn|exec|execSync)\b[^}]*\}\s*from\s*['"]node:child_process['"]/);
  assert.doesNotMatch(source, /shell\s*:/);
  assert.doesNotMatch(source, /process\.env\.(?:TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL|AUTH)/i);
  assert.match(source, /GIT_TERMINAL_PROMPT: '0'/);
  assert.match(source, /GIT_NO_LAZY_FETCH: '1'/);
  assert.match(source, /includeUntracked: false/);
});

async function withFixture(callback) {
  const fixtureRoot = await mkdtemp(path.join(os.tmpdir(), 'assurance-doctor-test-'));
  const root = path.join(fixtureRoot, 'candidate');
  const bundleRoot = path.join(fixtureRoot, 'bundle');
  const dossierRoot = path.join(fixtureRoot, 'dossiers');
  const mcpConfigPath = path.join(fixtureRoot, 'mcp.json');
  try {
    const bundle = createExampleBundle(new Date('2030-01-01T12:00:00.000Z'));
    await Promise.all([
      mkdir(path.join(root, '.assurance'), { recursive: true }),
      mkdir(bundleRoot, { recursive: true }),
      mkdir(dossierRoot, { recursive: true }),
    ]);
    await Promise.all([
      writeFile(path.join(root, 'app.txt'), 'canonical candidate bytes\n'),
      writeJson(path.join(root, '.assurance/policy.json'), bundle.policy),
      writeJson(path.join(root, '.assurance/trust.json'), bundle.trustStore),
    ]);
    git(root, ['init', '--quiet']);
    commitAll(root, 'candidate');
    const head = git(root, ['rev-parse', 'HEAD']).trim();
    const tree = git(root, ['rev-parse', 'HEAD^{tree}']).trim();
    const policyDigest = documentDigest(bundle.policy);
    const trustDigest = documentDigest(bundle.trustStore);
    const receiverRoot = path.join(root, '.assurance');
    await writeJson(mcpConfigPath, {
      schemaVersion: 'assurance.sprintloop.dev/mcp-server-config/v1',
      roots: [
        { id: 'bundle', kind: 'bundle', path: bundleRoot },
        { id: 'receiver', kind: 'receiver', path: receiverRoot },
        { id: 'dossiers', kind: 'dossier', path: dossierRoot },
      ],
    });
    const fixture = {
      root,
      bundle,
      bundleRoot,
      dossierRoot,
      mcpConfigPath,
      head,
      tree,
      policyDigest,
      trustDigest,
      options({ mcp = false } = {}) {
        return {
          root,
          expectedHead: head,
          expectedTree: tree,
          expectedPolicyDigest: policyDigest,
          expectedTrustStoreDigest: trustDigest,
          ...(mcp ? { mcpConfigPath } : {}),
        };
      },
      currentOptions({ mcp = false } = {}) {
        return {
          root,
          expectedHead: git(root, ['rev-parse', 'HEAD']).trim(),
          expectedTree: git(root, ['rev-parse', 'HEAD^{tree}']).trim(),
          expectedPolicyDigest: policyDigest,
          expectedTrustStoreDigest: trustDigest,
          ...(mcp ? { mcpConfigPath } : {}),
        };
      },
    };
    await callback(fixture);
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
}

function commitAll(root, message) {
  git(root, ['add', '--all']);
  git(root, ['-c', 'user.name=fixture', '-c', 'user.email=fixture@invalid', 'commit', '--quiet', '-m', message]);
}

function git(root, args) {
  return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8' });
}

async function writeJson(file, value) {
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`);
}

async function inventory(root) {
  const result = [];
  async function walk(directory, relative = '') {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
      if (relative === '' && entry.name === '.git') continue;
      const next = relative ? `${relative}/${entry.name}` : entry.name;
      result.push(`${entry.isDirectory() ? 'd' : entry.isSymbolicLink() ? 'l' : 'f'}:${next}`);
      if (entry.isDirectory()) await walk(path.join(directory, entry.name), next);
    }
  }
  await walk(root);
  return result;
}

function byId(result, id) {
  const entry = result.checks.find((candidate) => candidate.id === id);
  assert.ok(entry, `missing doctor check ${id}`);
  return entry;
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
