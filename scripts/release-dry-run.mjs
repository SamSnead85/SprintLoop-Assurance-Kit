import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const root = process.cwd();
const packageJson = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
if (packageJson.private !== true) fail('package.json must set private:true for the authorized GitHub-only pre-1.0 release');
await access(path.join(root, 'docs/SOURCE-INVENTORY.md')).catch(() => fail('docs/SOURCE-INVENTORY.md is required'));

const inside = run('git', ['rev-parse', '--is-inside-work-tree'], { allowFailure: true });
if (inside.status !== 0 || inside.stdout.trim() !== 'true') fail('release:dry-run requires a Git repository');
const source = run('git', ['rev-parse', '--verify', 'HEAD']).stdout.trim();
if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(source)) fail('release:dry-run requires a full reviewed Git commit SHA');
const status = run('git', ['status', '--porcelain=v1', '--untracked-files=all']).stdout;
if (status.trim()) fail('release:dry-run requires a clean Git worktree and index');
const unresolvedMarker = `${['REPLACE', 'WITH'].join('_')}_`;
const unresolved = run('git', ['grep', '-n', '--fixed-strings', unresolvedMarker, '--', '.'], { allowFailure: true });
if (unresolved.status === 0) fail(`release:dry-run found an unresolved bootstrap marker:\n${unresolved.stdout}`);
if (unresolved.status !== 1) fail('release:dry-run could not verify bootstrap markers');

const [integrationExample, shadowExample, shadowGuide, cliTemplate, remoteSmoke] = await Promise.all([
  readFile(path.join(root, 'examples/github/assurance.yml'), 'utf8'),
  readFile(path.join(root, 'examples/github/shadow-provider.yml'), 'utf8'),
  readFile(path.join(root, 'docs/SHADOW-PROVIDER.md'), 'utf8'),
  readFile(path.join(root, 'src/cli.mjs'), 'utf8'),
  readFile(path.join(root, '.github/workflows/remote-action-smoke.yml'), 'utf8'),
]);
const actionPins = [
  ...integrationExample.matchAll(/SamSnead85\/SprintLoop-Assurance-Kit(?:\/materialize-bundle)?@([0-9a-f]{40})/g),
  ...shadowExample.matchAll(/SamSnead85\/SprintLoop-Assurance-Kit\/prepare-shadow-bundle@([0-9a-f]{40})/g),
  ...cliTemplate.matchAll(/SamSnead85\/SprintLoop-Assurance-Kit(?:\/materialize-bundle)?@([0-9a-f]{40})/g),
  ...remoteSmoke.matchAll(/SamSnead85\/SprintLoop-Assurance-Kit(?:\/(?:materialize-bundle|prepare-shadow-bundle))?@([0-9a-f]{40})/g),
].map((match) => match[1]);
if (actionPins.length !== 8 || actionPins.some((revision) => revision !== actionPins[0])) {
  fail('release:dry-run requires eight identical full immutable Action revisions across examples, generated workflow, and remote smoke');
}
const actionRevision = actionPins[0];
const guidePins = [...shadowGuide.matchAll(/SamSnead85\/SprintLoop-Assurance-Kit\/prepare-shadow-bundle@([0-9a-f]{40})/g)]
  .map((match) => match[1]);
if (guidePins.length !== 1 || guidePins[0] !== actionRevision) {
  fail('release:dry-run requires the shadow-provider guide to use the reviewed Action revision');
}

run('npm', ['run', 'verify']);
await mkdir(path.join(root, 'artifacts'), { recursive: true });
const packed = run('npm', ['pack', '--json', '--pack-destination', 'artifacts']);
const details = JSON.parse(packed.stdout)[0];
const tarballPath = path.join(root, 'artifacts', details.filename);
const sbomPath = path.join(root, 'artifacts/sbom.spdx.json');
const tarball = await readFile(tarballPath);
const sbom = await readFile(sbomPath);
const packageRelease = {
  schemaVersion: 'assurance.sprintloop.dev/package-release/v1',
  npmPublished: false,
  distribution: 'github-prerelease-candidate',
  package: details.name,
  version: details.version,
  filename: details.filename,
  digest: digest(tarball),
  size: tarball.length,
  sourceRevision: source,
  actionRevision,
  sbom: {
    path: 'artifacts/sbom.spdx.json',
    digest: digest(sbom),
  },
};
if (packageRelease.npmPublished !== false || !packageRelease.sourceRevision) fail('Package release publication and source invariants failed');
const packageReleasePath = path.join(root, 'artifacts/package-release.json');
await writeFile(packageReleasePath, `${JSON.stringify(packageRelease, null, 2)}\n`, 'utf8');
const packageReleaseBytes = await readFile(packageReleasePath);
const sums = [
  [details.filename, digest(tarball).slice(7)],
  ['package-release.json', digest(packageReleaseBytes).slice(7)],
  ['sbom.spdx.json', digest(sbom).slice(7)],
].sort((left, right) => left[0].localeCompare(right[0]));
await writeFile(
  path.join(root, 'artifacts/SHA256SUMS'),
  `${sums.map(([file, hash]) => `${hash}  ${file}`).join('\n')}\n`,
  'utf8',
);
const notes = `# SprintLoop Assurance Kit ${details.version}\n\nGitHub prerelease candidate for source \`${source}\`.\n\n- Distribution: GitHub source/Action only; no npm package is published.\n- Release/tag source revision: \`${source}\`\n- Reviewed immutable Action revision: \`${actionRevision}\`\n- Candidate artifact: \`${details.filename}\`\n- Artifact digest: \`${packageRelease.digest}\`\n- SBOM: \`${packageRelease.sbom.path}\` (\`${packageRelease.sbom.digest}\`)\n- Verification: run \`npm ci --ignore-scripts && npm run verify\` from this exact source revision.\n- Status: pre-1.0 shadow/minimum integration; see the security and enforcement boundaries in README.\n`;
await writeFile(path.join(root, 'artifacts/release-notes.md'), notes, 'utf8');
process.stdout.write(`Unpublished GitHub candidate: ${packageRelease.filename} ${packageRelease.digest} source:${source}\n`);

function digest(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function fail(message) {
  process.stderr.write(`Release gate: ${message}\n`);
  process.exit(1);
}

function run(command, args, { allowFailure = false } = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: 'utf8',
    env: {
      ...process.env,
      npm_config_cache: path.join(os.tmpdir(), 'sprintloop-assurance-kit-npm-cache'),
    },
  });
  if (!allowFailure && result.status !== 0) {
    process.stderr.write(result.stdout ?? '');
    process.stderr.write(result.stderr ?? '');
    process.exit(result.status ?? 1);
  }
  return result;
}
