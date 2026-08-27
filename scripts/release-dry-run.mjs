import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const root = process.cwd();
const packageJson = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
if (packageJson.private !== true) fail('package.json must set private:true for the authorized GitHub-only v0.1 release');
await access(path.join(root, 'docs/SOURCE-INVENTORY.md')).catch(() => fail('docs/SOURCE-INVENTORY.md is required'));

const inside = run('git', ['rev-parse', '--is-inside-work-tree'], { allowFailure: true });
if (inside.status !== 0 || inside.stdout.trim() !== 'true') fail('release:dry-run requires a Git repository');
const source = run('git', ['rev-parse', '--verify', 'HEAD']).stdout.trim();
if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(source)) fail('release:dry-run requires a full reviewed Git commit SHA');
const status = run('git', ['status', '--porcelain=v1', '--untracked-files=all']).stdout;
if (status.trim()) fail('release:dry-run requires a clean Git worktree and index');

run('npm', ['run', 'verify']);
await mkdir(path.join(root, 'artifacts'), { recursive: true });
const packed = run('npm', ['pack', '--json', '--pack-destination', 'artifacts']);
const details = JSON.parse(packed.stdout)[0];
const tarballPath = path.join(root, 'artifacts', details.filename);
const sbomPath = path.join(root, 'artifacts/sbom.spdx.json');
const tarball = await readFile(tarballPath);
const sbom = await readFile(sbomPath);
const subject = {
  schemaVersion: 'assurance.sprintloop.dev/release-subject/v1',
  npmPublished: false,
  distribution: 'github-prerelease-candidate',
  package: details.name,
  version: details.version,
  filename: details.filename,
  digest: digest(tarball),
  size: tarball.length,
  sourceRevision: source,
  sbom: {
    path: 'artifacts/sbom.spdx.json',
    digest: digest(sbom),
  },
};
if (subject.npmPublished !== false || !subject.sourceRevision) fail('Release subject publication and source invariants failed');
const subjectPath = path.join(root, 'artifacts/release-subject.json');
await writeFile(subjectPath, `${JSON.stringify(subject, null, 2)}\n`, 'utf8');
const subjectBytes = await readFile(subjectPath);
const sums = [
  [details.filename, digest(tarball).slice(7)],
  ['release-subject.json', digest(subjectBytes).slice(7)],
  ['sbom.spdx.json', digest(sbom).slice(7)],
].sort((left, right) => left[0].localeCompare(right[0]));
await writeFile(
  path.join(root, 'artifacts/SHA256SUMS'),
  `${sums.map(([file, hash]) => `${hash}  ${file}`).join('\n')}\n`,
  'utf8',
);
const notes = `# SprintLoop Assurance Kit ${details.version}\n\nGitHub prerelease candidate for source \`${source}\`.\n\n- Distribution: GitHub source/Action only; no npm package is published.\n- Candidate artifact: \`${details.filename}\`\n- Artifact digest: \`${subject.digest}\`\n- SBOM: \`${subject.sbom.path}\` (\`${subject.sbom.digest}\`)\n- Verification: run \`npm ci --ignore-scripts && npm run verify\` from this exact source revision.\n- Status: pre-1.0 shadow/minimum integration; see the security and enforcement boundaries in README.\n`;
await writeFile(path.join(root, 'artifacts/release-notes.md'), notes, 'utf8');
process.stdout.write(`Unpublished GitHub candidate: ${subject.filename} ${subject.digest} source:${source}\n`);

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
