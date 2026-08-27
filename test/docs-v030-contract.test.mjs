import assert from 'node:assert/strict';
import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

const root = path.resolve(import.meta.dirname, '..');
const V02_SOURCE_PIN = '35febce58e85ceec126ee6ce940461a25cfbe93e';
const V02_RELEASE_SOURCE = '378a6cd7156c03dce1aca8774fa066f902f10396';
const V02_TARBALL_SHA256 = 'a2c14d9e618b689e9358611637783f087798b38f9fd6a54bd0b1da4e591840f2';

test('public onboarding separates published v0.2 from unreleased v0.3', async () => {
  const [readme, changelog, roadmap, decision] = await Promise.all([
    read('README.md'),
    read('CHANGELOG.md'),
    read('ROADMAP.md'),
    read('docs/decisions/0003-v0.3-developer-utility-gate.md'),
  ]);

  assert.match(readme, /latest public prerelease is \*\*v0\.2\.0\*\*/);
  assert.match(readme, /v0\.3\.0 development line is not released yet/);
  assert.match(readme, new RegExp(V02_SOURCE_PIN));
  assert.match(readme, new RegExp(V02_RELEASE_SOURCE));
  assert.match(readme, new RegExp(V02_TARBALL_SHA256));
  assert.match(readme, /npm exec --yes[\s\S]*releases\/download\/v0\.2\.0\/sprintloop-assurance-kit-0\.2\.0\.tgz/);
  assert.match(readme, /shasum -a 256 -c sprintloop-assurance-kit\.sha256/);
  assert.match(changelog, /## 0\.3\.0 — Unreleased/);
  assert.match(roadmap, /no v0\.3 tag, artifact checksum, source pin, Action pin, or release approval is claimed yet/);
  assert.match(decision, /Status: proposed; implementation under review/);
  assert.match(decision, /Do not tag, publish, announce v0\.3 as released/);
});

test('v0.3 integration docs preserve advisory authority and path-base contracts', async () => {
  const [readme, mcp, doctor, collector] = await Promise.all([
    read('README.md'),
    read('docs/MCP.md'),
    read('docs/DOCTOR.md'),
    read('docs/EVIDENCE-COLLECTORS.md'),
  ]);

  assert.match(readme, /seven fixed read-only tools/);
  assert.match(readme, /Exact Git observation requires Git 2\.45 or newer/);
  assert.match(mcp, /assurance_collect_evidence/);
  assert.equal((mcp.match(/^\| `assurance_[a-z_]+` \|/gm) ?? []).length, 7);
  assert.match(mcp, /enforcementEligible: false/);
  assert.match(doctor, /## CLI\n/);
  assert.doesNotMatch(doctor, /future CLI command/);
  assert.match(doctor, /Git is present[\s\S]*>=2\.45\.0/);
  assert.match(collector, /`--path-base` records where that root will sit in the bundle/);
  assert.match(collector, /output also contains `manifestEvidence`/);
  assert.match(collector, /returns `evidenceRoot` as `pathBase`/);
  assert.match(collector, /For CLI output it is `\.`/);
  assert.match(collector, /claimsVerified: false/);
});

test('local Markdown links resolve', async () => {
  const misses = [];
  let checked = 0;
  for (const file of await markdownFiles(root)) {
    const source = await readFile(file, 'utf8');
    for (const match of source.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)) {
      let target = match[1].trim();
      if (target.startsWith('<') && target.endsWith('>')) target = target.slice(1, -1);
      if (/^(?:https?:|mailto:|#)/u.test(target)) continue;
      target = target.split('#')[0].split('?')[0];
      if (!target) continue;
      checked += 1;
      try {
        await stat(path.resolve(path.dirname(file), decodeURIComponent(target)));
      } catch {
        misses.push(`${path.relative(root, file)} -> ${match[1]}`);
      }
    }
  }
  assert.ok(checked > 0);
  assert.deepEqual(misses, []);
});

async function read(relative) {
  return readFile(path.join(root, relative), 'utf8');
}

async function markdownFiles(directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (['.git', 'artifacts', 'node_modules'].includes(entry.name)) continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) output.push(...await markdownFiles(absolute));
    else if (entry.name.endsWith('.md')) output.push(absolute);
  }
  return output;
}
