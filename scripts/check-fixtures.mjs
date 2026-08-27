import { readdir } from 'node:fs/promises';
import path from 'node:path';
import { createDossier, verifyDossier } from '../src/dossier.mjs';
import { readJson } from '../src/io.mjs';

const root = process.cwd();
const groups = ['fixtures/conformance', 'fixtures/adversarial'];
let checked = 0;

for (const group of groups) {
  const parent = path.join(root, group);
  for (const entry of await readdir(parent, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const directory = path.join(parent, entry.name);
    const [manifest, receipt, authorization, policy, trustStore, expected] = await Promise.all([
      readJson(path.join(directory, 'manifest.json')),
      readJson(path.join(directory, 'verifier-receipt.json')),
      readJson(path.join(directory, 'authorization.json')),
      readJson(path.join(directory, 'policy.json')),
      readJson(path.join(directory, 'trust.json')),
      readJson(path.join(directory, 'expected.json')),
    ]);
    const dossier = await createDossier({
      manifest,
      receipt,
      authorization,
      policy,
      trustStore,
      evidenceRoot: directory,
      candidate: expected.candidate,
      receiverContext: {
        ...expected.receiverContext,
        actualCandidateDigest: expected.candidate,
        actualTreeDigest: manifest.candidate.treeDigest,
        workingTreeClean: true,
      },
      at: expected.at,
      embedEvidence: true,
    });
    if (dossier.decision.conclusion !== expected.conclusion) {
      throw new Error(`${group}/${entry.name}: expected ${expected.conclusion}, received ${dossier.decision.conclusion}`);
    }
    const verified = verifyDossier(dossier, trustStore, {
      at: expected.at,
      candidate: expected.candidate,
      receiverContext: dossier.receiverContext,
    });
    if (verified.integrity !== 'VALID' || verified.current.conclusion !== expected.conclusion) {
      throw new Error(`${group}/${entry.name}: offline verification failed`);
    }
    checked += 1;
  }
}

process.stdout.write(`Fixture gate: ${checked} conformance/adversarial bundles verified\n`);
