import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { createExampleBundle, writeExampleBundle } from '../src/example.mjs';
import { writeJsonAtomic } from '../src/io.mjs';

const root = process.cwd();
const baseTime = new Date('2030-01-01T12:00:00.000Z');

await scenario('fixtures/conformance/pass', 'PASS', baseTime.toISOString(), (bundle) => bundle);
await scenario('fixtures/conformance/hold-expired', 'HOLD', '2030-01-02T13:00:00.000Z', (bundle) => bundle);
await scenario('fixtures/adversarial/candidate-substitution', 'BLOCK', baseTime.toISOString(), (bundle) => {
  bundle.manifest.candidate.digest = 'git:sha1:0000000000000000000000000000000000000000';
  return bundle;
});
await scenario('fixtures/adversarial/forged-receipt', 'BLOCK', baseTime.toISOString(), (bundle) => {
  bundle.receipt.verdict = 'BLOCK';
  return bundle;
});
await scenario('fixtures/adversarial/evidence-tamper', 'BLOCK', baseTime.toISOString(), (bundle) => {
  bundle.evidence['evidence/test-report.json'] = Buffer.from('{"tampered":true}\n', 'utf8');
  return bundle;
});
await scenario('fixtures/adversarial/owner-collision', 'BLOCK', baseTime.toISOString(), (bundle) => {
  bundle.receipt.verifier.ownerId = bundle.manifest.candidate.producer.ownerId;
  return bundle;
});

process.stdout.write('Generated 6 public conformance/adversarial fixture bundles with public keys only\n');

async function scenario(relative, conclusion, at, mutate) {
  const directory = path.join(root, relative);
  const bundle = mutate(createExampleBundle(baseTime));
  await writeExampleBundle(directory, bundle);
  for (const [relativePath, bytes] of Object.entries(bundle.evidence)) {
    const output = path.join(directory, relativePath);
    await mkdir(path.dirname(output), { recursive: true });
    await writeFile(output, bytes, { mode: 0o644 });
  }
  await writeJsonAtomic(path.join(directory, 'expected.json'), {
    conclusion,
    at,
    candidate: bundle.candidate,
    receiverContext: bundle.receiverContext,
  });
}
