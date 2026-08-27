import { generateKeyPairSync } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { canonicalize, documentDigest, sha256 } from './canonical.mjs';
import { signDocument } from './crypto.mjs';
import { writeJsonAtomic } from './io.mjs';

const DEMO_CANDIDATE = 'git:sha1:9d10bb3ff25e3f56c1a768ddf201dd6763c4bca2';
const DEMO_TREE = 'git-tree:sha1:8a91a64c1d4a82d98b0f5a839459b12280f542ad';

function iso(milliseconds) {
  return new Date(milliseconds).toISOString();
}

export function createExampleBundle(now = new Date(), overrides = {}) {
  const base = now.getTime();
  const candidateDigest = overrides.candidate ?? DEMO_CANDIDATE;
  const treeDigest = overrides.treeDigest ?? DEMO_TREE;
  const repository = overrides.repository ?? 'https://example.invalid/engineering/sample-service';
  const environment = overrides.environment ?? 'staging';
  const issuedAt = iso(base - 60_000);
  const verifierExpiresAt = iso((base - 60_000) + (24 * 60 * 60 * 1000));
  const authorityExpiresAt = iso((base - 60_000) + (4 * 60 * 60 * 1000));

  const testReport = Buffer.from(`${JSON.stringify({
    schemaVersion: 'example.test-report/v1',
    subjectDigest: candidateDigest,
    suite: 'release',
    passed: 42,
    failed: 0,
  }, null, 2)}\n`, 'utf8');
  const sbom = Buffer.from(`${JSON.stringify({
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: 'example-candidate',
    documentNamespace: 'https://assurance.sprintloop.dev/examples/sbom/1',
    packages: [],
  }, null, 2)}\n`, 'utf8');

  const intent = {
    outcome: 'Demonstrate exact-candidate assurance without a model dependency.',
    acceptanceCriteria: ['Release suite passes', 'SBOM is present'],
  };
  const manifest = {
    schemaVersion: 'assurance.sprintloop.dev/manifest/v1',
    changeId: 'change:example-001',
    candidate: {
      repository,
      digest: candidateDigest,
      treeDigest,
      environment,
      producer: {
        principalId: 'agent:builder',
        ownerId: 'team:delivery',
        controlDomain: 'delivery',
      },
    },
    intent: {
      id: 'intent:example-001',
      digest: sha256(canonicalize(intent)),
    },
    evidence: [
      {
        id: 'evidence:release-tests',
        type: 'test-report',
        path: 'evidence/test-report.json',
        mediaType: 'application/json',
        digest: sha256(testReport),
        subjectDigest: candidateDigest,
      },
      {
        id: 'evidence:sbom',
        type: 'sbom',
        path: 'evidence/sbom.spdx.json',
        mediaType: 'application/spdx+json',
        digest: sha256(sbom),
        subjectDigest: candidateDigest,
      },
    ],
  };

  const policy = {
    schemaVersion: 'assurance.sprintloop.dev/policy/v1',
    policyId: 'policy:consequential-default',
    requiredEvidenceTypes: ['test-report', 'sbom'],
    allowedVerifierMethods: ['deterministic', 'hybrid'],
    separation: {
      producerVerifier: 'owner',
      verifierAuthority: 'principal',
      producerAuthority: 'principal',
    },
    requireNamedHumanAuthority: true,
    requireSignedReceipt: true,
    requireSignedAuthorization: true,
    maxReceiptValiditySeconds: 86400,
    maxAuthorizationValiditySeconds: 14400,
    maxClockSkewSeconds: 60,
    maxEvidenceBytes: 5_242_880,
    maxEvidenceItems: 32,
    maxTotalEvidenceBytes: 20_971_520,
  };

  const verifierKeys = generateKeyPairSync('ed25519');
  const authorityKeys = generateKeyPairSync('ed25519');
  const trustStore = {
    schemaVersion: 'assurance.sprintloop.dev/trust-store/v1',
    trustDomain: 'example:release',
    keys: [
      {
        keyId: 'key:example-verifier-v1',
        principalId: 'service:independent-verifier',
        ownerId: 'team:assurance',
        controlDomain: 'assurance',
        roles: ['verifier'],
        publicKeyPem: verifierKeys.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        validFrom: iso(base - (24 * 60 * 60 * 1000)),
        validUntil: iso(base + (365 * 24 * 60 * 60 * 1000)),
      },
      {
        keyId: 'key:example-authority-v1',
        principalId: 'person:release-authority',
        ownerId: 'team:release-management',
        controlDomain: 'release-management',
        roles: ['authority'],
        publicKeyPem: authorityKeys.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        validFrom: iso(base - (24 * 60 * 60 * 1000)),
        validUntil: iso(base + (365 * 24 * 60 * 60 * 1000)),
      },
    ],
  };
  const policyDigest = documentDigest(policy);
  const trustStoreDigest = documentDigest(trustStore);

  const receipt = signDocument({
    schemaVersion: 'assurance.sprintloop.dev/verifier-receipt/v1',
    receiptId: 'receipt:example-001',
    subjectDigest: candidateDigest,
    manifestDigest: documentDigest(manifest),
    policyDigest,
    trustStoreDigest,
    trustDomain: trustStore.trustDomain,
    evidenceDigests: manifest.evidence.map((entry) => entry.digest),
    verdict: 'PASS',
    verifier: {
      principalId: 'service:independent-verifier',
      ownerId: 'team:assurance',
      controlDomain: 'assurance',
      engine: 'example-deterministic-verifier',
      method: 'deterministic',
    },
    issuedAt,
    expiresAt: verifierExpiresAt,
  }, verifierKeys.privateKey, 'key:example-verifier-v1');

  const authorization = signDocument({
    schemaVersion: 'assurance.sprintloop.dev/authorization/v1',
    authorizationId: 'authorization:example-001',
    subjectDigest: candidateDigest,
    manifestDigest: documentDigest(manifest),
    receiptDigest: documentDigest(receipt),
    policyDigest,
    trustStoreDigest,
    trustDomain: trustStore.trustDomain,
    decision: 'ALLOW',
    authority: {
      principalId: 'person:release-authority',
      ownerId: 'team:release-management',
      controlDomain: 'release-management',
      role: 'release-authority',
      kind: 'human',
    },
    scope: { repository, environment, operation: 'release' },
    issuedAt,
    expiresAt: authorityExpiresAt,
  }, authorityKeys.privateKey, 'key:example-authority-v1');

  return {
    candidate: candidateDigest,
    treeDigest,
    at: now.toISOString(),
    manifest,
    receipt,
    authorization,
    policy,
    trustStore,
    receiverContext: {
      expectedPolicyDigest: policyDigest,
      expectedTrustStoreDigest: trustStoreDigest,
      expectedRepository: repository,
      expectedEnvironment: environment,
      actualCandidateDigest: candidateDigest,
      actualTreeDigest: treeDigest,
      workingTreeClean: true,
    },
    evidence: {
      'evidence/test-report.json': testReport,
      'evidence/sbom.spdx.json': sbom,
    },
  };
}

export async function writeExampleBundle(directory, bundle) {
  await mkdir(directory, { recursive: true });
  for (const [relative, bytes] of Object.entries(bundle.evidence)) {
    const output = path.join(directory, relative);
    await mkdir(path.dirname(output), { recursive: true });
    await writeFile(output, bytes, { mode: 0o644 });
  }
  await writeJsonAtomic(path.join(directory, 'manifest.json'), bundle.manifest);
  await writeJsonAtomic(path.join(directory, 'verifier-receipt.json'), bundle.receipt);
  await writeJsonAtomic(path.join(directory, 'authorization.json'), bundle.authorization);
  await writeJsonAtomic(path.join(directory, 'policy.json'), bundle.policy);
  await writeJsonAtomic(path.join(directory, 'trust.json'), bundle.trustStore);
}
