# SprintLoop Assurance Kit

[![CI](https://github.com/SamSnead85/SprintLoop-Assurance-Kit/actions/workflows/ci.yml/badge.svg)](https://github.com/SamSnead85/SprintLoop-Assurance-Kit/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-6f5cff)
![Node: 20.11–24](https://img.shields.io/badge/node-20.11%E2%80%9324-2f855a)
![Runtime dependencies: zero](https://img.shields.io/badge/runtime_dependencies-zero-0f766e)

**Proof before permission for agent-built software.**

An AI builder can plan, code, and self-test a change. SprintLoop Assurance Kit independently determines whether the **exact Git candidate** is eligible to release by binding deterministic evidence to a receiver-trusted verifier and a finite, named authorization. It emits `PASS`, `HOLD`, or `BLOCK` plus a portable dossier that can be verified offline.

This is the open protocol, CLI, library, and GitHub Action for that boundary. It is model-neutral, has no runtime dependencies, makes no network calls, and never treats an AI opinion as release authority.

## Where it fits

```text
AISDLC intent
    ↓
Builder or coding agent ── self-QA ──→ deterministic evidence
    ↓ exact Git candidate                 ↓
                    independent verifier receipt
                                  ↓
                         finite named authority
                                  ↓
                 authenticated external bundle provider
                                  ↓
                   PASS / HOLD / BLOCK required check
                                  ↓
                     deployment + portable audit dossier
```

| Layer | Owns | Assurance Kit consumes or emits |
| --- | --- | --- |
| Intent / planning | Outcome, scope, acceptance criteria | Intent digest |
| Agent or developer | Candidate creation and self-QA | Exact Git digest and evidence |
| CI / security tools | Tests, scans, provenance, SBOM | Deterministically hashed evidence |
| Independent verifier | Eligibility finding | Receiver-trusted signed receipt |
| Release authority | Accountable permission | Signed, scoped, expiring authorization |
| SCM / deployment interlock | Effect enforcement | `PASS`, `HOLD`, or `BLOCK` |
| Audit / compliance | Historical reconstruction | Offline-verifiable dossier |

It complements SLSA, in-toto, Sigstore, artifact attestations, test systems, and policy engines. Those systems produce or verify facts. Assurance Kit binds facts, independent standing, and accountable permission to one exact candidate.

## Ten-minute golden path

Prerequisite: Node.js 20.11 or newer and earlier than Node.js 25.

```bash
git clone https://github.com/SamSnead85/SprintLoop-Assurance-Kit.git
cd SprintLoop-Assurance-Kit
npm ci --ignore-scripts
npm test
npm run demo
```

The demo creates two ephemeral Ed25519 keypairs in memory, discards the private keys, writes public inputs and deterministic evidence under `artifacts/demo`, and produces a `PASS` dossier.

Verify the result without a network or model:

```bash
POLICY_DIGEST="$(node src/cli.mjs document-digest --file artifacts/demo/policy.json)"
TRUST_DIGEST="$(node src/cli.mjs document-digest --file artifacts/demo/trust.json)"
node src/cli.mjs verify-dossier \
  --dossier artifacts/demo/dossier.json \
  --trust artifacts/demo/trust.json \
  --candidate git:sha1:9d10bb3ff25e3f56c1a768ddf201dd6763c4bca2 \
  --tree-digest git-tree:sha1:8a91a64c1d4a82d98b0f5a839459b12280f542ad \
  --working-tree-clean true \
  --expected-policy-digest "$POLICY_DIGEST" \
  --expected-trust-digest "$TRUST_DIGEST" \
  --expected-repository https://example.invalid/engineering/sample-service \
  --expected-environment staging
```

The expected result is:

```text
Integrity: VALID
Reproduction: REPRODUCED
Evidence: FULL
Anchoring: UNANCHORED
Recorded: PASS
Current: PASS
```

## Use it in GitHub Actions

Choose the integration lane that matches the controls you actually operate:

| Lane | Use it for | What it can conclude |
| --- | --- | --- |
| [No-secret shadow manifest](docs/SHADOW-PROVIDER.md) | A protected manual or scheduled pilot with receiver-declared CI evidence, but no verifier/signing service yet | Always `HOLD`, always `partial`, never enforcement eligible |
| [Authenticated complete provider](docs/BUNDLE-PROVIDER-CONTRACT.md) | A receiver-governed workflow that can retrieve a signed receipt and finite authorization for the exact candidate | `PASS`, `HOLD`, or `BLOCK` after full evaluation |

For the first lane, install the [manual/scheduled shadow workflow](examples/github/shadow-provider.yml). `prepare-shadow-bundle` disables Git replacement objects, compares canonical tree entries directly with raw worktree bytes and executable modes without candidate index flags or clean filters, and uses a receiver-owned temporary index only to find non-ignored untracked files. It hashes a bounded exact evidence inventory under runner-temporary storage and writes only a canonical manifest plus declared evidence. It never fetches, signs, handles credentials, creates a receipt/authorization, or emits `PASS`. Candidate evidence commands must write outside the checkout and leave it clean. Aggregate multiple JUnit, SARIF, or similar fragments into one declared artifact per evidence type. Because the sample runs candidate code and capture in the same unprivileged job, its output is producer-controlled telemetry—not a receiver-isolated observation or immutable assurance artifact.

For the second lane, start with the [authenticated-provider scaffold](examples/github/assurance.yml). It checks out a fork pull request's exact head SHA into `candidate/`, checks out only the protected base branch's policy and trust files into `receiver/`, and materializes a post-candidate assurance bundle under runner-temporary storage. The scaffold intentionally fails until a receiver-governed authenticated provider step populates its external inbox. The included materializer performs no network or credential work.

The manifest, receipt, authorization, and evidence must never come from `candidate/`: a tracked manifest cannot bind the final commit/tree that contains itself. They are generated after the candidate is sealed and retrieved by exact candidate, repository, environment, policy digest, and trust boundary. The main Action consumes only checked materializer outputs, verifies actual Git `HEAD`, tree, and tracked cleanliness, and fails on empty or substituted receiver values. See the [external bundle provider contract](docs/BUNDLE-PROVIDER-CONTRACT.md).

Bundle bytes are treated as untrusted until those signatures and bindings verify, so integrity does not depend on trusting the transport. The operator still owns provider identity, authorization, authenticated exact-coordinate lookup, availability, and confidentiality; the kit deliberately does not fetch from storage or handle provider credentials.

The no-secret lane must never be a required check. The authenticated sample is also not enterprise-grade enforcement by itself: a pull request can alter a repo-local workflow. Make a complete result required only when the check/workflow source is receiver-governed through a GitHub App, organization-required workflow and ruleset, or an equivalent protected control that a candidate cannot spoof or replace.

Pin every Action to an immutable reviewed commit, never a mutable tag. The main evaluator exits `0` on `PASS`, `10` on `HOLD`, `20` on `BLOCK`, and `2` on usage or runtime failure. GitHub treats every nonzero evaluator result as not eligible. The advisory shadow preparer exits successfully after capture but publishes `enforcement-eligible: false`; its green job status is not release permission.

The action requires only `contents: read`; it does not write checks, deployments, comments, or repository contents. Promotion remains the responsibility of the repository's protected environment or deployment system.

## Connect an AI engineering client

The Kit includes a local, dependency-free stdio MCP server for Codex, Claude Code, Cursor, and compatible engineering clients. It exposes six fixed read-only tools for capabilities, policy requirements, manifest validation, external-bundle evaluation, dossier verification, and reason-code explanation. Until an audited `0.2.x` artifact is released, run it only from an exact reviewed source checkout and pin the full commit SHA.

```bash
git clone https://github.com/SamSnead85/SprintLoop-Assurance-Kit.git /absolute/pinned/SprintLoop-Assurance-Kit
git -C /absolute/pinned/SprintLoop-Assurance-Kit checkout --detach FULL_40_CHARACTER_REVIEWED_COMMIT_SHA
codex mcp add sprintloop-assurance -- node /absolute/pinned/SprintLoop-Assurance-Kit/bin/sprintloop-assure.mjs mcp --config /absolute/path/assurance-mcp.json
```

The shorter global `sprintloop-assure` registration form is reserved for a future reviewed package release; it is not the current source-checkout installation path.

The server uses capability-granted `bundle`, `receiver`, and `dossier` root IDs. It rejects arbitrary paths, parent traversal, symlinked or replaced roots/documents, overlapping roots, oversized frames/documents, missing current context, unsafe candidate metadata, and output that violates its advertised JSON Schema 2020-12 contracts. Manifest metadata is explicitly labeled untrusted. MCP `2026-07-28` stateless discovery is primary, with `2025-11-25` and `2025-06-18` initialize compatibility.

This is an engineering inspection lane, not a release lane. Every tool is read-only, closed-world, and returns `enforcementEligible: false`; it cannot sign, approve, mutate policy/trust, write a check, merge, deploy, or enable enforcement. Use the receiver-governed Action or deployment interlock for authoritative effects.

See the [MCP integration and threat-boundary guide](docs/MCP.md) and [copyable client/config examples](examples/mcp/).

## The independence rule

Builder self-QA is valuable evidence, but it is not independent eligibility.

The default example requires the builder and verifier to have different `ownerId` values, and requires the verifier and release authority to be different principals. A second model invoked by the same builder owner does **not** satisfy this rule. Neither does renaming an agent, changing a prompt, or placing another step in the same workflow.

The receiver-owned trust store—not provider metadata—decides which public keys may sign verifier receipts or authorizations. The deterministic evaluator verifies:

- exact candidate, manifest, evidence-set, receipt, and authorization binding;
- actual Git commit, tree, clean tracked state, repository, and target environment;
- receiver-owned canonical policy and trust-store digests bound into both signatures;
- evidence bytes against SHA-256 digests;
- Ed25519 signatures and receiver-owned key roles;
- principal, owner, and control-domain separation;
- policy-required evidence and verifier method;
- issue time, expiry, maximum lifetime, and revocation; and
- authorization scope and named-human requirements.

Model metadata is descriptive only. It never creates identity, independence, trust, or authority.

## CLI

```text
sprintloop-assure init [--directory DIR]
sprintloop-assure demo [--out DIR]
sprintloop-assure mcp --config ABSOLUTE_FILE
sprintloop-assure digest --file FILE
sprintloop-assure document-digest --file JSON
sprintloop-assure sign-receipt --input FILE --private-key PEM --key-id ID --output FILE
sprintloop-assure sign-authorization --input FILE --private-key PEM --key-id ID --output FILE
sprintloop-assure check --candidate SHA --expected-policy-digest SHA256 \
  --expected-trust-digest SHA256 --expected-repository URI --expected-environment NAME [inputs]
sprintloop-assure verify-dossier --dossier FILE --trust FILE --candidate SHA --tree-digest TREE \
  --working-tree-clean true|false \
  --expected-policy-digest SHA256 --expected-trust-digest SHA256 \
  --expected-repository URI --expected-environment NAME
```

`init` writes a policy, an empty public trust-store template, and a GitHub workflow. It never generates or stores credentials.

The library API is also dependency-free when used from a clone or GitHub source artifact. Recorded reproduction may use the dossier's stored historical context; current standing requires an external candidate and complete receiver context:

```js
import { createDossier, verifyDossier } from '@sprintloop/assurance-kit';

const standing = verifyDossier(dossier, receiverTrustStore, {
  at: new Date().toISOString(),
  candidate: observedCandidateDigest,
  receiverContext: {
    expectedPolicyDigest,
    expectedTrustStoreDigest,
    expectedRepository,
    expectedEnvironment,
    actualCandidateDigest: observedCandidateDigest,
    actualTreeDigest: observedTreeDigest,
    workingTreeClean: observedTrackedCleanliness,
  },
});
```

`verifyDossier(dossier, trustStore)` can still reproduce recorded history, but its `current` result is deliberately `BLOCK`; it never promotes dossier-controlled context into current receiver intent.

See [the protocol](docs/PROTOCOL.md), [bundle provider contract](docs/BUNDLE-PROVIDER-CONTRACT.md), [decision semantics](docs/DECISION-SEMANTICS.md), [MCP integration guide](docs/MCP.md), and [GitHub integration guide](examples/github/README.md).

## Dossier verification levels

- `FULL`: evidence bytes are embedded and their digests can be recomputed offline.
- `ENVELOPE_ONLY`: signed bindings and current standing are verifiable offline, but the original evidence bytes must be retrieved separately.

Embedding is opt-in because test reports, scan results, and source-derived artifacts may be confidential. Classify and minimize a dossier before exporting it.

Every v1 dossier is explicitly `UNANCHORED`: its recorded time and local digest are reproducible integrity metadata, not an independent timestamp or signature. Anchor the dossier digest in a separately trusted transparency log, timestamp authority, or signed release system when external historical proof is required.

## AI and custom models

No model is needed for authoritative evaluation. A model may produce a code-review finding, intent-quality score, control mapping, or anomaly signal that becomes evidence for a separately owned verifier. It never signs as the human authority and cannot override deterministic failures.

A custom model should be considered only after real pilot data demonstrates a repeated, measurable classification task. Training one before that would add attack surface and operating cost without improving the trust boundary. See [model neutrality](docs/MODEL-NEUTRALITY.md).

## Status and safety boundary

Version `0.2.x` is a pre-1.0 integration kit suitable for evaluation and controlled shadow pilots. It is not a hosted identity system, key-management service, deployment engine, compliance certification, or legal determination. Before enforcement, an operator must supply authenticated identities, independently governed signing keys, a protected trust store, repository rules, key rotation and revocation, time synchronization, retention controls, and recovery procedures.

No npm package is published or authorized. `package.json` is `private:true`; the npm-format tarball exists only to test GitHub source-artifact installation. Use the pinned GitHub Action or clone an exact reviewed source commit.

Run the complete local gate:

```bash
npm run verify
npm run release:dry-run
```

`verify` works before the first commit. `release:dry-run` intentionally requires a clean Git repository and full reviewed commit SHA, then tests, scans, creates an SPDX SBOM, installation-smokes the private npm-format artifact, and writes a package release record, notes, and `SHA256SUMS`. It does **not** publish anything.

## Open-source and commercial boundary

This MIT-licensed kit is the portable adoption layer: schemas, evaluator, CLI, Action, fixtures, and dossier verification. A managed SprintLoop Assurance deployment can add organization identity, tenant isolation, policy administration, key lifecycle, evidence retention, required-check reconciliation, SIEM integrations, and operated pilots without changing the public protocol.

See [commercial boundary](docs/COMMERCIAL-BOUNDARY.md) and [AISDLC placement](docs/AISDLC-INTEGRATION.md).

## Security and contribution

Read [SECURITY.md](SECURITY.md) before reporting a vulnerability. Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

MIT © 2026 LockedIn Labs contributors.
