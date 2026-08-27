# SprintLoop Assurance Kit

[![CI](https://github.com/SamSnead85/SprintLoop-Assurance-Kit/actions/workflows/ci.yml/badge.svg)](https://github.com/SamSnead85/SprintLoop-Assurance-Kit/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-6f5cff)
![Node: maintained 22/24 LTS](https://img.shields.io/badge/node-maintained_22%2F24_LTS-2f855a)
![Git observer: 2.45+](https://img.shields.io/badge/Git_observer-2.45%2B-374151)
![Runtime dependencies: zero](https://img.shields.io/badge/runtime_dependencies-zero-0f766e)

**Independent proof before permission for agent-built software.**

SprintLoop Assurance Kit is a model-neutral release-assurance control for the AI software development lifecycle. It sits between evidence-producing CI and the protected SCM/deployment gate, binding the **exact Git candidate**, receiver-owned policy and trust, an independent verifier receipt, and a finite named authorization into deterministic `PASS`, `HOLD`, or `BLOCK` plus an offline-verifiable dossier.

The open-source Kit is the inspectable adoption layer: protocol, schemas, CLI, library, GitHub Action, CI evidence collectors, setup doctor, conformance fixtures, and local read-only MCP tools. Its evaluation, doctor, collector, materializer, shadow, and local MCP runtime paths have no third-party runtime dependencies and make no network calls when run with Git 2.45 or newer; release tooling and an operator-supplied provider are separate boundaries. The Kit never treats an AI opinion, agent identity claim, or transport/provider assertion as release authority.

The latest public prerelease is **v0.2.0**. The repository's **v0.3.0 development line is not released yet**; it adds the doctor, standard evidence collectors, strict CLI/version contracts, and a seventh MCP tool. Use v0.2.0 for the published no-clone evaluation below, and do not treat a branch or working tree as an immutable v0.3 security pin.

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

## Evaluate it in under a minute

Prerequisites: a maintained Node.js 22 LTS runtime at 22.23.2 or newer, or Node.js 24 LTS at 24.20.0 or newer. Git-backed observation also requires Git 2.45 or newer; the self-contained demo below does not inspect Git. This runs the published v0.2.0 GitHub artifact without cloning the repository or installing a global binary:

```bash
npm exec --yes \
  --package=https://github.com/SamSnead85/SprintLoop-Assurance-Kit/releases/download/v0.2.0/sprintloop-assurance-kit-0.2.0.tgz \
  -- sprintloop-assure demo --out artifacts/assurance-demo
```

The expected decision is `PASS`. The demo creates two ephemeral Ed25519 keypairs in memory, discards the private keys, and writes public inputs plus deterministic evidence under `artifacts/assurance-demo`. It proves the local protocol loop; it is not evidence about your repository and does not establish production readiness.

For a checksum-first evaluation, verify the artifact **before** executing it:

```bash
set -euo pipefail
mkdir sprintloop-assurance-eval && cd sprintloop-assurance-eval
curl -fLO https://github.com/SamSnead85/SprintLoop-Assurance-Kit/releases/download/v0.2.0/SHA256SUMS
curl -fLO https://github.com/SamSnead85/SprintLoop-Assurance-Kit/releases/download/v0.2.0/sprintloop-assurance-kit-0.2.0.tgz
grep ' sprintloop-assurance-kit-0.2.0.tgz$' SHA256SUMS > sprintloop-assurance-kit.sha256
shasum -a 256 -c sprintloop-assurance-kit.sha256
npm exec --yes --package="file:$PWD/sprintloop-assurance-kit-0.2.0.tgz" -- \
  sprintloop-assure demo --out artifacts/assurance-demo
```

The published v0.2.0 tarball digest is `sha256:a2c14d9e618b689e9358611637783f087798b38f9fd6a54bd0b1da4e591840f2`, generated from release/tag source `378a6cd7156c03dce1aca8774fa066f902f10396`. Confirm it against the release's `SHA256SUMS`, not this README alone. Fetching the artifact and checksum from the same GitHub release detects mismatch with the recorded bytes; it is not an independent publisher-signature or transparency proof.

To inspect and test the v0.2 code path instead, detach at its reviewed source/pin revision:

```bash
set -euo pipefail
git clone https://github.com/SamSnead85/SprintLoop-Assurance-Kit.git SprintLoop-Assurance-Kit
git -C SprintLoop-Assurance-Kit checkout --detach 35febce58e85ceec126ee6ce940461a25cfbe93e
cd SprintLoop-Assurance-Kit
npm ci --ignore-scripts
npm test
npm run demo
```

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

## Put the v0.3 development workflow against your repository

The useful handoff is a sequence, not a chatbot opinion:

```text
doctor exact tracked receiver checkout
  -> collect and raw-byte-hash standard CI evidence
  -> inspect requirements / evidence / decisions through local read-only MCP
  -> hand an external exact-candidate bundle to an independently governed verifier
  -> require finite authorization in receiver-governed CI or deployment controls
```

The v0.3 source line exposes the first three steps locally. For a repository that already tracks `.assurance/policy.json` and `.assurance/trust.json`, run the doctor with explicit receiver-controlled pins:

```bash
node /absolute/reviewed/kit/bin/sprintloop-assure.mjs doctor \
  --root /absolute/service \
  --expected-head 0123456789abcdef0123456789abcdef01234567 \
  --expected-tree 89abcdef0123456789abcdef0123456789abcdef \
  --expected-policy-digest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --expected-trust-digest sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --json
```

Replace every illustrative value with an observation or pin from outside the candidate. Deriving the expected digest from the same untrusted checkout inside an enforcement job defeats the binding. Omitting expected values is useful for diagnosis but intentionally returns warning exit `10`, never enforcement readiness. Exact Git observation requires Git 2.45 or newer. See the [setup doctor contract](docs/DOCTOR.md).

After test, scan, SBOM, provenance, and signature producers have exited, describe their immutable handoff files in a JSON array and collect bounded metadata:

```bash
node /absolute/reviewed/kit/bin/sprintloop-assure.mjs collect-evidence \
  --input /absolute/receiver/evidence-inputs.json \
  --root /absolute/receiver/handoff \
  --path-base evidence \
  --subject-digest git:sha1:<receiver-observed-40-hex-commit> > evidence-collection.json
```

Descriptor paths are portable relative paths under `--root`. `--path-base` records their bundle namespace without exposing a host path, and an explicit receiver-observed `--subject-digest` adds a deterministic `manifestEvidence` projection ready for the existing evaluator. The MCP collector returns its selected bundle-relative `evidenceRoot` as `pathBase` but deliberately cannot provide the receiver subject or create release authority. Collection establishes exact bytes and supported structure, not truth, signature validity, policy satisfaction, or release eligibility. See [deterministic CI evidence collectors](docs/EVIDENCE-COLLECTORS.md).

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

The Kit includes a local, dependency-free stdio MCP server for Codex, Claude Code, Cursor, and compatible engineering clients. The v0.3 development source exposes seven fixed read-only tools: capabilities, standard evidence collection, policy requirements, manifest validation, external-bundle evaluation, dossier verification, and reason-code explanation. It gives an engineer a local inspection interface to the same deterministic contracts; it does not give the client, model, or MCP server authority to release.

The latest published v0.2.0 MCP surface has six tools and does not include `assurance_collect_evidence`. Its GitHub-only distribution uses the exact reviewed source revision below; no npm package is published:

```bash
set -euo pipefail
git clone https://github.com/SamSnead85/SprintLoop-Assurance-Kit.git /absolute/pinned/SprintLoop-Assurance-Kit
git -C /absolute/pinned/SprintLoop-Assurance-Kit checkout --detach 35febce58e85ceec126ee6ce940461a25cfbe93e
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
sprintloop-assure version [--json]
sprintloop-assure doctor [--root DIR] [--policy FILE] [--trust FILE] [immutable expectations] [--json]
sprintloop-assure collect-evidence --input JSON_FILE [--root DIR] [bounds]
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

Version `0.2.0` is the latest public pre-1.0 integration kit and is suitable for evaluation and controlled shadow pilots. Version `0.3.0` is under development and is not yet a published or approved release. Neither line is a hosted identity system, key-management service, deployment engine, compliance certification, or legal determination. Before enforcement, an operator must supply authenticated identities, independently governed signing keys, a protected trust store, repository rules, key rotation and revocation, time synchronization, retention controls, and recovery procedures.

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

Read [SECURITY.md](SECURITY.md) before reporting a vulnerability. Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md), and [CODE_OF_CONDUCT.md). Project direction, compatibility intent, maintainer scope, and support channels are public in [ROADMAP.md](ROADMAP.md), [MAINTAINERS.md](MAINTAINERS.md), and [SUPPORT.md](SUPPORT.md).

Adoption is measured through reproducible runs, real-repository diagnostics, integrations, field reports, and independently useful contributions. The project does not buy stars, automate engagement, exchange stars, manufacture field reports, or use undisclosed promotion.

MIT © 2026 LockedIn Labs contributors.
