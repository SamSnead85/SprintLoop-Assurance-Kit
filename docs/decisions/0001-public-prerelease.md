# Decision 0001: authorize the first public GitHub prerelease

- Status: approved
- Date: 2026-08-27
- Decision owner: LockedIn Labs release owner

## Decision

Authorize publication of SprintLoop Assurance Kit as an MIT-licensed public GitHub repository and `v0.1.0` prerelease after every gate below passes.

The approved public scope is the dependency-free evaluator, CLI, library, schemas, conformance fixtures, offline dossier verifier, root composite Action, no-network bundle materializer, examples, and governance/security documentation. No private SprintLoop service, customer data, credential, signing key, private adapter, npm publication, GitHub Marketplace listing, hosted enforcement service, or production-authority claim is authorized.

## Immutable revisions

- Reviewed Action execution revision: `d5307358ce6a39d12de025748cb0676acbe461bf`
- Release/tag source revision: the clean successor commit that resolves this Action pin, dates the changelog, records this decision, and adds the remote-resolution smoke workflow.

If evaluator, cryptography, materializer, schema, or Action runtime behavior changes after the reviewed Action revision, this approval is void and the two-commit bootstrap must restart.

## Required publication gates

1. Local verify, fixture, sensitive-data, SBOM, package-inventory, packed-install, and release-dry-run gates are green from a clean full Git revision.
2. Hosted `verify`, local-source `golden-path`, remote Action resolution, and release-candidate dry-run workflows are green.
3. The repository is made public without announcement, then private vulnerability reporting, read-only workflow permissions, dependency alerts, secret scanning, push protection, and immutable releases are enabled and verified.
4. Branch protection requires `verify` and `golden-path`, enforces linear history and conversation resolution, and prohibits force pushes and deletion.
5. The annotated tag targets the reviewed release source; release assets include the private npm-format installation tarball, SPDX SBOM, release subject, and `SHA256SUMS` generated from that source.

The prerelease remains a pre-1.0 shadow/minimum integration kit. Production enforcement requires separately governed identity, key lifecycle, authenticated exact-coordinate bundle retrieval, repository rules, operational recovery, and customer pilot evidence.
