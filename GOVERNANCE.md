# Governance

SprintLoop Assurance Kit is maintained in public under a lightweight maintainer model.

## Roles

- Contributors submit issues, fixtures, documentation, and code.
- Maintainers review and merge changes, manage releases, and respond to security reports.
- Release owners approve a specific source revision and artifact for publication.

No contributor gains verifier or release authority in a consuming organization by contributing to this project.

## Decisions

Routine changes require one maintainer approval and green repository gates. Changes to schemas, canonicalization, cryptography, trust semantics, separation, conclusion precedence, or release workflows require:

- a public design issue;
- threat-model and compatibility analysis;
- conformance and adversarial fixtures;
- release-owner approval while the project has one maintainer, and two independent maintainer approvals once a second maintainer exists; and
- a documented versioning decision.

Security fixes may be prepared privately and disclosed after a patched release. Maintainers will document material governance changes in the changelog.

## Releases

Release owners must review the lockfile, license, source inventory, sensitive-data scan, tests, fixture gate, SBOM, package inventory, full clean source revision, release subject, and `SHA256SUMS`. Version 0.1 is GitHub-only and `private:true`; npm publication is structurally blocked. The current workflow creates an unpublished candidate only; adding any publication requires a separately reviewed governance decision.
