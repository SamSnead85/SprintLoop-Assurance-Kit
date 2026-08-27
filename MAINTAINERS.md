# Maintainers

This file identifies who can review and release the public Kit. It does not grant verifier, authorization, or deployment authority inside any consuming organization.

## Current roster

| Maintainer | GitHub | Project roles | Status |
| --- | --- | --- | --- |
| LockedIn Labs release owner | [@SamSnead85](https://github.com/SamSnead85) | maintainer, release owner, security triage | active |

The project currently has one maintainer. That is an explicit bus-factor and review-independence limitation. A sole CODEOWNER approval must not be described as independent review. Repository-maintainer independence is also distinct from the receiver-owned builder/verifier/release-authority separation required when the Kit evaluates a candidate.

## Responsibilities

Maintainers:

- triage public issues and private vulnerability reports;
- preserve model neutrality, exact-candidate binding, and receiver-owned trust;
- review implementation, tests, fixtures, schemas, threat-model impact, and compatibility;
- keep public examples free of credentials, customer data, proprietary fixtures, and unsafe mutable pins;
- enforce the contribution and code-of-conduct policies; and
- document material decisions and limitations instead of converting uncertainty into a `PASS` claim.

Release owners additionally verify the clean source revision, lockfile, license and source inventory, sensitive-data scan, conformance and adversarial gates, package inventory, SBOM, release record, artifacts, and checksums before publication. The complete release requirements remain authoritative in [GOVERNANCE.md](GOVERNANCE.md) and the applicable decision record.

## Review ownership

[`.github/CODEOWNERS`](.github/CODEOWNERS) routes reviews for the default source tree and highlights security-sensitive surfaces. It is a routing mechanism, not a security control by itself. Branch rules and the governance requirements determine whether review is required.

Changes to schemas, canonicalization, cryptography, trust semantics, separation, conclusion precedence, evidence acquisition, or release workflows require the heightened process in [GOVERNANCE.md](GOVERNANCE.md). While the project has one maintainer, that includes a public design issue and explicit release-owner approval. Once a second independent maintainer exists, the two-approval rule applies.

## Adding a maintainer

A contributor may be nominated after demonstrating sustained, public work that includes review or adversarial testing—not only feature authorship. A nominee should:

- understand the documented threat model and be willing to reject unsafe convenience;
- produce small, reviewable changes with deterministic tests and public-safe fixtures;
- disclose relevant conflicts and commercial affiliations;
- respond constructively to security and compatibility concerns; and
- agree to the repository's governance, security, conduct, and release rules.

The current maintainer opens a public governance issue describing the proposed scope and evidence. Appointment requires an explicit recorded decision and an update to this roster and CODEOWNERS. Trust-boundary release approval should be distributed only after the new maintainer has independently reviewed at least one complete release candidate.

## Inactivity and succession

A maintainer who expects to be unavailable should say so publicly when safe and arrange issue, release, and private security-report coverage. A maintainer may be moved to emeritus status after 90 days without project activity or earlier at their request; this does not erase attribution. Removal for security or conduct reasons may be handled privately first, with the minimum public record needed to keep authority unambiguous.

If no active maintainer can complete the release checklist, the project may continue to accept discussion and patches but must not publish a release until ownership is re-established. Release urgency does not relax the trust boundary.
