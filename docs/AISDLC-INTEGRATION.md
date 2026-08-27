# AISDLC integration

Assurance is the control gate between verification and effect.

```text
Intent and acceptance criteria
  → plan and build
  → exact candidate seal
  → deterministic tests, scans, provenance, and self-QA
  → independent eligibility verification
  → finite named authorization
  → authenticated out-of-band bundle retrieval
  → release interlock
  → deployment observation and dossier retention
```

The kit contributes four portable AISDLC artifacts:

1. A candidate manifest binding intent, exact Git digest, producer identity, environment, and evidence.
2. A signed independent verifier receipt binding the complete evidence set.
3. A signed, scoped, expiring authorization binding that receipt.
4. A dossier containing the reproducible decision and current standing.

The first three artifacts are post-candidate records. They live in receiver/verifier-controlled storage, not in the Git candidate they bind. A trusted integration retrieves them by exact commit/tree, repository, environment, policy digest, and trust boundary into a separate runner directory before the deterministic gate runs.

Within a SprintLoop suite, a runtime may execute work and emit evidence, an FDE engagement may install and calibrate policies, and SprintLoop Assurance may operate the independent trust and decision plane. The open kit keeps the protocol usable with any tracker, coding agent, CI provider, model, policy engine, or deployment platform.

For SOC 2, ISO 27001, regulated SDLC, or internal audit, the dossier can support control evidence and change reconstruction. It does not itself certify compliance; control owners and auditors determine applicability and sufficiency.
