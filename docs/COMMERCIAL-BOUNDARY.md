# Open and commercial boundary

## MIT-licensed adoption layer

- Versioned schemas and decision semantics
- Dependency-free evaluator library
- CLI and GitHub composite Action
- Signature and trust-store verification
- Offline-verifiable dossier
- Conformance and adversarial fixtures

This layer should remain vendor-neutral so teams can inspect the release rule, integrate it anywhere, and verify exported records without a hosted service.

## Managed or enterprise layer

A commercial SprintLoop Assurance product can add:

- SSO, workload identity, delegated standing, and separation-of-duty administration
- KMS/HSM signing and key lifecycle
- Tenant-isolated event and artifact storage
- GitHub/GitLab/Jira/Linear and agent-runtime collectors
- Policy profiles, exception workflow, revocation, and recertification
- Required-check delivery, reconciliation, and deployment observation
- Audit search, retention, legal hold, SIEM, and compliance exports
- Operated FDE discovery, shadow calibration, and enforcement rollout

The commercial service should implement the public contracts rather than making exported evidence proprietary. Customers should retain the ability to verify a dossier offline.

## Recommended go-to-market

Start with a bounded shadow pilot: one consequential workflow, one to three repositories, one builder owner, one separately governed verifier owner, and one named release authority. Measure coverage, holds, false blocks, authorization latency, audit reconstruction time, and expansion. Enable required-check enforcement only after an agreed calibration threshold and rollback drill.
