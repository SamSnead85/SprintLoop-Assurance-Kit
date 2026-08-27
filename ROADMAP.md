# Roadmap

This is an outcome roadmap, not a release-date promise. Priorities change when field evidence shows that a different capability removes more adoption risk.

## Current position

The latest public line is the `v0.2` prerelease. `v0.3` is in development: its source surfaces may be tested, but no v0.3 tag, artifact checksum, source pin, Action pin, or release approval is claimed yet.

SprintLoop Assurance Kit is the MIT-licensed, inspectable adoption layer for exact-candidate release assurance: schemas, deterministic evaluation, a CLI, a GitHub Action, an offline-verifiable dossier, conformance fixtures, and a local read-only MCP surface. It is model-neutral; no AI model makes the authoritative decision.

The Kit is not a code-review model, hosted identity provider, key-management service, evidence-truth oracle, compliance certification, or deployment controller. The recommended pre-1.0 adoption posture is shadow or advisory. The MCP server and shadow provider are always advisory. A Kit `PASS` becomes release permission only when a consuming organization places it behind receiver-owned identity, trust, repository, and deployment controls.

## Product principles

- Preserve deterministic decisions and a small, inspectable trust boundary.
- Bind every result to the exact Git candidate, receiver-owned policy, and receiver-owned trust roots.
- Keep model output non-authoritative and provider-reported identity outside the receiver trust boundary.
- Make local evaluation useful without accounts, telemetry, network access, or proprietary evidence formats.
- Add an integration only when its permissions, failure modes, and enforcement eligibility can be stated precisely.
- Measure independent use and operational outcomes, not stars, impressions, or manufactured engagement.

## Now: `v0.3` developer utility

The `v0.3` target is to reduce time from checkout to a truthful first diagnostic on a real repository.

- Add an offline, read-only setup doctor for runtime, exact tracked Git state, protected policy/trust inputs, canonical digests, and optional MCP root configuration.
- Collect common CI artifacts into deterministic, data-minimized descriptors: JUnit, SARIF 2.1, SPDX JSON, CycloneDX JSON, in-toto/SLSA statements, and Sigstore bundles.
- Expose stable human and machine output, strict option handling, bounded reads, no-follow path controls, and actionable failure codes.
- Keep collected claims explicitly unverified. Collection establishes artifact identity and supported structure; an independent verifier and receiver policy establish release eligibility.
- Expand local MCP from six to seven read-only tools so an AI engineer can inspect requirements, collect privacy-minimized evidence metadata, validate a manifest, evaluate an external bundle, verify a dossier, and explain reasons without granting the client any effect.
- Require Git 2.45 or newer for Git-backed observation so lazy fetching can be disabled fail-closed; keep non-Git demo, parsing, and offline dossier workflows separate from that observer prerequisite.
- Publish copyable zero-install and checksum-first evaluation paths, with immutable source and Action pins.

`v0.3` is not complete because source files exist. It is complete only after the public CLI/library surfaces are integrated, positive and adversarial tests pass, the threat model and documentation agree with behavior, package and release dry-runs pass from a clean revision, and tagged artifacts are checksum-verifiable.

The intended adoption loop is: doctor the exact receiver state; collect standard evidence after producer handoff; inspect locally through CLI/MCP; materialize a post-candidate external bundle; obtain an independently governed verifier receipt and finite authorization; then let receiver-governed SCM/deployment controls apply any effect. A faster path that collapses those owners is not the product target.

## Compatibility posture

- Published artifacts, full source revisions, and executable Action references are immutable pins; branches and mutable tags are never security pins.
- Versioned JSON `schemaVersion` values remain the machine contract. A breaking schema change requires a new schema identifier rather than silent reinterpretation.
- Pre-1.0 minor releases may tighten rejected inputs or change CLI/MCP surfaces, but the changelog must name the migration. Stable reason codes and exit meanings do not change silently.
- New evidence formats must define exactly what is structurally inspected, what remains unverified, what metadata can leave the collector, and how paths bind into the external bundle.
- Protected-provider semantics remain invariant: candidate bytes never supply receiver intent, trust roots, independent identity, signing authority, current observation, or enforcement authority.

## Next: integration evidence

These items are ordered by pilot friction, not by marketing value:

1. Add stable reason-code lookup (`explain --code`) and an explicit receiver-context JSON input so CI failures are self-diagnosing and reproducible.
2. Keep the exact maintained-LTS floor matrix—Node 22.23.2 and 24.20.0—green on Ubuntu 24.04, macOS 14, and Windows 2022; document any narrower boundary found by hosted runs.
3. Add public-safe GitLab CI, Buildkite, and portable shell examples that preserve exact-candidate and out-of-band trust boundaries.
4. Add provenance and artifact-attestation examples without treating an attestation envelope as verified merely because it parses.
5. Publish anonymized pilot field reports covering time to first own-repository `HOLD`, missing controls, remediation effort, decision latency, and false `HOLD`/`BLOCK` findings.
6. Define a receiver-governed GitHub App or organization-required-workflow design only after shadow pilots establish the permission model, recovery path, and check-reconciliation semantics.

## Enforcement-readiness gate

Production enforcement is a separate decision, not a version-number shortcut. Before recommending a required release check, the project must demonstrate:

- authenticated retrieval by the full exact-candidate coordinate with no mutable-locator fallback;
- receiver-governed workload identity, public-key trust, key rotation, expiry, revocation, and recovery;
- independently owned verifier and release-authority paths with tested separation failures;
- deterministic check reconciliation, deployment observation, rollback, and break-glass exercises;
- documented availability, retention, privacy, incident-response, and audit-export responsibilities; and
- pilot evidence showing acceptable coverage, decision latency, and false-block behavior for the intended risk tier.

The open Kit may define and verify portable contracts for these controls. It does not claim to operate them.

## Thirty-day adoption scorecard

Measure the first 30 days after the `v0.3` release against these public, falsifiable targets:

| Outcome | Target |
| --- | ---: |
| Median fresh-checkout or zero-install demo time | under 60 seconds |
| Fresh-user sessions completed without maintainer intervention | at least 4 of 5 |
| Independent demo runs reported | at least 10 |
| Doctor runs against the operator's own repository | at least 5 |
| Shadow integrations on a real CI workflow | at least 3 |
| External workflows using an immutable Action commit | at least 1 |
| External merged contribution | at least 1 |
| Median public issue first-triage time | under 2 business days |
| Known false `PASS` outcomes | 0 |

Also record time to first own-repository `HOLD`, the missing controls found, time to remediation, exact-candidate coverage, decision latency, false `HOLD`/`BLOCK` reports, retained pilots, and reasons a pilot did not proceed. Counts without operator context are not evidence of product value.

## Explicit non-goals

- No CLI telemetry, background upload, credential discovery, or automatic trust-root discovery.
- No signing, approval, merge, check-write, deployment, or enforcement capability in MCP.
- No custom model merely to make the product appear more sophisticated. A model belongs only in an optional evidence-producing role after a benchmark shows material detection value; its output remains non-authoritative.
- No production-enforcement, compliance-certification, npm-publication, or Marketplace claim without a separately reviewed decision and release record.
- No purchased stars, automated engagement, undisclosed promotion, star exchanges, or synthetic field reports.

Use the feature proposal form for roadmap changes and the pilot field-report form for public-safe evidence. Security findings belong in private vulnerability reporting, not roadmap discussion.
