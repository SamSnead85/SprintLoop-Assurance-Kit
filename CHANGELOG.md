# Changelog

All notable changes follow semantic versioning. The project is pre-1.0; minor releases may change contracts with an explicit migration note.

## 0.2.0 — Unreleased

- Add a zero-dependency local stdio MCP server with `2026-07-28` stateless discovery, `2025-11-25` / `2025-06-18` compatibility, and six deterministic advisory read-only tools.
- Add closed JSON Schema 2020-12 tool/config contracts, logical non-overlapping root grants, identity-bound reads, bounded framing, source-pinned client examples, adversarial protocol/path/output tests, and installed-package smoke coverage.
- Bound and label candidate metadata as untrusted, sanitize displayed MCP text, suppress malformed-notification responses, and isolate the model-facing MCP module graph from the signing/write-capable general CLI.
- Keep every MCP outcome non-enforcement-eligible with no network, credentials, private-key ingestion, signing, policy/trust mutation, SCM/check/deploy writes, or model sampling exposed.
- Make `check --json` emit one parseable JSON document containing the decision and dossier coordinates.
- Add the no-secret `prepare-shadow-bundle` composite Action and manual/scheduled example: it captures bounded producer evidence into a canonical partial manifest, always reports `HOLD`, and is structurally ineligible for enforcement or required-check use.
- Harden Git observation with replacement objects disabled and a receiver-owned temporary index so candidate-controlled index flags cannot conceal tracked-byte drift.

## 0.1.0 — 2026-08-27

- Added dependency-free evaluator library and CLI.
- Added exact Git candidate, evidence-set, independent receipt, and finite authorization bindings.
- Added Ed25519 verification against receiver-owned trust roots.
- Added principal, owner, and control-domain separation policies.
- Added portable dossiers with full and envelope-only offline verification.
- Added composite GitHub Action, conformance fixtures, adversarial fixtures, security scanning, SPDX SBOM, and non-publishing release-candidate workflow.
- Added receiver-owned canonical policy/trust digests signed into receipts and authorizations.
- Added exact repository, environment, Git commit, Git tree, and clean tracked-tree bindings.
- Added bounded no-follow file reads, evidence count/aggregate limits, exact-key runtime validation, and authorization ordering checks.
- Marked dossier history as unanchored, added installed-package smoke tests, and restricted v0.1 distribution to GitHub with `private:true`.
- Added a no-network external-bundle materializer so manifests, evidence, receipts, and authorizations are created after—and remain outside—the exact candidate they bind.
- Added fail-closed out-of-band bundle materialization so post-candidate proof never self-references the Git tree it binds.
- Required an external candidate and complete receiver context for dossier current standing; stored context is historical reproduction only.
