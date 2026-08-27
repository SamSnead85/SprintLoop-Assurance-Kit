# Changelog

All notable changes follow semantic versioning. The project is pre-1.0; minor releases may change contracts with an explicit migration note.

## 0.1.0 — Unreleased

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
- Added fail-closed out-of-band bundle materialization so post-candidate proof never self-references the Git tree it binds.
- Required an external candidate and complete receiver context for dossier current standing; stored context is historical reproduction only.
