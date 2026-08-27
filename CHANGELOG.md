# Changelog

All notable changes follow semantic versioning. The project is pre-1.0; minor releases may change contracts with an explicit migration note.

## 0.3.0 — Unreleased

- Add an offline, read-only setup doctor with stable human/JSON output for the supported Node runtime, Git `>=2.45`, exact tracked `HEAD`/tree state, byte-exact protected policy and trust files, receiver-controlled canonical pins, and optional MCP configuration readiness.
- Add dependency-free deterministic collectors for JUnit, SARIF 2.1, SPDX 2.2/2.3/3.0.1, CycloneDX 1.4–1.7, in-toto/SLSA statements, and Sigstore bundles. Collection binds exact raw bytes and supported structure while explicitly leaving every producer claim and signature unverified; an explicit receiver subject can produce the exact manifest evidence projection without hand-written path glue.
- Add versioned doctor and evidence-collection schemas, bounded/no-follow reads, stable identity checks, duplicate-key JSON rejection, fail-closed XML/JSON parsing, data-minimized summaries, and stable collector error codes.
- Expand the local advisory MCP catalog from six to seven tools with `assurance_collect_evidence`. It reads only below a granted bundle root, returns no evidence bodies or report summaries, and remains structurally ineligible for enforcement.
- Add `version`, `doctor`, and `collect-evidence` CLI commands plus installed-artifact coverage. CLI parsing now rejects duplicate options, positional arguments, non-canonical uppercase/underscore aliases, and values supplied to presence-only booleans; inline values preserve all bytes after their first `=`.
- Harden canonical object handling, strict JSON use across CLI/MCP/doctor inputs, Git lazy-fetch prevention, sensitive-data detection, and root/document replacement checks.
- Add a public outcome roadmap, support and maintainer boundaries, security-routed ownership, integration-help and pilot field-report templates, and an explicit prohibition on purchased stars, automated engagement, star exchanges, and synthetic field evidence.

Migration note: v0.3 supports maintained Node 22 and 24 LTS lines only (`>=22.23.2 <23` or `>=24.20.0 <25`); Node 20 and odd-numbered release lines are EOL and fail closed. Git-backed observation now requires Git 2.45 or newer so lazy fetching can be disabled fail-closed. Scripts that relied on duplicate flags, positional arguments, `--UPPERCASE`, `--under_score`, or `--json=value` must use the documented canonical option forms. The v0.3 MCP tool list is additive, but clients that hard-code exactly six tools must tolerate or explicitly approve `assurance_collect_evidence`.

This section describes the development line and is not a release claim. Final source, Action, and artifact revisions will be recorded only after the v0.3 release decision and publication gates pass.

## 0.2.0 — 2026-08-27

- Add a zero-dependency local stdio MCP server with `2026-07-28` stateless discovery, `2025-11-25` / `2025-06-18` compatibility, and six deterministic advisory read-only tools.
- Add closed JSON Schema 2020-12 tool/config contracts, logical non-overlapping root grants, identity-bound reads, bounded framing, source-pinned client examples, adversarial protocol/path/output tests, and installed-package smoke coverage.
- Bound and label candidate metadata as untrusted, sanitize displayed MCP text, suppress malformed-notification responses, and isolate the model-facing MCP module graph from the signing/write-capable general CLI.
- Keep every MCP outcome non-enforcement-eligible with no network, credentials, private-key ingestion, signing, policy/trust mutation, SCM/check/deploy writes, or model sampling exposed.
- Make `check --json` emit one parseable JSON document containing the decision and dossier coordinates.
- Add the no-secret `prepare-shadow-bundle` composite Action and manual/scheduled example: it captures bounded producer evidence into a canonical partial manifest, always reports `HOLD`, and is structurally ineligible for enforcement or required-check use.
- Harden exact-candidate observation with replacement objects and lazy fetching disabled; canonical `ls-tree` inventory; raw blob, mode, symlink, ancestor, and portable-path checks; and a receiver-owned temporary index used only to enumerate non-ignored untracked files.

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
