# Read-only MCP integration

SprintLoop Assurance Kit includes a dependency-free local MCP server for Claude Code, Codex, Cursor, and other stdio clients. It lets an AI engineer inspect receiver requirements, collect bounded metadata for standard CI evidence, validate candidate metadata, evaluate an external exact-candidate bundle, verify a dossier, and explain stable reason codes without granting the model release authority.

This page describes the seven-tool v0.3 development contract. The latest public prerelease, v0.2.0, has the same boundary but exposes six tools and does not include `assurance_collect_evidence`. No v0.3 source or Action pin is final until a reviewed release decision records it.

The integration boundary is intentional:

```text
agent / IDE
    │  local stdio, read-only MCP
    ▼
Assurance inspection tools ──► advisory PASS / HOLD / BLOCK + reason codes
    │
    └── cannot approve, sign, mutate, merge, write a check, deploy, or enforce

receiver-governed CI Action / deployment interlock ──► authoritative effect
```

An MCP `PASS` is not a release approval. Every MCP result declares `mode: "ADVISORY_READ_ONLY"` and `enforcementEligible: false`. Required checks and deployment effects remain in the protected receiver-controlled integration described in the [bundle provider contract](BUNDLE-PROVIDER-CONTRACT.md).

## What the server exposes

The tool catalog is fixed and returned in deterministic alphabetical order.

| Tool | Purpose |
| --- | --- |
| `assurance_capabilities` | Report protocol support, root grant IDs, limits, and the non-authoritative security boundary without exposing host paths |
| `assurance_collect_evidence` | Hash bounded JUnit, SARIF, SPDX, CycloneDX, in-toto/SLSA, or Sigstore files below a granted bundle root and return privacy-minimized structural metadata; never verify claims or return report content |
| `assurance_evaluate_bundle` | Hash live evidence and evaluate a post-candidate bundle against protected policy, trust, and explicit current receiver observations |
| `assurance_explain_decision` | Explain stable reason codes and give operator actions; never waive or override a reason |
| `assurance_policy_requirements` | Return a validated receiver policy digest and the evidence, signing, separation, time, and size obligations engineers must satisfy |
| `assurance_validate_manifest` | Validate a manifest and return its exact candidate coordinates and digest-bound evidence inventory |
| `assurance_verify_dossier` | Reproduce recorded history and separately evaluate current standing using a mandatory external candidate and complete current receiver context |

Every tool has closed JSON Schema 2020-12 input and output contracts, plus `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`, and `openWorldHint: false`. The schemas returned by `tools/list` are the machine-readable invocation contract. The server configuration contract is [mcp-server-config.v1.schema.json](../schemas/mcp-server-config.v1.schema.json).

`assurance_collect_evidence` returns exact raw-byte digests, byte counts, detected format/version, and `STRUCTURE_FULL` or `ENVELOPE_ONLY`. It removes the library collector's per-format summary before returning model-facing output and always declares `claimsVerified: false` and `enforcementEligible: false`. Its redacted result therefore uses the distinct schema identity `assurance.sprintloop.dev/mcp-evidence-collection/v1`; it must not be validated as the fuller library/CLI evidence-collection document. Parsing an attestation or signature envelope is not authentication. See the [collector contract](EVIDENCE-COLLECTORS.md).

`assurance_validate_manifest` marks every result with `provenance: "UNTRUSTED_CANDIDATE_METADATA"`. Repository, environment, evidence path, and media type are candidate assertions—not instructions. Normative validation bounds them, rejects control characters and non-normalized paths, and the MCP output layer removes control characters and bounds all displayed validation and decision text. A client or model must still treat valid metadata as inert data.

## Filesystem capability grants

Start the server with one absolute configuration path:

```text
node /absolute/pinned/SprintLoop-Assurance-Kit/bin/sprintloop-assure.mjs mcp --config /absolute/path/assurance-mcp.json
```

The configuration grants logical IDs—not arbitrary host paths—to three root classes:

```json
{
  "$schema": "https://assurance.sprintloop.ai/schemas/mcp-server-config.v1.schema.json",
  "schemaVersion": "assurance.sprintloop.dev/mcp-server-config/v1",
  "roots": [
    {
      "id": "bundle",
      "kind": "bundle",
      "path": "/srv/sprintloop-assurance/bundles/current"
    },
    {
      "id": "receiver",
      "kind": "receiver",
      "path": "/srv/sprintloop-assurance/receiver"
    },
    {
      "id": "dossiers",
      "kind": "dossier",
      "path": "/srv/sprintloop-assurance/dossiers"
    }
  ],
  "limits": {
    "maxMessageBytes": 1048576,
    "maxJsonBytes": 1048576,
    "maxDossierBytes": 67108864,
    "maxToolCalls": 256
  }
}
```

All configured directories must already exist, use absolute paths, be pairwise non-overlapping, and not be symbolic links. Granting an entire filesystem root is prohibited. Tool calls refer only to root IDs and normalized relative paths. Parent traversal, absolute document paths, backslash aliases, symlinked document paths, non-regular JSON files, oversized JSON, and paths outside a grant fail closed.

For evidence collection, `bundleRootId` must name a `bundle` grant. Optional `evidenceRoot` is `.` or a portable relative directory below that grant; each descriptor `path` is then relative to `evidenceRoot`. Returned paths preserve that descriptor-relative base rather than becoming host paths. Root identity is rebound and checked during collection so replacing the granted evidence directory does not silently retarget the read.

The server never returns configured host paths. Give it the narrowest directories possible; do not grant a home directory, credential directory, repository root, or general-purpose workspace.

The expected topology is:

```text
bundle root (post-candidate, external)   receiver root (protected)   dossier root (read-only)
├── manifest.json                       ├── policy.json              └── dossier.json
├── verifier-receipt.json               └── trust.json
├── authorization.json
└── evidence/
```

The bundle remains external to the Git candidate it names. MCP does not fetch or materialize it and does not replace the authenticated provider contract.

## Connect an engineering client

The GitHub-only distribution is not published to npm. For the published six-tool v0.2.0 surface, clone the repository to a controlled absolute path, review it, and detach at the complete reviewed commit SHA before registering the server:

```bash
set -euo pipefail
git clone https://github.com/SamSnead85/SprintLoop-Assurance-Kit.git /absolute/pinned/SprintLoop-Assurance-Kit
git -C /absolute/pinned/SprintLoop-Assurance-Kit checkout --detach 35febce58e85ceec126ee6ce940461a25cfbe93e
```

Do not use a branch, mutable tag, or global binary for the v0.2.0 MCP surface. The shorter global command is reserved for a future audited package release. The v0.3 working tree is available for review and testing, but it is not an immutable security pin; replace this section only after its release decision records a reviewed complete revision.

Codex CLI:

```bash
codex mcp add sprintloop-assurance -- node /absolute/pinned/SprintLoop-Assurance-Kit/bin/sprintloop-assure.mjs mcp --config /absolute/path/assurance-mcp.json
```

Claude Code and Cursor accept a stdio server definition equivalent to:

```json
{
  "mcpServers": {
    "sprintloop-assurance": {
      "command": "node",
      "args": [
        "/absolute/pinned/SprintLoop-Assurance-Kit/bin/sprintloop-assure.mjs",
        "mcp",
        "--config",
        "/absolute/path/assurance-mcp.json"
      ]
    }
  }
}
```

Copyable examples are under [`examples/mcp/`](../examples/mcp/). Client configuration locations and approval UX vary by client version; review the displayed command and exposed tools before enabling them.

## Engineering workflow handoff

Use MCP to put deterministic Assurance context where engineers already work without confusing inspection with authority:

1. Run `sprintloop-assure doctor` outside MCP to establish the exact tracked receiver checkout, protected policy/trust documents, canonical pins, and optional MCP configuration. Git-backed observation requires Git 2.45 or newer.
2. After evidence producers stop and artifacts cross into a receiver-owned handoff, invoke `assurance_collect_evidence` or the CLI collector. Treat every returned claim as unverified.
3. Use `assurance_policy_requirements` and `assurance_validate_manifest` to diagnose whether the exact-candidate inventory matches receiver expectations.
4. Use `assurance_evaluate_bundle` only after a post-candidate external provider has materialized the manifest, evidence, independently governed receipt, and finite authorization. Supply current receiver observations explicitly.
5. Hand the result to receiver-governed CI or a deployment interlock for any authoritative effect. MCP cannot make its own `PASS` required, write a check, persist a dossier, or deploy.

This separation also permits the builder and MCP client to be Claude, Codex, Cursor, another model, or no model at all. Independence comes from receiver-owned identities, keys, policy, observations, and control domains—not from choosing a different model brand.

## Protocol compatibility

The primary transport path implements MCP `2026-07-28`:

- `server/discover` capability discovery;
- per-request `_meta.io.modelcontextprotocol/protocolVersion` and client-capability validation;
- `resultType: "complete"`, server identity metadata, and cache hints;
- deterministic `tools/list`; and
- `tools/call` with structured content plus a serialized text copy.

The same stdio entrypoint supports the legacy `initialize` / `notifications/initialized` lifecycle for `2025-11-25` and `2025-06-18` clients. JSON-RPC batches are rejected. Messages are one UTF-8 JSON object per newline, stdout contains protocol messages only, and diagnostic text is restricted to stderr.

Input framing is byte-bounded before JSON parsing. Oversized frames are discarded only through their newline boundary so the next valid message can be processed. Tool calls are processed sequentially and capped per process. Client implementations should still impose request timeouts and surface tool calls for user review.

Protocol references: [MCP 2026-07-28 discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover), [tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools), and [stdio transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio).

## Explicit current context

`assurance_evaluate_bundle` and `assurance_verify_dossier` require all of the following in the tool invocation:

- canonical candidate digest;
- receiver-pinned policy digest;
- receiver-pinned trust-store digest;
- expected repository and environment;
- independently observed candidate digest and tree digest;
- tracked-working-tree cleanliness; and
- a canonical UTC evaluation instant.

The server does not inspect the current Git checkout, read client roots, consult environment variables, or infer values from a dossier. Missing current context is an input error. Conflicting current context produces the evaluator's normal `BLOCK` reasons. Because an MCP caller supplies these observations, the result remains advisory even when cryptographic verification succeeds.

## Deliberately absent authority

The shipped binary routes `mcp` before loading the general CLI. Its dedicated MCP module graph imports read-only JSON/filesystem operations and public-key signature verification only: no network, HTTP, DNS, TLS, child-process, source-control, filesystem-write, environment-variable, private-key, key-generation, or signing implementation is loaded. It has no tool for:

- receipt or authorization signing;
- approval or denial;
- evidence submission;
- review requests;
- policy or trust-store mutation;
- private-key ingestion, generation, or signing;
- status-check, pull-request, or deployment writes;
- enabling enforcement; or
- model sampling.

A future managed remote MCP endpoint would need its own reviewed Streamable HTTP implementation, OAuth resource/audience binding, tenant isolation, authorization policy, rate limits, audit trail, and explicit prevention of token passthrough. Those controls are not claimed by this local offline Kit.
