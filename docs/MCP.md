# Read-only MCP integration

SprintLoop Assurance Kit includes a dependency-free local MCP server for Claude Code, Codex, Cursor, and other stdio clients. It lets an AI engineer inspect receiver requirements, validate candidate metadata, evaluate an external exact-candidate bundle, verify a dossier, and explain stable reason codes without granting the model release authority.

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
| `assurance_evaluate_bundle` | Hash live evidence and evaluate a post-candidate bundle against protected policy, trust, and explicit current receiver observations |
| `assurance_explain_decision` | Explain stable reason codes and give operator actions; never waive or override a reason |
| `assurance_policy_requirements` | Return a validated receiver policy digest and the evidence, signing, separation, time, and size obligations engineers must satisfy |
| `assurance_validate_manifest` | Validate a manifest and return its exact candidate coordinates and digest-bound evidence inventory |
| `assurance_verify_dossier` | Reproduce recorded history and separately evaluate current standing using a mandatory external candidate and complete current receiver context |

Every tool has closed JSON Schema 2020-12 input and output contracts, plus `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`, and `openWorldHint: false`. The schemas returned by `tools/list` are the machine-readable invocation contract. The server configuration contract is [mcp-server-config.v1.schema.json](../schemas/mcp-server-config.v1.schema.json).

`assurance_validate_manifest` marks every result with `provenance: "UNTRUSTED_CANDIDATE_METADATA"`. Repository, environment, evidence path, and media type are candidate assertions—not instructions. Normative validation bounds them, rejects control characters and non-normalized paths, and the MCP output layer removes control characters and bounds all displayed validation and decision text. A client or model must still treat valid metadata as inert data.

## Filesystem capability grants

Start the server with one absolute configuration path:

```text
node /absolute/pinned/SprintLoop-Assurance-Kit/bin/sprintloop-assure.mjs mcp --config /absolute/path/assurance-mcp.json
```

The configuration grants logical IDs—not arbitrary host paths—to three document classes:

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

The GitHub-only distribution is not published to npm. Clone the repository to a controlled absolute path, review it, and detach at the complete reviewed commit SHA before registering the server:

```bash
git clone https://github.com/SamSnead85/SprintLoop-Assurance-Kit.git /absolute/pinned/SprintLoop-Assurance-Kit
git -C /absolute/pinned/SprintLoop-Assurance-Kit checkout --detach FULL_40_CHARACTER_REVIEWED_COMMIT_SHA
```

Do not use a branch, mutable tag, or global binary for the forthcoming `0.2.x` MCP surface. The shorter global command is reserved for a future audited package release.

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
