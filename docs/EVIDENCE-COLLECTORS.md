# Deterministic CI evidence collectors

SprintLoop Assurance collectors turn common CI artifacts into small, deterministic evidence descriptors. They do not trust a filename or extension: each artifact is read under a receiver-owned bound, identified from its content, structurally inspected, and bound to the SHA-256 digest of its **exact raw bytes**.

The collector is local and dependency-free. It opens no network connections, resolves no remote schemas, discovers no credential stores or credential APIs/environment, writes no files, invokes no subprocesses, and performs no signing or policy decision. It will read an explicitly granted, named regular file that matches a supported format, so callers must never grant or pass credential-bearing artifacts. Report bytes are not returned.

The library, CLI, and read-only MCP collector are part of the v0.3 development line and are not present in the latest public v0.2.0 artifact. Until v0.3 has a reviewed release revision and checksum, use this surface for source review and controlled evaluation rather than as a mutable production pin.

## Supported inputs

| Input | Supported profile | Output type | Level |
| --- | --- | --- | --- |
| JUnit XML | `testsuite` or `testsuites` root; DTDs and custom entities prohibited | `test-report` | `STRUCTURE_FULL` |
| SARIF JSON | [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) runs, tools, results, levels, and suppressions | `static-analysis` | `STRUCTURE_FULL` |
| SPDX JSON | [SPDX 2.2 or 2.3](https://spdx.github.io/spdx-spec/v2.3/) document inventory | `sbom` | `STRUCTURE_FULL` |
| SPDX JSON-LD | [SPDX 3.0.1](https://spdx.github.io/spdx-spec/v3.0.1/serializations/) context, graph identities, and single-document envelope | `sbom` | `ENVELOPE_ONLY` |
| CycloneDX JSON | [CycloneDX 1.4 through 1.7](https://cyclonedx.org/specification/overview/) components, services, dependency nodes, vulnerabilities, and compositions | `sbom` | `STRUCTURE_FULL` |
| in-toto statement JSON | [Statement v0.1 or v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md), including SLSA provenance v0.2 and [v1](https://slsa.dev/spec/v1.0/provenance) profiles | `provenance` | `ENVELOPE_ONLY` |
| Sigstore bundle JSON or bounded JSONL | [Bundle v0.1 through v0.3](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto), message-signature or single-signature DSSE content; single-object JSON and the multi-bundle JSONL emitted by `gh attestation download` are accepted | `signature-bundle` | `ENVELOPE_ONLY` |

`STRUCTURE_FULL` has a deliberately narrow meaning: the collector safely acquired the complete file and inspected the complete supported structural profile used to derive its summary. It does **not** mean the producer's claims are true, that the artifact conforms to every optional rule in the upstream standard, that dossier evidence is embedded for offline reproduction, or that policy passed. The separate `inspectionLevel` name intentionally avoids the dossier protocol's `verificationLevel` semantics.

`ENVELOPE_ONLY` means the collector safely acquired and hashed the complete file but inspected only its supported outer structure. In particular:

- SPDX 3 output is not JSON-LD-expanded or validated against the remote JSON Schema, OWL ontology, or SHACL model;
- in-toto and SLSA subjects, predicates, builders, and claimed dependencies are not authenticated or evaluated; and
- Sigstore signatures, certificates, timestamps, transparency-log entries, DSSE payloads, and trust roots are not cryptographically verified.

Every descriptor therefore includes `claimsVerified: false`. A verifier independently governed from the producer must authenticate claims and apply receiver-owned policy before a release can pass.

## Library API

```js
import { collectEvidence } from './src/collect-evidence.mjs';

const collection = await collectEvidence([
  { id: 'evidence:tests', path: 'artifacts/junit.xml', format: 'junit' },
  { id: 'evidence:sast', path: 'artifacts/results.sarif' },
  { id: 'evidence:sbom', path: 'artifacts/bom.cdx.json', format: 'cyclonedx' },
], {
  root: process.cwd(),
  pathBase: '.',
  subjectDigest: 'git:sha1:<receiver-observed-40-hex-commit>',
  maxFiles: 16,
  maxFileBytes: 8 * 1024 * 1024,
  maxTotalBytes: 24 * 1024 * 1024,
});
```

Each input is an exact object:

- `id` is a manifest-compatible identifier;
- `path` is a portable relative path below `root`; and
- `format` is optional. It may be `junit`, `sarif`, `spdx`, `cyclonedx`, `in-toto`, or `sigstore`. When omitted, content-based identification must produce exactly one format.

Unknown descriptor fields, unsafe paths, unknown formats, duplicate IDs, and duplicate paths are rejected. `collectEvidenceFile(input, options)` provides the same behavior for one artifact. Errors are `EvidenceCollectionError` instances with a stable machine-readable `code`.

Default bounds are 32 files, 16 MiB per file, and 64 MiB total. Hard ceilings are 256 files, 64 MiB per file, and 256 MiB total; callers can lower but cannot raise them. `maxTotalBytes` must be at least `maxFileBytes`.

`root` is the host path below which every descriptor is safely resolved; it is never emitted. `pathBase` is separate portable metadata describing where that root sits in the downstream bundle namespace. It defaults to `.`, is normalized and bounded, and never changes which host files are read. A descriptor such as `artifacts/junit.xml` remains `artifacts/junit.xml` in output. The root and each file are identity-checked during collection. Choose a narrow immutable handoff directory, not a home directory, repository root, credential directory, or general workspace.

## CLI

The CLI accepts one bounded JSON file containing the descriptor array and writes only the collection document to stdout:

```json
[
  { "id": "evidence:tests", "path": "junit.xml", "format": "junit" },
  { "id": "evidence:sast", "path": "results.sarif", "format": "sarif" },
  { "id": "evidence:sbom", "path": "bom.cdx.json", "format": "cyclonedx" }
]
```

```bash
node /absolute/reviewed/kit/bin/sprintloop-assure.mjs collect-evidence \
  --input /absolute/receiver/evidence-inputs.json \
  --root /absolute/receiver/handoff \
  --path-base evidence \
  --subject-digest git:sha1:<receiver-observed-40-hex-commit> \
  --max-files 16 \
  --max-file-bytes 8388608 \
  --max-total-bytes 25165824 > evidence-collection.json
```

`--input` names the descriptor JSON file; it is not inline JSON. Its location does not change file resolution. Every descriptor `path` is relative to `--root` (the current directory by default), every output `path` remains descriptor-relative, and `--path-base` records where that root will sit in the bundle without changing acquisition. When `--subject-digest` supplies the receiver-observed exact Git candidate, output also contains `manifestEvidence`: the exact six-field manifest projection with `pathBase` composed once. Collection errors return exit `2`, write no collection to stdout, and expose a stable collector error code without leaking an absolute path.

## Read-only MCP

The seventh v0.3 tool, `assurance_collect_evidence`, operates only below a configured `bundle` capability grant. `bundleRootId` selects that grant, optional `evidenceRoot` selects `.` or a relative directory below it, and descriptor paths are relative to `evidenceRoot`. The tool rebinds the selected directory identity for the collection, returns `evidenceRoot` as `pathBase` (for example `ci`), and keeps each evidence entry path relative to that base. It never emits a host path.

MCP accepts at most 32 inputs and returns the same exact-byte digest, format/version, level, byte size, and totals, but deliberately removes per-format `summary` fields from model-facing output. Because that redacted shape is not the public library/CLI collection schema, it uses the distinct identity `assurance.sprintloop.dev/mcp-evidence-collection/v1`. It returns no raw evidence content and always adds `mode: "ADVISORY_READ_ONLY"`, `enforcementEligible: false`, and `claimsVerified: false`. The full tool contract is returned by MCP `tools/list`; see the [MCP guide](MCP.md).

## Output contract

Results are sorted by `id`, then `path`, regardless of caller order:

```json
{
  "schemaVersion": "assurance.sprintloop.dev/evidence-collection/v1",
  "pathBase": ".",
  "evidence": [
    {
      "id": "evidence:sast",
      "type": "static-analysis",
      "path": "artifacts/results.sarif",
      "mediaType": "application/sarif+json",
      "digest": "sha256:<64 lowercase hex characters>",
      "sizeBytes": 12345,
      "format": "sarif",
      "formatVersion": "2.1.0",
      "inspectionLevel": "STRUCTURE_FULL",
      "claimsVerified": false,
      "summary": {
        "runCount": 1,
        "resultCount": 4,
        "errorCount": 1,
        "warningCount": 3,
        "noteCount": 0,
        "noneCount": 0,
        "unresolvedLevelCount": 0,
        "suppressionRequestCount": 0
      }
    }
  ],
  "totals": {
    "itemCount": 1,
    "byteCount": 12345,
    "structureFullCount": 1,
    "envelopeOnlyCount": 0
  }
}
```

The source JSON Schema is [evidence-collection.v1.schema.json](../schemas/evidence-collection.v1.schema.json). The library and CLI output includes the privacy-minimized per-format `summary` shown above. The MCP projection intentionally omits `summary` and uses its closed tool output schema instead.

The digest covers the bytes exactly as read. The collector does not normalize JSON, whitespace, newlines, XML, or a byte-order mark before hashing.

Only the caller-supplied `id` and portable `path`, media type, format/version, byte size, level, and aggregate counts leave the collector. It never emits test or suite names, failure text, logs, rule IDs, result messages, code locations, package or service names, vulnerabilities, SPDX namespaces, component references, provenance subjects, builder identities, external parameters, signatures, certificates, transparency-log bodies, timestamps, or DSSE payloads. Summaries are operational metadata, not a replacement for the raw digest-bound evidence.

## Manifest binding

Each collected descriptor contains the five manifest fields the collector can determine without inventing release context. The deterministic helper adds only the sixth, receiver-supplied subject field:

```js
import { toManifestEvidence } from '@sprintloop/assurance-kit';

const manifestEvidence = toManifestEvidence(collection, exactCandidateDigest);
```

`pathBase` must be composed with each descriptor path exactly once when the downstream manifest is rooted at the bundle grant. For CLI output it is `.`, so the path is unchanged; for an MCP collection under `evidenceRoot: "ci"`, `junit.xml` becomes `ci/junit.xml`. Reject rather than normalize conflicting bases at the handoff.

`subjectDigest` must come from the receiver-observed exact candidate; the collector never infers it from report contents or candidate metadata. Pass it explicitly through the CLI/library only in a receiver-owned phase. Do not add `pathBase`, `summary`, `sizeBytes`, `inspectionLevel`, or `claimsVerified` to the current manifest evidence-item schema. Store a collection record as separate digest-bound evidence if a verifier needs the summary or base provenance.

The raw files remain authoritative. The receiver should independently recalculate their digests during dossier creation or verification. A candidate-controlled workflow must never turn collector counts into a release decision on its own.

## Safe CI placement

Use the collector after all evidence producers have exited and before untrusted build steps resume:

```text
exact Git candidate
  -> test / scan / SBOM / provenance producers
  -> immutable artifact handoff
  -> receiver-owned collector
  -> exact-digest manifest
  -> independent verifier and finite authorization
  -> dossier / release gate
```

For matrix builds, aggregate producer outputs into intentionally distinct files before collection. Two descriptors that resolve to the same device/inode are rejected, including hard-link aliases; this prevents one file from being weighted twice under different names.

## Fail-closed controls

The collector rejects:

- missing files, directories, devices, pipes, and other non-regular inputs;
- absolute paths, traversal, backslashes, empty components, control characters, and paths outside the canonical root;
- symbolic links in any input path component and leaf symlinks at `open` time;
- file identity, size, mode, creation-time, or modification-time changes during collection;
- per-file, aggregate, item-count, JSON depth/value, and XML depth/token limit violations;
- invalid UTF-8, malformed JSON, non-finite JSON numbers, lone Unicode surrogates, and duplicate JSON object keys;
- XML DTDs, entity declarations, custom entities, malformed nesting, duplicate attributes, and invalid JUnit element placement;
- format mismatch, unknown identity, or a JSON document advertising more than one supported identity;
- duplicate descriptor IDs, paths, open-file identities, SPDX identifiers, CycloneDX references/dependency nodes, and in-toto subject digests; and
- ambiguous Sigstore key material/content and DSSE envelopes whose signature count is not exactly one.

The open handle is checked before and after the bounded read, and the path is checked again against the handle identity and canonical root. As with any user-space collector, run it in an isolated CI phase on a filesystem where an attacker cannot race parent-directory replacement at the kernel boundary.

## Shipped v0.3 development surfaces

The v0.3 source currently exposes the collector through four reviewed contracts:

1. `src/index.mjs` re-exports `collectEvidence`, `collectEvidenceFile`, `toManifestEvidence`, `EVIDENCE_FORMATS`, and `EvidenceCollectionError`.
2. `sprintloop-assure collect-evidence` accepts one descriptor JSON file plus explicit path/bound flags, writes only collection JSON to stdout, and preserves stable errors on stderr.
3. Local read-only MCP exposes `assurance_collect_evidence` below a receiver-granted bundle directory without adding network, credential, write, signing, or decision authority.
4. `schemas/evidence-collection.v1.schema.json` defines the library/CLI collection document; MCP advertises and validates its smaller model-facing projection separately.

Manifest assembly remains an explicit receiver-owned step. The library helper and CLI can produce the exact six-field projection only when the receiver supplies its observed `subjectDigest`; the MCP tool intentionally cannot add that authority-bearing input. Independently recalculate the raw evidence digests at the evaluator boundary. The collection document by itself is not an Assurance manifest, verifier receipt, authorization, or decision.
