# Source inventory and provenance boundary

This inventory defines what may enter the public SprintLoop Assurance Kit repository.

## Authored source

All JavaScript under `src/`, `bin/`, `scripts/`, and `test/`; all JSON Schemas under `schemas/`; the evaluator and bundle-materializer composite Actions and workflows; examples; decision semantics; provider contract; threat model; integration guidance; and governance documents were authored specifically for this public kit.

The implementation is a clean, dependency-free Node.js design. No private assurance engine, private service implementation, customer adapter, private repository history, customer configuration, internal operational data, or unresolved-provenance source is copied into this tree.

## Design inputs

The kit uses public, non-code conventions and platform interfaces:

- Git commit and tree object identifiers
- SHA-256 and Ed25519 through the Node.js standard library
- JSON Schema draft 2020-12 vocabulary
- SPDX 2.3 document structure for the generated SBOM
- GitHub composite Action and workflow syntax
- The standard MIT license text

These inputs inform interoperability; they do not contribute copied third-party source code. The only workflow dependency is `actions/checkout`, referenced by an immutable reviewed commit.

## Generated fixtures

`scripts/generate-fixtures.mjs` creates the public bundles under `fixtures/`. It generates Ed25519 keys ephemerally, writes public keys and signed fictional documents, and never writes a private key. Fixture repositories, principals, owners, environments, evidence, and identifiers are synthetic.

Changing a fixture generator changes signatures because keys are generated afresh. Fixture semantics—not signature bytes—are the stable conformance contract.

## Generated release artifacts

`artifacts/` is ignored source output. It may contain a demo dossier, SPDX SBOM, npm-format installation tarball used only for local smoke testing, release subject, release notes, and `SHA256SUMS`. These files are not authored source and are regenerated from a clean reviewed commit.

The npm-format tarball is a test and GitHub prerelease artifact. `package.json` is `private:true`; no npm publication is authorized.

## Dependency and data boundary

- Runtime dependencies: zero
- Development package dependencies: zero
- Customer or production data: prohibited
- Credentials or private keys: prohibited
- Personal names or personal contact details: prohibited
- Private repository links or internal filesystem paths: prohibited

The release gate requires this inventory, a clean full Git revision, tests, adversarial fixtures, sensitive-data scanning, SBOM generation, package installation smoke, and a deterministic release subject before it can create a release candidate.
