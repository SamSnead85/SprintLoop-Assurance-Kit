# External bundle provider contract

An assurance bundle is created **after** an exact Git candidate is sealed. It cannot be committed into the candidate it names: adding the manifest, receipt, authorization, or evidence would change that candidate's commit and tree.

## Provider boundary

A receiver-governed integration authenticates to verifier-controlled storage and resolves one bundle by this complete coordinate:

- exact candidate commit and tree;
- receiver repository and target environment;
- canonical policy digest;
- canonical trust-store digest and trust domain; and
- operation `release`.

The provider writes a dedicated, new inbox outside the candidate checkout. It must never use a mutable `latest` locator, a locator supplied by candidate files, or a fallback to candidate-local assurance documents.

The inbox contains only:

```text
manifest.json
verifier-receipt.json
authorization.json
<manifest-relative evidence paths>
```

Policy, trust-store bytes, private keys, credentials, and dossiers are prohibited. Transport credentials stay inside the receiver-governed provider step and are not inputs to this kit.

The evaluator treats retrieved bytes as untrusted until signature, digest, scope, and trust checks succeed. An untrusted transport therefore cannot manufacture `PASS` by changing bundle content. The operator still owns provider identity, access authorization, authenticated exact-coordinate lookup, confidentiality, and availability; failures in those controls must stop the workflow rather than select another bundle.

## Checked materialization

`materialize-bundle/action.yml` is a no-network provider stub. It does not fetch or authenticate anything. A preceding trusted integration must populate its `source` directory. On a fresh runner the documented scaffold therefore fails closed until a provider is installed.

The stub:

- rejects a missing source, an existing destination, and source/destination overlap with the candidate;
- requires an exact regular-file inventory with no symlinks or special files;
- resolves actual Git `HEAD`, tree, and tracked cleanliness;
- validates document shape and the candidate/repository/environment/policy/trust coordinate graph;
- requires signed receipt and authorization objects and checks their cross-document digests;
- bounds document, item, per-evidence, and aggregate evidence processing; and
- copies only declared files into a new destination atomically.

This is structural and coordinate preflight, not a second decision engine. The main SprintLoop Assurance Action cryptographically verifies signatures, key roles, standing, separation, evidence, and policy before emitting `PASS`, `HOLD`, or `BLOCK`.

Any authentication failure, ambiguity, missing object, malformed input, digest mismatch, over-limit input, or path violation must return nonzero and leave no usable destination. Provider implementations should be read-only, auditable, and governed independently from the candidate producer.

## GitHub integration

Use two immutable Action references at the same reviewed commit:

1. `SamSnead85/SprintLoop-Assurance-Kit/materialize-bundle@<FULL_SHA>`
2. `SamSnead85/SprintLoop-Assurance-Kit@<FULL_SHA>`

The first consumes a runner-temporary provider inbox. The second consumes only the first Action's materialized outputs, plus policy/trust from a protected receiver checkout. See [`examples/github/assurance.yml`](../examples/github/assurance.yml).
