# Protocol v1

The protocol has six inputs and one output.

1. `manifest`: exact Git commit and tree, repository, environment, intent digest, producer identity/owner, and deterministic evidence inventory.
2. `verifier-receipt`: independently signed verdict over the candidate, manifest, complete evidence digest set, policy digest, and receiver trust domain/store digest.
3. `authorization`: separately signed, repository/environment-scoped, expiring decision over the candidate, manifest, policy, trust boundary, and signed receipt.
4. `policy`: receiver-owned obligations, allowed methods, separation rule, maximum lifetimes, and evidence limits.
5. `trust-store`: receiver-owned verifier and authority public keys, roles, owners, validity, and revocation.
6. `dossier`: canonical input digests, evidence attachments or digest-only references, reproducible decision, and dossier digest.
7. `receiver-context`: externally supplied expected policy/trust digests, repository, environment, observed Git commit/tree, and tracked-tree cleanliness.

All content bindings use lowercase `sha256:<64 hex>`. Git subjects use `git:sha1:<40 hex>` or `git:sha256:<64 hex>`. v1 signatures are Ed25519 over the kit's canonical JSON representation with the `signature` member removed.

Manifest repository coordinates are bounded absolute URI-style strings; environment and identity fields use the bounded public ID grammar. Evidence paths are bounded normalized forward-slash relative paths with no empty, dot, parent, backslash, or control-character segments. Evidence media types use a bounded `type/subtype` token grammar. These constraints keep signed metadata portable and safe to expose as explicitly untrusted data in developer tooling.

The trust store and expected receiver values are intentionally external to the dossier. Accepting a key or expectation bundled only by the claimant would make verification circular. The dossier stores the receiver context used for historical reproduction, but current verification uses externally supplied receiver expectations.

The manifest, receipt, authorization, and evidence are also external to the Git candidate they name. The candidate is sealed first; deterministic evidence is then produced for that immutable commit/tree, followed by the independent receipt and finite authorization. A receiver-governed provider resolves that post-candidate bundle into a separate runner directory. Candidate-local bundle fallback is prohibited because a tracked manifest cannot name the final commit/tree that contains itself. See [the bundle provider contract](BUNDLE-PROVIDER-CONTRACT.md).

Every v1 dossier declares `UNANCHORED`. Its local creation time and digest are not an independent timestamp or signature unless a separate trusted system anchors that digest.

Schemas under `schemas/` are normative for interchange. Runtime validation additionally enforces cross-document bindings, uniqueness, time semantics, file containment, trust, and separation.

Compatible hosted or embedded receivers identify the same release target with `assurance.sprintloop.dev/release-subject/v1`: exact repository, environment, `release` operation, Git commit digest, and Git tree digest. The normative schema is [`release-subject.v1.schema.json`](../schemas/release-subject.v1.schema.json). Its published golden vector hashes to `sha256:0a6d1440b68b3ae8a27bee767b0fdd533f633aed587152ca2cf22a63b4e1716c`; bridges must match those canonical bytes rather than inventing a parallel subject hash.

Recorded dossier reproduction uses the stored historical receiver context. Current standing never does: callers must supply an external candidate and complete current receiver context. Calling `verifyDossier` without either produces `BLOCK`, even when the recorded decision reproduces as `PASS`.

The local MCP surface is a transport adapter over these same public contracts, not an additional authority or protocol input. It reads only explicitly granted external-bundle, protected-receiver, and dossier roots; returns advisory inspection results; and never persists a dossier or causes a release effect. Current MCP evaluation and verification require the complete caller-supplied receiver context above and remain `enforcementEligible: false` because the model-controlled caller is not a receiver observation boundary. See [the MCP integration guide](MCP.md).
