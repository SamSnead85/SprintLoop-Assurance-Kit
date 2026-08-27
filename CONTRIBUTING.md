# Contributing

Contributions are welcome when they preserve the kit's small, inspectable trust boundary.

## Before opening a pull request

1. Open an issue for a schema, decision-semantics, cryptographic, or compatibility change.
2. Do not include customer data, credentials, private keys, local filesystem paths, or proprietary fixtures.
3. Add a positive conformance case and an adversarial case for changed decision behavior.
4. Preserve model neutrality and receiver-owned trust.
5. Run `npm ci --ignore-scripts` and `npm run verify`.

Pull requests must explain the security invariant affected, backward-compatibility impact, test evidence, and whether a schema version or migration is needed. Maintainers may require a threat-model update and two approvals for trust-boundary changes.

By contributing, you agree that your contribution is licensed under the repository's MIT license and that you have the right to submit it.
