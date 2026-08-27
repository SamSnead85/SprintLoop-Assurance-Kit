# GitHub required-check integration

1. Run `sprintloop-assure init` in the target repository.
2. Replace the generated trust template with public keys owned by the receiving organization.
3. Seal the exact pull-request head commit/tree; do not commit its assurance manifest into that candidate.
4. Generate deterministic evidence for that sealed candidate and store it outside the candidate repository.
5. Obtain a signed receipt from a verifier with a different policy-required owner.
6. Obtain a scoped, expiring authorization from the named authority.
7. Place the manifest, receipt, authorization, and declared evidence in receiver/verifier-controlled storage keyed by the complete exact-candidate coordinate.
8. Compute canonical receiver digests with `sprintloop-assure document-digest --file .assurance/policy.json` and the same command for `trust.json`.
9. Store those values and the target environment in receiver-owned repository or environment variables named `ASSURANCE_POLICY_DIGEST`, `ASSURANCE_TRUST_DIGEST`, and `ASSURANCE_ENVIRONMENT`.
10. Install a receiver-governed authenticated retrieval step that writes only the exact bundle into `${{ runner.temp }}/assurance-provider-inbox`.
11. Pin both Actions to the same reviewed immutable commit and run the workflow in shadow mode.

Copy [assurance.yml](assurance.yml) into `.github/workflows/assurance.yml` and add the authenticated retrieval step before `Require authenticated out-of-band bundle`. On a fresh runner the checked materializer finds no inbox and exits nonzero by design; it is not a fetcher.

All Actions are pinned to reviewed v0.3 implementation revision `0d3f6f0a27f7244d0ec0eb6d924df191b6180a0a`. Keep the references identical and immutable; do not replace them with a branch or tag.

The inbox contract is `manifest.json`, `verifier-receipt.json`, `authorization.json`, and only manifest-relative evidence. It excludes policy, trust, credentials, private keys, and dossiers. Do not use a mutable `latest` object, a candidate-supplied locator, or candidate-local fallback. See [the provider contract](../../docs/BUNDLE-PROVIDER-CONTRACT.md).

Retrieved bytes remain untrusted until the main Action validates signatures and cross-bindings. The receiving organization nevertheless owns provider identity, read authorization, exact-coordinate lookup, availability, and evidence confidentiality; this kit does not implement or silently replace those controls.

This repo-local workflow is a minimum shadow integration. Do not treat its job name alone as enforcement: a pull request may replace a repo-local workflow. After calibration, make the check required only from a receiver-governed GitHub App, organization-required workflow/ruleset, or equivalent protected source. The candidate checkout explicitly selects a fork repository and exact head SHA; policy/trust bytes come only from an exact protected base SHA; bundle inputs come only through out-of-band materializer outputs.

Do not place private keys, provider tokens, or raw credentials in `.assurance`. Signing should happen in a KMS/HSM or separately governed workload with only signed JSON returned to the repository.
