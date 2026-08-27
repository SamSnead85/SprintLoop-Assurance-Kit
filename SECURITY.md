# Security policy

## Supported versions

Until 1.0, only the latest tagged minor release receives security fixes.

## Report privately

Use GitHub's **Report a vulnerability** private-reporting feature for this repository. Do not open a public issue for a suspected vulnerability, leaked key, bypass, or unsafe default.

Include the affected version and commit, reproduction, expected trust boundary, impact, and any proposed remediation. Do not include real customer data, active credentials, or regulated evidence.

Maintainers will acknowledge a complete report within three business days, coordinate validation and remediation, prepare an advisory when appropriate, and credit reporters who request credit.

## Security boundary

The kit verifies local documents and files. It does not authenticate people, issue credentials, protect a trust store, manage keys, configure repository rules, or authorize a deployment by itself. Operators own those controls.

Security invariants:

- No model output is authority.
- Provider-reported identity is not receiver trust.
- Loaded policy/trust bytes must match receiver-owned canonical expected digests.
- A `PASS` for one candidate cannot be replayed for another candidate.
- Repository, environment, Git commit, Git tree, and clean tracked state must match receiver expectations.
- Missing or expired preconditions never become `PASS`.
- Invalid signatures, digest drift, negative findings, and separation violations become `BLOCK`.
- A different model name does not establish independent ownership.
- The offline verifier requires an external receiver-owned trust store.
- Embedded dossiers may contain sensitive evidence and require classification.
- Dossier time and digest are unanchored unless an external trusted system signs or timestamps them.
- MCP tools are read-only advisory inspection and are never enforcement-eligible, even when they return `PASS`.
- MCP current standing requires an explicit external candidate, tree, cleanliness, repository, environment, policy/trust digests, and evaluation time; it never falls back to dossier or Git working-directory state.
- MCP filesystem access is limited to narrow configured root grants; root paths are never returned to the client.
- The shipped binary routes `mcp` into a dedicated module graph before loading the general CLI; that graph has no network, environment-variable, credential, private-key, signing, source-control, filesystem-write, model-sampling, approval, check-write, or deployment capability. Verification uses receiver-granted public keys only.

See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) for the detailed analysis.
