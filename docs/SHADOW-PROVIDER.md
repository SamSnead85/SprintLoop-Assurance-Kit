# No-secret shadow evidence provider

`prepare-shadow-bundle/action.yml` is the smallest concrete on-ramp from an existing CI system into the SprintLoop assurance protocol. It captures what the receiver can observe about one exact Git candidate and a declared set of runner-produced evidence. Its output is useful for integration discovery and telemetry, but it is intentionally **not** release assurance.

The Action always reports:

```text
disposition: HOLD
completeness: partial
enforcement-eligible: false
```

`HOLD` here is unsigned structural metadata. It is not a verifier verdict, a synthetic dossier decision, or an authorization. The output directory contains only `manifest.json` plus its declared evidence paths. It contains no receipt, authorization, dossier, policy, trust store, credential, private key, or generated key.

## Where it fits

```text
protected manual/scheduled receiver workflow
  -> candidate checkout (HEAD + tree + tracked/non-ignored cleanliness checked)
  -> no-secret candidate evidence run
  -> dedicated runner.temp evidence directory
  -> prepare-shadow-bundle
  -> canonical manifest + captured evidence / HOLD
  -> operator review or separately governed verifier intake
```

The provider closes the first-mile integration gap: an engineering team can produce a bounded candidate manifest without operating a signing service. It does not collapse the control boundary. In the sample, candidate code and capture share one unprivileged job, so the result is producer-controlled telemetry rather than an isolated receiver observation; a surviving candidate process could still interfere with later job files. Promotion from this shadow artifact to an enforceable result still requires a separate receiver-owned job or service, an independently governed verifier receipt, a receiver authority authorization, protected current policy/trust context, and evaluation by the main Kit Action.

## Enforced v0 boundary

The implementation:

- runs only when GitHub reports `workflow_dispatch` or `schedule`; it rejects `pull_request`, `pull_request_target`, `push`, `merge_group`, `workflow_call`, and every other event;
- requires a dedicated evidence source and fresh destination under `RUNNER_TEMP`, both outside the candidate checkout;
- requires policy and public trust-store bytes under `RUNNER_TEMP`, outside both the candidate and evidence source, and matches them to explicit protected digests;
- receives repository, environment, change, intent, and producer coordinates only as explicit receiver inputs—never from candidate files;
- disables Git replacement objects; compares canonical tree entries directly with raw worktree bytes, symlink targets, and executable modes without executing candidate clean filters or trusting candidate index flags; then uses a receiver-owned temporary index only to reject non-ignored untracked files before and after capture;
- accepts only an exact JSON declaration of `id`, `type`, `path`, and `mediaType`; computes every evidence and subject digest itself; rejects duplicate IDs, types, and paths;
- rejects symlinks, special files, traversal, undeclared files/directories, path changes, file changes during reads, over-limit inputs, and overlapping roots;
- applies policy limits plus hard ceilings of 128 items, 16 MiB per item, and 64 MiB total; and
- exclusively claims a fresh output directory (never overwriting an existing path), writes captured evidence, then atomically publishes canonical `manifest.json` as the final commit marker; and
- publishes only non-secret paths, digests, and advisory state as outputs.

The policy and trust store are read only to validate the receiver context and limits. They are never copied or modified. Public trust material is accepted; any value containing a private-key PEM marker is rejected.

## Protected manual pilot

Use a dedicated workflow file on the protected default branch and a protected GitHub environment such as `assurance-shadow`. Grant only `contents: read`, do not expose repository or environment secrets, and never configure the job name as a required status check.

The skeleton below is deliberately `workflow_dispatch`-only and pins the reviewed immutable implementation revision that contains this Action. Keep policy/trust in a protected receiver source and keep their canonical digests in protected environment variables. Upgrade only by reviewing and replacing the complete SHA.

```yaml
name: assurance-shadow-observe-only-NOT-A-GATE

on:
  workflow_dispatch:
    inputs:
      candidate:
        description: Exact commit to observe
        required: true
      change-id:
        description: Receiver change identifier
        required: true

permissions:
  contents: read

jobs:
  observe-only-not-a-gate:
    name: shadow-observe-only-NOT-A-GATE
    environment: assurance-shadow
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - name: Checkout exact candidate without retained credentials
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          ref: ${{ inputs.candidate }}
          path: candidate
          persist-credentials: false

      - name: Install exact Assurance runtime
        uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0
        with:
          node-version: 24.20.0
          check-latest: false
          package-manager-cache: false
          token: ''
          mirror-token: ''
      - name: Require exact Node runtime
        run: node -e "if(process.versions.node!=='24.20.0')process.exit(1)"

      # Bind the receiver-selected checkout before any candidate code runs.
      # The Action re-observes HEAD afterward and rejects drift.
      - name: Bind resolved candidate before execution
        id: candidate
        shell: bash
        run: |
          set -euo pipefail
          resolved="$(git -C candidate rev-parse --verify HEAD)"
          printf 'sha=%s\n' "$resolved" >> "$GITHUB_OUTPUT"

      # Run candidate-controlled code before receiver configuration is staged.
      # This job has no secrets and no write permissions. A test exit code is
      # observed as evidence; this step does not convert it into PASS.
      - name: Produce bounded candidate evidence without secrets
        shell: bash
        env:
          EVIDENCE_ROOT: ${{ runner.temp }}/assurance-shadow-evidence
        run: |
          set -euo pipefail
          mkdir -p "$EVIDENCE_ROOT"
          set +e
          npm --prefix candidate test >/dev/null 2>&1
          test_exit="$?"
          set -e
          TEST_EXIT="$test_exit" node -e "const fs=require('node:fs');const p=require('node:path');const value={schemaVersion:'sprintloop.shadow-test-observation/v1',exitCode:Number(process.env.TEST_EXIT)};fs.writeFileSync(p.join(process.env.EVIDENCE_ROOT,'test-result.json'),JSON.stringify(value)+'\n',{mode:0o600,flag:'wx'})"

      - name: Checkout protected receiver configuration
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          ref: refs/heads/main
          path: receiver
          sparse-checkout: |
            .assurance/policy.json
            .assurance/trust.json
          sparse-checkout-cone-mode: false
          persist-credentials: false

      - name: Stage protected public receiver context
        shell: bash
        env:
          RECEIVER_ROOT: ${{ runner.temp }}/assurance-shadow-receiver
        run: |
          set -euo pipefail
          mkdir -p "$RECEIVER_ROOT"
          cp receiver/.assurance/policy.json "$RECEIVER_ROOT/policy.json"
          cp receiver/.assurance/trust.json "$RECEIVER_ROOT/trust.json"

      - name: Prepare partial shadow evidence — always HOLD
        id: shadow
        uses: SamSnead85/SprintLoop-Assurance-Kit/prepare-shadow-bundle@0d3f6f0a27f7244d0ec0eb6d924df191b6180a0a
        with:
          candidate-root: candidate
          candidate: ${{ steps.candidate.outputs.sha }}
          evidence-root: ${{ runner.temp }}/assurance-shadow-evidence
          evidence: '[{"id":"evidence:receiver-shadow-tests","type":"test-report","path":"test-result.json","mediaType":"application/json"}]'
          destination: ${{ runner.temp }}/assurance-shadow-bundle
          policy: ${{ runner.temp }}/assurance-shadow-receiver/policy.json
          trust: ${{ runner.temp }}/assurance-shadow-receiver/trust.json
          expected-policy-digest: ${{ vars.ASSURANCE_POLICY_DIGEST }}
          expected-trust-digest: ${{ vars.ASSURANCE_TRUST_DIGEST }}
          expected-repository: ${{ github.server_url }}/${{ github.repository }}
          expected-environment: shadow
          change-id: ${{ inputs.change-id }}
          intent-id: ${{ vars.ASSURANCE_INTENT_ID }}
          intent-digest: ${{ vars.ASSURANCE_INTENT_DIGEST }}
          producer-principal-id: ${{ vars.ASSURANCE_PRODUCER_PRINCIPAL }}
          producer-owner-id: ${{ vars.ASSURANCE_PRODUCER_OWNER }}
          producer-control-domain: ${{ vars.ASSURANCE_PRODUCER_CONTROL_DOMAIN }}

      - name: Assert advisory-only output contract
        shell: bash
        env:
          DISPOSITION: ${{ steps.shadow.outputs.disposition }}
          COMPLETENESS: ${{ steps.shadow.outputs.completeness }}
          ENFORCEMENT_ELIGIBLE: ${{ steps.shadow.outputs.enforcement-eligible }}
        run: |
          test "$DISPOSITION" = HOLD
          test "$COMPLETENESS" = partial
          test "$ENFORCEMENT_ELIGIBLE" = false
```

The two checkouts are transport/setup steps; the shadow provider itself performs no network access, authentication, fetch, signing, or secret handling. The receiver digest comparisons prevent a candidate-controlled configuration substitution from becoming the declared receiver context.

## Evidence declaration contract

The `evidence` input is a bounded JSON array. Each item has exactly four fields:

```json
[
  {
    "id": "evidence:receiver-shadow-tests",
    "type": "test-report",
    "path": "test-result.json",
    "mediaType": "application/json"
  }
]
```

Paths are normalized relative POSIX paths. The evidence directory must contain exactly the declared files and necessary parent directories—nothing else. Digests and `subjectDigest` are not accepted from the caller; the provider derives them from stable file handles and the observed candidate commit.

## Operating rules

1. Keep this workflow advisory and manually/schedule triggered. It must not be a required check, deployment gate, ruleset check, or merge condition.
2. Never add secrets, cloud credentials, signing keys, provider tokens, or private material to the job. Candidate commands execute without them.
3. Treat candidate-generated evidence as producer evidence, not independent verification.
4. Retain the manifest/evidence only in access-controlled storage appropriate for its contents. The Action does not upload artifacts.
5. Route the partial bundle to a separately governed verifier if you want to continue the protocol. Do not manufacture a receipt or authorization in the candidate job.
6. Use the main Kit Action only after the complete external bundle contract is met. Its signed receipt and authorization requirements remain unchanged.

Automated pull-request collection is a later receiver-owned `workflow_run`/GitHub App design. It needs an isolated receiver job, authenticated exact-run artifact selection, fork-safe identity binding, and replay controls. The v0 Action rejects that event until those controls exist; it does not imply that automation is already production-ready.
