# Setup doctor

The setup doctor answers one narrow question before Assurance is placed in an engineering workflow: **is this local receiver checkout exact, bounded, and correctly bound to its protected policy and trust inputs?**

It is a zero-dependency, offline, read-only diagnostic. It does not create configuration, repair a checkout, contact Git remotes, discover credentials, start the MCP server, sign documents, or make an assurance decision. A passing doctor result is setup evidence; it is not a verifier receipt, authorization, dossier, or release approval.

The command is part of the v0.3 development line and is not present in the latest public v0.2.0 artifact. Until v0.3 has a reviewed release revision, run it only from source you have reviewed; do not use a branch name as a production security pin.

## What it checks

Checks have stable IDs and one of three statuses: `pass`, `warn`, or `error`.

| Check ID | What is established |
| --- | --- |
| `runtime.node` | The active runtime is a maintained LTS line: `>=22.23.2 <23.0.0` or `>=24.20.0 <25.0.0`. EOL and odd-numbered release lines fail closed. |
| `runtime.git` | Git is present and satisfies the hardened observer baseline, currently `>=2.45.0`, including fail-closed lazy-fetch disabling. This gate completes before repository objects are inspected. |
| `repository.exactness` | The configured root is the Git worktree top level; HEAD is a commit with a supported object format; every tracked file's raw bytes, mode, symlink target, and submodule identity match HEAD; optional expected HEAD and tree IDs match. |
| `policy.document` | The policy path is a bounded relative path with no symlink traversal; it is a non-executable regular blob tracked by HEAD; worktree bytes match that blob; JSON is bounded and satisfies the closed policy contract. |
| `policy.digest` | The policy's canonical SHA-256 digest matches the receiver-controlled expected digest. |
| `trust.document` | The trust-store path passes the same protected-path, tracked-blob, byte-exactness, bound, and schema checks. |
| `trust.digest` | The trust store's canonical SHA-256 digest matches the receiver-controlled expected digest. |
| `mcp.configuration` | When requested, the MCP configuration and every declared root grant pass the production loader's bounds, non-overlap, directory, symlink, and stable-identity checks. |

Repository exactness is deliberately labeled `TRACKED_HEAD` in machine output. Non-ignored untracked-file enumeration would require an auxiliary Git index; the doctor does not create one because its contract prohibits filesystem writes. Run it in a fresh or otherwise hermetic checkout when untracked build inputs are a concern. Protected policy and trust files cannot exploit that distinction: each must be a byte-exact blob tracked by HEAD.

## Module API

The engine is in `src/doctor.mjs`:

```js
import {
  diagnoseSetup,
  doctorExitCode,
  formatDoctorHuman,
  formatDoctorJson,
} from './src/doctor.mjs';

const result = await diagnoseSetup({
  root: process.cwd(),
  expectedHead: process.env.EXPECTED_HEAD,
  expectedTree: process.env.EXPECTED_TREE,
  expectedPolicyDigest: process.env.ASSURANCE_POLICY_DIGEST,
  expectedTrustStoreDigest: process.env.ASSURANCE_TRUST_DIGEST,
  mcpConfigPath: '/absolute/path/assurance-mcp.json',
});

process.stdout.write(formatDoctorHuman(result));
process.exitCode = doctorExitCode(result);
```

Environment variables above are an integration example only. The doctor engine itself reads no receiver digest, token, key, secret, or configuration variable. A CLI adapter must pass explicit values.

### Options

Unknown options and out-of-bound values return one sanitized `doctor.input` error without touching Git or the filesystem.

| Option | Default | Contract |
| --- | --- | --- |
| `root` | `process.cwd()` | Non-empty path, at most 4,096 characters. It must resolve to the worktree top level and must not itself be a symlink. |
| `policyPath` | `.assurance/policy.json` | Normalized forward-slash relative path, at most 1,024 characters. Segments use bounded portable ASCII names; absolute paths, `.`/`..`, controls, backslashes, and symlinks are rejected. |
| `trustPath` | `.assurance/trust.json` | Same contract as `policyPath`; the two paths must differ. |
| `expectedHead` | omitted | Lowercase 40- or 64-hex Git object ID. Omission produces a warning. |
| `expectedTree` | omitted | Lowercase 40- or 64-hex Git tree ID. Omission produces a warning. |
| `expectedPolicyDigest` | omitted | Canonical lowercase `sha256:` digest. Omission produces a warning; mismatch is an error. |
| `expectedTrustStoreDigest` | omitted | Canonical lowercase `sha256:` digest. Omission produces a warning; mismatch is an error. |
| `mcpConfigPath` | omitted | Absolute path to an optional MCP server configuration. Omission is a pass because MCP is optional. |
| `timeoutMs` | `15000` | Monotonic reporting deadline, from 250 through 30,000 milliseconds. Git subprocesses and tracked-file streams are aborted; ordinary OS filesystem metadata calls are not cancelable by Node and may outlive the report on a stalled NFS/FUSE/automount. |
| `maxDocumentBytes` | `1048576` | Per protected document, from 1,024 through 16,777,216 bytes. JSON is additionally capped at depth 64 and 100,000 structural nodes. |

The engine accepts only a plain object. It does not interpolate option values into a shell.

## Human and JSON output

`formatDoctorHuman(result)` emits a concise operator report:

```text
SprintLoop Assurance doctor 0.3.0: PASS
[PASS] runtime.node NODE_SUPPORTED: Node runtime is supported.
[PASS] runtime.git GIT_SUPPORTED: Git is available and supported.
[PASS] repository.exactness REPOSITORY_EXACT: Tracked worktree and immutable repository identity are exact.
       head=<observed object ID>
       tree=<observed tree ID>
...
Summary: 8 pass, 0 warn, 0 error.
```

`formatDoctorJson(result)` emits canonical one-line JSON with sorted object keys and ordered checks. There is no timestamp, duration, hostname, username, absolute path, remote URL, environment dump, raw exception, policy body, trust-store body, or key material, so identical observations serialize identically.

The machine contract is versioned as `assurance.sprintloop.dev/doctor-result/v1`; its published source schema is [doctor-result.v1.schema.json](../schemas/doctor-result.v1.schema.json). It includes:

```json
{
  "schemaVersion": "assurance.sprintloop.dev/doctor-result/v1",
  "kitVersion": "0.3.0",
  "mode": "READ_ONLY_OFFLINE",
  "status": "pass",
  "summary": { "pass": 8, "warn": 0, "error": 0, "total": 8 },
  "checks": [],
  "securityBoundary": {
    "networkAccess": false,
    "credentialAccess": false,
    "filesystemWrites": false,
    "sourceControlWrites": false
  }
}
```

Every check has exactly `id`, `status`, `code`, `message`, and `data`. Messages are controlled text rather than relayed exception strings. Check data exposes only normalized versions, relative protected paths, object IDs, canonical digests, booleans, bounds, counts, and MCP root kinds.

## Status and exit contract

The overall status is the highest observed severity:

| Status | Exit | Meaning |
| --- | ---: | --- |
| `pass` | `0` | Every requested setup binding is established. |
| `warn` | `10` | Inspection succeeded, but one or more immutable expectations were omitted. This must not be treated as enforcement-ready. |
| `error` | `2` | An input is invalid, an operation failed or timed out, protected state is unavailable/unsafe/invalid, or an immutable expectation mismatched. |

`doctorExitCode(result)` owns this mapping. An adapter should return it unchanged.

## CLI

The v0.3 source exposes the engine through the main binary with this exact flag surface:

```text
sprintloop-assure doctor
  [--root DIRECTORY]
  [--policy RELATIVE_FILE]
  [--trust RELATIVE_FILE]
  [--expected-head OBJECT_ID]
  [--expected-tree OBJECT_ID]
  [--expected-policy-digest SHA256]
  [--expected-trust-digest SHA256]
  [--mcp-config ABSOLUTE_FILE]
  [--timeout-ms INTEGER]
  [--max-document-bytes INTEGER]
  [--json]
```

For an initial advisory diagnostic, the expected values may be omitted; each omission is explicit in the report and produces overall `warn` / exit `10`. For an exact setup check, pass all four receiver-controlled expectations:

```bash
node /absolute/reviewed/kit/bin/sprintloop-assure.mjs doctor \
  --root /absolute/service \
  --policy .assurance/policy.json \
  --trust .assurance/trust.json \
  --expected-head 0123456789abcdef0123456789abcdef01234567 \
  --expected-tree 89abcdef0123456789abcdef0123456789abcdef \
  --expected-policy-digest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --expected-trust-digest sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --mcp-config /absolute/receiver/assurance-mcp.json \
  --json
```

Every object ID and digest above is illustrative. Obtain expectations through receiver-governed configuration or observation outside the candidate. Computing an “expected” digest from the same untrusted checkout in the enforcement step proves only self-consistency and is not a receiver binding.

Do not add automatic discovery of digest pins, MCP configuration, environment values, credential stores, Git remotes, or hosted state. Explicit receiver input is part of the trust boundary.

## Security boundary

- Only Node built-ins and existing Kit validation/observation modules are loaded; no package installation is required.
- Git is invoked with an argument array, never a shell. Global/system configuration, replacement objects, optional locks, lazy fetch, terminal prompts, filesystem monitors, sparse-index behavior, and local attributes/excludes are disabled or bypassed for observations.
- The child environment is allowlisted to executable lookup, locale, platform runtime paths on Windows, and defensive Git controls. Tokens, auth headers, askpass helpers, SSH commands, proxy values, and credential-helper variables are not inherited by doctor-owned Git commands.
- The hardened worktree observer compares raw bytes and executable modes without trusting mutable index flags or candidate clean filters. Protected JSON is opened without following the final symlink, bounded while reading, identity-checked before and after, and bound to stable non-symlink ancestors.
- MCP readiness calls the same strict loader used by the MCP server, but it neither starts the server nor reads documents under granted roots. Reports include root kinds/count only, never root paths or IDs.
- Failures are converted to controlled codes. Raw filesystem, Git, JSON, and MCP exception text is never returned.

Run the doctor from a reviewed, immutable Kit revision. Like any local executable, a modified doctor source is outside this diagnostic's trust claim.
