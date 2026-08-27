import { execFile } from 'node:child_process';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import process from 'node:process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { readHandleBounded } from './bounded.mjs';
import { canonicalize, documentDigest } from './canonical.mjs';
import { inspectGitState } from './git-state.mjs';
import { loadMcpConfig } from './mcp-config.mjs';
import { validatePolicy, validateTrustStore } from './validate.mjs';
import { KIT_VERSION } from './version.mjs';
import { parseJsonStrictText } from './strict-json.mjs';

const execFileAsync = promisify(execFile);
const utf8 = new TextDecoder('utf-8', { fatal: true });

export const DOCTOR_SCHEMA_VERSION = 'assurance.sprintloop.dev/doctor-result/v1';
export const DOCTOR_MODE = 'READ_ONLY_OFFLINE';
export const DOCTOR_EXIT_CODES = Object.freeze({ pass: 0, warn: 10, error: 2 });

const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_DOCUMENT_BYTES = 1_048_576;
const MINIMUM_NODE_22 = Object.freeze([22, 23, 2]);
const MINIMUM_NODE_24 = Object.freeze([24, 20, 0]);
const MINIMUM_GIT = Object.freeze([2, 45, 0]);
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const OBJECT_ID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const SAFE_SEGMENT = /^[A-Za-z0-9._@+-]{1,255}$/;
const ALLOWED_OPTIONS = new Set([
  'root',
  'policyPath',
  'trustPath',
  'expectedHead',
  'expectedTree',
  'expectedPolicyDigest',
  'expectedTrustStoreDigest',
  'mcpConfigPath',
  'timeoutMs',
  'maxDocumentBytes',
]);

/**
 * Inspect whether a local checkout is ready to act as an Assurance receiver.
 *
 * The default engine is deliberately offline and read-only. It never asks Git
 * for remotes, credentials, or mutable-index state; never enables lazy fetch;
 * and never writes a cache, lock, report, or configuration file.
 */
export async function diagnoseSetup(input = {}) {
  let options;
  try {
    options = normalizeOptions(input);
  } catch {
    return report([
      check('doctor.input', 'error', 'INPUT_INVALID', 'Doctor options are invalid or exceed a configured bound.', {}),
    ]);
  }

  const deadline = performance.now() + options.timeoutMs;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(timeoutError('OVERALL_TIMEOUT')), options.timeoutMs);
  try {
    return await diagnoseSetupBounded(options, deadline, controller.signal);
  } finally {
    // A local Promise-race deadline may settle before the shared timer fires.
    // Abort every losing Git/stream operation before clearing that timer so a
    // completed report cannot leave diagnostic work alive in the process.
    controller.abort(timeoutError('OVERALL_TIMEOUT'));
    clearTimeout(timer);
  }
}

async function diagnoseSetupBounded(options, deadline, signal) {
  const checks = [nodeVersionCheck()];
  const mcpPromise = mcpCheck(options.mcpConfigPath, deadline);
  const gitVersion = await gitVersionCheck(deadline, signal);
  checks.push(gitVersion);
  if (gitVersion.status === 'error') {
    checks.push(repositoryFailure(new Error('Git safety capability unavailable')));
    checks.push(unavailableDocumentCheck('policy', options.policyPath));
    checks.push(unavailableDigestCheck('policy', options.expectedPolicyDigest));
    checks.push(unavailableDocumentCheck('trust', options.trustPath));
    checks.push(unavailableDigestCheck('trust', options.expectedTrustStoreDigest));
    checks.push(await mcpPromise);
    return report(checks);
  }

  let rootBinding;
  try {
    rootBinding = await withinDeadline(deadline, bindRoot(options.root), 'ROOT_TIMEOUT');
  } catch (error) {
    checks.push(repositoryFailure(signal.aborted ? signal.reason ?? timeoutError('ROOT_TIMEOUT') : error));
    checks.push(unavailableDocumentCheck('policy', options.policyPath));
    checks.push(unavailableDigestCheck('policy', options.expectedPolicyDigest));
    checks.push(unavailableDocumentCheck('trust', options.trustPath));
    checks.push(unavailableDigestCheck('trust', options.expectedTrustStoreDigest));
    checks.push(await mcpPromise);
    return report(checks);
  }

  let gitState;
  try {
    // includeUntracked=false is intentional: it avoids the observer's optional
    // temporary index. Protected receiver documents are checked independently
    // against the immutable HEAD tree below.
    gitState = await withinDeadline(
      deadline,
      inspectGitState(rootBinding.path, { includeUntracked: false, signal }),
      'REPOSITORY_TIMEOUT',
    );
  } catch (error) {
    checks.push(repositoryFailure(signal.aborted ? signal.reason ?? timeoutError('REPOSITORY_TIMEOUT') : error));
    checks.push(unavailableDocumentCheck('policy', options.policyPath));
    checks.push(unavailableDigestCheck('policy', options.expectedPolicyDigest));
    checks.push(unavailableDocumentCheck('trust', options.trustPath));
    checks.push(unavailableDigestCheck('trust', options.expectedTrustStoreDigest));
    checks.push(await mcpPromise);
    return report(checks);
  }

  const [policy, trust] = await Promise.all([
    protectedDocumentCheck({
      kind: 'policy',
      root: rootBinding,
      relative: options.policyPath,
      head: gitState.head,
      maxBytes: options.maxDocumentBytes,
      deadline,
      signal,
      validator: validatePolicy,
    }),
    protectedDocumentCheck({
      kind: 'trust',
      root: rootBinding,
      relative: options.trustPath,
      head: gitState.head,
      maxBytes: options.maxDocumentBytes,
      deadline,
      signal,
      validator: validateTrustStore,
    }),
  ]);

  checks.push(repositoryCheck(gitState, options));
  checks.push(policy.check);
  checks.push(digestCheck('policy', policy.digest, options.expectedPolicyDigest));
  checks.push(trust.check);
  checks.push(digestCheck('trust', trust.digest, options.expectedTrustStoreDigest));
  checks.push(await mcpPromise);
  return report(checks);
}

/** Return canonical, one-line JSON suitable for scripts and snapshots. */
export function formatDoctorJson(result) {
  return `${canonicalize(result)}\n`;
}

/** Return a bounded, path-free operator rendering of a doctor result. */
export function formatDoctorHuman(result) {
  const version = typeof result?.kitVersion === 'string' ? safeToken(result.kitVersion, 'unknown') : 'unknown';
  const overall = ['pass', 'warn', 'error'].includes(result?.status) ? result.status.toUpperCase() : 'ERROR';
  const lines = [`SprintLoop Assurance doctor ${version}: ${overall}`];
  for (const entry of Array.isArray(result?.checks) ? result.checks : []) {
    const status = ['pass', 'warn', 'error'].includes(entry?.status) ? entry.status.toUpperCase() : 'ERROR';
    const id = safeToken(entry?.id, 'doctor.unknown');
    const code = safeToken(entry?.code, 'RESULT_INVALID');
    const message = safeMessage(entry?.message);
    lines.push(`[${status}] ${id} ${code}: ${message}`);
    for (const detail of humanDetails(entry)) lines.push(`       ${detail}`);
  }
  const summary = result?.summary;
  if (validSummary(summary)) {
    lines.push(`Summary: ${summary.pass} pass, ${summary.warn} warn, ${summary.error} error.`);
  } else {
    lines.push('Summary: result contract is invalid.');
  }
  return `${lines.join('\n')}\n`;
}

export function doctorExitCode(result) {
  return DOCTOR_EXIT_CODES[result?.status] ?? DOCTOR_EXIT_CODES.error;
}

function normalizeOptions(input) {
  if (!isPlainObject(input)) throw new TypeError('options');
  for (const key of Object.keys(input)) if (!ALLOWED_OPTIONS.has(key)) throw new TypeError('option');
  const root = boundedPath(input.root ?? process.cwd(), 4096, false);
  const policyPath = protectedRelativePath(input.policyPath ?? '.assurance/policy.json');
  const trustPath = protectedRelativePath(input.trustPath ?? '.assurance/trust.json');
  if (policyPath === trustPath) throw new TypeError('protected paths');
  const expectedHead = optionalObjectId(input.expectedHead);
  const expectedTree = optionalObjectId(input.expectedTree);
  const expectedPolicyDigest = optionalDigest(input.expectedPolicyDigest);
  const expectedTrustStoreDigest = optionalDigest(input.expectedTrustStoreDigest);
  const mcpConfigPath = input.mcpConfigPath === undefined
    ? null
    : boundedPath(input.mcpConfigPath, 4096, true);
  const timeoutMs = boundedInteger(input.timeoutMs ?? DEFAULT_TIMEOUT_MS, 250, 30_000);
  const maxDocumentBytes = boundedInteger(input.maxDocumentBytes ?? DEFAULT_DOCUMENT_BYTES, 1_024, 16_777_216);
  return {
    root: path.resolve(root),
    policyPath,
    trustPath,
    expectedHead,
    expectedTree,
    expectedPolicyDigest,
    expectedTrustStoreDigest,
    mcpConfigPath,
    timeoutMs,
    maxDocumentBytes,
  };
}

export function nodeVersionCheck(runtimeVersion = process.version) {
  const parsed = parseVersion(runtimeVersion, /^v(\d+)\.(\d+)\.(\d+)$/);
  const data = { version: parsed ? versionText(parsed) : null, required: '>=22.23.2 <23.0.0 || >=24.20.0 <25.0.0' };
  if (!parsed) return check('runtime.node', 'error', 'NODE_VERSION_UNRECOGNIZED', 'Node runtime version could not be recognized.', data);
  const supported = (parsed[0] === 22 && compareVersions(parsed, MINIMUM_NODE_22) >= 0)
    || (parsed[0] === 24 && compareVersions(parsed, MINIMUM_NODE_24) >= 0);
  if (!supported) {
    return check('runtime.node', 'error', 'NODE_UNSUPPORTED', 'Node runtime is outside the supported version range.', data);
  }
  return check('runtime.node', 'pass', 'NODE_SUPPORTED', 'Node runtime is supported.', data);
}

async function gitVersionCheck(deadline, signal) {
  const data = { version: null, required: '>=2.45.0', lazyFetchDisableAvailable: false };
  try {
    // Plain --version cannot inspect a repository or trigger object fetching.
    // Parse it first so an older Git receives the precise unsupported result
    // instead of being mislabeled unavailable for not knowing the safety flag.
    const { stdout } = await execGit(['--version'], deadline, { maxBuffer: 4_096, signal });
    const parsed = parseVersion(stdout.trim(), /^git version (\d+)\.(\d+)\.(\d+)(?:[^\r\n]*)?$/);
    if (!parsed) return check('runtime.git', 'error', 'GIT_VERSION_UNRECOGNIZED', 'Git version output could not be recognized.', data);
    data.version = versionText(parsed);
    if (compareVersions(parsed, MINIMUM_GIT) < 0) {
      return check('runtime.git', 'error', 'GIT_UNSUPPORTED', 'Git is older than the supported version baseline.', data);
    }
    await execGit(['--no-lazy-fetch', '--version'], deadline, { maxBuffer: 4_096, signal });
    data.lazyFetchDisableAvailable = true;
    return check('runtime.git', 'pass', 'GIT_SUPPORTED', 'Git is available and supported.', data);
  } catch (error) {
    const timedOut = signal.aborted || isTimeoutError(error);
    return check('runtime.git', 'error', timedOut ? 'GIT_CHECK_TIMEOUT' : 'GIT_UNAVAILABLE', timedOut
      ? 'Git version inspection exceeded the configured deadline.'
      : 'Git is unavailable to the diagnostic process.', data);
  }
}

function repositoryCheck(state, options) {
  const expectedHeadMatch = options.expectedHead === null ? null : state.head === options.expectedHead;
  const expectedTreeMatch = options.expectedTree === null ? null : state.tree === options.expectedTree;
  const data = {
    head: state.head,
    tree: state.tree,
    workingTreeClean: state.workingTreeClean,
    exactnessScope: 'TRACKED_HEAD',
    expectedHeadMatch,
    expectedTreeMatch,
  };
  if (!state.workingTreeClean) {
    return check('repository.exactness', 'error', 'WORKTREE_NOT_EXACT', 'Tracked worktree bytes or modes do not exactly match HEAD.', data);
  }
  if (expectedHeadMatch === false || expectedTreeMatch === false) {
    return check('repository.exactness', 'error', 'REPOSITORY_IDENTITY_MISMATCH', 'Observed repository identity does not match the supplied immutable expectation.', data);
  }
  if (expectedHeadMatch === null || expectedTreeMatch === null) {
    return check('repository.exactness', 'warn', 'REPOSITORY_IDENTITY_UNPINNED', 'Tracked HEAD is exact, but both expected HEAD and tree were not supplied.', data);
  }
  return check('repository.exactness', 'pass', 'REPOSITORY_EXACT', 'Tracked worktree and immutable repository identity are exact.', data);
}

function repositoryFailure(error) {
  const timedOut = isTimeoutError(error);
  return check('repository.exactness', 'error', timedOut ? 'REPOSITORY_CHECK_TIMEOUT' : 'REPOSITORY_UNAVAILABLE', timedOut
    ? 'Repository inspection exceeded the configured deadline.'
    : 'The configured root is unavailable or is not an inspectable Git worktree top level.', repositoryData());
}

async function protectedDocumentCheck({ kind, root, relative, head, maxBytes, deadline, signal, validator }) {
  const data = documentData(relative);
  try {
    const [entry, observed] = await Promise.all([
      trackedEntry(root.path, head, relative, deadline, signal),
      withinDeadline(deadline, readProtectedJson(root, relative, maxBytes, signal), 'DOCUMENT_TIMEOUT'),
    ]);
    data.byteLength = observed.bytes.length;
    if (entry === null) {
      return {
        check: check(`${kind}.document`, 'error', `${kind.toUpperCase()}_NOT_PROTECTED`, 'Protected document is not a regular non-executable blob tracked by HEAD.', data),
        digest: null,
      };
    }
    data.tracked = true;
    data.trackedObjectId = entry.objectId;
    if (entry.mode !== '100644') {
      return {
        check: check(`${kind}.document`, 'error', `${kind.toUpperCase()}_MODE_INVALID`, 'Protected document must be a non-executable regular file in HEAD.', data),
        digest: null,
      };
    }
    const algorithm = entry.objectId.length === 40 ? 'sha1' : 'sha256';
    if (gitBlobDigest(observed.bytes, algorithm) !== entry.objectId) {
      return {
        check: check(`${kind}.document`, 'error', `${kind.toUpperCase()}_WORKTREE_MISMATCH`, 'Protected document bytes do not exactly match the blob recorded by HEAD.', data),
        digest: null,
      };
    }
    enforceJsonComplexity(observed.document);
    const validationErrors = validator(observed.document);
    if (validationErrors.length > 0) {
      data.validationIssueCount = Math.min(validationErrors.length, 1_000_000);
      return {
        check: check(`${kind}.document`, 'error', `${kind.toUpperCase()}_SCHEMA_INVALID`, 'Protected document does not satisfy its closed semantic contract.', data),
        digest: null,
      };
    }
    const digest = documentDigest(observed.document);
    data.canonicalDigest = digest;
    data.schemaValid = true;
    return {
      check: check(`${kind}.document`, 'pass', `${kind.toUpperCase()}_VALID`, 'Protected document is tracked, exact, bounded, and schema-valid.', data),
      digest,
    };
  } catch (error) {
    const code = protectedErrorCode(kind, signal.aborted ? signal.reason ?? timeoutError('DOCUMENT_TIMEOUT') : error);
    return {
      check: check(`${kind}.document`, 'error', code, protectedErrorMessage(code), data),
      digest: null,
    };
  }
}

function digestCheck(kind, actual, expected) {
  const data = { actualDigest: actual, expectedDigest: expected, match: actual === null || expected === null ? null : actual === expected };
  const upper = kind.toUpperCase();
  if (actual === null) {
    return check(`${kind}.digest`, 'error', `${upper}_DIGEST_UNAVAILABLE`, 'Canonical digest is unavailable because the protected document check failed.', data);
  }
  if (expected === null) {
    return check(`${kind}.digest`, 'warn', `${upper}_DIGEST_UNPINNED`, 'Canonical digest was computed, but no receiver-controlled expected digest was supplied.', data);
  }
  if (actual !== expected) {
    return check(`${kind}.digest`, 'error', `${upper}_DIGEST_MISMATCH`, 'Canonical digest does not match the receiver-controlled expected digest.', data);
  }
  return check(`${kind}.digest`, 'pass', `${upper}_DIGEST_MATCH`, 'Canonical digest matches the receiver-controlled expectation.', data);
}

async function mcpCheck(configPath, deadline) {
  const empty = { configured: false, rootCount: 0, rootKinds: [] };
  if (configPath === null) {
    return check('mcp.configuration', 'pass', 'MCP_NOT_REQUESTED', 'Optional MCP readiness inspection was not requested.', empty);
  }
  try {
    const config = await withinDeadline(deadline, loadMcpConfig(configPath), 'MCP_TIMEOUT');
    const rootKinds = [...new Set(config.roots.map((entry) => entry.kind))].sort();
    return check('mcp.configuration', 'pass', 'MCP_READY', 'MCP configuration and every declared root grant are ready.', {
      configured: true,
      rootCount: config.roots.length,
      rootKinds,
    });
  } catch (error) {
    const timedOut = error?.code === 'DOCTOR_TIMEOUT';
    return check('mcp.configuration', 'error', timedOut ? 'MCP_CHECK_TIMEOUT' : 'MCP_CONFIG_INVALID', timedOut
      ? 'MCP readiness inspection exceeded the configured deadline.'
      : 'MCP configuration or a declared root grant is invalid or unavailable.', { ...empty, configured: true });
  }
}

async function bindRoot(candidate) {
  const requested = path.resolve(candidate);
  const before = await lstat(requested);
  if (!before.isDirectory() || before.isSymbolicLink()) throw new Error('root');
  const resolved = await realpath(requested);
  const after = await lstat(resolved);
  if (!after.isDirectory() || after.isSymbolicLink() || !sameIdentity(before, after)) throw new Error('root');
  return { path: resolved, identity: identity(after) };
}

async function readProtectedJson(root, relative, maxBytes, signal) {
  signal?.throwIfAborted();
  const segments = relative.split('/');
  const ancestors = [];
  let cursor = root.path;
  for (const segment of segments.slice(0, -1)) {
    cursor = path.join(cursor, segment);
    const metadata = await lstat(cursor);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw taggedError('PATH_UNSAFE');
    ancestors.push({ path: cursor, identity: identity(metadata) });
  }
  const file = path.join(root.path, ...segments);
  const resolved = await realpath(file);
  if (!inside(root.path, resolved) || resolved !== file) throw taggedError('PATH_UNSAFE');
  const handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const before = await handle.stat();
    if (!before.isFile()) throw taggedError('NOT_REGULAR');
    if (before.size > maxBytes) throw taggedError('TOO_LARGE');
    const bytes = await readHandleBounded(handle, maxBytes, { signal });
    const after = await handle.stat();
    if (!sameIdentity(before, after) || bytes.length !== after.size) throw taggedError('PATH_CHANGED');
    let document;
    try {
      document = parseJsonStrictText(utf8.decode(bytes), { maxDepth: 64, maxValues: 100_000 });
    } catch (error) {
      if (error instanceof RangeError) throw taggedError('COMPLEXITY');
      throw taggedError('JSON_INVALID');
    }
    for (const ancestor of ancestors) {
      const current = await lstat(ancestor.path);
      if (!current.isDirectory() || current.isSymbolicLink() || !sameIdentity(ancestor.identity, current)) {
        throw taggedError('PATH_CHANGED');
      }
    }
    const currentRoot = await lstat(root.path);
    if (!currentRoot.isDirectory() || currentRoot.isSymbolicLink() || !sameIdentity(root.identity, currentRoot)) {
      throw taggedError('PATH_CHANGED');
    }
    const [currentLeaf, currentResolved] = await Promise.all([lstat(file), realpath(file)]);
    if (!currentLeaf.isFile() || currentLeaf.isSymbolicLink() || currentResolved !== file
      || !sameIdentity(before, currentLeaf)) {
      throw taggedError('PATH_CHANGED');
    }
    return { bytes, document };
  } finally {
    await handle.close();
  }
}

async function trackedEntry(root, head, relative, deadline, signal) {
  const { stdout } = await execGit([
    '-c', 'core.attributesFile=/dev/null',
    '-c', 'core.excludesFile=/dev/null',
    '-c', 'core.filemode=true',
    '-c', 'core.fsmonitor=false',
    '-c', 'core.ignoreCase=false',
    '-c', 'core.sparseCheckout=false',
    '-c', 'core.symlinks=true',
    '-c', 'core.untrackedCache=false',
    '-c', 'index.sparse=false',
    '-C', root,
    'ls-tree', '-z', '--full-tree', head, '--', `:(literal)${relative}`,
  ], deadline, { encoding: 'buffer', maxBuffer: 65_536, signal });
  if (stdout.length === 0) return null;
  if (stdout.at(-1) !== 0 || stdout.indexOf(0) !== stdout.length - 1) throw taggedError('TREE_INVALID');
  const record = stdout.subarray(0, -1);
  const tab = record.indexOf(9);
  if (tab < 1) throw taggedError('TREE_INVALID');
  const header = record.subarray(0, tab).toString('ascii');
  const match = /^(100644|100755) blob ([0-9a-f]{40}|[0-9a-f]{64})$/.exec(header);
  if (!match) return null;
  let observedPath;
  try {
    observedPath = utf8.decode(record.subarray(tab + 1));
  } catch {
    throw taggedError('TREE_INVALID');
  }
  if (observedPath !== relative) throw taggedError('TREE_INVALID');
  return { mode: match[1], objectId: match[2] };
}

async function execGit(args, deadline, overrides = {}) {
  const remaining = Math.max(1, Math.floor(deadline - performance.now()));
  const environment = {
    PATH: process.env.PATH ?? '',
    LC_ALL: 'C',
    LANG: 'C',
    GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_NO_LAZY_FETCH: '1',
    GIT_NO_REPLACE_OBJECTS: '1',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_TERMINAL_PROMPT: '0',
  };
  if (process.platform === 'win32') {
    if (process.env.SystemRoot) environment.SystemRoot = process.env.SystemRoot;
    if (process.env.WINDIR) environment.WINDIR = process.env.WINDIR;
  }
  try {
    return await execFileAsync('git', args, {
      encoding: 'utf8',
      timeout: Math.min(10_000, remaining),
      killSignal: 'SIGKILL',
      maxBuffer: 65_536,
      env: environment,
      ...overrides,
    });
  } catch (error) {
    if (error?.killed || error?.signal === 'SIGKILL' || error?.name === 'AbortError') error.code = 'ETIMEDOUT';
    throw error;
  }
}

function enforceJsonComplexity(value) {
  const stack = [{ value, depth: 0 }];
  let nodes = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    nodes += 1;
    if (nodes > 100_000 || current.depth > 64) throw taggedError('COMPLEXITY');
    if (Array.isArray(current.value)) {
      for (const entry of current.value) stack.push({ value: entry, depth: current.depth + 1 });
    } else if (isPlainObject(current.value)) {
      for (const entry of Object.values(current.value)) stack.push({ value: entry, depth: current.depth + 1 });
    }
  }
}

function report(checks) {
  const summary = { pass: 0, warn: 0, error: 0, total: checks.length };
  for (const entry of checks) summary[entry.status] += 1;
  const status = summary.error > 0 ? 'error' : summary.warn > 0 ? 'warn' : 'pass';
  return {
    schemaVersion: DOCTOR_SCHEMA_VERSION,
    kitVersion: KIT_VERSION,
    mode: DOCTOR_MODE,
    status,
    summary,
    checks,
    securityBoundary: {
      networkAccess: false,
      credentialAccess: false,
      filesystemWrites: false,
      sourceControlWrites: false,
    },
  };
}

function check(id, status, code, message, data) {
  return { id, status, code, message, data };
}

function unavailableDocumentCheck(kind, relative) {
  return check(`${kind}.document`, 'error', `${kind.toUpperCase()}_UNAVAILABLE`, 'Protected document cannot be inspected until the repository root is available.', documentData(relative));
}

function unavailableDigestCheck(kind, expected) {
  return check(`${kind}.digest`, 'error', `${kind.toUpperCase()}_DIGEST_UNAVAILABLE`, 'Canonical digest is unavailable because the protected document check failed.', {
    actualDigest: null,
    expectedDigest: expected,
    match: null,
  });
}

function documentData(relative) {
  return {
    path: relative,
    tracked: false,
    trackedObjectId: null,
    byteLength: null,
    schemaValid: false,
    validationIssueCount: 0,
    canonicalDigest: null,
  };
}

function repositoryData() {
  return {
    head: null,
    tree: null,
    workingTreeClean: false,
    exactnessScope: 'TRACKED_HEAD',
    expectedHeadMatch: null,
    expectedTreeMatch: null,
  };
}

function protectedErrorCode(kind, error) {
  const upper = kind.toUpperCase();
  if (isTimeoutError(error)) return `${upper}_CHECK_TIMEOUT`;
  if (error?.code === 'ETOOLARGE' || error?.doctorCode === 'TOO_LARGE') return `${upper}_TOO_LARGE`;
  if (error?.doctorCode === 'JSON_INVALID') return `${upper}_JSON_INVALID`;
  if (error?.doctorCode === 'COMPLEXITY') return `${upper}_COMPLEXITY_EXCEEDED`;
  if (['PATH_UNSAFE', 'PATH_CHANGED', 'TREE_INVALID'].includes(error?.doctorCode)) return `${upper}_PATH_UNSAFE`;
  return `${upper}_UNAVAILABLE`;
}

function protectedErrorMessage(code) {
  if (code.endsWith('_CHECK_TIMEOUT')) return 'Protected document inspection exceeded the configured deadline.';
  if (code.endsWith('_TOO_LARGE')) return 'Protected document exceeds the configured byte limit.';
  if (code.endsWith('_JSON_INVALID')) return 'Protected document is not valid JSON.';
  if (code.endsWith('_COMPLEXITY_EXCEEDED')) return 'Protected document exceeds the configured structural complexity limit.';
  if (code.endsWith('_PATH_UNSAFE')) return 'Protected document path is unsafe or changed during inspection.';
  return 'Protected document is unavailable or is not a regular readable file.';
}

function protectedRelativePath(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 1024 || CONTROL.test(value)
    || value.includes('\\') || path.posix.isAbsolute(value) || path.posix.normalize(value) !== value) {
    throw new TypeError('relative path');
  }
  const segments = value.split('/');
  if (segments.some((segment) => !SAFE_SEGMENT.test(segment) || segment === '.' || segment === '..')) {
    throw new TypeError('relative path');
  }
  return value;
}

function boundedPath(value, maximum, absolute) {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum || CONTROL.test(value)) throw new TypeError('path');
  if (absolute && !path.isAbsolute(value)) throw new TypeError('absolute path');
  return value;
}

function optionalObjectId(value) {
  if (value === undefined) return null;
  if (typeof value !== 'string' || !OBJECT_ID.test(value)) throw new TypeError('object id');
  return value;
}

function optionalDigest(value) {
  if (value === undefined) return null;
  if (typeof value !== 'string' || !SHA256.test(value)) throw new TypeError('digest');
  return value;
}

function boundedInteger(value, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new TypeError('integer');
  return value;
}

function parseVersion(value, pattern) {
  if (typeof value !== 'string' || value.length > 256 || CONTROL.test(value)) return null;
  const match = pattern.exec(value);
  if (!match) return null;
  const parsed = match.slice(1, 4).map(Number);
  return parsed.every((entry) => Number.isSafeInteger(entry)) ? parsed : null;
}

function compareVersions(left, right) {
  for (let index = 0; index < 3; index += 1) {
    if (left[index] !== right[index]) return left[index] < right[index] ? -1 : 1;
  }
  return 0;
}

function versionText(value) {
  return value.join('.');
}

function gitBlobDigest(bytes, algorithm) {
  return createHash(algorithm)
    .update(Buffer.from(`blob ${bytes.length}\0`, 'utf8'))
    .update(bytes)
    .digest('hex');
}

function identity(metadata) {
  return { dev: metadata.dev, ino: metadata.ino, size: metadata.size, mtimeMs: metadata.mtimeMs };
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size && left.mtimeMs === right.mtimeMs;
}

function inside(root, candidate) {
  return candidate === root || candidate.startsWith(`${root}${path.sep}`);
}

function taggedError(code) {
  const error = new Error('doctor operation failed');
  error.doctorCode = code;
  return error;
}

async function withinDeadline(deadline, operation, code) {
  const remaining = deadline - performance.now();
  if (remaining <= 0) throw timeoutError(code);
  let timer;
  try {
    return await Promise.race([
      operation,
      new Promise((resolve, reject) => {
        timer = setTimeout(() => reject(timeoutError(code)), remaining);
        timer.unref?.();
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function timeoutError(operation) {
  const error = new Error('doctor deadline exceeded');
  error.code = 'DOCTOR_TIMEOUT';
  error.operation = operation;
  return error;
}

function isTimeoutError(error) {
  const seen = new Set();
  let current = error;
  for (let depth = 0; current && depth < 8 && !seen.has(current); depth += 1) {
    seen.add(current);
    if (current.code === 'DOCTOR_TIMEOUT' || current.code === 'ETIMEDOUT' || current.code === 'ABORT_ERR'
      || current.name === 'AbortError') return true;
    current = current.cause;
  }
  return false;
}

function humanDetails(entry) {
  const data = isPlainObject(entry?.data) ? entry.data : {};
  const details = [];
  if ((entry.id === 'runtime.node' || entry.id === 'runtime.git') && typeof data.version === 'string') {
    details.push(`version=${safeToken(data.version, 'unknown')} required=${safeToken(data.required, 'unknown')}`);
  }
  if (entry.id === 'repository.exactness') {
    if (OBJECT_ID.test(data.head ?? '')) details.push(`head=${data.head}`);
    if (OBJECT_ID.test(data.tree ?? '')) details.push(`tree=${data.tree}`);
  }
  if ((entry.id === 'policy.document' || entry.id === 'trust.document') && SHA256.test(data.canonicalDigest ?? '')) {
    details.push(`digest=${data.canonicalDigest}`);
  }
  if (entry.id === 'mcp.configuration' && data.configured === true) {
    const kinds = Array.isArray(data.rootKinds) ? data.rootKinds.filter((entryKind) => ['bundle', 'receiver', 'dossier'].includes(entryKind)) : [];
    details.push(`roots=${Number.isSafeInteger(data.rootCount) ? data.rootCount : 0} kinds=${kinds.join(',') || 'none'}`);
  }
  return details;
}

function safeToken(value, fallback) {
  return typeof value === 'string' && /^[A-Za-z0-9._:<>/=+ -]{1,256}$/.test(value) ? value : fallback;
}

function safeMessage(value) {
  return typeof value === 'string' && value.length >= 1 && value.length <= 512 && !CONTROL.test(value)
    ? value
    : 'Diagnostic result is unavailable.';
}

function validSummary(value) {
  return isPlainObject(value)
    && ['pass', 'warn', 'error', 'total'].every((key) => Number.isSafeInteger(value[key]) && value[key] >= 0)
    && value.pass + value.warn + value.error === value.total;
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}
