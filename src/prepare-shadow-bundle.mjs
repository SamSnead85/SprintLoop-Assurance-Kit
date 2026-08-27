#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { constants, realpathSync } from 'node:fs';
import {
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  rename,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { readHandleBounded } from './bounded.mjs';
import { canonicalize, documentDigest } from './canonical.mjs';
import { inspectGitState as inspectReceiverGitState } from './git-state.mjs';
import { appendGithubOutput, readJson, safeLogMessage } from './io.mjs';
import { validateManifest, validatePolicy, validateTrustStore } from './validate.mjs';

const SAFE_GITHUB_EVENTS = new Set(['schedule', 'workflow_dispatch']);
const DECLARATION_MAX_BYTES = 65_536;
const DOCUMENT_MAX_BYTES = 1_048_576;
const HARD_MAX_EVIDENCE_ITEMS = 128;
const HARD_MAX_EVIDENCE_BYTES = 16 * 1024 * 1024;
const HARD_MAX_TOTAL_EVIDENCE_BYTES = 64 * 1024 * 1024;
const SUBJECT = /^git:(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;

/**
 * Prepare a receiver-coordinate-bound, intentionally incomplete shadow bundle.
 *
 * This function emits a canonical manifest and declared evidence only. It
 * never creates a verifier receipt, release authorization, key, decision, or
 * dossier. Its returned HOLD is structural metadata, not a signed verdict.
 */
export async function prepareShadowBundle({
  runnerTemp,
  candidateRoot,
  candidate,
  evidenceRoot,
  evidenceDeclaration,
  destination,
  policyPath,
  trustPath,
  expectedPolicyDigest,
  expectedTrustStoreDigest,
  expectedRepository,
  expectedEnvironment,
  changeId,
  intentId,
  intentDigest,
  producerPrincipalId,
  producerOwnerId,
  producerControlDomain,
}) {
  requireText(runnerTemp, 'runner-temp');
  requireText(candidateRoot, 'candidate-root');
  requireText(evidenceRoot, 'evidence-root');
  requireText(destination, 'destination');
  requireText(policyPath, 'policy');
  requireText(trustPath, 'trust');
  requireText(expectedRepository, 'expected-repository');
  requireText(expectedEnvironment, 'expected-environment');
  requireText(changeId, 'change-id');
  requireText(intentId, 'intent-id');
  requireText(producerPrincipalId, 'producer-principal-id');
  requireText(producerOwnerId, 'producer-owner-id');
  requireText(producerControlDomain, 'producer-control-domain');
  requireSha256(expectedPolicyDigest, 'expected-policy-digest');
  requireSha256(expectedTrustStoreDigest, 'expected-trust-digest');
  requireSha256(intentDigest, 'intent-digest');
  const expectedCandidate = normalizeCandidate(candidate);

  const runnerDirectory = await requiredDirectory(runnerTemp, 'Runner temporary root');
  const candidateDirectory = await requiredDirectory(candidateRoot, 'Candidate checkout');
  const evidenceDirectory = await requiredDirectory(evidenceRoot, 'External evidence root');
  if (evidenceDirectory === runnerDirectory || !inside(runnerDirectory, evidenceDirectory)) {
    throw new Error('External evidence root must be a dedicated directory inside the runner temporary root');
  }
  rejectOverlap(candidateDirectory, evidenceDirectory, 'External evidence root must be outside the candidate checkout');

  const protectedPolicy = await requiredRegularFile(policyPath, 'Protected policy');
  const protectedTrust = await requiredRegularFile(trustPath, 'Protected trust store');
  for (const [label, file] of [['policy', protectedPolicy.path], ['trust store', protectedTrust.path]]) {
    if (!inside(runnerDirectory, file) || file === runnerDirectory) {
      throw new Error(`Protected ${label} must be inside the receiver-controlled runner temporary root`);
    }
    if (inside(candidateDirectory, file) || inside(evidenceDirectory, file)) {
      throw new Error(`Protected ${label} must be outside the candidate and external evidence root`);
    }
  }
  if (protectedPolicy.path === protectedTrust.path) {
    throw new Error('Protected policy and trust store must be distinct regular files');
  }

  const output = await resolveFreshDestination(destination, runnerDirectory);
  rejectOverlap(candidateDirectory, output, 'Shadow bundle destination must be outside the candidate checkout');
  rejectOverlap(evidenceDirectory, output, 'Evidence source and shadow bundle destination must not overlap');
  if (output === protectedPolicy.path || output === protectedTrust.path) {
    throw new Error('Shadow bundle destination must not replace protected receiver configuration');
  }

  const [beforeGit, policy, trustStore] = await Promise.all([
    inspectGitState(candidateDirectory),
    readJson(protectedPolicy.path, { maxBytes: DOCUMENT_MAX_BYTES, expectedIdentity: protectedPolicy.identity }),
    readJson(protectedTrust.path, { maxBytes: DOCUMENT_MAX_BYTES, expectedIdentity: protectedTrust.identity }),
  ]);
  requireValid('policy', validatePolicy(policy));
  requireValid('trust store', validateTrustStore(trustStore));
  if (JSON.stringify(trustStore).includes('PRIVATE KEY')) {
    throw new Error('Protected trust store must contain public material only');
  }
  const policyDigest = documentDigest(policy);
  const trustStoreDigest = documentDigest(trustStore);
  requireEqual(policyDigest, expectedPolicyDigest, 'Protected policy digest');
  requireEqual(trustStoreDigest, expectedTrustStoreDigest, 'Protected trust-store digest');
  requireEqual(beforeGit.candidateDigest, expectedCandidate, 'Checked-out candidate');
  if (!beforeGit.workingTreeClean) {
    throw new Error('Candidate worktree is not clean (tracked or non-ignored untracked files)');
  }

  const declarations = parseEvidenceDeclaration(evidenceDeclaration, policy);
  await requireExactEvidenceInventory(evidenceDirectory, declarations.map((item) => item.path));
  const evidence = [];
  const evidenceBytes = [];
  let aggregateBytes = 0;
  for (const declaration of declarations) {
    const perItemLimit = Math.min(policy.maxEvidenceBytes, HARD_MAX_EVIDENCE_BYTES);
    const totalLimit = Math.min(policy.maxTotalEvidenceBytes, HARD_MAX_TOTAL_EVIDENCE_BYTES);
    const remaining = totalLimit - aggregateBytes;
    if (remaining < 1) throw new Error('Declared evidence exceeds the aggregate receiver-owned byte limit');
    const bytes = await readEvidence(evidenceDirectory, declaration.path, Math.min(perItemLimit, remaining));
    aggregateBytes += bytes.length;
    evidenceBytes.push({ path: declaration.path, bytes });
    evidence.push({
      id: declaration.id,
      type: declaration.type,
      path: declaration.path,
      mediaType: declaration.mediaType,
      digest: digest(bytes),
      subjectDigest: beforeGit.candidateDigest,
    });
  }
  await requireExactEvidenceInventory(evidenceDirectory, declarations.map((item) => item.path));

  const afterGit = await inspectGitState(candidateDirectory);
  requireEqual(afterGit.candidateDigest, beforeGit.candidateDigest, 'Candidate after evidence capture');
  requireEqual(afterGit.treeDigest, beforeGit.treeDigest, 'Git tree after evidence capture');
  if (!afterGit.workingTreeClean) throw new Error('Candidate worktree changed during evidence capture');

  const manifest = {
    schemaVersion: 'assurance.sprintloop.dev/manifest/v1',
    changeId,
    candidate: {
      repository: expectedRepository,
      digest: beforeGit.candidateDigest,
      treeDigest: beforeGit.treeDigest,
      environment: expectedEnvironment,
      producer: {
        principalId: producerPrincipalId,
        ownerId: producerOwnerId,
        controlDomain: producerControlDomain,
      },
    },
    intent: { id: intentId, digest: intentDigest },
    evidence,
  };
  requireValid('generated shadow manifest', validateManifest(manifest));
  const manifestDigest = documentDigest(manifest);
  await writeShadowBundle(output, manifest, evidenceBytes);

  const presentTypes = new Set(evidence.map((item) => item.type));
  const missingEvidenceTypes = policy.requiredEvidenceTypes.filter((type) => !presentTypes.has(type)).sort(compareText);
  return {
    bundleRoot: output,
    evidenceRoot: output,
    manifest: path.join(output, 'manifest.json'),
    manifestDigest,
    candidateDigest: beforeGit.candidateDigest,
    treeDigest: beforeGit.treeDigest,
    policyDigest,
    trustStoreDigest,
    disposition: 'HOLD',
    completeness: 'partial',
    enforcementEligible: false,
    missingEvidenceTypes,
  };
}

function parseEvidenceDeclaration(value, policy) {
  const bytes = Buffer.byteLength(typeof value === 'string' ? value : JSON.stringify(value ?? null), 'utf8');
  if (bytes > DECLARATION_MAX_BYTES) throw new Error(`Evidence declaration exceeds ${DECLARATION_MAX_BYTES} bytes`);
  let parsed;
  try {
    parsed = typeof value === 'string' ? JSON.parse(value) : value;
  } catch (error) {
    throw new Error(`Evidence declaration is not valid JSON: ${error.message}`);
  }
  const limit = Math.min(policy.maxEvidenceItems, HARD_MAX_EVIDENCE_ITEMS);
  if (!Array.isArray(parsed) || parsed.length < 1) throw new Error('Evidence declaration must be a non-empty JSON array');
  if (parsed.length > limit) throw new Error(`Evidence declaration exceeds the ${limit}-item receiver limit`);
  const ids = new Set();
  const types = new Set();
  const paths = new Set();
  const result = [];
  for (const [index, item] of parsed.entries()) {
    if (!plainObject(item)) throw new Error(`Evidence declaration item ${index} must be an object`);
    const keys = Object.keys(item).sort(compareText);
    if (keys.join(',') !== 'id,mediaType,path,type') {
      throw new Error(`Evidence declaration item ${index} must contain exactly id, type, path, and mediaType`);
    }
    const provisional = {
      schemaVersion: 'assurance.sprintloop.dev/manifest/v1',
      changeId: 'shadow:declaration-check',
      candidate: {
        repository: 'https://example.invalid/shadow/declaration-check',
        digest: 'git:sha1:0000000000000000000000000000000000000000',
        treeDigest: 'git-tree:sha1:0000000000000000000000000000000000000000',
        environment: 'shadow',
        producer: { principalId: 'shadow:producer', ownerId: 'shadow:owner', controlDomain: 'shadow' },
      },
      intent: { id: 'shadow:intent', digest: `sha256:${'0'.repeat(64)}` },
      evidence: [{ ...item, digest: `sha256:${'0'.repeat(64)}`, subjectDigest: 'git:sha1:0000000000000000000000000000000000000000' }],
    };
    const errors = validateManifest(provisional).filter((entry) => entry.startsWith('evidence'));
    if (errors.length) throw new Error(`Evidence declaration item ${index} is invalid: ${errors.join(', ')}`);
    if (ids.has(item.id)) throw new Error(`Evidence declaration duplicates id: ${item.id}`);
    if (types.has(item.type)) throw new Error(`Evidence declaration duplicates type: ${item.type}`);
    if (paths.has(item.path)) throw new Error(`Evidence declaration duplicates path: ${item.path}`);
    ids.add(item.id);
    types.add(item.type);
    paths.add(item.path);
    result.push({ id: item.id, type: item.type, path: item.path, mediaType: item.mediaType });
  }
  return result.sort((left, right) => compareText(left.id, right.id)
    || compareText(left.type, right.type)
    || compareText(left.path, right.path));
}

async function inspectGitState(root) {
  const state = await inspectReceiverGitState(root, { includeUntracked: true });
  return {
    candidateDigest: normalizeCandidate(state.head),
    treeDigest: normalizeTree(state.tree),
    workingTreeClean: state.workingTreeClean,
  };
}

async function readEvidence(root, relative, maxBytes) {
  const resolved = path.resolve(root, relative);
  if (!inside(root, resolved)) throw new Error(`Declared evidence escapes the external evidence root: ${relative}`);
  const actual = await realpath(resolved);
  if (!inside(root, actual)) throw new Error(`Declared evidence resolves outside the external evidence root: ${relative}`);
  const handle = await open(actual, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const before = await handle.stat();
    if (!before.isFile()) throw new Error(`Declared evidence is not a regular file: ${relative}`);
    if (before.size > maxBytes) throw new Error(`Declared evidence exceeds its receiver-owned byte limit: ${relative}`);
    if (await realpath(resolved) !== actual) throw new Error(`Declared evidence path changed during capture: ${relative}`);
    const bytes = await readHandleBounded(handle, maxBytes);
    const after = await handle.stat();
    if (!sameIdentity(before, after) || bytes.length !== after.size) {
      throw new Error(`Declared evidence changed during capture: ${relative}`);
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

async function requireExactEvidenceInventory(root, relativePaths) {
  const allowedFiles = new Set(relativePaths);
  const allowedDirectories = new Set();
  for (const file of allowedFiles) {
    let directory = path.posix.dirname(file);
    while (directory !== '.') {
      allowedDirectories.add(directory);
      directory = path.posix.dirname(directory);
    }
  }
  const seen = new Set();
  await walk(root);
  for (const expected of allowedFiles) {
    if (!seen.has(expected)) throw new Error(`Declared evidence file is missing: ${expected}`);
  }

  async function walk(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => compareText(left.name, right.name));
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      const relative = path.relative(root, absolute).split(path.sep).join('/');
      if (entry.isSymbolicLink()) throw new Error(`External evidence symlinks are prohibited: ${relative}`);
      if (entry.isDirectory()) {
        if (!allowedDirectories.has(relative)) throw new Error(`External evidence contains an unexpected directory: ${relative}`);
        await walk(absolute);
        continue;
      }
      if (!entry.isFile()) throw new Error(`External evidence contains a non-regular file: ${relative}`);
      if (!allowedFiles.has(relative)) throw new Error(`External evidence contains an undeclared file: ${relative}`);
      seen.add(relative);
    }
  }
}

async function writeShadowBundle(destination, manifest, evidence) {
  let claimed = false;
  try {
    await mkdir(destination, { recursive: false, mode: 0o700 });
    claimed = true;
    for (const item of evidence) {
      const output = path.join(destination, item.path);
      await mkdir(path.dirname(output), { recursive: true, mode: 0o700 });
      const handle = await open(output, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
      try {
        await handle.writeFile(item.bytes);
      } finally {
        await handle.close();
      }
    }
    // `manifest.json` is the commit marker. A killed/failed process may leave a
    // claimed directory, but it can never leave a usable shadow bundle without
    // this final atomic rename. Existing destinations are never overwritten.
    const temporaryManifest = path.join(destination, `.manifest.${process.pid}.tmp`);
    await writeFile(temporaryManifest, `${canonicalize(manifest)}\n`, { flag: 'wx', mode: 0o600 });
    await rename(temporaryManifest, path.join(destination, 'manifest.json'));
  } catch (error) {
    if (claimed) await rm(destination, { recursive: true, force: true });
    if (error?.code === 'EEXIST') throw new Error(`Shadow bundle destination already exists: ${destination}`);
    throw error;
  }
}

async function requiredDirectory(value, label) {
  rejectControlPath(value, label);
  const requested = path.resolve(value);
  const requestedStat = await lstat(requested);
  if (requestedStat.isSymbolicLink()) throw new Error(`${label} must not be a symlink`);
  const actual = await realpath(requested);
  const actualStat = await stat(actual);
  if (!actualStat.isDirectory()) throw new Error(`${label} must be a directory`);
  return actual;
}

async function requiredRegularFile(value, label) {
  rejectControlPath(value, label);
  const requested = path.resolve(value);
  const requestedStat = await lstat(requested);
  if (requestedStat.isSymbolicLink()) throw new Error(`${label} must not be a symlink`);
  const actual = await realpath(requested);
  const actualStat = await stat(actual);
  if (!actualStat.isFile()) throw new Error(`${label} must be a regular file`);
  return { path: actual, identity: actualStat };
}

async function resolveFreshDestination(value, runnerRoot) {
  rejectControlPath(value, 'Shadow bundle destination');
  const requested = path.resolve(value);
  const parentInput = path.dirname(requested);
  const parentStat = await lstat(parentInput);
  if (parentStat.isSymbolicLink()) throw new Error('Shadow bundle destination parent must not be a symlink');
  const parent = await realpath(parentInput);
  if (!inside(runnerRoot, parent)) throw new Error('Shadow bundle destination must be inside the runner temporary root');
  const destination = path.join(parent, path.basename(requested));
  if (destination === runnerRoot) throw new Error('Shadow bundle destination must be a dedicated child path');
  return destination;
}

function normalizeCandidate(value) {
  if (SUBJECT.test(value ?? '')) return value;
  if (/^[0-9a-f]{40}$/.test(value ?? '')) return `git:sha1:${value}`;
  if (/^[0-9a-f]{64}$/.test(value ?? '')) return `git:sha256:${value}`;
  throw new Error('candidate must be a lowercase 40/64-character Git digest');
}

function normalizeTree(value) {
  if (/^[0-9a-f]{40}$/.test(value)) return `git-tree:sha1:${value}`;
  if (/^[0-9a-f]{64}$/.test(value)) return `git-tree:sha256:${value}`;
  throw new Error('Git tree must be a lowercase 40/64-character digest');
}

function requireValid(label, errors) {
  if (errors.length) throw new Error(`${label} is invalid: ${errors.join(', ')}`);
}

function requireEqual(actual, expected, label) {
  if (actual !== expected) throw new Error(`${label} does not match the protected receiver coordinate`);
}

function requireSha256(value, name) {
  if (!SHA256.test(value ?? '')) throw new Error(`${name} must be canonical sha256:<64 hex>`);
}

function requireText(value, name) {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`${name} is required`);
}

function rejectControlPath(value, label) {
  requireText(value, label);
  if (/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u.test(value)) throw new Error(`${label} contains prohibited control characters`);
}

function plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size && left.mtimeMs === right.mtimeMs;
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function inside(root, candidatePath) {
  return candidatePath === root || candidatePath.startsWith(`${root}${path.sep}`);
}

function rejectOverlap(left, right, message) {
  if (inside(left, right) || inside(right, left)) throw new Error(message);
}

function digest(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

async function main(environment = process.env) {
  try {
    if (environment.GITHUB_ACTIONS !== 'true') {
      throw new Error('Shadow bundle preparation is available only inside a receiver-run GitHub Actions job');
    }
    if (!SAFE_GITHUB_EVENTS.has(environment.GITHUB_EVENT_NAME)) {
      throw new Error('Shadow bundle preparation permits only workflow_dispatch or schedule; PR, push, merge-group, and reusable-workflow gates are prohibited');
    }
    const result = await prepareShadowBundle({
      runnerTemp: environment.RUNNER_TEMP,
      candidateRoot: environment.ASSURANCE_CANDIDATE_ROOT,
      candidate: environment.ASSURANCE_CANDIDATE,
      evidenceRoot: environment.ASSURANCE_EVIDENCE_ROOT,
      evidenceDeclaration: environment.ASSURANCE_EVIDENCE_DECLARATION,
      destination: environment.ASSURANCE_SHADOW_DESTINATION,
      policyPath: environment.ASSURANCE_POLICY,
      trustPath: environment.ASSURANCE_TRUST,
      expectedPolicyDigest: environment.ASSURANCE_EXPECTED_POLICY,
      expectedTrustStoreDigest: environment.ASSURANCE_EXPECTED_TRUST,
      expectedRepository: environment.ASSURANCE_EXPECTED_REPOSITORY,
      expectedEnvironment: environment.ASSURANCE_EXPECTED_ENVIRONMENT,
      changeId: environment.ASSURANCE_CHANGE_ID,
      intentId: environment.ASSURANCE_INTENT_ID,
      intentDigest: environment.ASSURANCE_INTENT_DIGEST,
      producerPrincipalId: environment.ASSURANCE_PRODUCER_PRINCIPAL,
      producerOwnerId: environment.ASSURANCE_PRODUCER_OWNER,
      producerControlDomain: environment.ASSURANCE_PRODUCER_CONTROL_DOMAIN,
    });
    if (environment.GITHUB_OUTPUT) {
      await appendGithubOutput(environment.GITHUB_OUTPUT, {
        bundle_root: result.bundleRoot,
        evidence_root: result.evidenceRoot,
        manifest: result.manifest,
        manifest_digest: result.manifestDigest,
        candidate_digest: result.candidateDigest,
        tree_digest: result.treeDigest,
        policy_digest: result.policyDigest,
        trust_store_digest: result.trustStoreDigest,
        disposition: result.disposition,
        completeness: result.completeness,
        enforcement_eligible: String(result.enforcementEligible),
        missing_evidence_types: result.missingEvidenceTypes.join(','),
      });
    }
    process.stdout.write('::warning title=Shadow evidence only::HOLD — partial unsigned evidence manifest; enforcement eligible: false. Independent verification and release authorization are absent.\n');
    process.stdout.write(`Shadow evidence bundle prepared at ${result.bundleRoot}\n`);
    return 0;
  } catch (error) {
    process.stderr.write(`Shadow bundle preparation failed closed: ${safeLogMessage(error)}\n`);
    return 2;
  }
}

function isDirectInvocation() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
}

if (isDirectInvocation()) {
  main().then((code) => {
    process.exitCode = code;
  });
}
