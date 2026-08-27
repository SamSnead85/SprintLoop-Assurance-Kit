#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { constants, realpathSync } from 'node:fs';
import { lstat, mkdir, mkdtemp, open, readdir, realpath, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { readHandleBounded } from './bounded.mjs';
import { documentDigest } from './canonical.mjs';
import { appendGithubOutput, readJson, writeJsonAtomic } from './io.mjs';
import {
  validateAuthorization,
  validateManifest,
  validatePolicy,
  validateReceipt,
  validateTrustStore,
} from './validate.mjs';

const execFileAsync = promisify(execFile);
const DOCUMENTS = {
  manifest: 'manifest.json',
  receipt: 'verifier-receipt.json',
  authorization: 'authorization.json',
};
const RESERVED = new Set([...Object.values(DOCUMENTS), 'policy.json', 'trust.json']);

export async function materializeExternalBundle({
  source,
  destination,
  candidateRoot,
  candidate,
  policyPath,
  trustPath,
  expectedPolicyDigest,
  expectedTrustStoreDigest,
  expectedRepository,
  expectedEnvironment,
}) {
  requireText(source, 'source');
  requireText(destination, 'destination');
  requireText(candidateRoot, 'candidate-root');
  requireText(policyPath, 'policy');
  requireText(trustPath, 'trust');
  requireText(expectedRepository, 'expected-repository');
  requireText(expectedEnvironment, 'expected-environment');
  const expectedCandidate = normalizeCandidate(candidate);
  requireSha256(expectedPolicyDigest, 'expected-policy-digest');
  requireSha256(expectedTrustStoreDigest, 'expected-trust-digest');

  const candidateDirectory = await requiredRealpath(candidateRoot, 'Candidate checkout');
  const sourceDirectory = await requiredRealpath(source, 'External bundle source');
  const [candidateStat, sourceStat] = await Promise.all([lstat(candidateDirectory), lstat(sourceDirectory)]);
  if (!candidateStat.isDirectory()) throw new Error('Candidate checkout must be a directory');
  if (!sourceStat.isDirectory()) throw new Error('External bundle source must be a directory');
  rejectOverlap(candidateDirectory, sourceDirectory, 'External bundle source must be outside the candidate checkout');
  const [protectedPolicy, protectedTrust] = await Promise.all([
    requiredRealpath(policyPath, 'Protected policy'),
    requiredRealpath(trustPath, 'Protected trust store'),
  ]);
  for (const [label, file] of [['policy', protectedPolicy], ['trust store', protectedTrust]]) {
    if (inside(candidateDirectory, file) || inside(sourceDirectory, file)) {
      throw new Error(`Protected ${label} must be outside the candidate and external bundle source`);
    }
  }

  const destinationInput = await resolveProspectivePath(destination);
  rejectOverlap(candidateDirectory, destinationInput, 'Materialized bundle must be outside the candidate checkout');
  rejectOverlap(sourceDirectory, destinationInput, 'Source and materialized bundle directories must not overlap');
  await mkdir(path.dirname(destinationInput), { recursive: true });
  const destinationParent = await realpath(path.dirname(destinationInput));
  const destinationDirectory = path.join(destinationParent, path.basename(destinationInput));
  rejectOverlap(candidateDirectory, destinationDirectory, 'Materialized bundle must be outside the candidate checkout');
  rejectOverlap(sourceDirectory, destinationDirectory, 'Source and materialized bundle directories must not overlap');
  try {
    await lstat(destinationDirectory);
    throw new Error(`Materialized bundle destination already exists: ${destinationDirectory}`);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }

  const [gitState, policy, trustStore, manifest, receipt, authorization] = await Promise.all([
    inspectGitState(candidateDirectory),
    readJson(protectedPolicy),
    readJson(protectedTrust),
    readJson(path.join(sourceDirectory, DOCUMENTS.manifest)),
    readJson(path.join(sourceDirectory, DOCUMENTS.receipt)),
    readJson(path.join(sourceDirectory, DOCUMENTS.authorization)),
  ]);
  requireValid('policy', validatePolicy(policy));
  requireValid('trust store', validateTrustStore(trustStore));
  requireValid('manifest', validateManifest(manifest));
  requireValid('verifier receipt', validateReceipt(receipt));
  requireValid('authorization', validateAuthorization(authorization));
  if (!receipt.signature) throw new Error('External bundle verifier receipt must be signed');
  if (!authorization.signature) throw new Error('External bundle authorization must be signed');

  const policyDigest = documentDigest(policy);
  const trustStoreDigest = documentDigest(trustStore);
  const manifestDigest = documentDigest(manifest);
  const receiptDigest = documentDigest(receipt);
  requireEqual(policyDigest, expectedPolicyDigest, 'Protected policy digest');
  requireEqual(trustStoreDigest, expectedTrustStoreDigest, 'Protected trust-store digest');
  requireEqual(gitState.candidateDigest, expectedCandidate, 'Checked-out candidate');
  if (!gitState.workingTreeClean) throw new Error('Candidate tracked worktree is not clean');
  requireEqual(manifest.candidate.digest, expectedCandidate, 'Manifest candidate');
  requireEqual(manifest.candidate.treeDigest, gitState.treeDigest, 'Manifest Git tree');
  requireEqual(manifest.candidate.repository, expectedRepository, 'Manifest repository');
  requireEqual(manifest.candidate.environment, expectedEnvironment, 'Manifest environment');
  requireEqual(receipt.subjectDigest, expectedCandidate, 'Receipt candidate');
  requireEqual(receipt.manifestDigest, manifestDigest, 'Receipt manifest digest');
  requireEqual(receipt.policyDigest, policyDigest, 'Receipt policy digest');
  requireEqual(receipt.trustStoreDigest, trustStoreDigest, 'Receipt trust-store digest');
  requireEqual(receipt.trustDomain, trustStore.trustDomain, 'Receipt trust domain');
  requireSameSet(receipt.evidenceDigests, manifest.evidence.map((item) => item.digest), 'Receipt evidence set');
  requireEqual(authorization.subjectDigest, expectedCandidate, 'Authorization candidate');
  requireEqual(authorization.manifestDigest, manifestDigest, 'Authorization manifest digest');
  requireEqual(authorization.receiptDigest, receiptDigest, 'Authorization receipt digest');
  requireEqual(authorization.policyDigest, policyDigest, 'Authorization policy digest');
  requireEqual(authorization.trustStoreDigest, trustStoreDigest, 'Authorization trust-store digest');
  requireEqual(authorization.trustDomain, trustStore.trustDomain, 'Authorization trust domain');
  requireEqual(authorization.scope.repository, expectedRepository, 'Authorization repository');
  requireEqual(authorization.scope.environment, expectedEnvironment, 'Authorization environment');
  requireEqual(authorization.scope.operation, 'release', 'Authorization operation');
  if (manifest.evidence.length > policy.maxEvidenceItems) {
    throw new Error('External bundle evidence count exceeds the receiver-owned limit');
  }

  const evidencePaths = new Set();
  for (const item of manifest.evidence) {
    if (RESERVED.has(item.path) || evidencePaths.has(item.path)) {
      throw new Error(`Evidence path is reserved or duplicated: ${item.path}`);
    }
    evidencePaths.add(item.path);
  }
  await requireExactSourceInventory(sourceDirectory, new Set([...Object.values(DOCUMENTS), ...evidencePaths]));

  const temporary = await mkdtemp(path.join(destinationParent, '.assurance-bundle-'));
  try {
    await Promise.all([
      writeJsonAtomic(path.join(temporary, DOCUMENTS.manifest), manifest),
      writeJsonAtomic(path.join(temporary, DOCUMENTS.receipt), receipt),
      writeJsonAtomic(path.join(temporary, DOCUMENTS.authorization), authorization),
    ]);
    let aggregateBytes = 0;
    for (const item of manifest.evidence) {
      const remaining = policy.maxTotalEvidenceBytes - aggregateBytes;
      if (remaining < 0) throw new Error('External bundle evidence exceeds the aggregate byte limit');
      const bytes = await readExternalEvidence(sourceDirectory, item.path, Math.min(policy.maxEvidenceBytes, remaining));
      if (digest(bytes) !== item.digest) throw new Error(`External bundle evidence digest mismatch: ${item.id}`);
      aggregateBytes += bytes.length;
      const output = path.join(temporary, item.path);
      await mkdir(path.dirname(output), { recursive: true });
      const handle = await open(output, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
      try {
        await handle.writeFile(bytes);
      } finally {
        await handle.close();
      }
    }
    await rename(temporary, destinationDirectory);
  } catch (error) {
    await rm(temporary, { recursive: true, force: true });
    throw error;
  }

  return {
    bundleRoot: destinationDirectory,
    evidenceRoot: destinationDirectory,
    manifest: path.join(destinationDirectory, DOCUMENTS.manifest),
    receipt: path.join(destinationDirectory, DOCUMENTS.receipt),
    authorization: path.join(destinationDirectory, DOCUMENTS.authorization),
  };
}

async function readExternalEvidence(root, relative, maxBytes) {
  const resolved = path.resolve(root, relative);
  if (!inside(root, resolved)) throw new Error(`External evidence escapes the bundle source: ${relative}`);
  const actual = await realpath(resolved);
  if (!inside(root, actual)) throw new Error(`External evidence resolves outside the bundle source: ${relative}`);
  const handle = await open(actual, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const before = await handle.stat();
    if (!before.isFile()) throw new Error(`External evidence is not a regular file: ${relative}`);
    if (before.size > maxBytes) throw new Error(`External evidence exceeds its receiver-owned byte limit: ${relative}`);
    const confirmed = await realpath(resolved);
    if (confirmed !== actual) throw new Error(`External evidence path changed during materialization: ${relative}`);
    const bytes = await readHandleBounded(handle, maxBytes);
    const after = await handle.stat();
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size
      || before.mtimeMs !== after.mtimeMs || bytes.length !== after.size) {
      throw new Error(`External evidence changed during materialization: ${relative}`);
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

async function requireExactSourceInventory(root, allowed) {
  const seen = new Set();
  const allowedDirectories = new Set();
  for (const file of allowed) {
    let directory = path.posix.dirname(file);
    while (directory !== '.') {
      allowedDirectories.add(directory);
      directory = path.posix.dirname(directory);
    }
  }
  await walk(root);
  for (const expected of allowed) {
    if (!seen.has(expected)) throw new Error(`External bundle file is missing: ${expected}`);
  }

  async function walk(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      const relative = path.relative(root, absolute).split(path.sep).join('/');
      if (entry.isSymbolicLink()) throw new Error(`External bundle symlinks are prohibited: ${relative}`);
      if (entry.isDirectory()) {
        if (!allowedDirectories.has(relative)) throw new Error(`External bundle contains an unexpected directory: ${relative}`);
        await walk(absolute);
        continue;
      }
      if (!entry.isFile()) throw new Error(`External bundle contains a non-regular file: ${relative}`);
      if (!allowed.has(relative)) throw new Error(`External bundle contains an unexpected file: ${relative}`);
      seen.add(relative);
    }
  }
}

async function inspectGitState(root) {
  const [{ stdout: head }, { stdout: tree }, { stdout: status }] = await Promise.all([
    execFileAsync('git', ['-C', root, 'rev-parse', '--verify', 'HEAD'], { encoding: 'utf8' }),
    execFileAsync('git', ['-C', root, 'rev-parse', '--verify', 'HEAD^{tree}'], { encoding: 'utf8' }),
    execFileAsync('git', ['-C', root, 'status', '--porcelain=v1', '--untracked-files=no'], { encoding: 'utf8' }),
  ]);
  return {
    candidateDigest: normalizeCandidate(head.trim()),
    treeDigest: normalizeTree(tree.trim()),
    workingTreeClean: status.trim().length === 0,
  };
}

function normalizeCandidate(value) {
  if (/^git:(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$/.test(value ?? '')) return value;
  if (/^[0-9a-f]{40}$/.test(value ?? '')) return `git:sha1:${value}`;
  if (/^[0-9a-f]{64}$/.test(value ?? '')) return `git:sha256:${value}`;
  throw new Error('candidate must be a lowercase 40/64-character Git digest');
}

function normalizeTree(value) {
  if (/^[0-9a-f]{40}$/.test(value)) return `git-tree:sha1:${value}`;
  if (/^[0-9a-f]{64}$/.test(value)) return `git-tree:sha256:${value}`;
  throw new Error('Git tree must be a lowercase 40/64-character digest');
}

function inside(root, candidate) {
  return candidate === root || candidate.startsWith(`${root}${path.sep}`);
}

function rejectOverlap(left, right, message) {
  if (inside(left, right) || inside(right, left)) throw new Error(message);
}

async function requiredRealpath(value, label) {
  try {
    return await realpath(path.resolve(value));
  } catch (error) {
    throw new Error(`${label} is unavailable: ${error.message}`);
  }
}

async function resolveProspectivePath(value) {
  let cursor = path.resolve(value);
  const missing = [];
  while (true) {
    try {
      await lstat(cursor);
      return path.join(await realpath(cursor), ...missing);
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      const parent = path.dirname(cursor);
      if (parent === cursor) throw error;
      missing.unshift(path.basename(cursor));
      cursor = parent;
    }
  }
}

function requireText(value, name) {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`${name} is required`);
}

function requireSha256(value, name) {
  if (!/^sha256:[0-9a-f]{64}$/.test(value ?? '')) throw new Error(`${name} must be canonical sha256:<64 hex>`);
}

function requireValid(label, errors) {
  if (errors.length) throw new Error(`${label} is invalid: ${errors.join(', ')}`);
}

function requireEqual(actual, expected, label) {
  if (actual !== expected) throw new Error(`${label} does not match the external receiver coordinate`);
}

function requireSameSet(actual, expected, label) {
  const left = [...actual].sort();
  const right = [...expected].sort();
  if (left.length !== right.length || left.some((value, index) => value !== right[index])) {
    throw new Error(`${label} does not match`);
  }
}

function digest(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

async function main(environment = process.env) {
  try {
    const result = await materializeExternalBundle({
      source: environment.ASSURANCE_BUNDLE_SOURCE,
      destination: environment.ASSURANCE_BUNDLE_DESTINATION,
      candidateRoot: environment.ASSURANCE_CANDIDATE_ROOT,
      candidate: environment.ASSURANCE_CANDIDATE,
      policyPath: environment.ASSURANCE_POLICY,
      trustPath: environment.ASSURANCE_TRUST,
      expectedPolicyDigest: environment.ASSURANCE_EXPECTED_POLICY,
      expectedTrustStoreDigest: environment.ASSURANCE_EXPECTED_TRUST,
      expectedRepository: environment.ASSURANCE_EXPECTED_REPOSITORY,
      expectedEnvironment: environment.ASSURANCE_EXPECTED_ENVIRONMENT,
    });
    if (environment.GITHUB_OUTPUT) {
      await appendGithubOutput(environment.GITHUB_OUTPUT, {
        bundle_root: result.bundleRoot,
        evidence_root: result.evidenceRoot,
        manifest: result.manifest,
        receipt: result.receipt,
        authorization: result.authorization,
      });
    }
    process.stdout.write(`External assurance bundle materialized at ${result.bundleRoot}\n`);
    return 0;
  } catch (error) {
    process.stderr.write(`Bundle materialization failed closed: ${error.message}\n`);
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
