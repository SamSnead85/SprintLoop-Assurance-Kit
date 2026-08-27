import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { sha256 } from './canonical.mjs';
import { readHandleBounded } from './bounded.mjs';

function finding(code, severity, message) {
  return { code, severity, message };
}

function inside(root, candidate) {
  return candidate === root || candidate.startsWith(`${root}${path.sep}`);
}

export async function inspectLiveEvidence(
  manifest,
  evidenceRoot,
  policy,
  embed,
  evidenceRootBinding,
  inspectionHooks = {},
) {
  const findings = [];
  const attachments = [];
  const binding = await bindEvidenceRoot(evidenceRoot, evidenceRootBinding);
  const root = binding.path;
  if (!Array.isArray(manifest?.evidence)) {
    await assertEvidenceRootStable(binding);
    return { attachments, findings, verificationLevel: 'FULL' };
  }
  if (!Number.isSafeInteger(policy?.maxEvidenceItems) || manifest.evidence.length > policy.maxEvidenceItems) {
    findings.push(finding('evidence.count_limit', 'BLOCK', 'Evidence item count exceeds the receiver policy limit'));
    await assertEvidenceRootStable(binding);
    return { attachments, findings, verificationLevel: 'FULL' };
  }
  let aggregateBytes = 0;

  for (const item of manifest.evidence) {
    await assertEvidenceRootStable(binding);
    const resolved = path.resolve(root, item.path);
    if (!inside(root, resolved)) {
      findings.push(finding('evidence.path_escape', 'BLOCK', `Evidence ${item.id} escapes the evidence root`));
      continue;
    }

    let leafBefore;
    try {
      leafBefore = await lstat(resolved);
    } catch (error) {
      if (error?.code === 'ENOENT') {
        findings.push(finding('evidence.missing', 'HOLD', `Evidence ${item.id} is missing`));
        continue;
      }
      throw error;
    }
    if (leafBefore.isSymbolicLink()) {
      const target = await realpath(resolved).catch(() => null);
      const code = target !== null && !inside(root, target) ? 'evidence.symlink_escape' : 'evidence.symlink_rejected';
      findings.push(finding(code, 'BLOCK', `Evidence ${item.id} is a symbolic link`));
      continue;
    }
    if (!leafBefore.isFile()) {
      findings.push(finding('evidence.not_file', 'BLOCK', `Evidence ${item.id} is not a regular file`));
      continue;
    }

    let actualPath;
    try {
      actualPath = await realpath(resolved);
    } catch {
      findings.push(finding('evidence.path_changed', 'BLOCK', `Evidence ${item.id} path changed during collection`));
      continue;
    }

    if (!inside(root, actualPath)) {
      findings.push(finding('evidence.symlink_escape', 'BLOCK', `Evidence ${item.id} resolves outside the evidence root`));
      continue;
    }

    let handle;
    let bytes;
    try {
      await inspectionHooks.beforeEvidenceFileOpen?.(Object.freeze({ evidenceId: item.id }));
      handle = await open(actualPath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
      await inspectionHooks.afterEvidenceFileOpen?.(Object.freeze({ evidenceId: item.id }));
      const before = await handle.stat();
      if (!before.isFile() || !sameIdentity(leafBefore, before)) {
        findings.push(finding('evidence.path_changed', 'BLOCK', `Evidence ${item.id} path changed during collection`));
        continue;
      }
      if (before.size > policy.maxEvidenceBytes) {
        findings.push(finding('evidence.too_large', 'HOLD', `Evidence ${item.id} exceeds the configured size limit`));
        continue;
      }
      if (aggregateBytes + before.size > policy.maxTotalEvidenceBytes) {
        findings.push(finding('evidence.aggregate_too_large', 'HOLD', 'Evidence set exceeds the receiver aggregate byte limit'));
        continue;
      }
      const confirmedLeaf = await inspectLeaf(resolved);
      if (!confirmedLeaf || confirmedLeaf.metadata.isSymbolicLink() || !confirmedLeaf.metadata.isFile()
        || !sameIdentity(confirmedLeaf.metadata, before)
        || confirmedLeaf.path !== actualPath || !inside(root, confirmedLeaf.path)) {
        findings.push(finding('evidence.path_changed', 'BLOCK', `Evidence ${item.id} path changed during collection`));
        continue;
      }
      await assertEvidenceRootStable(binding);
      try {
        bytes = await readHandleBounded(handle, Math.min(policy.maxEvidenceBytes, policy.maxTotalEvidenceBytes - aggregateBytes));
      } finally {
        await assertEvidenceRootStable(binding);
      }
      const after = await handle.stat();
      if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs || bytes.length !== after.size) {
        findings.push(finding('evidence.concurrent_mutation', 'BLOCK', `Evidence ${item.id} changed during collection`));
        continue;
      }
      const leafAfter = await inspectLeaf(resolved);
      if (!leafAfter || leafAfter.metadata.isSymbolicLink() || !leafAfter.metadata.isFile()
        || !sameIdentity(leafAfter.metadata, after)
        || leafAfter.path !== actualPath || !inside(root, leafAfter.path)) {
        findings.push(finding('evidence.path_changed', 'BLOCK', `Evidence ${item.id} path changed during collection`));
        continue;
      }
      aggregateBytes += bytes.length;
    } catch (error) {
      if (error?.code === 'ELOOP') {
        findings.push(finding('evidence.symlink_rejected', 'BLOCK', `Evidence ${item.id} is a symbolic link`));
        continue;
      }
      if (error?.code === 'ETOOLARGE') {
        findings.push(finding('evidence.concurrent_growth', 'BLOCK', `Evidence ${item.id} exceeded its bound during collection`));
        continue;
      }
      throw error;
    } finally {
      await handle?.close();
    }

    const digest = sha256(bytes);
    if (digest !== item.digest) {
      findings.push(finding('evidence.digest_mismatch', 'BLOCK', `Evidence ${item.id} does not match its bound digest`));
      if (embed) {
        attachments.push({
          id: item.id,
          path: item.path,
          mediaType: item.mediaType,
          digest: item.digest,
          encoding: 'base64',
          data: bytes.toString('base64'),
        });
      }
      continue;
    }

    if (embed) {
      attachments.push({
        id: item.id,
        path: item.path,
        mediaType: item.mediaType,
        digest,
        encoding: 'base64',
        data: bytes.toString('base64'),
      });
    }
  }

  await assertEvidenceRootStable(binding);
  return { attachments, findings, verificationLevel: 'FULL' };
}

async function bindEvidenceRoot(evidenceRoot, supplied) {
  if (supplied !== undefined) {
    if (supplied === null || typeof supplied !== 'object'
      || typeof supplied.path !== 'string' || !path.isAbsolute(supplied.path)
      || typeof supplied.requested !== 'string' || !path.isAbsolute(supplied.requested)
      || !Number.isSafeInteger(supplied.identity?.dev) || !Number.isSafeInteger(supplied.identity?.ino)) {
      throw staleEvidenceRoot();
    }
    const binding = Object.freeze({
      requested: supplied.requested,
      path: supplied.path,
      identity: Object.freeze({ dev: supplied.identity.dev, ino: supplied.identity.ino }),
    });
    await assertEvidenceRootStable(binding);
    return binding;
  }

  const resolved = await realpath(evidenceRoot);
  const metadata = await lstat(resolved);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw staleEvidenceRoot();
  const binding = Object.freeze({
    requested: resolved,
    path: resolved,
    identity: Object.freeze({ dev: metadata.dev, ino: metadata.ino }),
  });
  await assertEvidenceRootStable(binding);
  return binding;
}

async function assertEvidenceRootStable(binding) {
  let requestedMetadata;
  let canonicalMetadata;
  let resolved;
  try {
    requestedMetadata = await lstat(binding.requested);
    resolved = await realpath(binding.requested);
    canonicalMetadata = await lstat(binding.path);
  } catch {
    throw staleEvidenceRoot();
  }
  if (requestedMetadata.isSymbolicLink() || !requestedMetadata.isDirectory()
    || canonicalMetadata.isSymbolicLink() || !canonicalMetadata.isDirectory()
    || resolved !== binding.path
    || requestedMetadata.dev !== binding.identity.dev || requestedMetadata.ino !== binding.identity.ino
    || canonicalMetadata.dev !== binding.identity.dev || canonicalMetadata.ino !== binding.identity.ino) {
    throw staleEvidenceRoot();
  }
}

function staleEvidenceRoot() {
  const error = new Error('Evidence root changed during inspection');
  error.code = 'ESTALE';
  return error;
}

async function inspectLeaf(requested) {
  try {
    const metadata = await lstat(requested);
    const resolved = await realpath(requested);
    return { metadata, path: resolved };
  } catch {
    return null;
  }
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

export function inspectDossierEvidence(manifest, attachments, evidenceMode, policy) {
  const findings = [];
  if (!Array.isArray(manifest?.evidence) || !Number.isSafeInteger(policy?.maxEvidenceItems)
    || !Number.isSafeInteger(policy?.maxEvidenceBytes) || !Number.isSafeInteger(policy?.maxTotalEvidenceBytes)) {
    return {
      findings: [finding('dossier.evidence_contract_invalid', 'BLOCK', 'Dossier evidence limits or manifest are invalid')],
      verificationLevel: 'ENVELOPE_ONLY',
    };
  }
  if (evidenceMode === 'digest-only') {
    return { findings, verificationLevel: 'ENVELOPE_ONLY' };
  }

  if (manifest.evidence.length > policy.maxEvidenceItems || (attachments ?? []).length > policy.maxEvidenceItems) {
    findings.push(finding('evidence.count_limit', 'BLOCK', 'Evidence item count exceeds the receiver policy limit'));
    return { findings, verificationLevel: 'FULL' };
  }

  const byId = new Map();
  for (const attachment of attachments ?? []) {
    if (byId.has(attachment.id)) {
      findings.push(finding('dossier.duplicate_attachment', 'BLOCK', `Attachment ${attachment.id} is duplicated`));
    }
    byId.set(attachment.id, attachment);
  }

  const expectedIds = new Set(manifest.evidence.map((entry) => entry.id));
  for (const id of byId.keys()) {
    if (!expectedIds.has(id)) {
      findings.push(finding('dossier.unexpected_attachment', 'BLOCK', `Attachment ${id} is not in the manifest`));
    }
  }

  let aggregateBytes = 0;
  for (const item of manifest.evidence) {
    const attachment = byId.get(item.id);
    if (!attachment) {
      findings.push(finding('dossier.attachment_missing', 'BLOCK', `Embedded evidence ${item.id} is missing`));
      continue;
    }
    if (attachment.encoding !== 'base64' || attachment.digest !== item.digest || attachment.path !== item.path) {
      findings.push(finding('dossier.attachment_binding', 'BLOCK', `Embedded evidence ${item.id} metadata does not match`));
      continue;
    }
    try {
      if (typeof attachment.data !== 'string') throw new TypeError('attachment data must be base64 text');
      const estimatedBytes = Math.floor((attachment.data.length * 3) / 4);
      if (estimatedBytes > policy.maxEvidenceBytes) {
        findings.push(finding('evidence.too_large', 'BLOCK', `Embedded evidence ${item.id} exceeds the configured size limit`));
        continue;
      }
      if (aggregateBytes + estimatedBytes > policy.maxTotalEvidenceBytes) {
        findings.push(finding('evidence.aggregate_too_large', 'BLOCK', 'Embedded evidence set exceeds the receiver aggregate byte limit'));
        continue;
      }
      const bytes = Buffer.from(attachment.data, 'base64');
      aggregateBytes += bytes.length;
      if (bytes.length > policy.maxEvidenceBytes) {
        findings.push(finding('evidence.too_large', 'BLOCK', `Embedded evidence ${item.id} exceeds the configured size limit`));
      } else if (aggregateBytes > policy.maxTotalEvidenceBytes) {
        findings.push(finding('evidence.aggregate_too_large', 'BLOCK', 'Embedded evidence set exceeds the receiver aggregate byte limit'));
      } else if (bytes.toString('base64') !== attachment.data || sha256(bytes) !== item.digest) {
        findings.push(finding('evidence.digest_mismatch', 'BLOCK', `Evidence ${item.id} does not match its bound digest`));
      }
    } catch {
      findings.push(finding('dossier.attachment_encoding', 'BLOCK', `Embedded evidence ${item.id} is not valid base64`));
    }
  }

  return { findings, verificationLevel: 'FULL' };
}
