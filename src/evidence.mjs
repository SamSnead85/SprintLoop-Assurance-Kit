import { constants } from 'node:fs';
import { open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { sha256 } from './canonical.mjs';
import { readHandleBounded } from './bounded.mjs';

function finding(code, severity, message) {
  return { code, severity, message };
}

function inside(root, candidate) {
  return candidate === root || candidate.startsWith(`${root}${path.sep}`);
}

export async function inspectLiveEvidence(manifest, evidenceRoot, policy, embed) {
  const findings = [];
  const attachments = [];
  const root = await realpath(evidenceRoot);
  if (!Array.isArray(manifest?.evidence)) {
    return { attachments, findings, verificationLevel: 'FULL' };
  }
  if (!Number.isSafeInteger(policy?.maxEvidenceItems) || manifest.evidence.length > policy.maxEvidenceItems) {
    findings.push(finding('evidence.count_limit', 'BLOCK', 'Evidence item count exceeds the receiver policy limit'));
    return { attachments, findings, verificationLevel: 'FULL' };
  }
  let aggregateBytes = 0;

  for (const item of manifest.evidence) {
    const resolved = path.resolve(root, item.path);
    if (!inside(root, resolved)) {
      findings.push(finding('evidence.path_escape', 'BLOCK', `Evidence ${item.id} escapes the evidence root`));
      continue;
    }

    let actualPath;
    try {
      actualPath = await realpath(resolved);
    } catch (error) {
      if (error?.code === 'ENOENT') {
        findings.push(finding('evidence.missing', 'HOLD', `Evidence ${item.id} is missing`));
        continue;
      }
      throw error;
    }

    if (!inside(root, actualPath)) {
      findings.push(finding('evidence.symlink_escape', 'BLOCK', `Evidence ${item.id} resolves outside the evidence root`));
      continue;
    }

    let handle;
    let bytes;
    try {
      handle = await open(actualPath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
      const before = await handle.stat();
      if (!before.isFile()) {
        findings.push(finding('evidence.not_file', 'BLOCK', `Evidence ${item.id} is not a regular file`));
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
      const confirmedPath = await realpath(resolved);
      if (confirmedPath !== actualPath || !inside(root, confirmedPath)) {
        findings.push(finding('evidence.path_changed', 'BLOCK', `Evidence ${item.id} path changed during collection`));
        continue;
      }
      bytes = await readHandleBounded(handle, Math.min(policy.maxEvidenceBytes, policy.maxTotalEvidenceBytes - aggregateBytes));
      const after = await handle.stat();
      if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs || bytes.length !== after.size) {
        findings.push(finding('evidence.concurrent_mutation', 'BLOCK', `Evidence ${item.id} changed during collection`));
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

  return { attachments, findings, verificationLevel: 'FULL' };
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
