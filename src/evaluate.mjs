import { documentDigest } from './canonical.mjs';
import { verifyDocumentSignature } from './crypto.mjs';
import {
  validateAuthorization,
  validateManifest,
  validatePolicy,
  validateReceiverContext,
  validateReceipt,
  validateTrustStore,
} from './validate.mjs';

function reason(code, severity, message) {
  return { code, severity, message };
}

function addValidationReasons(reasons, label, errors) {
  for (const field of errors) {
    reasons.push(reason(`${label}.invalid`, 'BLOCK', `${label} is invalid at ${field}`));
  }
}

function milliseconds(iso) {
  return Date.parse(iso);
}

function sorted(values) {
  return [...values].sort();
}

function sameSet(left, right) {
  return left.length === right.length && sorted(left).every((entry, index) => entry === sorted(right)[index]);
}

function checkTemporalStanding(reasons, label, document, maximumSeconds, at, skewSeconds) {
  const issued = milliseconds(document.issuedAt);
  const expires = milliseconds(document.expiresAt);
  const now = milliseconds(at);
  if (expires <= issued) {
    reasons.push(reason(`${label}.invalid_window`, 'BLOCK', `${label} expiry must follow issuance`));
  }
  if ((expires - issued) / 1000 > maximumSeconds) {
    reasons.push(reason(`${label}.window_too_long`, 'BLOCK', `${label} exceeds the maximum validity window`));
  }
  if (issued > now + (skewSeconds * 1000)) {
    reasons.push(reason(`${label}.not_yet_valid`, 'HOLD', `${label} was issued in the future`));
  }
  if (expires <= now) {
    reasons.push(reason(`${label}.expired`, 'HOLD', `${label} has expired`));
  }
}

function checkSeparation(reasons, edge, rule, left, right) {
  if (rule === 'none') return;
  if (left.principalId === right.principalId) {
    reasons.push(reason(`separation.${edge}`, 'BLOCK', `${edge} principals are not independent`));
    return;
  }
  if (rule === 'owner' && left.ownerId === right.ownerId) {
    reasons.push(reason(`separation.${edge}`, 'BLOCK', `${edge} owners are not independent`));
  }
  if (rule === 'control-domain' && left.controlDomain === right.controlDomain) {
    reasons.push(reason(`separation.${edge}`, 'BLOCK', `${edge} control domains are not independent`));
  }
}

function findSigningKey(reasons, label, document, signer, role, trustStore, at) {
  if (!document.signature) return null;
  const key = trustStore.keys.find((entry) => entry.keyId === document.signature.keyId);
  if (!key) {
    reasons.push(reason(`${label}.untrusted_key`, 'BLOCK', `${label} uses a key outside the receiver-owned trust store`));
    return null;
  }
  if (!key.roles.includes(role)) reasons.push(reason(`${label}.wrong_key_role`, 'BLOCK', `${label} key is not trusted for ${role}`));
  if (key.principalId !== signer.principalId || key.ownerId !== signer.ownerId || key.controlDomain !== signer.controlDomain) {
    reasons.push(reason(`${label}.signer_mismatch`, 'BLOCK', `${label} signer does not match the trusted key owner`));
  }

  const issued = milliseconds(document.issuedAt);
  const now = milliseconds(at);
  if (key.validFrom && issued < milliseconds(key.validFrom)) reasons.push(reason(`${label}.key_not_yet_valid`, 'BLOCK', `${label} was signed before key validity`));
  if (key.validUntil && issued >= milliseconds(key.validUntil)) reasons.push(reason(`${label}.key_expired_at_signing`, 'BLOCK', `${label} was signed after key expiry`));
  if (key.revokedAt && issued >= milliseconds(key.revokedAt)) reasons.push(reason(`${label}.key_revoked_at_signing`, 'BLOCK', `${label} was signed after key revocation`));
  if (key.validFrom && now < milliseconds(key.validFrom)) reasons.push(reason(`${label}.key_not_current`, 'HOLD', `${label} key is not currently valid`));
  if (key.validUntil && now >= milliseconds(key.validUntil)) reasons.push(reason(`${label}.key_not_current`, 'HOLD', `${label} key is no longer current`));
  if (key.revokedAt && now >= milliseconds(key.revokedAt)) reasons.push(reason(`${label}.key_revoked`, 'BLOCK', `${label} key has been revoked`));

  if (!verifyDocumentSignature(document, key.publicKeyPem)) {
    reasons.push(reason(`${label}.invalid_signature`, 'BLOCK', `${label} signature is invalid`));
  }
  return key;
}

function conclusionFor(reasons) {
  if (reasons.some((entry) => entry.severity === 'BLOCK')) return 'BLOCK';
  if (reasons.some((entry) => entry.severity === 'HOLD')) return 'HOLD';
  return 'PASS';
}

export function evaluateAssurance({
  manifest,
  receipt,
  authorization,
  policy,
  trustStore,
  at = new Date().toISOString(),
  candidate,
  evidenceFindings = [],
  verificationLevel = 'ENVELOPE_ONLY',
  receiverContext,
}) {
  const reasons = [...evidenceFindings];
  if (!candidate) {
    reasons.push(reason('candidate.runtime_missing', 'BLOCK', 'An externally supplied runtime candidate is required'));
  }
  const policyErrors = validatePolicy(policy);
  const trustErrors = validateTrustStore(trustStore);
  const manifestErrors = validateManifest(manifest);
  const receiverErrors = validateReceiverContext(receiverContext);
  addValidationReasons(reasons, 'policy', policyErrors);
  addValidationReasons(reasons, 'trust', trustErrors);
  addValidationReasons(reasons, 'manifest', manifestErrors);
  addValidationReasons(reasons, 'receiver', receiverErrors);

  if (policyErrors.length || trustErrors.length || manifestErrors.length || receiverErrors.length) {
    return finalize(reasons, at, manifest?.candidate?.digest, verificationLevel);
  }

  if (!Number.isFinite(Date.parse(at))) {
    reasons.push(reason('evaluation.invalid_time', 'BLOCK', 'Evaluation time is invalid'));
    return finalize(reasons, at, manifest.candidate.digest, verificationLevel);
  }

  if (candidate && candidate !== manifest.candidate.digest) {
    reasons.push(reason('candidate.runtime_mismatch', 'BLOCK', 'Runtime candidate does not match the manifest candidate'));
  }

  const policyDigest = documentDigest(policy);
  const trustStoreDigest = documentDigest(trustStore);
  if (receiverContext.expectedPolicyDigest !== policyDigest) {
    reasons.push(reason('receiver.policy_digest_mismatch', 'BLOCK', 'Loaded policy does not match the receiver-owned expected digest'));
  }
  if (receiverContext.expectedTrustStoreDigest !== trustStoreDigest) {
    reasons.push(reason('receiver.trust_digest_mismatch', 'BLOCK', 'Loaded trust store does not match the receiver-owned expected digest'));
  }
  if (receiverContext.expectedRepository !== manifest.candidate.repository) {
    reasons.push(reason('receiver.repository_mismatch', 'BLOCK', 'Candidate repository does not match the receiver-owned repository'));
  }
  if (receiverContext.expectedEnvironment !== manifest.candidate.environment) {
    reasons.push(reason('receiver.environment_mismatch', 'BLOCK', 'Candidate environment does not match the receiver-owned environment'));
  }
  if (receiverContext.actualCandidateDigest !== manifest.candidate.digest) {
    reasons.push(reason('candidate.head_mismatch', 'BLOCK', 'Checked-out Git HEAD does not match the manifest candidate'));
  }
  if (receiverContext.actualTreeDigest !== manifest.candidate.treeDigest) {
    reasons.push(reason('candidate.tree_mismatch', 'BLOCK', 'Checked-out Git tree does not match the manifest tree'));
  }
  if (!receiverContext.workingTreeClean) {
    reasons.push(reason('candidate.tracked_tree_dirty', 'BLOCK', 'Tracked candidate files differ from the checked-out Git tree'));
  }

  const evidenceTypes = new Set(manifest.evidence.map((entry) => entry.type));
  for (const type of policy.requiredEvidenceTypes) {
    if (!evidenceTypes.has(type)) reasons.push(reason('evidence.required_missing', 'HOLD', `Required evidence type ${type} is missing`));
  }

  const manifestDigest = documentDigest(manifest);
  let receiptDigest;

  if (!receipt) {
    reasons.push(reason('receipt.missing', 'HOLD', 'Independent verifier receipt is missing'));
  } else {
    const receiptErrors = validateReceipt(receipt);
    addValidationReasons(reasons, 'receipt', receiptErrors);
    if (receiptErrors.length === 0) {
      if (receipt.subjectDigest !== manifest.candidate.digest) reasons.push(reason('receipt.subject_mismatch', 'BLOCK', 'Verifier receipt is bound to a different candidate'));
      if (receipt.manifestDigest !== manifestDigest) reasons.push(reason('receipt.manifest_mismatch', 'BLOCK', 'Verifier receipt is bound to a different manifest'));
      if (receipt.policyDigest !== policyDigest) reasons.push(reason('receipt.policy_mismatch', 'BLOCK', 'Verifier receipt is bound to a different policy'));
      if (receipt.trustStoreDigest !== trustStoreDigest || receipt.trustDomain !== trustStore.trustDomain) reasons.push(reason('receipt.trust_mismatch', 'BLOCK', 'Verifier receipt is bound to a different receiver trust boundary'));
      if (!sameSet(receipt.evidenceDigests, manifest.evidence.map((entry) => entry.digest))) {
        reasons.push(reason('receipt.evidence_set_mismatch', 'BLOCK', 'Verifier receipt does not bind the complete evidence set'));
      }
      if (!policy.allowedVerifierMethods.includes(receipt.verifier.method)) {
        reasons.push(reason('receipt.method_not_allowed', 'BLOCK', 'Verifier method is not allowed by policy'));
      }
      if (policy.requireSignedReceipt && !receipt.signature) reasons.push(reason('receipt.signature_missing', 'HOLD', 'Signed verifier receipt is required'));
      if (receipt.signature) findSigningKey(reasons, 'receipt', receipt, receipt.verifier, 'verifier', trustStore, at);
      checkTemporalStanding(reasons, 'receipt', receipt, policy.maxReceiptValiditySeconds, at, policy.maxClockSkewSeconds);
      if (receipt.verdict === 'HOLD') reasons.push(reason('receipt.indeterminate', 'HOLD', 'Independent verifier returned HOLD'));
      if (receipt.verdict === 'BLOCK') reasons.push(reason('receipt.negative', 'BLOCK', 'Independent verifier returned BLOCK'));
      receiptDigest = documentDigest(receipt);
      checkSeparation(reasons, 'producer_verifier', policy.separation.producerVerifier, manifest.candidate.producer, receipt.verifier);
    }
  }

  if (!authorization) {
    reasons.push(reason('authorization.missing', 'HOLD', 'Finite named authorization is missing'));
  } else {
    const authorizationErrors = validateAuthorization(authorization);
    addValidationReasons(reasons, 'authorization', authorizationErrors);
    if (authorizationErrors.length === 0) {
      if (authorization.subjectDigest !== manifest.candidate.digest) reasons.push(reason('authorization.subject_mismatch', 'BLOCK', 'Authorization is bound to a different candidate'));
      if (authorization.manifestDigest !== manifestDigest) reasons.push(reason('authorization.manifest_mismatch', 'BLOCK', 'Authorization is bound to a different manifest'));
      if (authorization.policyDigest !== policyDigest) reasons.push(reason('authorization.policy_mismatch', 'BLOCK', 'Authorization is bound to a different policy'));
      if (authorization.trustStoreDigest !== trustStoreDigest || authorization.trustDomain !== trustStore.trustDomain) reasons.push(reason('authorization.trust_mismatch', 'BLOCK', 'Authorization is bound to a different receiver trust boundary'));
      if (!receiptDigest) reasons.push(reason('authorization.receipt_unavailable', 'HOLD', 'Authorization cannot be evaluated until the verifier receipt is available'));
      else if (authorization.receiptDigest !== receiptDigest) reasons.push(reason('authorization.receipt_mismatch', 'BLOCK', 'Authorization is bound to a different verifier receipt'));
      if (authorization.scope.environment !== manifest.candidate.environment) reasons.push(reason('authorization.scope_mismatch', 'BLOCK', 'Authorization environment does not match the candidate'));
      if (authorization.scope.repository !== manifest.candidate.repository) reasons.push(reason('authorization.repository_scope_mismatch', 'BLOCK', 'Authorization repository does not match the candidate'));
      if (policy.requireNamedHumanAuthority && authorization.authority.kind !== 'human') reasons.push(reason('authorization.human_required', 'BLOCK', 'Policy requires a named human authority'));
      if (policy.requireSignedAuthorization && !authorization.signature) reasons.push(reason('authorization.signature_missing', 'HOLD', 'Signed authorization is required'));
      if (authorization.signature) findSigningKey(reasons, 'authorization', authorization, authorization.authority, 'authority', trustStore, at);
      checkTemporalStanding(reasons, 'authorization', authorization, policy.maxAuthorizationValiditySeconds, at, policy.maxClockSkewSeconds);
      if (receipt && milliseconds(authorization.issuedAt) + (policy.maxClockSkewSeconds * 1000) < milliseconds(receipt.issuedAt)) {
        reasons.push(reason('authorization.precedes_receipt', 'BLOCK', 'Authorization predates the verifier receipt beyond allowed clock skew'));
      }
      if (authorization.decision === 'DENY') reasons.push(reason('authorization.denied', 'BLOCK', 'Named authority denied release'));
      if (receipt?.verifier) checkSeparation(reasons, 'verifier_authority', policy.separation.verifierAuthority, receipt.verifier, authorization.authority);
      checkSeparation(reasons, 'producer_authority', policy.separation.producerAuthority, manifest.candidate.producer, authorization.authority);
    }
  }

  return finalize(reasons, at, manifest.candidate.digest, verificationLevel);
}

function finalize(reasons, evaluatedAt, subjectDigest, verificationLevel) {
  const unique = [...new Map(reasons.map((entry) => [`${entry.code}:${entry.message}`, entry])).values()]
    .sort((left, right) => left.code.localeCompare(right.code) || left.message.localeCompare(right.message));
  const conclusion = conclusionFor(unique);
  const summary = conclusion === 'PASS'
    ? 'Exact candidate, evidence, independent verification, and finite authority are valid.'
    : conclusion === 'HOLD'
      ? 'Release is not currently eligible; one or more required preconditions are incomplete or stale.'
      : 'Release is blocked by a negative decision, integrity failure, or trust-boundary violation.';
  return { conclusion, subjectDigest, evaluatedAt, verificationLevel, summary, reasons: unique };
}
