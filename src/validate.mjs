import { isPortableRelativePath, portablePathAliasKey } from './portable-path.mjs';

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const SUBJECT = /^git:(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$/;
const TREE = /^git-tree:(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u;
const URI = /^[A-Za-z][A-Za-z0-9+.-]{0,31}:[^\s\u0000-\u001f\u007f-\u009f\u2028\u2029]{1,2015}$/u;
const MEDIA_TYPE = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,127}\/[A-Za-z0-9!#$%&'*+.^_`|~-]{1,127}$/;
const PUBLIC_KEY_PEM = /^-----BEGIN PUBLIC KEY-----\r?\n(?:[A-Za-z0-9+/=]{1,64}\r?\n)+-----END PUBLIC KEY-----\r?\n?$/;

function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function text(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function id(value) {
  return typeof value === 'string' && ID.test(value);
}

function repository(value) {
  return typeof value === 'string' && value.length <= 2048 && URI.test(value);
}

function relativePath(value) {
  return isPortableRelativePath(value);
}

function mediaType(value) {
  return typeof value === 'string' && value.length <= 255 && MEDIA_TYPE.test(value);
}

function iso(value) {
  return typeof value === 'string' && ISO_UTC.test(value) && Number.isFinite(Date.parse(value));
}

function unique(values) {
  return new Set(values).size === values.length;
}

function exactKeys(value, allowed, path, errors) {
  if (!object(value)) return;
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) errors.push(`${path}: unexpected property`);
  }
}

function signature(value, errors, path) {
  exactKeys(value, ['algorithm', 'keyId', 'value'], path, errors);
  return object(value)
    && value.algorithm === 'Ed25519'
    && id(value.keyId)
    && typeof value.value === 'string'
    && /^[A-Za-z0-9+/]{86}==$/.test(value.value);
}

export function validateManifest(value) {
  const errors = [];
  if (!object(value)) return ['manifest must be an object'];
  exactKeys(value, ['schemaVersion', 'changeId', 'candidate', 'intent', 'evidence'], 'manifest', errors);
  if (value.schemaVersion !== 'assurance.sprintloop.dev/manifest/v1') errors.push('schemaVersion');
  if (!id(value.changeId)) errors.push('changeId');
  if (!object(value.candidate)) errors.push('candidate');
  else {
    exactKeys(value.candidate, ['repository', 'digest', 'treeDigest', 'environment', 'producer'], 'candidate', errors);
    if (!repository(value.candidate.repository)) errors.push('candidate.repository');
    if (!SUBJECT.test(value.candidate.digest ?? '')) errors.push('candidate.digest');
    if (!TREE.test(value.candidate.treeDigest ?? '')) errors.push('candidate.treeDigest');
    if (!id(value.candidate.environment)) errors.push('candidate.environment');
    if (!object(value.candidate.producer)) errors.push('candidate.producer');
    else {
      exactKeys(value.candidate.producer, ['principalId', 'ownerId', 'controlDomain'], 'candidate.producer', errors);
      if (!id(value.candidate.producer.principalId)) errors.push('candidate.producer.principalId');
      if (!id(value.candidate.producer.ownerId)) errors.push('candidate.producer.ownerId');
      if (!id(value.candidate.producer.controlDomain)) errors.push('candidate.producer.controlDomain');
    }
  }
  if (!object(value.intent) || !id(value.intent.id) || !SHA256.test(value.intent.digest ?? '')) errors.push('intent');
  else exactKeys(value.intent, ['id', 'digest'], 'intent', errors);
  if (!Array.isArray(value.evidence) || value.evidence.length === 0) errors.push('evidence');
  else {
    const ids = [];
    const paths = [];
    for (const [index, item] of value.evidence.entries()) {
      if (!object(item)) {
        errors.push(`evidence[${index}]`);
        continue;
      }
      exactKeys(item, ['id', 'type', 'path', 'mediaType', 'digest', 'subjectDigest'], `evidence[${index}]`, errors);
      ids.push(item.id);
      paths.push(item.path);
      if (!id(item.id)) errors.push(`evidence[${index}].id`);
      if (!id(item.type)) errors.push(`evidence[${index}].type`);
      if (!relativePath(item.path)) errors.push(`evidence[${index}].path`);
      if (!SHA256.test(item.digest ?? '')) errors.push(`evidence[${index}].digest`);
      if (item.subjectDigest !== value.candidate?.digest) errors.push(`evidence[${index}].subjectDigest`);
      if (!mediaType(item.mediaType)) errors.push(`evidence[${index}].mediaType`);
    }
    if (!unique(ids)) errors.push('evidence ids must be unique');
    if (!unique(paths) || !unique(paths.filter((entry) => relativePath(entry)).map((entry) => portablePathAliasKey(entry)))) {
      errors.push('evidence paths must be portable-alias unique');
    }
  }
  return errors;
}

export function validateReceipt(value) {
  const errors = [];
  if (!object(value)) return ['receipt must be an object'];
  exactKeys(value, ['schemaVersion', 'receiptId', 'subjectDigest', 'manifestDigest', 'policyDigest', 'trustStoreDigest', 'trustDomain', 'evidenceDigests', 'verdict', 'verifier', 'issuedAt', 'expiresAt', 'signature'], 'receipt', errors);
  if (value.schemaVersion !== 'assurance.sprintloop.dev/verifier-receipt/v1') errors.push('schemaVersion');
  if (!id(value.receiptId)) errors.push('receiptId');
  if (!SUBJECT.test(value.subjectDigest ?? '')) errors.push('subjectDigest');
  if (!SHA256.test(value.manifestDigest ?? '')) errors.push('manifestDigest');
  if (!SHA256.test(value.policyDigest ?? '')) errors.push('policyDigest');
  if (!SHA256.test(value.trustStoreDigest ?? '')) errors.push('trustStoreDigest');
  if (!id(value.trustDomain)) errors.push('trustDomain');
  if (!['PASS', 'HOLD', 'BLOCK'].includes(value.verdict)) errors.push('verdict');
  if (!Array.isArray(value.evidenceDigests) || !value.evidenceDigests.every((entry) => SHA256.test(entry)) || !unique(value.evidenceDigests)) {
    errors.push('evidenceDigests');
  }
  if (!object(value.verifier)) errors.push('verifier');
  else {
    exactKeys(value.verifier, ['principalId', 'ownerId', 'controlDomain', 'engine', 'method', 'model'], 'verifier', errors);
    if (!id(value.verifier.principalId)) errors.push('verifier.principalId');
    if (!id(value.verifier.ownerId)) errors.push('verifier.ownerId');
    if (!id(value.verifier.controlDomain)) errors.push('verifier.controlDomain');
    if (!text(value.verifier.engine)) errors.push('verifier.engine');
    if (!['deterministic', 'hybrid'].includes(value.verifier.method)) errors.push('verifier.method');
    if (value.verifier.model !== undefined && !text(value.verifier.model)) errors.push('verifier.model');
  }
  if (!iso(value.issuedAt)) errors.push('issuedAt');
  if (!iso(value.expiresAt)) errors.push('expiresAt');
  if (value.signature !== undefined && !signature(value.signature, errors, 'signature')) errors.push('signature');
  return errors;
}

export function validateAuthorization(value) {
  const errors = [];
  if (!object(value)) return ['authorization must be an object'];
  exactKeys(value, ['schemaVersion', 'authorizationId', 'subjectDigest', 'manifestDigest', 'receiptDigest', 'policyDigest', 'trustStoreDigest', 'trustDomain', 'decision', 'authority', 'scope', 'issuedAt', 'expiresAt', 'signature'], 'authorization', errors);
  if (value.schemaVersion !== 'assurance.sprintloop.dev/authorization/v1') errors.push('schemaVersion');
  if (!id(value.authorizationId)) errors.push('authorizationId');
  if (!SUBJECT.test(value.subjectDigest ?? '')) errors.push('subjectDigest');
  if (!SHA256.test(value.manifestDigest ?? '')) errors.push('manifestDigest');
  if (!SHA256.test(value.receiptDigest ?? '')) errors.push('receiptDigest');
  if (!SHA256.test(value.policyDigest ?? '')) errors.push('policyDigest');
  if (!SHA256.test(value.trustStoreDigest ?? '')) errors.push('trustStoreDigest');
  if (!id(value.trustDomain)) errors.push('trustDomain');
  if (!['ALLOW', 'DENY'].includes(value.decision)) errors.push('decision');
  if (!object(value.authority)) errors.push('authority');
  else {
    exactKeys(value.authority, ['principalId', 'ownerId', 'controlDomain', 'role', 'kind'], 'authority', errors);
    if (!id(value.authority.principalId)) errors.push('authority.principalId');
    if (!id(value.authority.ownerId)) errors.push('authority.ownerId');
    if (!id(value.authority.controlDomain)) errors.push('authority.controlDomain');
    if (!text(value.authority.role)) errors.push('authority.role');
    if (!['human', 'service'].includes(value.authority.kind)) errors.push('authority.kind');
  }
  if (!object(value.scope) || !repository(value.scope.repository) || !id(value.scope.environment) || value.scope.operation !== 'release') errors.push('scope');
  else exactKeys(value.scope, ['repository', 'environment', 'operation'], 'scope', errors);
  if (!iso(value.issuedAt)) errors.push('issuedAt');
  if (!iso(value.expiresAt)) errors.push('expiresAt');
  if (value.signature !== undefined && !signature(value.signature, errors, 'signature')) errors.push('signature');
  return errors;
}

export function validatePolicy(value) {
  const errors = [];
  if (!object(value)) return ['policy must be an object'];
  exactKeys(value, ['schemaVersion', 'policyId', 'requiredEvidenceTypes', 'allowedVerifierMethods', 'separation', 'requireNamedHumanAuthority', 'requireSignedReceipt', 'requireSignedAuthorization', 'maxReceiptValiditySeconds', 'maxAuthorizationValiditySeconds', 'maxClockSkewSeconds', 'maxEvidenceBytes', 'maxEvidenceItems', 'maxTotalEvidenceBytes'], 'policy', errors);
  if (value.schemaVersion !== 'assurance.sprintloop.dev/policy/v1') errors.push('schemaVersion');
  if (!id(value.policyId)) errors.push('policyId');
  if (!Array.isArray(value.requiredEvidenceTypes) || !value.requiredEvidenceTypes.every(id) || !unique(value.requiredEvidenceTypes)) {
    errors.push('requiredEvidenceTypes');
  }
  if (!Array.isArray(value.allowedVerifierMethods) || value.allowedVerifierMethods.length === 0
    || !value.allowedVerifierMethods.every((entry) => ['deterministic', 'hybrid'].includes(entry))) {
    errors.push('allowedVerifierMethods');
  }
  if (!object(value.separation)) errors.push('separation');
  else {
    exactKeys(value.separation, ['producerVerifier', 'verifierAuthority', 'producerAuthority'], 'separation', errors);
    for (const edge of ['producerVerifier', 'verifierAuthority', 'producerAuthority']) {
      if (!['none', 'principal', 'owner', 'control-domain'].includes(value.separation[edge])) errors.push(`separation.${edge}`);
    }
  }
  if (value.requireNamedHumanAuthority !== true && value.requireNamedHumanAuthority !== false) errors.push('requireNamedHumanAuthority');
  if (value.requireSignedReceipt !== true && value.requireSignedReceipt !== false) errors.push('requireSignedReceipt');
  if (value.requireSignedAuthorization !== true && value.requireSignedAuthorization !== false) errors.push('requireSignedAuthorization');
  if (!Number.isSafeInteger(value.maxReceiptValiditySeconds) || value.maxReceiptValiditySeconds < 60) errors.push('maxReceiptValiditySeconds');
  if (!Number.isSafeInteger(value.maxAuthorizationValiditySeconds) || value.maxAuthorizationValiditySeconds < 60) errors.push('maxAuthorizationValiditySeconds');
  if (!Number.isSafeInteger(value.maxClockSkewSeconds) || value.maxClockSkewSeconds < 0) errors.push('maxClockSkewSeconds');
  if (!Number.isSafeInteger(value.maxEvidenceBytes) || value.maxEvidenceBytes < 1) errors.push('maxEvidenceBytes');
  if (!Number.isSafeInteger(value.maxEvidenceItems) || value.maxEvidenceItems < 1) errors.push('maxEvidenceItems');
  if (!Number.isSafeInteger(value.maxTotalEvidenceBytes) || value.maxTotalEvidenceBytes < value.maxEvidenceBytes) errors.push('maxTotalEvidenceBytes');
  return errors;
}

export function validateTrustStore(value) {
  const errors = [];
  if (!object(value)) return ['trust store must be an object'];
  exactKeys(value, ['schemaVersion', 'trustDomain', 'keys'], 'trust', errors);
  if (value.schemaVersion !== 'assurance.sprintloop.dev/trust-store/v1') errors.push('schemaVersion');
  if (!id(value.trustDomain)) errors.push('trustDomain');
  if (!Array.isArray(value.keys) || value.keys.length === 0) errors.push('keys');
  else {
    const ids = [];
    for (const [index, key] of value.keys.entries()) {
      if (!object(key)) {
        errors.push(`keys[${index}]`);
        continue;
      }
      exactKeys(key, ['keyId', 'principalId', 'ownerId', 'controlDomain', 'roles', 'publicKeyPem', 'validFrom', 'validUntil', 'revokedAt'], `keys[${index}]`, errors);
      ids.push(key.keyId);
      if (!id(key.keyId)) errors.push(`keys[${index}].keyId`);
      if (!id(key.principalId)) errors.push(`keys[${index}].principalId`);
      if (!id(key.ownerId)) errors.push(`keys[${index}].ownerId`);
      if (!id(key.controlDomain)) errors.push(`keys[${index}].controlDomain`);
      if (!Array.isArray(key.roles) || !key.roles.every((role) => ['verifier', 'authority'].includes(role)) || !unique(key.roles)) errors.push(`keys[${index}].roles`);
      if (typeof key.publicKeyPem !== 'string' || key.publicKeyPem.length > 4096 || !PUBLIC_KEY_PEM.test(key.publicKeyPem)) {
        errors.push(`keys[${index}].publicKeyPem`);
      }
      if (key.validFrom !== undefined && !iso(key.validFrom)) errors.push(`keys[${index}].validFrom`);
      if (key.validUntil !== undefined && !iso(key.validUntil)) errors.push(`keys[${index}].validUntil`);
      if (key.revokedAt !== undefined && !iso(key.revokedAt)) errors.push(`keys[${index}].revokedAt`);
    }
    if (!unique(ids)) errors.push('key ids must be unique');
  }
  return errors;
}

export function validateReceiverContext(value) {
  const errors = [];
  if (!object(value)) return ['receiver context must be an object'];
  exactKeys(value, ['expectedPolicyDigest', 'expectedTrustStoreDigest', 'expectedRepository', 'expectedEnvironment', 'actualCandidateDigest', 'actualTreeDigest', 'workingTreeClean'], 'receiver', errors);
  if (!SHA256.test(value.expectedPolicyDigest ?? '')) errors.push('expectedPolicyDigest');
  if (!SHA256.test(value.expectedTrustStoreDigest ?? '')) errors.push('expectedTrustStoreDigest');
  if (!repository(value.expectedRepository)) errors.push('expectedRepository');
  if (!id(value.expectedEnvironment)) errors.push('expectedEnvironment');
  if (!SUBJECT.test(value.actualCandidateDigest ?? '')) errors.push('actualCandidateDigest');
  if (!TREE.test(value.actualTreeDigest ?? '')) errors.push('actualTreeDigest');
  if (typeof value.workingTreeClean !== 'boolean') errors.push('workingTreeClean');
  return errors;
}

export function validateDossier(value) {
  const errors = [];
  if (!object(value)) return ['dossier must be an object'];
  exactKeys(value, ['schemaVersion', 'createdAt', 'anchoring', 'evidenceMode', 'receiverContext', 'inputs', 'inputDigests', 'attachments', 'decision', 'dossierDigest'], 'dossier', errors);
  if (value.schemaVersion !== 'assurance.sprintloop.dev/dossier/v1') errors.push('schemaVersion');
  if (!iso(value.createdAt)) errors.push('createdAt');
  if (!object(value.anchoring)) errors.push('anchoring');
  else {
    exactKeys(value.anchoring, ['status', 'statement'], 'anchoring', errors);
    if (value.anchoring.status !== 'UNANCHORED' || !text(value.anchoring.statement)) errors.push('anchoring');
  }
  if (!['embedded', 'digest-only'].includes(value.evidenceMode)) errors.push('evidenceMode');
  for (const entry of validateReceiverContext(value.receiverContext)) errors.push(`receiverContext.${entry}`);
  if (!object(value.inputs)) errors.push('inputs');
  else exactKeys(value.inputs, ['manifest', 'receipt', 'authorization', 'policy'], 'inputs', errors);
  if (!object(value.inputDigests)) errors.push('inputDigests');
  else {
    exactKeys(value.inputDigests, ['manifest', 'receipt', 'authorization', 'policy'], 'inputDigests', errors);
    if (!SHA256.test(value.inputDigests.manifest ?? '')) errors.push('inputDigests.manifest');
    if (value.inputDigests.receipt !== null && !SHA256.test(value.inputDigests.receipt ?? '')) errors.push('inputDigests.receipt');
    if (value.inputDigests.authorization !== null && !SHA256.test(value.inputDigests.authorization ?? '')) errors.push('inputDigests.authorization');
    if (!SHA256.test(value.inputDigests.policy ?? '')) errors.push('inputDigests.policy');
  }
  if (!Array.isArray(value.attachments)) errors.push('attachments');
  else {
    for (const [index, attachment] of value.attachments.entries()) {
      if (!object(attachment)) {
        errors.push(`attachments[${index}]`);
        continue;
      }
      exactKeys(attachment, ['id', 'path', 'mediaType', 'digest', 'encoding', 'data'], `attachments[${index}]`, errors);
      if (!id(attachment.id) || !relativePath(attachment.path) || !mediaType(attachment.mediaType) || !SHA256.test(attachment.digest ?? '')
        || attachment.encoding !== 'base64' || typeof attachment.data !== 'string') errors.push(`attachments[${index}]`);
    }
  }
  if (!object(value.decision)) errors.push('decision');
  else {
    exactKeys(value.decision, ['conclusion', 'subjectDigest', 'evaluatedAt', 'verificationLevel', 'summary', 'reasons'], 'decision', errors);
    if (!['PASS', 'HOLD', 'BLOCK'].includes(value.decision.conclusion)) errors.push('decision.conclusion');
    if (!SUBJECT.test(value.decision.subjectDigest ?? '')) errors.push('decision.subjectDigest');
    if (!iso(value.decision.evaluatedAt)) errors.push('decision.evaluatedAt');
    if (!['FULL', 'ENVELOPE_ONLY'].includes(value.decision.verificationLevel)) errors.push('decision.verificationLevel');
    if (!text(value.decision.summary) || !Array.isArray(value.decision.reasons)) errors.push('decision');
    else for (const [index, entry] of value.decision.reasons.entries()) {
      if (!object(entry)) errors.push(`decision.reasons[${index}]`);
      else {
        exactKeys(entry, ['code', 'severity', 'message'], `decision.reasons[${index}]`, errors);
        if (!text(entry.code) || !['HOLD', 'BLOCK'].includes(entry.severity) || !text(entry.message)) errors.push(`decision.reasons[${index}]`);
      }
    }
  }
  if (!SHA256.test(value.dossierDigest ?? '')) errors.push('dossierDigest');
  return errors;
}

export function isSha256(value) {
  return SHA256.test(value ?? '');
}

export function isCandidateDigest(value) {
  return SUBJECT.test(value ?? '');
}

export function isTreeDigest(value) {
  return TREE.test(value ?? '');
}
