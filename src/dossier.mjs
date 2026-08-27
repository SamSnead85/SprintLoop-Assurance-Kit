import { documentDigest, withoutDossierDigest } from './canonical.mjs';
import { inspectDossierEvidence, inspectLiveEvidence } from './evidence.mjs';
import { evaluateAssurance } from './evaluate.mjs';
import { validateDossier } from './validate.mjs';

export async function createDossier({
  manifest,
  receipt,
  authorization,
  policy,
  trustStore,
  evidenceRoot,
  candidate,
  at = new Date().toISOString(),
  embedEvidence = false,
  receiverContext,
}) {
  const evidence = await inspectLiveEvidence(manifest, evidenceRoot, policy, embedEvidence);
  const decision = evaluateAssurance({
    manifest,
    receipt,
    authorization,
    policy,
    trustStore,
    at,
    candidate,
    evidenceFindings: evidence.findings,
    verificationLevel: evidence.verificationLevel,
    receiverContext,
  });

  const dossier = {
    schemaVersion: 'assurance.sprintloop.dev/dossier/v1',
    createdAt: at,
    anchoring: {
      status: 'UNANCHORED',
      statement: 'Local time and dossier digest are not independently timestamped or signed.',
    },
    evidenceMode: embedEvidence ? 'embedded' : 'digest-only',
    receiverContext,
    inputs: { manifest, receipt: receipt ?? null, authorization: authorization ?? null, policy },
    inputDigests: {
      manifest: documentDigest(manifest),
      receipt: receipt ? documentDigest(receipt) : null,
      authorization: authorization ? documentDigest(authorization) : null,
      policy: documentDigest(policy),
    },
    attachments: evidence.attachments,
    decision,
  };
  return { ...dossier, dossierDigest: documentDigest(dossier) };
}

export function verifyDossier(dossier, trustStore, { at = new Date().toISOString(), candidate, receiverContext } = {}) {
  const integrityFindings = [];
  for (const field of validateDossier(dossier)) {
    integrityFindings.push(block('dossier.invalid', `Dossier is invalid at ${field}`));
  }
  if (dossier?.schemaVersion !== 'assurance.sprintloop.dev/dossier/v1') {
    integrityFindings.push(block('dossier.invalid_schema', 'Dossier schema version is invalid'));
  }
  const digest = dossier && typeof dossier === 'object'
    ? documentDigest(withoutDossierDigest(dossier))
    : null;
  if (digest !== dossier?.dossierDigest) integrityFindings.push(block('dossier.digest_mismatch', 'Dossier content digest is invalid'));

  const inputs = dossier?.inputs ?? {};
  const expectedDigests = dossier?.inputDigests ?? {};
  for (const name of ['manifest', 'receipt', 'authorization', 'policy']) {
    const value = inputs[name];
    const actual = value ? documentDigest(value) : null;
    if (actual !== (expectedDigests[name] ?? null)) {
      integrityFindings.push(block('dossier.input_digest_mismatch', `Dossier ${name} digest is invalid`));
    }
  }

  const evidence = inputs.manifest
    ? inspectDossierEvidence(inputs.manifest, dossier.attachments, dossier.evidenceMode, inputs.policy)
    : { findings: [block('dossier.manifest_missing', 'Dossier manifest is missing')], verificationLevel: 'ENVELOPE_ONLY' };
  const recorded = evaluateAssurance({
    manifest: inputs.manifest,
    receipt: inputs.receipt,
    authorization: inputs.authorization,
    policy: inputs.policy,
    trustStore,
    at: dossier?.decision?.evaluatedAt ?? dossier?.createdAt,
    candidate: dossier?.decision?.subjectDigest,
    evidenceFindings: [...integrityFindings, ...evidence.findings],
    verificationLevel: evidence.verificationLevel,
    receiverContext: dossier?.receiverContext,
  });
  const recordedMatch = documentDigest(semanticDecision(recorded)) === documentDigest(semanticDecision(dossier?.decision));
  if (!recordedMatch) {
    recorded.reasons = [...recorded.reasons, block('dossier.decision_mismatch', 'Recorded decision cannot be reproduced')]
      .sort((left, right) => left.code.localeCompare(right.code));
    recorded.conclusion = 'BLOCK';
    recorded.summary = 'Release is blocked because the recorded decision cannot be reproduced.';
  }

  const current = evaluateAssurance({
    manifest: inputs.manifest,
    receipt: inputs.receipt,
    authorization: inputs.authorization,
    policy: inputs.policy,
    trustStore,
    at,
    candidate,
    evidenceFindings: [...integrityFindings, ...evidence.findings],
    verificationLevel: evidence.verificationLevel,
    receiverContext,
  });

  return {
    integrity: integrityFindings.length === 0 ? 'VALID' : 'INVALID',
    recordedReproduction: recordedMatch ? 'REPRODUCED' : 'DIVERGED',
    verificationLevel: evidence.verificationLevel,
    recorded,
    current,
  };
}

function semanticDecision(decision) {
  if (!decision || typeof decision !== 'object') return null;
  const { verificationLevel: _verificationLevel, ...semantic } = decision;
  return semantic;
}

function block(code, message) {
  return { code, severity: 'BLOCK', message };
}
