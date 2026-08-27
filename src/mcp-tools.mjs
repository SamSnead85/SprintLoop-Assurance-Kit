import { documentDigest } from './canonical.mjs';
import { collectEvidence, EvidenceCollectionError } from './collect-evidence.mjs';
import { createDossier, verifyDossier } from './dossier.mjs';
import { validateManifest, validatePolicy } from './validate.mjs';
import { validateJsonSchema } from './schema-check.mjs';
import {
  McpToolInputError,
  publicMcpConfig,
  readGrantedJson,
  resolveGrantedDirectoryBinding,
} from './mcp-config.mjs';

import { KIT_VERSION } from './version.mjs';
import { isPortableRelativePath, PORTABLE_RELATIVE_PATH_PATTERN } from './portable-path.mjs';

export const MCP_SERVER_VERSION = KIT_VERSION;
export const MODERN_MCP_VERSION = '2026-07-28';
export const LEGACY_MCP_VERSIONS = Object.freeze(['2025-11-25', '2025-06-18']);
export const SUPPORTED_MCP_VERSIONS = Object.freeze([MODERN_MCP_VERSION, ...LEGACY_MCP_VERSIONS]);

const JSON_SCHEMA = 'https://json-schema.org/draft/2020-12/schema';
const ADVISORY = 'ADVISORY_READ_ONLY';
const CANONICAL_CANDIDATE = '^git:(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$';
const CANONICAL_TREE = '^git-tree:(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$';
const SHA256 = '^sha256:[0-9a-f]{64}$';
const ROOT_ID = '^[a-z][a-z0-9_-]{0,63}$';
const PUBLIC_ID = '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$';
const REPOSITORY = '^[A-Za-z][A-Za-z0-9+.-]{0,31}:[^\\s\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029]{1,2015}$';
const MEDIA_TYPE = "^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,127}/[A-Za-z0-9!#$%&'*+.^_`|~-]{1,127}$";
const RELATIVE_PATH = PORTABLE_RELATIVE_PATH_PATTERN;
const CANONICAL_TIME = '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$';
const SAFE_TEXT = '^[^\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029]+$';
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/gu;
const HAS_CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u;

const annotations = Object.freeze({
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
});

const reasonSchema = {
  type: 'object',
  additionalProperties: false,
  required: ['code', 'severity', 'message'],
  properties: {
    code: { type: 'string', pattern: '^[a-z][a-z0-9_.]{0,127}$' },
    severity: { enum: ['HOLD', 'BLOCK'] },
    message: { type: 'string', minLength: 1, maxLength: 1024, pattern: SAFE_TEXT },
  },
};

const decisionSchema = {
  type: 'object',
  additionalProperties: false,
  required: ['conclusion', 'subjectDigest', 'evaluatedAt', 'verificationLevel', 'summary', 'reasons'],
  properties: {
    conclusion: { enum: ['PASS', 'HOLD', 'BLOCK'] },
    subjectDigest: { type: ['string', 'null'], pattern: CANONICAL_CANDIDATE },
    evaluatedAt: { type: ['string', 'null'], format: 'date-time', pattern: CANONICAL_TIME },
    verificationLevel: { enum: ['FULL', 'ENVELOPE_ONLY'] },
    summary: { type: 'string', minLength: 1, maxLength: 1024, pattern: SAFE_TEXT },
    reasons: { type: 'array', maxItems: 1024, items: reasonSchema },
  },
};

const receiverContextSchema = {
  type: 'object',
  additionalProperties: false,
  required: [
    'expectedPolicyDigest',
    'expectedTrustStoreDigest',
    'expectedRepository',
    'expectedEnvironment',
    'actualCandidateDigest',
    'actualTreeDigest',
    'workingTreeClean',
  ],
  properties: {
    expectedPolicyDigest: { type: 'string', pattern: SHA256 },
    expectedTrustStoreDigest: { type: 'string', pattern: SHA256 },
    expectedRepository: { type: 'string', maxLength: 2048, pattern: REPOSITORY },
    expectedEnvironment: { type: 'string', pattern: PUBLIC_ID },
    actualCandidateDigest: { type: 'string', pattern: CANONICAL_CANDIDATE },
    actualTreeDigest: { type: 'string', pattern: CANONICAL_TREE },
    workingTreeClean: { type: 'boolean' },
  },
};

const rootIdSchema = { type: 'string', pattern: ROOT_ID };
const pathSchema = { type: 'string', pattern: RELATIVE_PATH, maxLength: 1024 };
const atSchema = { type: 'string', format: 'date-time', minLength: 24, maxLength: 24, pattern: CANONICAL_TIME };
const advisoryProperties = {
  mode: { const: ADVISORY },
  enforcementEligible: { const: false },
};

const TOOLS = deepFreeze([
  {
    name: 'assurance_capabilities',
    title: 'Assurance integration capabilities',
    description: 'Report the offline read-only Assurance surface, configured root grant IDs, protocol support, limits, and the non-authoritative enforcement boundary. Returns no host paths.',
    inputSchema: {
      $schema: JSON_SCHEMA,
      type: 'object',
      additionalProperties: false,
    },
    outputSchema: {
      $schema: JSON_SCHEMA,
      type: 'object',
      additionalProperties: false,
      required: ['mode', 'enforcementEligible', 'product', 'serverVersion', 'protocolVersions', 'transport', 'tools', 'rootGrants', 'limits', 'securityBoundary', 'enforcementPath'],
      properties: {
        ...advisoryProperties,
        product: { const: 'SprintLoop Assurance Kit' },
        serverVersion: { type: 'string' },
        protocolVersions: { type: 'array', items: { type: 'string' } },
        transport: { const: 'stdio' },
        tools: { type: 'array', items: { type: 'string' } },
        rootGrants: {
          type: 'array',
          items: {
            type: 'object',
            additionalProperties: false,
            required: ['id', 'kind'],
            properties: { id: { type: 'string' }, kind: { enum: ['bundle', 'receiver', 'dossier'] } },
          },
        },
        limits: {
          type: 'object',
          additionalProperties: false,
          required: ['maxMessageBytes', 'maxJsonBytes', 'maxDossierBytes', 'maxToolCalls'],
          properties: {
            maxMessageBytes: { type: 'integer' },
            maxJsonBytes: { type: 'integer' },
            maxDossierBytes: { type: 'integer' },
            maxToolCalls: { type: 'integer' },
          },
        },
        securityBoundary: {
          type: 'object',
          additionalProperties: false,
          required: ['network', 'filesystemWrites', 'sourceControl', 'credentials', 'privateKeyAccess', 'signing', 'modelSampling', 'arbitraryPaths', 'evidenceBytesReturned'],
          properties: {
            network: { const: false },
            filesystemWrites: { const: false },
            sourceControl: { const: false },
            credentials: { const: false },
            privateKeyAccess: { const: false },
            signing: { const: false },
            modelSampling: { const: false },
            arbitraryPaths: { const: false },
            evidenceBytesReturned: { const: false },
          },
        },
        enforcementPath: { type: 'string' },
      },
    },
    annotations,
  },
  {
    name: 'assurance_collect_evidence',
    title: 'Collect standard CI evidence metadata',
    description: 'Read bounded JUnit, SARIF, SPDX, CycloneDX, in-toto/SLSA, or Sigstore files below a granted bundle root and return exact raw-byte digests plus data-minimized structural metadata. Claims and signatures are not verified, no evidence bytes are returned, and no decision or effect is produced.',
    inputSchema: {
      $schema: JSON_SCHEMA,
      type: 'object',
      additionalProperties: false,
      required: ['bundleRootId', 'inputs'],
      properties: {
        bundleRootId: rootIdSchema,
        evidenceRoot: { anyOf: [{ const: '.' }, pathSchema] },
        inputs: {
          type: 'array',
          minItems: 1,
          maxItems: 32,
          items: {
            type: 'object',
            additionalProperties: false,
            required: ['id', 'path'],
            properties: {
              id: { type: 'string', pattern: PUBLIC_ID },
              path: pathSchema,
              format: { enum: ['auto', 'junit', 'sarif', 'spdx', 'cyclonedx', 'in-toto', 'sigstore'] },
            },
          },
        },
        maxFileBytes: { type: 'integer', minimum: 1, maximum: 67108864 },
        maxTotalBytes: { type: 'integer', minimum: 1, maximum: 268435456 },
      },
    },
    outputSchema: {
      $schema: JSON_SCHEMA,
      type: 'object',
      additionalProperties: false,
      required: ['mode', 'enforcementEligible', 'schemaVersion', 'pathBase', 'claimsVerified', 'evidence', 'totals'],
      properties: {
        ...advisoryProperties,
        schemaVersion: { const: 'assurance.sprintloop.dev/mcp-evidence-collection/v1' },
        pathBase: { anyOf: [{ const: '.' }, pathSchema] },
        claimsVerified: { const: false },
        evidence: {
          type: 'array',
          maxItems: 32,
          items: {
            type: 'object',
            additionalProperties: false,
            required: ['id', 'type', 'path', 'mediaType', 'digest', 'sizeBytes', 'format', 'formatVersion', 'inspectionLevel', 'claimsVerified'],
            properties: {
              id: { type: 'string', pattern: PUBLIC_ID },
              type: { type: 'string', pattern: PUBLIC_ID },
              path: pathSchema,
              mediaType: { type: 'string', maxLength: 255, pattern: MEDIA_TYPE },
              digest: { type: 'string', pattern: SHA256 },
              sizeBytes: { type: 'integer', minimum: 0, maximum: 67108864 },
              format: { enum: ['junit', 'sarif', 'spdx', 'cyclonedx', 'in-toto', 'sigstore'] },
              formatVersion: { type: 'string', minLength: 1, maxLength: 32, pattern: SAFE_TEXT },
              inspectionLevel: { enum: ['STRUCTURE_FULL', 'ENVELOPE_ONLY'] },
              claimsVerified: { const: false },
            },
          },
        },
        totals: {
          type: 'object',
          additionalProperties: false,
          required: ['itemCount', 'byteCount', 'structureFullCount', 'envelopeOnlyCount'],
          properties: {
            itemCount: { type: 'integer', minimum: 1, maximum: 32 },
            byteCount: { type: 'integer', minimum: 0, maximum: 268435456 },
            structureFullCount: { type: 'integer', minimum: 0, maximum: 32 },
            envelopeOnlyCount: { type: 'integer', minimum: 0, maximum: 32 },
          },
        },
      },
    },
    annotations,
  },
  {
    name: 'assurance_evaluate_bundle',
    title: 'Evaluate an external Assurance bundle',
    description: 'Read an externally materialized post-candidate bundle plus protected receiver policy/trust, hash live evidence, and return a deterministic advisory decision. Exact current candidate, tree, cleanliness, repository, environment, policy/trust digests, and time are mandatory; no Git or dossier fallback occurs.',
    inputSchema: {
      $schema: JSON_SCHEMA,
      type: 'object',
      additionalProperties: false,
      required: ['bundleRootId', 'receiverRootId', 'candidate', 'receiverContext', 'at'],
      properties: {
        bundleRootId: rootIdSchema,
        receiverRootId: rootIdSchema,
        candidate: { type: 'string', pattern: CANONICAL_CANDIDATE },
        receiverContext: receiverContextSchema,
        at: atSchema,
        paths: bundlePathsSchema(),
      },
    },
    outputSchema: {
      $schema: JSON_SCHEMA,
      type: 'object',
      additionalProperties: false,
      required: ['mode', 'enforcementEligible', 'anchoring', 'dossierPersisted', 'ephemeralDossierDigest', 'inputDigests', 'decision'],
      properties: {
        ...advisoryProperties,
        anchoring: { const: 'UNANCHORED' },
        dossierPersisted: { const: false },
        ephemeralDossierDigest: { type: 'string', pattern: SHA256 },
        inputDigests: {
          type: 'object',
          additionalProperties: false,
          required: ['manifest', 'receipt', 'authorization', 'policy'],
          properties: {
            manifest: { type: 'string', pattern: SHA256 },
            receipt: { type: ['string', 'null'] },
            authorization: { type: ['string', 'null'] },
            policy: { type: 'string', pattern: SHA256 },
          },
        },
        decision: decisionSchema,
      },
    },
    annotations,
  },
  {
    name: 'assurance_explain_decision',
    title: 'Explain Assurance reason codes',
    description: 'Explain stable evaluator reason codes and give trust-boundary-aware operator actions. This tool cannot waive, override, or repair a decision.',
    inputSchema: {
      $schema: JSON_SCHEMA,
      type: 'object',
      additionalProperties: false,
      required: ['reasonCodes'],
      properties: {
        reasonCodes: {
          type: 'array',
          minItems: 1,
          maxItems: 64,
          uniqueItems: true,
          items: { type: 'string', pattern: '^[a-z][a-z0-9_.]{0,127}$' },
        },
      },
    },
    outputSchema: {
      $schema: JSON_SCHEMA,
      type: 'object',
      additionalProperties: false,
      required: ['mode', 'enforcementEligible', 'explanations'],
      properties: {
        ...advisoryProperties,
        explanations: {
          type: 'array',
          items: {
            type: 'object',
            additionalProperties: false,
            required: ['code', 'known', 'family', 'typicalSeverity', 'meaning', 'operatorAction', 'agentMayOverride'],
            properties: {
              code: { type: 'string' },
              known: { type: 'boolean' },
              family: { type: 'string' },
              typicalSeverity: { enum: ['HOLD', 'BLOCK', 'CONTEXTUAL', 'UNKNOWN'] },
              meaning: { type: 'string' },
              operatorAction: { type: 'string' },
              agentMayOverride: { const: false },
            },
          },
        },
      },
    },
    annotations,
  },
  {
    name: 'assurance_policy_requirements',
    title: 'Inspect receiver policy requirements',
    description: 'Read and validate a receiver-granted policy, then return its digest and engineering obligations without exposing trust keys or document bytes.',
    inputSchema: {
      $schema: JSON_SCHEMA,
      type: 'object',
      additionalProperties: false,
      required: ['receiverRootId'],
      properties: {
        receiverRootId: rootIdSchema,
        policyPath: pathSchema,
      },
    },
    outputSchema: {
      $schema: JSON_SCHEMA,
      type: 'object',
      additionalProperties: false,
      required: ['mode', 'enforcementEligible', 'valid', 'errors', 'policyDigest', 'requirements'],
      properties: {
        ...advisoryProperties,
        valid: { type: 'boolean' },
        errors: { type: 'array', items: { type: 'string' } },
        policyDigest: { type: ['string', 'null'] },
        requirements: {
          type: ['object', 'null'],
          additionalProperties: false,
          required: ['policyId', 'requiredEvidenceTypes', 'allowedVerifierMethods', 'requireSignedReceipt', 'requireSignedAuthorization', 'requireNamedHumanAuthority', 'separation', 'validitySeconds', 'evidenceLimits'],
          properties: {
            policyId: { type: 'string' },
            requiredEvidenceTypes: { type: 'array', items: { type: 'string' } },
            allowedVerifierMethods: { type: 'array', items: { type: 'string' } },
            requireSignedReceipt: { type: 'boolean' },
            requireSignedAuthorization: { type: 'boolean' },
            requireNamedHumanAuthority: { type: 'boolean' },
            separation: {
              type: 'object',
              additionalProperties: false,
              required: ['producerVerifier', 'verifierAuthority', 'producerAuthority'],
              properties: {
                producerVerifier: { enum: ['none', 'principal', 'owner', 'control-domain'] },
                verifierAuthority: { enum: ['none', 'principal', 'owner', 'control-domain'] },
                producerAuthority: { enum: ['none', 'principal', 'owner', 'control-domain'] },
              },
            },
            validitySeconds: {
              type: 'object',
              additionalProperties: false,
              required: ['receipt', 'authorization', 'clockSkew'],
              properties: {
                receipt: { type: 'integer' },
                authorization: { type: 'integer' },
                clockSkew: { type: 'integer' },
              },
            },
            evidenceLimits: {
              type: 'object',
              additionalProperties: false,
              required: ['items', 'perItemBytes', 'aggregateBytes'],
              properties: {
                items: { type: 'integer' },
                perItemBytes: { type: 'integer' },
                aggregateBytes: { type: 'integer' },
              },
            },
          },
        },
      },
    },
    annotations,
  },
  {
    name: 'assurance_validate_manifest',
    title: 'Validate an Assurance manifest',
    description: 'Validate a manifest from a configured external bundle and return its digest, exact candidate coordinates, and evidence inventory. Returned repository, environment, path, and media-type strings remain explicitly marked as untrusted candidate metadata; no evidence bytes are returned.',
    inputSchema: {
      $schema: JSON_SCHEMA,
      type: 'object',
      additionalProperties: false,
      required: ['bundleRootId'],
      properties: {
        bundleRootId: rootIdSchema,
        manifestPath: pathSchema,
      },
    },
    outputSchema: {
      $schema: JSON_SCHEMA,
      type: 'object',
      additionalProperties: false,
      required: ['mode', 'enforcementEligible', 'provenance', 'valid', 'errors', 'manifestDigest', 'candidate', 'evidence'],
      properties: {
        ...advisoryProperties,
        provenance: { const: 'UNTRUSTED_CANDIDATE_METADATA' },
        valid: { type: 'boolean' },
        errors: { type: 'array', maxItems: 128, items: { type: 'string', minLength: 1, maxLength: 512, pattern: SAFE_TEXT } },
        manifestDigest: { type: ['string', 'null'] },
        candidate: {
          type: ['object', 'null'],
          additionalProperties: false,
          required: ['digest', 'treeDigest', 'repository', 'environment', 'intentDigest'],
          properties: {
            digest: { type: 'string', pattern: CANONICAL_CANDIDATE },
            treeDigest: { type: 'string', pattern: CANONICAL_TREE },
            repository: { type: 'string', maxLength: 2048, pattern: REPOSITORY },
            environment: { type: 'string', pattern: PUBLIC_ID },
            intentDigest: { type: 'string', pattern: SHA256 },
          },
        },
        evidence: {
          type: ['array', 'null'],
          items: {
            type: 'object',
            additionalProperties: false,
            required: ['id', 'type', 'path', 'digest', 'mediaType'],
            properties: {
              id: { type: 'string', pattern: PUBLIC_ID },
              type: { type: 'string', pattern: PUBLIC_ID },
              path: { type: 'string', maxLength: 1024, pattern: RELATIVE_PATH },
              digest: { type: 'string', pattern: SHA256 },
              mediaType: { type: 'string', maxLength: 255, pattern: MEDIA_TYPE },
            },
          },
        },
      },
    },
    annotations,
  },
  {
    name: 'assurance_verify_dossier',
    title: 'Verify an Assurance dossier',
    description: 'Verify dossier integrity, reproduce its recorded result, and separately evaluate current standing against an explicitly supplied candidate and complete current receiver context. The dossier is never allowed to provide current receiver intent.',
    inputSchema: {
      $schema: JSON_SCHEMA,
      type: 'object',
      additionalProperties: false,
      required: ['dossierRootId', 'receiverRootId', 'candidate', 'receiverContext', 'at'],
      properties: {
        dossierRootId: rootIdSchema,
        receiverRootId: rootIdSchema,
        candidate: { type: 'string', pattern: CANONICAL_CANDIDATE },
        receiverContext: receiverContextSchema,
        at: atSchema,
        dossierPath: pathSchema,
        trustPath: pathSchema,
      },
    },
    outputSchema: {
      $schema: JSON_SCHEMA,
      type: 'object',
      additionalProperties: false,
      required: ['mode', 'enforcementEligible', 'anchoring', 'integrity', 'recordedReproduction', 'verificationLevel', 'recorded', 'current'],
      properties: {
        ...advisoryProperties,
        anchoring: { const: 'UNANCHORED' },
        integrity: { enum: ['VALID', 'INVALID'] },
        recordedReproduction: { enum: ['REPRODUCED', 'DIVERGED'] },
        verificationLevel: { enum: ['FULL', 'ENVELOPE_ONLY'] },
        recorded: decisionSchema,
        current: decisionSchema,
      },
    },
    annotations,
  },
]);

const TOOL_BY_NAME = new Map(TOOLS.map((tool) => [tool.name, tool]));

export function listMcpTools() {
  return TOOLS;
}

export async function callMcpTool(name, rawArguments, config, hooks = {}) {
  const tool = TOOL_BY_NAME.get(name);
  if (!tool) throw new McpToolInputError('UNKNOWN_TOOL', 'Unknown Assurance MCP tool.');
  const inputErrors = validateJsonSchema(tool.inputSchema, rawArguments ?? {});
  if (inputErrors.length) throw new McpToolInputError('INVALID_TOOL_INPUT', `Tool input violates its advertised schema at ${inputErrors[0]}`);
  const args = validateArguments(name, rawArguments ?? {});
  let result;
  if (name === 'assurance_capabilities') result = capabilities(config);
  else if (name === 'assurance_collect_evidence') result = await collectEvidenceTool(args, config);
  else if (name === 'assurance_policy_requirements') result = await policyRequirements(args, config);
  else if (name === 'assurance_validate_manifest') result = await validateManifestTool(args, config);
  else if (name === 'assurance_evaluate_bundle') result = await evaluateBundle(args, config, hooks);
  else if (name === 'assurance_verify_dossier') result = await verifyDossierTool(args, config);
  else result = explainDecision(args);
  const outputErrors = validateJsonSchema(tool.outputSchema, result);
  if (outputErrors.length) throw new Error(`MCP tool output violates its advertised schema at ${outputErrors[0]}`);
  return result;
}

async function collectEvidenceTool(args, config) {
  const evidenceRoot = await resolveGrantedDirectoryBinding(config, args.bundleRootId, 'bundle', args.evidenceRoot);
  try {
    const collection = await collectEvidence(args.inputs, {
      root: evidenceRoot.path,
      rootIdentity: evidenceRoot.identity,
      pathBase: args.evidenceRoot ?? '.',
      maxFiles: 32,
      maxFileBytes: args.maxFileBytes,
      maxTotalBytes: args.maxTotalBytes,
    });
    return {
      mode: ADVISORY,
      enforcementEligible: false,
      // This redacted model-facing projection intentionally has a distinct
      // identity from the full library/CLI collection JSON Schema.
      schemaVersion: 'assurance.sprintloop.dev/mcp-evidence-collection/v1',
      pathBase: collection.pathBase,
      claimsVerified: false,
      evidence: collection.evidence.map(({ summary: _summary, ...entry }) => entry),
      totals: collection.totals,
    };
  } catch (error) {
    if (error instanceof EvidenceCollectionError) {
      throw new McpToolInputError('EVIDENCE_COLLECTION_FAILED', `Evidence collection failed with ${error.code}.`);
    }
    throw error;
  }
}

function capabilities(config) {
  const visible = publicMcpConfig(config);
  return {
    mode: ADVISORY,
    enforcementEligible: false,
    product: 'SprintLoop Assurance Kit',
    serverVersion: MCP_SERVER_VERSION,
    protocolVersions: [...SUPPORTED_MCP_VERSIONS],
    transport: 'stdio',
    tools: TOOLS.map((tool) => tool.name),
    rootGrants: visible.roots,
    limits: visible.limits,
    securityBoundary: {
      network: false,
      filesystemWrites: false,
      sourceControl: false,
      credentials: false,
      privateKeyAccess: false,
      signing: false,
      modelSampling: false,
      arbitraryPaths: false,
      evidenceBytesReturned: false,
    },
    enforcementPath: 'Use a receiver-governed CI required check or deployment interlock; MCP results are inspection evidence only.',
  };
}

async function policyRequirements(args, config) {
  const policy = await readGrantedJson(config, args.receiverRootId, 'receiver', args.policyPath);
  const errors = validatePolicy(policy);
  if (errors.length) return advisoryValidity(errors);
  return {
    mode: ADVISORY,
    enforcementEligible: false,
    valid: true,
    errors: [],
    policyDigest: documentDigest(policy),
    requirements: {
      policyId: policy.policyId,
      requiredEvidenceTypes: [...policy.requiredEvidenceTypes],
      allowedVerifierMethods: [...policy.allowedVerifierMethods],
      requireSignedReceipt: policy.requireSignedReceipt,
      requireSignedAuthorization: policy.requireSignedAuthorization,
      requireNamedHumanAuthority: policy.requireNamedHumanAuthority,
      separation: { ...policy.separation },
      validitySeconds: {
        receipt: policy.maxReceiptValiditySeconds,
        authorization: policy.maxAuthorizationValiditySeconds,
        clockSkew: policy.maxClockSkewSeconds,
      },
      evidenceLimits: {
        items: policy.maxEvidenceItems,
        perItemBytes: policy.maxEvidenceBytes,
        aggregateBytes: policy.maxTotalEvidenceBytes,
      },
    },
  };
}

async function validateManifestTool(args, config) {
  const manifest = await readGrantedJson(config, args.bundleRootId, 'bundle', args.manifestPath);
  const errors = validateManifest(manifest);
  if (errors.length) {
    return {
      mode: ADVISORY,
      enforcementEligible: false,
      provenance: 'UNTRUSTED_CANDIDATE_METADATA',
      valid: false,
      errors: safeErrors(errors),
      manifestDigest: null,
      candidate: null,
      evidence: null,
    };
  }
  return {
    mode: ADVISORY,
    enforcementEligible: false,
    provenance: 'UNTRUSTED_CANDIDATE_METADATA',
    valid: true,
    errors: [],
    manifestDigest: documentDigest(manifest),
    candidate: {
      digest: manifest.candidate.digest,
      treeDigest: manifest.candidate.treeDigest,
      repository: manifest.candidate.repository,
      environment: manifest.candidate.environment,
      intentDigest: manifest.intent.digest,
    },
    evidence: manifest.evidence.map(({ id, type, path, digest, mediaType }) => ({ id, type, path, digest, mediaType })),
  };
}

async function evaluateBundle(args, config, hooks) {
  const paths = args.paths;
  const [manifest, receipt, authorization, policy, trustStore, evidenceRoot] = await Promise.all([
    readGrantedJson(config, args.bundleRootId, 'bundle', paths.manifest),
    readGrantedJson(config, args.bundleRootId, 'bundle', paths.receipt, { optional: true }),
    readGrantedJson(config, args.bundleRootId, 'bundle', paths.authorization, { optional: true }),
    readGrantedJson(config, args.receiverRootId, 'receiver', paths.policy),
    readGrantedJson(config, args.receiverRootId, 'receiver', paths.trust),
    resolveGrantedDirectoryBinding(config, args.bundleRootId, 'bundle', paths.evidenceRoot),
  ]);
  const manifestErrors = validateManifest(manifest);
  if (manifestErrors.length) {
    throw new McpToolInputError('MANIFEST_INVALID', `Bundle manifest is invalid at ${safeOutputText(manifestErrors[0], 'manifest', 256)}.`);
  }
  const policyErrors = validatePolicy(policy);
  if (policyErrors.length) {
    throw new McpToolInputError('POLICY_INVALID', `Receiver policy is invalid at ${safeOutputText(policyErrors[0], 'policy', 256)}.`);
  }
  await hooks.afterEvidenceRootBound?.();
  let dossier;
  try {
    dossier = await createDossier({
      manifest,
      receipt,
      authorization,
      policy,
      trustStore,
      evidenceRoot: evidenceRoot.path,
      evidenceRootBinding: evidenceRoot,
      evidenceInspectionHooks: hooks,
      candidate: args.candidate,
      receiverContext: args.receiverContext,
      at: args.at,
      embedEvidence: false,
    });
  } catch (error) {
    if (error?.code === 'ESTALE') {
      throw new McpToolInputError('ROOT_CHANGED', 'Granted evidence root changed during bundle evaluation.');
    }
    throw error;
  }
  return {
    mode: ADVISORY,
    enforcementEligible: false,
    anchoring: 'UNANCHORED',
    dossierPersisted: false,
    ephemeralDossierDigest: dossier.dossierDigest,
    inputDigests: { ...dossier.inputDigests },
    decision: publicDecision(dossier.decision),
  };
}

async function verifyDossierTool(args, config) {
  const [dossier, trustStore] = await Promise.all([
    readGrantedJson(config, args.dossierRootId, 'dossier', args.dossierPath, { dossier: true }),
    readGrantedJson(config, args.receiverRootId, 'receiver', args.trustPath),
  ]);
  const result = verifyDossier(dossier, trustStore, {
    at: args.at,
    candidate: args.candidate,
    receiverContext: args.receiverContext,
  });
  return {
    mode: ADVISORY,
    enforcementEligible: false,
    anchoring: 'UNANCHORED',
    integrity: result.integrity,
    recordedReproduction: result.recordedReproduction,
    verificationLevel: result.verificationLevel,
    recorded: publicDecision(result.recorded),
    current: publicDecision(result.current),
  };
}

function explainDecision(args) {
  return {
    mode: ADVISORY,
    enforcementEligible: false,
    explanations: args.reasonCodes.map(explainReasonCode),
  };
}

export function explainReasonCode(code) {
  const family = code.split('.')[0];
  const guidance = REASON_FAMILIES[family];
  if (!guidance) {
    return {
      code,
      known: false,
      family: 'unknown',
      typicalSeverity: 'UNKNOWN',
      meaning: 'This reason code is not part of the current public Assurance evaluator catalog.',
      operatorAction: 'Confirm the producer version and inspect the matching protocol documentation; do not ignore or downgrade the reason.',
      agentMayOverride: false,
    };
  }
  const known = isKnownReasonCode(code);
  if (!known) {
    return {
      code,
      known: false,
      family,
      typicalSeverity: 'UNKNOWN',
      meaning: 'This reason suffix is not part of the current public Assurance evaluator catalog.',
      operatorAction: 'Confirm the producer version and inspect its matching reason catalog; do not infer severity or downgrade the result from the family name.',
      agentMayOverride: false,
    };
  }
  return {
    code,
    known: true,
    family,
    typicalSeverity: typicalSeverity(code),
    meaning: REASON_MEANINGS[code] ?? guidance.meaning,
    operatorAction: REASON_ACTIONS[code] ?? guidance.action,
    agentMayOverride: false,
  };
}

function validateArguments(name, value) {
  assertObject(value, '$');
  if (name === 'assurance_capabilities') {
    exact(value, [], '$');
    return {};
  }
  if (name === 'assurance_explain_decision') {
    exact(value, ['reasonCodes'], '$');
    if (!Array.isArray(value.reasonCodes) || value.reasonCodes.length < 1 || value.reasonCodes.length > 64) invalid('reasonCodes must contain 1-64 entries.');
    const unique = new Set();
    for (const code of value.reasonCodes) {
      if (typeof code !== 'string' || !/^[a-z][a-z0-9_.]{0,127}$/.test(code)) invalid('reasonCodes contains an invalid code.');
      if (unique.has(code)) invalid('reasonCodes must be unique.');
      unique.add(code);
    }
    return { reasonCodes: [...value.reasonCodes] };
  }
  if (name === 'assurance_collect_evidence') {
    exact(value, ['bundleRootId', 'evidenceRoot', 'inputs', 'maxFileBytes', 'maxTotalBytes'], '$');
    if (!Array.isArray(value.inputs) || value.inputs.length < 1 || value.inputs.length > 32) {
      invalid('inputs must contain 1-32 evidence descriptors.');
    }
    const ids = new Set();
    const paths = new Set();
    const inputs = value.inputs.map((entry) => {
      assertObject(entry, 'inputs[]');
      exact(entry, ['id', 'path', 'format'], 'inputs[]');
      if (typeof entry.id !== 'string' || !new RegExp(PUBLIC_ID, 'u').test(entry.id)) invalid('Evidence input id is invalid.');
      if (ids.has(entry.id)) invalid('Evidence input ids must be unique.');
      const entryPath = relativePath(entry.path, false);
      if (paths.has(entryPath)) invalid('Evidence input paths must be unique.');
      const format = entry.format ?? 'auto';
      if (!['auto', 'junit', 'sarif', 'spdx', 'cyclonedx', 'in-toto', 'sigstore'].includes(format)) invalid('Evidence input format is unsupported.');
      ids.add(entry.id);
      paths.add(entryPath);
      return { id: entry.id, path: entryPath, format };
    });
    return {
      bundleRootId: rootId(value.bundleRootId),
      evidenceRoot: relativePath(value.evidenceRoot ?? '.', true),
      inputs,
      maxFileBytes: boundedEvidenceLimit(value.maxFileBytes, 16_777_216, 67_108_864, 'maxFileBytes'),
      maxTotalBytes: boundedEvidenceLimit(value.maxTotalBytes, 67_108_864, 268_435_456, 'maxTotalBytes'),
    };
  }
  if (name === 'assurance_policy_requirements') {
    exact(value, ['receiverRootId', 'policyPath'], '$');
    return { receiverRootId: rootId(value.receiverRootId), policyPath: relativePath(value.policyPath ?? 'policy.json', false) };
  }
  if (name === 'assurance_validate_manifest') {
    exact(value, ['bundleRootId', 'manifestPath'], '$');
    return { bundleRootId: rootId(value.bundleRootId), manifestPath: relativePath(value.manifestPath ?? 'manifest.json', false) };
  }
  if (name === 'assurance_evaluate_bundle') {
    exact(value, ['bundleRootId', 'receiverRootId', 'candidate', 'receiverContext', 'at', 'paths'], '$');
    return {
      bundleRootId: rootId(value.bundleRootId),
      receiverRootId: rootId(value.receiverRootId),
      candidate: candidate(value.candidate),
      receiverContext: receiverContext(value.receiverContext),
      at: canonicalTime(value.at),
      paths: bundlePaths(value.paths),
    };
  }
  exact(value, ['dossierRootId', 'receiverRootId', 'candidate', 'receiverContext', 'at', 'dossierPath', 'trustPath'], '$');
  return {
    dossierRootId: rootId(value.dossierRootId),
    receiverRootId: rootId(value.receiverRootId),
    candidate: candidate(value.candidate),
    receiverContext: receiverContext(value.receiverContext),
    at: canonicalTime(value.at),
    dossierPath: relativePath(value.dossierPath ?? 'dossier.json', false),
    trustPath: relativePath(value.trustPath ?? 'trust.json', false),
  };
}

function boundedEvidenceLimit(value, fallback, maximum, label) {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < 1 || selected > maximum) {
    invalid(`${label} is outside the supported evidence bound.`);
  }
  return selected;
}

function receiverContext(value) {
  assertObject(value, 'receiverContext');
  exact(value, ['expectedPolicyDigest', 'expectedTrustStoreDigest', 'expectedRepository', 'expectedEnvironment', 'actualCandidateDigest', 'actualTreeDigest', 'workingTreeClean'], 'receiverContext');
  if (!/^sha256:[0-9a-f]{64}$/.test(value.expectedPolicyDigest ?? '')) invalid('receiverContext.expectedPolicyDigest must be canonical SHA-256.');
  if (!/^sha256:[0-9a-f]{64}$/.test(value.expectedTrustStoreDigest ?? '')) invalid('receiverContext.expectedTrustStoreDigest must be canonical SHA-256.');
  if (typeof value.expectedRepository !== 'string' || value.expectedRepository.length > 2048
    || !new RegExp(REPOSITORY, 'u').test(value.expectedRepository)) {
    invalid('receiverContext.expectedRepository must be a bounded absolute URI without whitespace or control characters.');
  }
  if (typeof value.expectedEnvironment !== 'string' || !new RegExp(PUBLIC_ID, 'u').test(value.expectedEnvironment)) {
    invalid('receiverContext.expectedEnvironment must use the bounded public ID syntax.');
  }
  const actualCandidateDigest = candidate(value.actualCandidateDigest);
  if (!/^git-tree:(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$/.test(value.actualTreeDigest ?? '')) invalid('receiverContext.actualTreeDigest must be canonical.');
  if (typeof value.workingTreeClean !== 'boolean') invalid('receiverContext.workingTreeClean must be boolean.');
  return {
    expectedPolicyDigest: value.expectedPolicyDigest,
    expectedTrustStoreDigest: value.expectedTrustStoreDigest,
    expectedRepository: value.expectedRepository,
    expectedEnvironment: value.expectedEnvironment,
    actualCandidateDigest,
    actualTreeDigest: value.actualTreeDigest,
    workingTreeClean: value.workingTreeClean,
  };
}

function bundlePaths(value) {
  if (value === undefined) value = {};
  assertObject(value, 'paths');
  exact(value, ['manifest', 'receipt', 'authorization', 'policy', 'trust', 'evidenceRoot'], 'paths');
  return {
    manifest: relativePath(value.manifest ?? 'manifest.json', false),
    receipt: relativePath(value.receipt ?? 'verifier-receipt.json', false),
    authorization: relativePath(value.authorization ?? 'authorization.json', false),
    policy: relativePath(value.policy ?? 'policy.json', false),
    trust: relativePath(value.trust ?? 'trust.json', false),
    evidenceRoot: relativePath(value.evidenceRoot ?? '.', true),
  };
}

function bundlePathsSchema() {
  return {
    type: 'object',
    additionalProperties: false,
    properties: {
      manifest: pathSchema,
      receipt: pathSchema,
      authorization: pathSchema,
      policy: pathSchema,
      trust: pathSchema,
      evidenceRoot: { anyOf: [{ const: '.' }, pathSchema] },
    },
  };
}

function publicDecision(decision) {
  return {
    conclusion: decision.conclusion,
    subjectDigest: typeof decision.subjectDigest === 'string' && new RegExp(CANONICAL_CANDIDATE, 'u').test(decision.subjectDigest)
      ? decision.subjectDigest
      : null,
    evaluatedAt: canonicalOutputTime(decision.evaluatedAt),
    verificationLevel: decision.verificationLevel,
    summary: safeOutputText(decision.summary, 'Assurance decision detail is unavailable.', 1024),
    reasons: decision.reasons.slice(0, 1024).map(({ code, severity, message }) => ({
      code: /^[a-z][a-z0-9_.]{0,127}$/.test(code ?? '') ? code : 'assurance.output_sanitized',
      severity: severity === 'HOLD' ? 'HOLD' : 'BLOCK',
      message: safeOutputText(message, 'Assurance reason detail is unavailable.', 1024),
    })),
  };
}

function advisoryValidity(errors) {
  return {
    mode: ADVISORY,
    enforcementEligible: false,
    valid: false,
    errors: safeErrors(errors),
    policyDigest: null,
    requirements: null,
  };
}

function rootId(value) {
  if (typeof value !== 'string' || !/^[a-z][a-z0-9_-]{0,63}$/.test(value)) invalid('Root grant ID is invalid.');
  return value;
}

function candidate(value) {
  if (typeof value !== 'string' || !/^git:(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$/.test(value)) invalid('Candidate must be a canonical Git digest.');
  return value;
}

function relativePath(value, allowDot) {
  if (!isPortableRelativePath(value, { allowDot })) invalid('Document path must be a portable forward-slash relative path.');
  return value;
}

function canonicalTime(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
    || !Number.isFinite(Date.parse(value))) invalid('at must be a canonical UTC ISO 8601 instant with milliseconds.');
  if (new Date(value).toISOString() !== value) invalid('at must use canonical UTC ISO 8601 milliseconds.');
  return value;
}

function exact(value, allowed, label) {
  const keys = new Set(allowed);
  const unexpected = Object.keys(value).find((key) => !keys.has(key));
  if (unexpected) invalid(`${label} contains an unexpected property.`);
}

function assertObject(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid(`${label} must be an object.`);
}

function invalid(message) {
  throw new McpToolInputError('INVALID_TOOL_INPUT', message);
}

function boundedString(value, minimum, maximum) {
  return typeof value === 'string' && value.length >= minimum && value.length <= maximum;
}

function canonicalOutputTime(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
    || !Number.isFinite(Date.parse(value))) return null;
  return new Date(value).toISOString() === value ? value : null;
}

function safeErrors(errors) {
  return errors.slice(0, 128).map((entry) => safeOutputText(entry, 'Document validation failed.', 512));
}

function safeOutputText(value, fallback, maximum) {
  if (typeof value !== 'string') return fallback;
  const sanitized = value.replace(CONTROL, ' ').replace(/\s+/gu, ' ').trim();
  CONTROL.lastIndex = 0;
  return (sanitized || fallback).slice(0, maximum);
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

const REASON_FAMILIES = Object.freeze({
  authorization: { meaning: 'Finite release authority is missing, stale, negative, untrusted, or bound to different scope or bytes.', action: 'Have the separately trusted named authority review the exact receipt and candidate, then issue a correctly scoped finite authorization; never synthesize or reuse one.' },
  candidate: { meaning: 'The runtime candidate, Git tree, or tracked cleanliness does not match the exact candidate bound by the manifest.', action: 'Stop promotion, re-observe the exact Git commit/tree in the receiver-controlled checkout, regenerate downstream evidence, receipt, and authorization for those bytes.' },
  dossier: { meaning: 'The dossier structure, input digests, evidence attachments, or recorded decision does not reproduce.', action: 'Treat the dossier as untrusted, retrieve it from the governed system of record, and reconstruct it from the original exact-candidate inputs.' },
  evaluation: { meaning: 'The requested evaluation instant is invalid.', action: 'Supply a canonical UTC ISO 8601 instant from a receiver-controlled synchronized clock.' },
  evidence: { meaning: 'Required evidence is absent, oversized, changed, path-unsafe, or different from its bound digest.', action: 'Regenerate deterministic evidence for the exact candidate in the receiver-governed pipeline and preserve the configured limits and external bundle boundary.' },
  manifest: { meaning: 'The candidate manifest violates its normative schema.', action: 'Regenerate the manifest from the sealed candidate using the protocol schema; do not hand-edit bindings after signing.' },
  policy: { meaning: 'The receiver-owned policy violates its normative schema.', action: 'Have the receiver policy owner correct and re-review the protected policy, then update the externally pinned digest through governance.' },
  receipt: { meaning: 'Independent verifier standing, signature, verdict, method, or exact-candidate binding is incomplete or invalid.', action: 'Run an independently owned verifier over the complete exact-candidate evidence set and obtain a fresh receiver-trusted signed receipt.' },
  receiver: { meaning: 'Current receiver intent or observations are absent, invalid, or do not match the loaded candidate, policy, trust store, repository, or environment.', action: 'Supply complete values from the protected receiver boundary; never copy current context from the dossier or candidate.' },
  separation: { meaning: 'Builder, verifier, or authority principals do not satisfy policy-required organizational independence.', action: 'Route review or authorization to a distinct trusted principal, owner, or control domain as required; changing a model name or prompt is insufficient.' },
  trust: { meaning: 'The receiver-owned trust store violates its normative schema.', action: 'Repair the protected public trust store through receiver governance and re-pin its canonical digest; never accept claimant-provided roots.' },
});

const REASON_MEANINGS = Object.freeze({
  'candidate.runtime_missing': 'No externally supplied runtime candidate was provided.',
  'candidate.runtime_mismatch': 'The supplied runtime candidate differs from the manifest candidate.',
  'candidate.head_mismatch': 'The independently observed Git HEAD differs from the manifest candidate.',
  'candidate.tree_mismatch': 'The independently observed Git tree differs from the manifest tree.',
  'candidate.tracked_tree_dirty': 'Tracked candidate files differ from the observed Git tree.',
  'receiver.policy_digest_mismatch': 'The loaded policy differs from the receiver-pinned canonical digest.',
  'receiver.trust_digest_mismatch': 'The loaded trust store differs from the receiver-pinned canonical digest.',
  'receiver.repository_mismatch': 'The candidate repository differs from the receiver-expected repository.',
  'receiver.environment_mismatch': 'The target environment differs from the receiver-expected environment.',
  'receipt.missing': 'An independent verifier receipt is absent.',
  'receipt.invalid_signature': 'The verifier receipt signature does not verify against its receiver-trusted public key.',
  'receipt.untrusted_key': 'The receipt signer key is outside the receiver-owned trust store.',
  'receipt.negative': 'The independent verifier explicitly returned BLOCK.',
  'receipt.indeterminate': 'The independent verifier returned HOLD.',
  'authorization.missing': 'Finite named release authorization is absent.',
  'authorization.denied': 'The named authority explicitly denied release.',
  'authorization.invalid_signature': 'The authorization signature does not verify against its receiver-trusted public key.',
  'authorization.untrusted_key': 'The authority signer key is outside the receiver-owned trust store.',
  'authorization.human_required': 'Policy requires a named human authority but the authorization does not identify one.',
  'dossier.decision_mismatch': 'The recorded decision cannot be reproduced from the dossier inputs.',
  'dossier.digest_mismatch': 'The dossier content differs from its canonical dossier digest.',
  'evidence.digest_mismatch': 'Evidence bytes differ from the digest bound by the manifest and receipt.',
  'evidence.missing': 'A manifest-declared evidence artifact is unavailable.',
  'evidence.path_escape': 'A declared evidence path escapes the configured evidence root.',
  'evidence.symlink_escape': 'A declared evidence path resolves outside the configured evidence root.',
});

const REASON_ACTIONS = Object.freeze({
  'receipt.expired': 'Obtain a fresh independent receipt for the same exact candidate, then obtain a new authorization bound to that receipt.',
  'authorization.expired': 'Have the named authority issue a fresh finite authorization after confirming the receipt and candidate remain current.',
  'receipt.signature_missing': 'Have the independently governed verifier sign the receipt using a receiver-trusted verifier-role key.',
  'authorization.signature_missing': 'Have the named authority sign the authorization using a receiver-trusted authority-role key.',
  'receipt.key_revoked': 'Stop release and investigate signer compromise or revocation; require a new receipt under a current trusted key.',
  'authorization.key_revoked': 'Stop release and investigate signer compromise or revocation; require new authority under a current trusted key.',
});

const HOLD_CODES = new Set([
  'authorization.expired',
  'authorization.key_not_current',
  'authorization.missing',
  'authorization.not_yet_valid',
  'authorization.receipt_unavailable',
  'authorization.signature_missing',
  'evidence.missing',
  'evidence.required_missing',
  'receipt.expired',
  'receipt.indeterminate',
  'receipt.key_not_current',
  'receipt.missing',
  'receipt.not_yet_valid',
  'receipt.signature_missing',
]);

const CONTEXTUAL_CODES = new Set(['evidence.aggregate_too_large', 'evidence.too_large']);

function typicalSeverity(code) {
  if (CONTEXTUAL_CODES.has(code)) return 'CONTEXTUAL';
  if (HOLD_CODES.has(code)) return 'HOLD';
  return 'BLOCK';
}

function isKnownReasonCode(code) {
  if (REASON_MEANINGS[code] || REASON_ACTIONS[code] || HOLD_CODES.has(code) || CONTEXTUAL_CODES.has(code)) return true;
  const [family, suffix] = code.split('.', 2);
  if (!REASON_FAMILIES[family] || !suffix) return false;
  if (family === 'separation') return ['producer_verifier', 'verifier_authority', 'producer_authority'].includes(suffix);
  return KNOWN_SUFFIXES.has(suffix);
}

const KNOWN_SUFFIXES = new Set([
  'aggregate_too_large', 'attachment_binding', 'attachment_encoding', 'attachment_missing', 'concurrent_growth',
  'concurrent_mutation', 'count_limit', 'decision_mismatch', 'denied', 'digest_mismatch', 'duplicate_attachment',
  'environment_mismatch', 'evidence_contract_invalid', 'evidence_set_mismatch', 'expired', 'head_mismatch',
  'human_required', 'indeterminate', 'input_digest_mismatch', 'invalid', 'invalid_schema', 'invalid_signature',
  'invalid_time', 'invalid_window', 'key_expired_at_signing', 'key_not_current', 'key_not_yet_valid', 'key_revoked',
  'key_revoked_at_signing', 'manifest_mismatch', 'manifest_missing', 'method_not_allowed', 'missing', 'negative',
  'not_file', 'not_yet_valid', 'path_changed', 'path_escape', 'policy_digest_mismatch', 'policy_mismatch',
  'precedes_receipt', 'receipt_mismatch', 'receipt_unavailable', 'repository_mismatch', 'repository_scope_mismatch',
  'required_missing', 'runtime_mismatch', 'runtime_missing', 'scope_mismatch', 'signature_missing', 'signer_mismatch',
  'subject_mismatch', 'symlink_escape', 'symlink_rejected', 'too_large', 'tracked_tree_dirty', 'tree_mismatch',
  'trust_digest_mismatch', 'trust_mismatch', 'unexpected_attachment', 'untrusted_key', 'window_too_long', 'wrong_key_role',
]);
