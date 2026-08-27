#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { documentDigest, sha256 } from './canonical.mjs';
import { signDocument } from './crypto.mjs';
import { createDossier, verifyDossier } from './dossier.mjs';
import { collectEvidence, EvidenceCollectionError } from './collect-evidence.mjs';
import {
  diagnoseSetup,
  doctorExitCode,
  formatDoctorHuman,
  formatDoctorJson,
} from './doctor.mjs';
import { createExampleBundle, writeExampleBundle } from './example.mjs';
import { inspectGitState as inspectReceiverGitState } from './git-state.mjs';
import {
  appendGithubOutput,
  readJson,
  readOptionalJson,
  safeLogMessage,
  writeJsonAtomic,
  writeTextExclusive,
} from './io.mjs';
import { KIT_VERSION } from './version.mjs';

const EXIT = { PASS: 0, HOLD: 10, BLOCK: 20, ERROR: 2 };

export async function run(argv = process.argv.slice(2), environment = process.env) {
  const [command = 'help', ...rest] = argv;
  const options = parseOptions(rest);

  if (command === 'help' || command === '--help' || command === '-h') {
    if (rest.length > 0) throw new UsageError('Help does not accept arguments');
    process.stdout.write(MCP_HELP);
    return 0;
  }
  if (rest.length === 1 && rest[0] === '-h') {
    process.stdout.write(MCP_HELP);
    return 0;
  }
  if (options.help !== undefined) {
    booleanFlag(options, 'help');
    assertOptions(options, ['help']);
    process.stdout.write(MCP_HELP);
    return 0;
  }
  if (command === 'version' || command === '--version' || command === '-V') {
    assertOptions(options, ['json']);
    const json = booleanFlag(options, 'json');
    process.stdout.write(json
      ? `${JSON.stringify({ name: '@sprintloop/assurance-kit', version: KIT_VERSION })}\n`
      : `SprintLoop Assurance Kit ${KIT_VERSION}\n`);
    return 0;
  }
  if (command === 'digest') return digestCommand(options);
  if (command === 'document-digest') return documentDigestCommand(options);
  if (command === 'doctor') return doctorCommand(options);
  if (command === 'collect-evidence') return collectEvidenceCommand(options);
  if (command === 'init') return initCommand(options);
  if (command === 'demo') return demoCommand(options);
  if (command === 'sign-receipt' || command === 'sign-authorization') return signCommand(command, options);
  if (command === 'check') return checkCommand(options, environment);
  if (command === 'verify-dossier') return verifyDossierCommand(options);
  throw new UsageError(`Unknown command: ${command}`);
}

async function doctorCommand(options) {
  assertOptions(options, [
    'root', 'policy', 'trust', 'expected_head', 'expected_tree', 'expected_policy_digest',
    'expected_trust_digest', 'mcp_config', 'timeout_ms', 'max_document_bytes', 'json',
  ]);
  const json = booleanFlag(options, 'json');
  const result = await diagnoseSetup({
    root: optionalText(options, 'root'),
    policyPath: optionalText(options, 'policy'),
    trustPath: optionalText(options, 'trust'),
    expectedHead: optionalText(options, 'expected_head'),
    expectedTree: optionalText(options, 'expected_tree'),
    expectedPolicyDigest: optionalText(options, 'expected_policy_digest'),
    expectedTrustStoreDigest: optionalText(options, 'expected_trust_digest'),
    mcpConfigPath: optionalText(options, 'mcp_config'),
    timeoutMs: optionalInteger(options, 'timeout_ms'),
    maxDocumentBytes: optionalInteger(options, 'max_document_bytes'),
  });
  process.stdout.write(json ? formatDoctorJson(result) : formatDoctorHuman(result));
  return doctorExitCode(result);
}

async function collectEvidenceCommand(options) {
  assertOptions(options, ['input', 'root', 'path_base', 'subject_digest', 'max_files', 'max_file_bytes', 'max_total_bytes']);
  let inputs;
  try {
    inputs = await readJson(required(options, 'input'), { maxBytes: 1_048_576 });
  } catch {
    throw new UsageError('Evidence descriptor input failed validation (EINPUT)');
  }
  if (!Array.isArray(inputs)) throw new UsageError('Evidence input file must contain a JSON array');
  try {
    const collection = await collectEvidence(inputs, {
      root: optionalText(options, 'root') ?? '.',
      pathBase: optionalText(options, 'path_base'),
      subjectDigest: optionalText(options, 'subject_digest'),
      maxFiles: optionalInteger(options, 'max_files'),
      maxFileBytes: optionalInteger(options, 'max_file_bytes'),
      maxTotalBytes: optionalInteger(options, 'max_total_bytes'),
    });
    process.stdout.write(`${JSON.stringify(collection, null, 2)}\n`);
    return 0;
  } catch (error) {
    if (error instanceof EvidenceCollectionError) {
      throw new UsageError(`Evidence collection failed (${error.code})`);
    }
    throw error;
  }
}

function parseOptions(tokens) {
  const result = { _: [] };
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (!token.startsWith('--')) {
      result._.push(token);
      continue;
    }
    const option = token.slice(2);
    const separator = option.indexOf('=');
    const rawKey = separator === -1 ? option : option.slice(0, separator);
    const inline = separator === -1 ? undefined : option.slice(separator + 1);
    if (!/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/.test(rawKey)) {
      throw new UsageError(`Invalid option: --${rawKey || '(empty)'}`);
    }
    const key = rawKey.replaceAll('-', '_');
    if (Object.hasOwn(result, key)) throw new UsageError(`Duplicate --${rawKey}`);
    if (inline !== undefined) {
      result[key] = inline;
    } else if (tokens[index + 1] && !tokens[index + 1].startsWith('--')) {
      result[key] = tokens[index + 1];
      index += 1;
    } else {
      result[key] = true;
    }
  }
  return result;
}

async function digestCommand(options) {
  assertOptions(options, ['file']);
  const file = required(options, 'file');
  process.stdout.write(`${sha256(await readFile(file))}\n`);
  return 0;
}

async function documentDigestCommand(options) {
  assertOptions(options, ['file']);
  process.stdout.write(`${documentDigest(await readJson(required(options, 'file')))}\n`);
  return 0;
}

async function signCommand(command, options) {
  assertOptions(options, ['input', 'private_key', 'key_id', 'output']);
  const input = await readJson(required(options, 'input'));
  const privateKey = await readFile(required(options, 'private_key'), 'utf8');
  const keyId = required(options, 'key_id');
  const output = required(options, 'output');
  const expected = command === 'sign-receipt'
    ? 'assurance.sprintloop.dev/verifier-receipt/v1'
    : 'assurance.sprintloop.dev/authorization/v1';
  if (input.schemaVersion !== expected) throw new UsageError(`Input must use ${expected}`);
  await writeJsonAtomic(output, signDocument(input, privateKey, keyId));
  process.stdout.write(`Signed document written to ${output}\n`);
  return 0;
}

async function checkCommand(options, environment) {
  assertOptions(options, [
    'candidate', 'git_root', 'root', 'evidence_root', 'manifest', 'receipt', 'authorization',
    'policy', 'trust', 'dossier', 'embed_evidence', 'at', 'json', 'expected_policy_digest',
    'expected_trust_digest', 'expected_repository', 'expected_environment',
  ]);
  const json = booleanFlag(options, 'json');
  const embedEvidence = booleanFlag(options, 'embed_evidence');
  const candidate = normalizeCandidate(required(options, 'candidate'));
  const gitRoot = path.resolve(options.git_root ?? options.root ?? process.cwd());
  const evidenceRoot = path.resolve(options.evidence_root ?? options.root ?? gitRoot);
  const manifestPath = options.manifest ?? '.assurance/manifest.json';
  const receiptPath = options.receipt ?? '.assurance/verifier-receipt.json';
  const authorizationPath = options.authorization ?? '.assurance/authorization.json';
  const policyPath = options.policy ?? '.assurance/policy.json';
  const trustPath = options.trust ?? '.assurance/trust.json';
  const dossierPath = path.resolve(options.dossier ?? '.assurance/out/dossier.json');
  const manifest = await readJson(path.resolve(manifestPath));
  const receipt = await readOptionalJson(path.resolve(receiptPath));
  const authorization = await readOptionalJson(path.resolve(authorizationPath));
  const policy = await readJson(path.resolve(policyPath));
  const trustStore = await readJson(path.resolve(trustPath));
  const gitState = await inspectGitState(gitRoot);
  const receiverContext = {
    expectedPolicyDigest: normalizeSha256(required(options, 'expected_policy_digest')),
    expectedTrustStoreDigest: normalizeSha256(required(options, 'expected_trust_digest')),
    expectedRepository: required(options, 'expected_repository'),
    expectedEnvironment: required(options, 'expected_environment'),
    actualCandidateDigest: gitState.candidateDigest,
    actualTreeDigest: gitState.treeDigest,
    workingTreeClean: gitState.workingTreeClean,
  };
  const at = options.at ?? new Date().toISOString();
  const dossier = await createDossier({
    manifest,
    receipt,
    authorization,
    policy,
    trustStore,
    evidenceRoot,
    candidate,
    receiverContext,
    at,
    embedEvidence,
  });
  await writeJsonAtomic(dossierPath, dossier);
  if (json) {
    process.stdout.write(`${JSON.stringify({
      decision: dossier.decision,
      dossier: dossierPath,
      dossierDigest: dossier.dossierDigest,
    }, null, 2)}\n`);
  } else {
    emitDecision(dossier.decision, false);
    process.stdout.write(`Dossier: ${dossierPath}\nDigest: ${dossier.dossierDigest}\n`);
  }
  if (environment.GITHUB_OUTPUT) {
    await appendGithubOutput(environment.GITHUB_OUTPUT, {
      conclusion: dossier.decision.conclusion,
      dossier: dossierPath,
      dossier_digest: dossier.dossierDigest,
    });
  }
  if (environment.GITHUB_STEP_SUMMARY) {
    await writeDecisionSummary(environment.GITHUB_STEP_SUMMARY, dossier.decision, dossierPath, dossier.dossierDigest);
  }
  return EXIT[dossier.decision.conclusion];
}

async function verifyDossierCommand(options) {
  assertOptions(options, [
    'dossier', 'trust', 'candidate', 'tree_digest', 'working_tree_clean', 'expected_policy_digest',
    'expected_trust_digest', 'expected_repository', 'expected_environment', 'at', 'json',
  ]);
  const json = booleanFlag(options, 'json');
  const dossier = await readJson(required(options, 'dossier'), { maxBytes: 67_108_864 });
  const trustStore = await readJson(required(options, 'trust'));
  const candidate = normalizeCandidate(required(options, 'candidate'));
  const receiverContext = {
    expectedPolicyDigest: normalizeSha256(required(options, 'expected_policy_digest')),
    expectedTrustStoreDigest: normalizeSha256(required(options, 'expected_trust_digest')),
    expectedRepository: required(options, 'expected_repository'),
    expectedEnvironment: required(options, 'expected_environment'),
    actualCandidateDigest: candidate,
    actualTreeDigest: normalizeTreeDigest(required(options, 'tree_digest')),
    workingTreeClean: normalizeBoolean(required(options, 'working_tree_clean'), 'working-tree-clean'),
  };
  const result = verifyDossier(dossier, trustStore, {
    at: options.at ?? new Date().toISOString(),
    candidate,
    receiverContext,
  });
  if (json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  else {
    process.stdout.write(`Integrity: ${result.integrity}\nReproduction: ${result.recordedReproduction}\nEvidence: ${result.verificationLevel}\nAnchoring: UNANCHORED\nRecorded: ${result.recorded.conclusion}\nCurrent: ${result.current.conclusion}\n`);
    for (const entry of result.current.reasons) process.stdout.write(`  ${entry.severity} ${entry.code}: ${entry.message}\n`);
  }
  return EXIT[result.current.conclusion];
}

async function demoCommand(options) {
  assertOptions(options, ['out', 'candidate', 'tree_digest', 'repository', 'environment']);
  const output = path.resolve(options.out ?? 'artifacts/demo');
  const bundle = createExampleBundle(new Date(), {
    candidate: options.candidate ? normalizeCandidate(options.candidate) : undefined,
    treeDigest: options.tree_digest ? normalizeTreeDigest(options.tree_digest) : undefined,
    repository: options.repository,
    environment: options.environment,
  });
  await writeExampleBundle(output, bundle);
  const dossier = await createDossier({
    manifest: bundle.manifest,
    receipt: bundle.receipt,
    authorization: bundle.authorization,
    policy: bundle.policy,
    trustStore: bundle.trustStore,
    evidenceRoot: output,
    candidate: bundle.candidate,
    receiverContext: bundle.receiverContext,
    at: bundle.at,
    embedEvidence: true,
  });
  const dossierPath = path.join(output, 'dossier.json');
  await writeJsonAtomic(dossierPath, dossier);
  const verification = verifyDossier(dossier, bundle.trustStore, {
    at: bundle.at,
    candidate: bundle.candidate,
    receiverContext: bundle.receiverContext,
  });
  process.stdout.write(`SprintLoop Assurance golden path\nDecision: ${dossier.decision.conclusion}\nIntegrity: ${verification.integrity}\nEvidence: ${verification.verificationLevel}\nDossier: ${dossierPath}\nDigest: ${dossier.dossierDigest}\n`);
  return EXIT[dossier.decision.conclusion];
}

async function initCommand(options) {
  assertOptions(options, ['directory']);
  const root = path.resolve(options.directory ?? '.');
  const policy = createExampleBundle(new Date()).policy;
  const workflow = `name: assurance-shadow

on:
  pull_request:

permissions:
  contents: read

jobs:
  exact-candidate-assurance:
    runs-on: ubuntu-24.04
    steps:
      - name: Checkout exact candidate
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          repository: \${{ github.event.pull_request.head.repo.full_name }}
          ref: \${{ github.event.pull_request.head.sha }}
          path: candidate
          fetch-depth: 1
          persist-credentials: false
      - name: Checkout protected receiver configuration
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          repository: \${{ github.repository }}
          ref: \${{ github.event.pull_request.base.sha }}
          path: receiver
          sparse-checkout: |
            .assurance/policy.json
            .assurance/trust.json
          sparse-checkout-cone-mode: false
          persist-credentials: false
      # A receiver-governed authenticated retrieval step must populate this
      # runner-temp inbox. The checked stub performs no network or credential work.
      - name: Require authenticated out-of-band bundle
        id: bundle
        uses: SamSnead85/SprintLoop-Assurance-Kit/materialize-bundle@0d3f6f0a27f7244d0ec0eb6d924df191b6180a0a
        with:
          source: \${{ runner.temp }}/assurance-provider-inbox
          destination: \${{ runner.temp }}/assurance-bundle
          candidate-root: candidate
          candidate: \${{ github.event.pull_request.head.sha }}
          policy: receiver/.assurance/policy.json
          trust: receiver/.assurance/trust.json
          expected-policy-digest: \${{ vars.ASSURANCE_POLICY_DIGEST }}
          expected-trust-digest: \${{ vars.ASSURANCE_TRUST_DIGEST }}
          expected-repository: \${{ github.server_url }}/\${{ github.repository }}
          expected-environment: \${{ vars.ASSURANCE_ENVIRONMENT }}
      # Shadow/minimum integration only. Pin both Actions to one reviewed commit.
      - name: Evaluate exact candidate
        uses: SamSnead85/SprintLoop-Assurance-Kit@0d3f6f0a27f7244d0ec0eb6d924df191b6180a0a
        with:
          candidate: \${{ github.event.pull_request.head.sha }}
          candidate-root: candidate
          evidence-root: \${{ steps.bundle.outputs.evidence-root }}
          manifest: \${{ steps.bundle.outputs.manifest }}
          receipt: \${{ steps.bundle.outputs.receipt }}
          authorization: \${{ steps.bundle.outputs.authorization }}
          policy: receiver/.assurance/policy.json
          trust: receiver/.assurance/trust.json
          expected-policy-digest: \${{ vars.ASSURANCE_POLICY_DIGEST }}
          expected-trust-digest: \${{ vars.ASSURANCE_TRUST_DIGEST }}
          expected-repository: \${{ github.server_url }}/\${{ github.repository }}
          expected-environment: \${{ vars.ASSURANCE_ENVIRONMENT }}
          dossier: \${{ runner.temp }}/assurance-dossier.json
`;
  await writeJsonAtomic(path.join(root, '.assurance/policy.json'), policy);
  await writeJsonAtomic(path.join(root, '.assurance/trust.example.json'), {
    schemaVersion: 'assurance.sprintloop.dev/trust-store/v1',
    trustDomain: 'organization:release',
    keys: [],
  });
  try {
    await writeTextExclusive(path.join(root, '.github/workflows/assurance.yml'), workflow);
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
  }
  process.stdout.write(`Initialized policy and workflow templates in ${root}\nNo credentials or private keys were generated.\nThe workflow fails closed until a receiver-governed provider populates its external runner inbox.\n`);
  return 0;
}

async function inspectGitState(root) {
  try {
    const state = await inspectReceiverGitState(root);
    return {
      candidateDigest: normalizeCandidate(state.head),
      treeDigest: normalizeTreeDigest(state.tree),
      workingTreeClean: state.workingTreeClean,
    };
  } catch (error) {
    throw new UsageError(`Cannot resolve an exact Git HEAD and tree at ${root}: ${error.message}`);
  }
}

function emitDecision(decision, json) {
  if (json) {
    process.stdout.write(`${JSON.stringify(decision, null, 2)}\n`);
    return;
  }
  process.stdout.write(`${decision.conclusion} ${decision.subjectDigest}\n${decision.summary}\n`);
  for (const entry of decision.reasons) process.stdout.write(`  ${entry.severity} ${entry.code}: ${entry.message}\n`);
}

async function writeDecisionSummary(file, decision, dossierPath, digest) {
  const rows = decision.reasons.length
    ? decision.reasons.map((entry) => `| ${entry.severity} | \`${entry.code}\` | ${entry.message} |`).join('\n')
    : '| PASS | `assurance.complete` | All required bindings and standing are valid. |';
  const markdown = `## SprintLoop Assurance: ${decision.conclusion}\n\n${decision.summary}\n\n| State | Code | Detail |\n| --- | --- | --- |\n${rows}\n\nDossier: \`${dossierPath}\`  \nDigest: \`${digest}\`\n`;
  const { appendFile } = await import('node:fs/promises');
  await appendFile(file, markdown, 'utf8');
}

function normalizeCandidate(candidate) {
  if (!candidate) return undefined;
  if (candidate.startsWith('git:')) return candidate;
  if (/^[0-9a-f]{40}$/.test(candidate)) return `git:sha1:${candidate}`;
  if (/^[0-9a-f]{64}$/.test(candidate)) return `git:sha256:${candidate}`;
  throw new UsageError('Candidate must be a lowercase 40/64-character Git digest or canonical git digest');
}

function normalizeTreeDigest(tree) {
  if (!tree) throw new UsageError('Tree digest is required');
  if (tree.startsWith('git-tree:')) return tree;
  if (/^[0-9a-f]{40}$/.test(tree)) return `git-tree:sha1:${tree}`;
  if (/^[0-9a-f]{64}$/.test(tree)) return `git-tree:sha256:${tree}`;
  throw new UsageError('Tree must be a lowercase 40/64-character Git tree digest or canonical git-tree digest');
}

function normalizeSha256(value) {
  if (!/^sha256:[0-9a-f]{64}$/.test(value)) throw new UsageError('Expected receiver digest must use lowercase sha256:<64 hex>');
  return value;
}

function normalizeBoolean(value, name) {
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new UsageError(`--${name} must be true or false`);
}

function required(options, name) {
  const value = options[name];
  if (!value || value === true) throw new UsageError(`Missing --${name.replaceAll('_', '-')}`);
  return value;
}

function assertOptions(options, allowed) {
  if (options._.length > 0) throw new UsageError(`Unexpected positional argument: ${options._[0]}`);
  const permitted = new Set(['_', ...allowed]);
  const unknown = Object.keys(options).filter((key) => !permitted.has(key)).sort();
  if (unknown.length > 0) throw new UsageError(`Unknown option: --${unknown[0].replaceAll('_', '-')}`);
}

function booleanFlag(options, name) {
  const value = options[name];
  if (value === undefined) return false;
  if (value !== true) throw new UsageError(`--${name.replaceAll('_', '-')} does not accept a value`);
  return true;
}

function optionalText(options, name) {
  const value = options[name];
  if (value === undefined) return undefined;
  if (value === true || typeof value !== 'string' || value.length === 0) {
    throw new UsageError(`--${name.replaceAll('_', '-')} requires a value`);
  }
  return value;
}

function optionalInteger(options, name) {
  const value = optionalText(options, name);
  if (value === undefined) return undefined;
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new UsageError(`--${name.replaceAll('_', '-')} must be a positive integer`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new UsageError(`--${name.replaceAll('_', '-')} must be a positive safe integer`);
  }
  return parsed;
}

export class UsageError extends Error {}

const HELP = `SprintLoop Assurance Kit

Proof before permission for an exact agent-built candidate.

Commands:
  version [--json]
  doctor [--root DIR] [--policy FILE] [--trust FILE] [--expected-head SHA]
         [--expected-tree SHA] [--expected-policy-digest SHA256] [--expected-trust-digest SHA256]
         [--mcp-config ABSOLUTE_FILE] [--timeout-ms INTEGER] [--max-document-bytes INTEGER] [--json]
  collect-evidence --input JSON [--root DIR] [--path-base RELATIVE_PATH]
         [--subject-digest GIT_DIGEST] [--max-files INTEGER]
         [--max-file-bytes INTEGER] [--max-total-bytes INTEGER]
  init [--directory DIR]
  demo [--out DIR] [--candidate SHA] [--tree-digest TREE] [--repository URL] [--environment NAME]
  digest --file FILE
  document-digest --file JSON
  sign-receipt --input FILE --private-key PEM --key-id ID --output FILE
  sign-authorization --input FILE --private-key PEM --key-id ID --output FILE
  check --candidate SHA --expected-policy-digest SHA256 --expected-trust-digest SHA256
        --expected-repository URL --expected-environment NAME [--git-root DIR] [--evidence-root DIR]
        [--manifest FILE] [--receipt FILE] [--authorization FILE] [--policy FILE] [--trust FILE]
        [--dossier FILE] [--embed-evidence] [--at ISO] [--json]
  verify-dossier --dossier FILE --trust FILE --candidate SHA --tree-digest TREE
        --working-tree-clean true|false --expected-policy-digest SHA256 --expected-trust-digest SHA256
        --expected-repository URL --expected-environment NAME [--at ISO] [--json]

Help flags (top-level or after a command): --help, -h.
Top-level version flags: --version, -V.
Exit codes: 0 PASS, 10 setup warning/HOLD, 20 BLOCK, 2 usage/runtime error.
`;

const MCP_HELP = HELP.replace('  digest --file FILE\n', '  mcp --config ABSOLUTE_FILE\n  digest --file FILE\n');

export async function main(argv = process.argv.slice(2), environment = process.env) {
  try {
    return await run(argv, environment);
  } catch (error) {
    const prefix = error instanceof UsageError ? 'Usage error' : 'Assurance error';
    process.stderr.write(`${prefix}: ${safeLogMessage(error)}\n`);
    return EXIT.ERROR;
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
