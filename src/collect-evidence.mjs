import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { readHandleBounded } from './bounded.mjs';
import { sha256 } from './canonical.mjs';
import { parseJsonStrictText, parseJsonStrictTextMeasured } from './strict-json.mjs';
import { isPortableRelativePath } from './portable-path.mjs';

const DEFAULT_MAX_FILES = 32;
const DEFAULT_MAX_FILE_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024;
const HARD_MAX_FILES = 256;
const HARD_MAX_FILE_BYTES = 64 * 1024 * 1024;
const HARD_MAX_TOTAL_BYTES = 256 * 1024 * 1024;
const MAX_XML_DEPTH = 128;
const MAX_XML_TOKENS = 250_000;
const MAX_JSON_VALUES = 250_000;
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const SUBJECT_PATTERN = /^git:(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$/u;
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const MEDIA_TYPE_PATTERN = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,127}\/[A-Za-z0-9!#$%&'*+.^_`|~-]{1,127}$/u;
const FORMAT_NAMES = Object.freeze(['junit', 'sarif', 'spdx', 'cyclonedx', 'in-toto', 'sigstore']);
const SIGSTORE_MEDIA_TYPES = new Map([
  ['application/vnd.dev.sigstore.bundle+json;version=0.1', '0.1'],
  ['application/vnd.dev.sigstore.bundle+json;version=0.2', '0.2'],
  ['application/vnd.dev.sigstore.bundle+json;version=0.3', '0.3'],
  ['application/vnd.dev.sigstore.bundle.v0.3+json', '0.3'],
]);

export const EVIDENCE_FORMATS = FORMAT_NAMES;

export class EvidenceCollectionError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = 'EvidenceCollectionError';
    this.code = code;
  }
}

/**
 * Collect bounded, deterministic metadata for CI evidence files.
 *
 * Paths are resolved below one canonical root. Output order is by input id,
 * then path, and no report messages, names, source locations, package names,
 * subjects, signatures, certificates, or payloads are copied to the result.
 */
export async function collectEvidence(inputs, options = {}, internalHooks = {}) {
  if (!Array.isArray(inputs) || inputs.length === 0) {
    fail('EINVAL', 'Evidence inputs must be a non-empty array');
  }
  const limits = readLimits(options);
  const subjectDigest = options.subjectDigest === undefined
    ? undefined
    : normalizeSubjectDigest(options.subjectDigest);
  if (inputs.length > limits.maxFiles) {
    fail('ECOUNT', `Evidence input count exceeds ${limits.maxFiles}`);
  }
  const root = await canonicalRoot(options.root ?? '.', options.rootIdentity, internalHooks);
  const descriptors = inputs.map((input) => normalizeInput(input));
  rejectDescriptorDuplicates(descriptors);
  descriptors.sort((left, right) => lexical(left.id, right.id) || lexical(left.path, right.path));

  const identities = new Set();
  let totalBytes = 0;
  const evidence = [];
  for (const descriptor of descriptors) {
    await assertRootStable(root);
    const remainingBytes = limits.maxTotalBytes - totalBytes;
    if (remainingBytes < 1) fail('ETOOLARGE', `Evidence inputs exceed ${limits.maxTotalBytes} aggregate bytes`);
    const loaded = await readEvidenceFile(root.path, descriptor, Math.min(limits.maxFileBytes, remainingBytes));
    if (identities.has(loaded.identity)) {
      fail('EDUPLICATE', `Evidence input ${descriptor.id} aliases another input`);
    }
    identities.add(loaded.identity);
    totalBytes += loaded.bytes.length;
    if (totalBytes > limits.maxTotalBytes) {
      fail('ETOOLARGE', `Evidence inputs exceed ${limits.maxTotalBytes} aggregate bytes`);
    }
    evidence.push(inspectEvidence(descriptor, loaded.bytes));
    await assertRootStable(root);
  }

  await assertRootStable(root);
  const collection = {
    schemaVersion: 'assurance.sprintloop.dev/evidence-collection/v1',
    // Every evidence path is relative to this caller-established base. The
    // collector never returns an absolute host path. MCP supplies the selected
    // bundle-relative evidence root here so downstream manifest construction
    // cannot silently assume the bundle root itself.
    pathBase: normalizePathBase(options.pathBase ?? '.'),
    evidence,
    totals: {
      itemCount: evidence.length,
      byteCount: totalBytes,
      structureFullCount: evidence.filter((item) => item.inspectionLevel === 'STRUCTURE_FULL').length,
      envelopeOnlyCount: evidence.filter((item) => item.inspectionLevel === 'ENVELOPE_ONLY').length,
    },
  };
  if (subjectDigest !== undefined) collection.manifestEvidence = toManifestEvidence(collection, subjectDigest);
  return collection;
}

export async function collectEvidenceFile(input, options = {}) {
  const collection = await collectEvidence([input], options);
  return collection.evidence[0];
}

/** Reduce a collection to exact manifest evidence bound to one observed Git subject. */
export function toManifestEvidence(collection, subjectDigest) {
  const subject = normalizeSubjectDigest(subjectDigest);
  if (!isPlainObject(collection)
    || collection.schemaVersion !== 'assurance.sprintloop.dev/evidence-collection/v1'
    || !isPortableRelativePath(collection.pathBase, { allowDot: true })
    || !Array.isArray(collection.evidence) || collection.evidence.length < 1 || collection.evidence.length > HARD_MAX_FILES) {
    fail('EINVAL', 'Evidence collection is invalid');
  }
  const ids = new Set();
  const paths = new Set();
  return collection.evidence.map((entry) => {
    if (!isPlainObject(entry) || !ID_PATTERN.test(entry.id ?? '') || !ID_PATTERN.test(entry.type ?? '')
      || !isPortableRelativePath(entry.path) || !MEDIA_TYPE_PATTERN.test(entry.mediaType ?? '')
      || !SHA256_PATTERN.test(entry.digest ?? '')) {
      fail('EINVAL', 'Evidence collection contains an invalid manifest projection');
    }
    const projectedPath = collection.pathBase === '.' ? entry.path : `${collection.pathBase}/${entry.path}`;
    if (!isPortableRelativePath(projectedPath)) fail('EPATH', 'Composed manifest evidence path is invalid');
    if (ids.has(entry.id) || paths.has(projectedPath)) fail('EDUPLICATE', 'Manifest evidence projection is ambiguous');
    ids.add(entry.id);
    paths.add(projectedPath);
    return {
      id: entry.id,
      type: entry.type,
      path: projectedPath,
      mediaType: entry.mediaType,
      digest: entry.digest,
      subjectDigest: subject,
    };
  });
}

function readLimits(options) {
  if (!isPlainObject(options)) fail('EINVAL', 'Collector options must be an object');
  const allowed = new Set(['root', 'rootIdentity', 'pathBase', 'subjectDigest', 'maxFiles', 'maxFileBytes', 'maxTotalBytes']);
  if (Object.keys(options).some((key) => !allowed.has(key))) fail('EINVAL', 'Collector options contain an unsupported field');
  const maxFiles = boundedOption(options.maxFiles, DEFAULT_MAX_FILES, HARD_MAX_FILES, 'maxFiles');
  const maxFileBytes = boundedOption(options.maxFileBytes, DEFAULT_MAX_FILE_BYTES, HARD_MAX_FILE_BYTES, 'maxFileBytes');
  const maxTotalBytes = boundedOption(options.maxTotalBytes, DEFAULT_MAX_TOTAL_BYTES, HARD_MAX_TOTAL_BYTES, 'maxTotalBytes');
  if (maxTotalBytes < maxFileBytes) {
    fail('EINVAL', 'maxTotalBytes must be greater than or equal to maxFileBytes');
  }
  return { maxFiles, maxFileBytes, maxTotalBytes };
}

function normalizePathBase(value) {
  if (!isPortableRelativePath(value, { allowDot: true })) fail('EINVAL', 'pathBase must be a portable relative path');
  return value;
}

function normalizeSubjectDigest(value) {
  if (typeof value !== 'string' || !SUBJECT_PATTERN.test(value)) fail('EINVAL', 'subjectDigest must be a canonical Git digest');
  return value;
}

function boundedOption(value, fallback, hardMaximum, name) {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < 1 || selected > hardMaximum) {
    fail('EINVAL', `${name} must be a positive safe integer no greater than ${hardMaximum}`);
  }
  return selected;
}

async function canonicalRoot(rootInput, expectedIdentity, { afterRootLeafLstat } = {}) {
  if (typeof rootInput !== 'string' || rootInput.length === 0) fail('EINVAL', 'Evidence root must be non-empty text');
  if (expectedIdentity !== undefined && (!isPlainObject(expectedIdentity)
    || !Number.isSafeInteger(expectedIdentity.dev) || !Number.isSafeInteger(expectedIdentity.ino)
    || Object.keys(expectedIdentity).some((key) => !['dev', 'ino'].includes(key)))) {
    fail('EINVAL', 'Evidence root identity is invalid');
  }
  try {
    const requested = path.resolve(rootInput);
    const before = await lstat(requested);
    if (!before.isDirectory() || before.isSymbolicLink()) {
      fail(expectedIdentity ? 'ESTALE' : 'ENOTDIR', 'Evidence root is not a stable directory');
    }
    await afterRootLeafLstat?.();
    const root = await realpath(requested);
    const stat = await lstat(root);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      fail(expectedIdentity ? 'ESTALE' : 'ENOTDIR', 'Evidence root is not a stable directory');
    }
    const identity = { dev: stat.dev, ino: stat.ino };
    if (!sameIdentity(before, identity)) fail('ESTALE', 'Evidence root changed while its capability was being bound');
    if (expectedIdentity && !sameIdentity(identity, expectedIdentity)) fail('ESTALE', 'Evidence root changed after capability resolution');
    const binding = { requested, path: root, identity };
    await assertRootStable(binding);
    return binding;
  } catch (error) {
    if (error instanceof EvidenceCollectionError) throw error;
    fail(expectedIdentity ? 'ESTALE' : 'EROOT', 'Evidence root is unavailable', error);
  }
}

async function assertRootStable(root) {
  try {
    const requestedMetadata = await lstat(root.requested);
    const resolvedAgain = await realpath(root.requested);
    const canonicalMetadata = await lstat(root.path);
    if (!requestedMetadata.isDirectory() || requestedMetadata.isSymbolicLink()
      || !canonicalMetadata.isDirectory() || canonicalMetadata.isSymbolicLink()
      || resolvedAgain !== root.path || !sameIdentity(requestedMetadata, root.identity)
      || !sameIdentity(canonicalMetadata, root.identity)) {
      fail('ESTALE', 'Evidence root changed during collection');
    }
  } catch (error) {
    if (error instanceof EvidenceCollectionError) throw error;
    fail('ESTALE', 'Evidence root changed during collection', error);
  }
}

function normalizeInput(input) {
  if (!isPlainObject(input)) fail('EINVAL', 'Each evidence input must be an object');
  const allowed = new Set(['id', 'path', 'format']);
  if (Object.keys(input).some((key) => !allowed.has(key))) fail('EINVAL', 'Evidence input contains an unsupported field');
  if (typeof input.id !== 'string' || !ID_PATTERN.test(input.id)) fail('EINVAL', 'Evidence input id is invalid');
  if (!isPortableRelativePath(input.path)) fail('EPATH', `Evidence input ${input.id} has an unsafe path`);
  const format = input.format ?? 'auto';
  if (format !== 'auto' && !FORMAT_NAMES.includes(format)) fail('EINVAL', `Evidence input ${input.id} has an unsupported format`);
  return { id: input.id, path: input.path, format };
}

function rejectDescriptorDuplicates(descriptors) {
  const ids = new Set();
  const paths = new Set();
  for (const descriptor of descriptors) {
    if (ids.has(descriptor.id)) fail('EDUPLICATE', `Evidence input id ${descriptor.id} is duplicated`);
    if (paths.has(descriptor.path)) fail('EDUPLICATE', `Evidence input path for ${descriptor.id} is duplicated`);
    ids.add(descriptor.id);
    paths.add(descriptor.path);
  }
}

async function readEvidenceFile(root, descriptor, maxBytes) {
  const absolute = path.join(root, ...descriptor.path.split('/'));
  if (!inside(root, absolute)) fail('EPATH', `Evidence input ${descriptor.id} escapes its root`);
  let current = root;
  let leaf;
  try {
    for (const [index, component] of descriptor.path.split('/').entries()) {
      current = path.join(current, component);
      const stat = await lstat(current);
      if (stat.isSymbolicLink()) fail('ESYMLINK', `Evidence input ${descriptor.id} contains a symbolic link`);
      const isLeaf = index === descriptor.path.split('/').length - 1;
      if (!isLeaf && !stat.isDirectory()) fail('EPATH', `Evidence input ${descriptor.id} has a non-directory path component`);
      if (isLeaf) leaf = stat;
    }
  } catch (error) {
    if (error instanceof EvidenceCollectionError) throw error;
    if (error?.code === 'ENOENT') fail('ENOENT', `Evidence input ${descriptor.id} is missing`, error);
    fail('EREAD', `Evidence input ${descriptor.id} cannot be inspected`, error);
  }
  if (!leaf?.isFile()) fail('ENOTFILE', `Evidence input ${descriptor.id} is not a regular file`);
  if (leaf.size > maxBytes) fail('ETOOLARGE', `Evidence input ${descriptor.id} exceeds ${maxBytes} bytes`);

  let handle;
  try {
    const actual = await realpath(absolute);
    if (!inside(root, actual) || actual !== absolute) fail('ESYMLINK', `Evidence input ${descriptor.id} does not resolve directly below its root`);
    handle = await open(absolute, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
    const before = await handle.stat();
    if (!before.isFile() || !sameIdentity(before, leaf)) fail('ESTALE', `Evidence input ${descriptor.id} changed before read`);
    const bytes = await readHandleBounded(handle, maxBytes);
    const [after, pathAfter, resolvedAfter] = await Promise.all([handle.stat(), lstat(absolute), realpath(absolute)]);
    if (!sameSnapshot(before, after) || !sameIdentity(after, pathAfter) || bytes.length !== after.size
      || pathAfter.isSymbolicLink() || resolvedAfter !== absolute || !inside(root, resolvedAfter)) {
      fail('ESTALE', `Evidence input ${descriptor.id} changed during read`);
    }
    return { bytes, identity: `${before.dev}:${before.ino}` };
  } catch (error) {
    if (error instanceof EvidenceCollectionError) throw error;
    if (error?.code === 'ELOOP') fail('ESYMLINK', `Evidence input ${descriptor.id} is a symbolic link`, error);
    if (error?.code === 'ETOOLARGE') fail('ETOOLARGE', `Evidence input ${descriptor.id} grew beyond ${maxBytes} bytes`, error);
    fail('EREAD', `Evidence input ${descriptor.id} cannot be read safely`, error);
  } finally {
    await handle?.close();
  }
}

function inside(root, candidate) {
  return candidate === root || candidate.startsWith(`${root}${path.sep}`);
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function sameSnapshot(left, right) {
  return sameIdentity(left, right) && left.size === right.size && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs && left.mode === right.mode;
}

function inspectEvidence(descriptor, bytes) {
  const text = decodeUtf8(bytes, descriptor.id);
  const leading = text.replace(/^\uFEFF/u, '').trimStart();
  let inspected;
  if (leading.startsWith('<')) {
    if (descriptor.format !== 'auto' && descriptor.format !== 'junit') {
      fail('EFORMAT', `Evidence input ${descriptor.id} does not match its declared format`);
    }
    inspected = inspectJunit(text, descriptor.id);
  } else if (leading.startsWith('{') || leading.startsWith('[')) {
    if (descriptor.format === 'junit') fail('EFORMAT', `Evidence input ${descriptor.id} does not match its declared format`);
    let document;
    try {
      document = parseJsonStrict(text, descriptor.id);
    } catch (error) {
      if (error instanceof EvidenceCollectionError && error.code === 'EMALFORMED'
        && (descriptor.format === 'auto' || descriptor.format === 'sigstore')) {
        inspected = inspectSigstoreJsonLines(text, descriptor.id);
      } else {
        throw error;
      }
    }
    if (!inspected) {
      const identified = identifyJsonFormat(document, descriptor.id);
      if (descriptor.format !== 'auto' && identified !== descriptor.format) {
        fail('EFORMAT', `Evidence input ${descriptor.id} does not match its declared format`);
      }
      inspected = inspectJsonFormat(identified, document, descriptor.id);
    }
  } else {
    fail('EFORMAT', `Evidence input ${descriptor.id} is not a supported evidence format`);
  }
  return {
    id: descriptor.id,
    type: inspected.type,
    path: descriptor.path,
    mediaType: inspected.mediaType,
    digest: sha256(bytes),
    sizeBytes: bytes.length,
    format: inspected.format,
    formatVersion: inspected.formatVersion,
    inspectionLevel: inspected.inspectionLevel,
    claimsVerified: false,
    summary: inspected.summary,
  };
}

function decodeUtf8(bytes, id) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (error) {
    fail('EUTF8', `Evidence input ${id} is not valid UTF-8`, error);
  }
}

function identifyJsonFormat(document, id) {
  if (!isPlainObject(document)) fail('EFORMAT', `Evidence input ${id} must contain a JSON object`);
  const matches = [];
  if (Object.hasOwn(document, 'version') && Object.hasOwn(document, 'runs')) matches.push('sarif');
  if (Object.hasOwn(document, 'spdxVersion') || Object.hasOwn(document, '@context')) matches.push('spdx');
  if (Object.hasOwn(document, 'bomFormat')) matches.push('cyclonedx');
  if (Object.hasOwn(document, '_type') || Object.hasOwn(document, 'predicateType')) matches.push('in-toto');
  if (Object.hasOwn(document, 'mediaType') && (Object.hasOwn(document, 'verificationMaterial')
    || String(document.mediaType).includes('sigstore.bundle'))) matches.push('sigstore');
  if (matches.length === 0) fail('EFORMAT', `Evidence input ${id} has no supported format identity`);
  if (matches.length > 1) fail('EAMBIGUOUS', `Evidence input ${id} matches multiple format identities`);
  return matches[0];
}

function inspectJsonFormat(format, document, id) {
  if (format === 'sarif') return inspectSarif(document, id);
  if (format === 'spdx') return inspectSpdx(document, id);
  if (format === 'cyclonedx') return inspectCycloneDx(document, id);
  if (format === 'in-toto') return inspectInToto(document, id);
  if (format === 'sigstore') return inspectSigstore(document, id);
  fail('EFORMAT', `Evidence input ${id} has an unsupported format`);
}

function inspectSarif(document, id) {
  requireExact(document.version, '2.1.0', id, 'SARIF version');
  const runs = requireArray(document.runs, id, 'SARIF runs');
  const counts = { error: 0, warning: 0, note: 0, none: 0, unresolved: 0, suppressionRequests: 0 };
  for (const run of runs) {
    requireObject(run, id, 'SARIF run');
    const tool = requireObject(run.tool, id, 'SARIF run tool');
    const driver = requireObject(tool.driver, id, 'SARIF tool driver');
    requireNonEmptyString(driver.name, id, 'SARIF driver name');
    const results = optionalArray(run.results, id, 'SARIF results');
    for (const result of results) {
      requireObject(result, id, 'SARIF result');
      if (result.level === undefined) counts.unresolved += 1;
      else {
        if (!['error', 'warning', 'note', 'none'].includes(result.level)) {
          fail('EMALFORMED', `Evidence input ${id} has an invalid SARIF result level`);
        }
        counts[result.level] += 1;
      }
      if (Object.hasOwn(result, 'suppressions')) {
        const suppressions = optionalArray(result.suppressions, id, 'SARIF suppressions');
        for (const suppression of suppressions) {
          requireObject(suppression, id, 'SARIF suppression');
          if (suppression.status !== undefined && !['accepted', 'underReview', 'rejected'].includes(suppression.status)) {
            fail('EMALFORMED', `Evidence input ${id} has an invalid SARIF suppression status`);
          }
        }
        counts.suppressionRequests += suppressions.length;
      }
    }
  }
  return inspected('static-analysis', 'application/sarif+json', 'sarif', '2.1.0', 'STRUCTURE_FULL', {
    runCount: runs.length,
    resultCount: counts.error + counts.warning + counts.note + counts.none + counts.unresolved,
    errorCount: counts.error,
    warningCount: counts.warning,
    noteCount: counts.note,
    noneCount: counts.none,
    unresolvedLevelCount: counts.unresolved,
    suppressionRequestCount: counts.suppressionRequests,
  });
}

function inspectSpdx(document, id) {
  if (Object.hasOwn(document, 'spdxVersion')) return inspectSpdx2(document, id);
  return inspectSpdx3(document, id);
}

function inspectSpdx2(document, id) {
  if (!['SPDX-2.2', 'SPDX-2.3'].includes(document.spdxVersion)) {
    fail('EMALFORMED', `Evidence input ${id} has an unsupported SPDX 2 version`);
  }
  requireExact(document.dataLicense, 'CC0-1.0', id, 'SPDX data license');
  requireExact(document.SPDXID, 'SPDXRef-DOCUMENT', id, 'SPDX document id');
  requireNonEmptyString(document.name, id, 'SPDX document name');
  requireNonEmptyString(document.documentNamespace, id, 'SPDX document namespace');
  const creationInfo = requireObject(document.creationInfo, id, 'SPDX creation info');
  const creators = requireArray(creationInfo.creators, id, 'SPDX creators');
  if (creators.length === 0) fail('EMALFORMED', `Evidence input ${id} has no SPDX creators`);
  creators.forEach((creator) => requireNonEmptyString(creator, id, 'SPDX creator'));
  requireTimestamp(creationInfo.created, id, 'SPDX creation timestamp');
  const packages = optionalArray(document.packages, id, 'SPDX packages');
  const files = optionalArray(document.files, id, 'SPDX files');
  const snippets = optionalArray(document.snippets, id, 'SPDX snippets');
  const relationships = optionalArray(document.relationships, id, 'SPDX relationships');
  const ids = new Set(['SPDXRef-DOCUMENT']);
  for (const entry of [...packages, ...files, ...snippets]) {
    requireObject(entry, id, 'SPDX element');
    const elementId = requireNonEmptyString(entry.SPDXID, id, 'SPDX element id');
    if (ids.has(elementId)) fail('EDUPLICATE', `Evidence input ${id} contains duplicate SPDX element ids`);
    ids.add(elementId);
  }
  for (const relationship of relationships) requireObject(relationship, id, 'SPDX relationship');
  return inspected('sbom', 'application/spdx+json', 'spdx', document.spdxVersion.slice(5), 'STRUCTURE_FULL', {
    documentCount: 1,
    packageCount: packages.length,
    fileCount: files.length,
    snippetCount: snippets.length,
    relationshipCount: relationships.length,
  });
}

function inspectSpdx3(document, id) {
  requireExact(document['@context'], 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld', id, 'SPDX context');
  const graph = requireArray(document['@graph'], id, 'SPDX graph');
  if (graph.length === 0) fail('EMALFORMED', `Evidence input ${id} has an empty SPDX graph`);
  const ids = new Set();
  let documentCount = 0;
  let packageCount = 0;
  let fileCount = 0;
  let relationshipCount = 0;
  for (const element of graph) {
    requireObject(element, id, 'SPDX graph element');
    const type = requireNonEmptyString(element.type ?? element['@type'], id, 'SPDX graph element type');
    const elementId = element.spdxId ?? element['@id'];
    if (elementId !== undefined) {
      requireNonEmptyString(elementId, id, 'SPDX graph element id');
      if (ids.has(elementId)) fail('EDUPLICATE', `Evidence input ${id} contains duplicate SPDX graph ids`);
      ids.add(elementId);
    }
    if (type === 'SpdxDocument' || type.endsWith('/SpdxDocument')) documentCount += 1;
    if (type === 'Package' || type.endsWith('_Package') || type.endsWith('/Package')) packageCount += 1;
    if (type === 'File' || type.endsWith('_File') || type.endsWith('/File')) fileCount += 1;
    if (type === 'Relationship' || type.endsWith('/Relationship')) relationshipCount += 1;
  }
  if (documentCount !== 1) fail('EMALFORMED', `Evidence input ${id} must contain exactly one SPDX document`);
  return inspected('sbom', 'application/spdx+json', 'spdx', '3.0.1', 'ENVELOPE_ONLY', {
    documentCount,
    graphElementCount: graph.length,
    packageCount,
    fileCount,
    relationshipCount,
  });
}

function inspectCycloneDx(document, id) {
  requireExact(document.bomFormat, 'CycloneDX', id, 'CycloneDX format');
  if (!['1.4', '1.5', '1.6', '1.7'].includes(document.specVersion)) {
    fail('EMALFORMED', `Evidence input ${id} has an unsupported CycloneDX version`);
  }
  if (!Number.isSafeInteger(document.version) || document.version < 1) {
    fail('EMALFORMED', `Evidence input ${id} has an invalid CycloneDX document version`);
  }
  const references = new Set();
  const roots = optionalArray(document.components, id, 'CycloneDX components');
  const components = [...roots];
  if (isPlainObject(document.metadata) && document.metadata.component !== undefined) components.push(document.metadata.component);
  let componentCount = 0;
  for (let index = 0; index < components.length; index += 1) {
    const component = requireObject(components[index], id, 'CycloneDX component');
    requireNonEmptyString(component.type, id, 'CycloneDX component type');
    requireNonEmptyString(component.name, id, 'CycloneDX component name');
    componentCount += 1;
    addOptionalReference(component['bom-ref'], references, id, 'CycloneDX component');
    components.push(...optionalArray(component.components, id, 'CycloneDX nested components'));
  }
  const services = optionalArray(document.services, id, 'CycloneDX services');
  for (const service of services) {
    requireObject(service, id, 'CycloneDX service');
    requireNonEmptyString(service.name, id, 'CycloneDX service name');
    addOptionalReference(service['bom-ref'], references, id, 'CycloneDX service');
  }
  const dependencies = optionalArray(document.dependencies, id, 'CycloneDX dependencies');
  const dependencyReferences = new Set();
  for (const dependency of dependencies) {
    requireObject(dependency, id, 'CycloneDX dependency');
    const reference = requireNonEmptyString(dependency.ref, id, 'CycloneDX dependency reference');
    if (dependencyReferences.has(reference)) fail('EDUPLICATE', `Evidence input ${id} contains duplicate CycloneDX dependency nodes`);
    dependencyReferences.add(reference);
    optionalArray(dependency.dependsOn, id, 'CycloneDX dependency edges').forEach((entry) => requireNonEmptyString(entry, id, 'CycloneDX dependency edge'));
  }
  const vulnerabilities = optionalArray(document.vulnerabilities, id, 'CycloneDX vulnerabilities');
  for (const vulnerability of vulnerabilities) requireObject(vulnerability, id, 'CycloneDX vulnerability');
  const compositions = optionalArray(document.compositions, id, 'CycloneDX compositions');
  for (const composition of compositions) requireObject(composition, id, 'CycloneDX composition');
  return inspected('sbom', 'application/vnd.cyclonedx+json', 'cyclonedx', document.specVersion, 'STRUCTURE_FULL', {
    componentCount,
    serviceCount: services.length,
    dependencyNodeCount: dependencies.length,
    vulnerabilityCount: vulnerabilities.length,
    compositionCount: compositions.length,
  });
}

function addOptionalReference(reference, references, id, label) {
  if (reference === undefined) return;
  requireNonEmptyString(reference, id, `${label} reference`);
  if (references.has(reference)) fail('EDUPLICATE', `Evidence input ${id} contains duplicate CycloneDX references`);
  references.add(reference);
}

function inspectInToto(document, id) {
  const statementVersions = new Map([
    ['https://in-toto.io/Statement/v0.1', '0.1'],
    ['https://in-toto.io/Statement/v1', '1'],
  ]);
  const statementVersion = statementVersions.get(document._type);
  if (!statementVersion) fail('EMALFORMED', `Evidence input ${id} has an unsupported in-toto statement version`);
  const subjects = requireArray(document.subject, id, 'in-toto subjects');
  if (subjects.length === 0) fail('EMALFORMED', `Evidence input ${id} has no in-toto subjects`);
  const subjectKeys = new Set();
  const algorithms = new Set();
  for (const subject of subjects) {
    requireObject(subject, id, 'in-toto subject');
    const digest = requireObject(subject.digest, id, 'in-toto subject digest');
    const entries = Object.entries(digest);
    if (entries.length === 0) fail('EMALFORMED', `Evidence input ${id} has an empty in-toto subject digest`);
    const normalized = [];
    for (const [algorithm, value] of entries.sort(([left], [right]) => lexical(left, right))) {
      if (!/^[A-Za-z][A-Za-z0-9_-]{0,63}$/u.test(algorithm) || typeof value !== 'string' || !/^[A-Fa-f0-9]{16,1024}$/u.test(value)) {
        fail('EMALFORMED', `Evidence input ${id} has an invalid in-toto subject digest`);
      }
      algorithms.add(algorithm);
      normalized.push(`${algorithm}:${value.toLowerCase()}`);
    }
    const key = normalized.join(',');
    if (subjectKeys.has(key)) fail('EDUPLICATE', `Evidence input ${id} contains duplicate in-toto subjects`);
    subjectKeys.add(key);
  }
  const predicateType = requireHttpsUri(document.predicateType, id, 'in-toto predicate type');
  const predicate = document.predicate ?? {};
  requireObject(predicate, id, 'in-toto predicate');
  let predicateProfile = 'generic';
  let dependencyCount = 0;
  if (predicateType === 'https://slsa.dev/provenance/v1') {
    predicateProfile = 'slsa-provenance-v1';
    const definition = requireObject(predicate.buildDefinition, id, 'SLSA build definition');
    requireHttpsUri(definition.buildType, id, 'SLSA build type');
    requireObject(definition.externalParameters, id, 'SLSA external parameters');
    if (definition.internalParameters !== undefined && definition.internalParameters !== null) {
      requireObject(definition.internalParameters, id, 'SLSA internal parameters');
    }
    const dependencies = optionalArray(definition.resolvedDependencies, id, 'SLSA resolved dependencies');
    dependencies.forEach((dependency) => requireObject(dependency, id, 'SLSA resolved dependency'));
    dependencyCount = dependencies.length;
    const runDetails = requireObject(predicate.runDetails, id, 'SLSA run details');
    const builder = requireObject(runDetails.builder, id, 'SLSA builder');
    requireHttpsUri(builder.id, id, 'SLSA builder id');
  } else if (predicateType === 'https://slsa.dev/provenance/v0.2') {
    predicateProfile = 'slsa-provenance-v0.2';
    const builder = requireObject(predicate.builder, id, 'SLSA builder');
    requireHttpsUri(builder.id, id, 'SLSA builder id');
    requireHttpsUri(predicate.buildType, id, 'SLSA build type');
    requireObject(predicate.invocation, id, 'SLSA invocation');
    const materials = optionalArray(predicate.materials, id, 'SLSA materials');
    materials.forEach((materialEntry) => requireObject(materialEntry, id, 'SLSA material'));
    dependencyCount = materials.length;
  }
  return inspected('provenance', 'application/vnd.in-toto+json', 'in-toto', statementVersion, 'ENVELOPE_ONLY', {
    predicateProfile,
    subjectCount: subjects.length,
    subjectDigestAlgorithmCount: algorithms.size,
    dependencyCount,
  });
}

function inspectSigstore(document, id) {
  const version = SIGSTORE_MEDIA_TYPES.get(document.mediaType);
  if (!version) fail('EMALFORMED', `Evidence input ${id} has an unsupported Sigstore bundle media type`);
  const material = requireObject(document.verificationMaterial, id, 'Sigstore verification material');
  const materialKinds = ['publicKey', 'x509CertificateChain', 'certificate'].filter((key) => Object.hasOwn(material, key));
  if (materialKinds.length !== 1) fail('EMALFORMED', `Evidence input ${id} has ambiguous Sigstore key material`);
  const keyMaterial = requireObject(material[materialKinds[0]], id, 'Sigstore key material');
  if (materialKinds[0] === 'certificate') requireBase64(keyMaterial.rawBytes, id, 'Sigstore certificate');
  if (materialKinds[0] === 'x509CertificateChain') {
    const certificates = requireArray(keyMaterial.certificates, id, 'Sigstore certificate chain');
    if (certificates.length === 0) fail('EMALFORMED', `Evidence input ${id} has an empty Sigstore certificate chain`);
    certificates.forEach((certificate) => requireBase64(
      requireObject(certificate, id, 'Sigstore certificate').rawBytes,
      id,
      'Sigstore certificate',
    ));
  }
  if (materialKinds[0] === 'publicKey' && keyMaterial.hint !== undefined) {
    requireNonEmptyString(keyMaterial.hint, id, 'Sigstore public-key hint');
  }
  const hasMessage = Object.hasOwn(document, 'messageSignature');
  const hasDsse = Object.hasOwn(document, 'dsseEnvelope');
  if (Number(hasMessage) + Number(hasDsse) !== 1) fail('EMALFORMED', `Evidence input ${id} has ambiguous Sigstore content`);
  let contentType;
  if (hasMessage) {
    contentType = 'message-signature';
    const signature = requireObject(document.messageSignature, id, 'Sigstore message signature');
    const messageDigest = requireObject(signature.messageDigest, id, 'Sigstore message digest');
    requireNonEmptyString(messageDigest.algorithm, id, 'Sigstore message-digest algorithm');
    requireBase64(messageDigest.digest, id, 'Sigstore message digest');
    requireBase64(signature.signature, id, 'Sigstore signature');
  } else {
    contentType = 'dsse-envelope';
    const envelope = requireObject(document.dsseEnvelope, id, 'Sigstore DSSE envelope');
    requireNonEmptyString(envelope.payloadType, id, 'Sigstore DSSE payload type');
    requireBase64(envelope.payload, id, 'Sigstore DSSE payload');
    const signatures = requireArray(envelope.signatures, id, 'Sigstore DSSE signatures');
    if (signatures.length !== 1) fail('EMALFORMED', `Evidence input ${id} must contain exactly one Sigstore DSSE signature`);
    requireBase64(requireObject(signatures[0], id, 'Sigstore DSSE signature').sig, id, 'Sigstore DSSE signature');
  }
  const tlogEntries = optionalArray(material.tlogEntries, id, 'Sigstore transparency log entries');
  tlogEntries.forEach((entry) => requireObject(entry, id, 'Sigstore transparency log entry'));
  let timestampCount = 0;
  if (material.timestampVerificationData !== undefined) {
    const timestamps = requireObject(material.timestampVerificationData, id, 'Sigstore timestamp material');
    const rfc3161 = optionalArray(timestamps.rfc3161Timestamps, id, 'Sigstore RFC3161 timestamps');
    rfc3161.forEach((timestamp) => requireBase64(
      requireObject(timestamp, id, 'Sigstore RFC3161 timestamp').signedTimestamp,
      id,
      'Sigstore RFC3161 timestamp',
    ));
    timestampCount = rfc3161.length;
  }
  return inspected('signature-bundle', 'application/vnd.dev.sigstore.bundle+json', 'sigstore', version, 'ENVELOPE_ONLY', {
    contentType,
    keyMaterialType: materialKinds[0],
    transparencyLogEntryCount: tlogEntries.length,
    timestampCount,
  });
}

function inspectSigstoreJsonLines(text, id) {
  const lines = text.replace(/\r\n/gu, '\n').split('\n');
  if (lines.at(-1) === '') lines.pop();
  if (lines.length < 1 || lines.length > HARD_MAX_FILES || lines.some((line) => line.trim().length === 0)) {
    fail('EMALFORMED', `Evidence input ${id} has invalid Sigstore JSONL framing`);
  }
  let remainingValues = MAX_JSON_VALUES;
  const bundles = lines.map((line) => {
    if (remainingValues < 1) fail('EMALFORMED', `Evidence input ${id} exceeds the JSON structural limit`);
    let parsed;
    try {
      parsed = parseJsonStrictTextMeasured(line, { maxValues: remainingValues });
    } catch (error) {
      fail('EMALFORMED', `Evidence input ${id} is malformed JSON`, error);
    }
    remainingValues -= parsed.valueCount;
    const document = parsed.value;
    if (identifyJsonFormat(document, id) !== 'sigstore') {
      fail('EFORMAT', `Evidence input ${id} contains a non-Sigstore JSONL record`);
    }
    return inspectSigstore(document, id);
  });
  const versions = new Set(bundles.map((bundle) => bundle.formatVersion));
  const contentTypes = new Set(bundles.map((bundle) => bundle.summary.contentType));
  const materialTypes = new Set(bundles.map((bundle) => bundle.summary.keyMaterialType));
  return inspected('signature-bundle', 'application/vnd.dev.sigstore.bundle+jsonl', 'sigstore',
    versions.size === 1 ? bundles[0].formatVersion : 'mixed', 'ENVELOPE_ONLY', {
      bundleCount: bundles.length,
      contentType: contentTypes.size === 1 ? bundles[0].summary.contentType : 'mixed',
      keyMaterialType: materialTypes.size === 1 ? bundles[0].summary.keyMaterialType : 'mixed',
      transparencyLogEntryCount: bundles.reduce((total, bundle) => total + bundle.summary.transparencyLogEntryCount, 0),
      timestampCount: bundles.reduce((total, bundle) => total + bundle.summary.timestampCount, 0),
    });
}

function inspected(type, mediaType, format, formatVersion, inspectionLevel, summary) {
  return { type, mediaType, format, formatVersion, inspectionLevel, summary };
}

function lexical(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function requireArray(value, id, label) {
  if (!Array.isArray(value)) fail('EMALFORMED', `Evidence input ${id} has invalid ${label}`);
  return value;
}

function optionalArray(value, id, label) {
  if (value === undefined || value === null) return [];
  return requireArray(value, id, label);
}

function requireObject(value, id, label) {
  if (!isPlainObject(value)) fail('EMALFORMED', `Evidence input ${id} has invalid ${label}`);
  return value;
}

function requireNonEmptyString(value, id, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 4096) {
    fail('EMALFORMED', `Evidence input ${id} has invalid ${label}`);
  }
  return value;
}

function requireHttpsUri(value, id, label) {
  requireNonEmptyString(value, id, label);
  let parsed;
  try {
    parsed = new URL(value);
  } catch (error) {
    fail('EMALFORMED', `Evidence input ${id} has invalid ${label}`, error);
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash || value.length > 2048) {
    fail('EMALFORMED', `Evidence input ${id} has invalid ${label}`);
  }
  return value;
}

function requireExact(value, expected, id, label) {
  if (value !== expected) fail('EMALFORMED', `Evidence input ${id} has invalid ${label}`);
}

function requireTimestamp(value, id, label) {
  requireNonEmptyString(value, id, label);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u.test(value) || !Number.isFinite(Date.parse(value))) {
    fail('EMALFORMED', `Evidence input ${id} has invalid ${label}`);
  }
}

function requireBase64(value, id, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 4 !== 0
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)
    || Buffer.from(value, 'base64').toString('base64') !== value) {
    fail('EMALFORMED', `Evidence input ${id} has invalid ${label}`);
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function parseJsonStrict(text, id) {
  try {
    return parseJsonStrictText(text);
  } catch (error) {
    if (error instanceof EvidenceCollectionError) throw error;
    fail('EMALFORMED', `Evidence input ${id} is malformed JSON`, error);
  }
}

function inspectJunit(text, id) {
  const source = text.startsWith('\uFEFF') ? text.slice(1) : text;
  const stack = [];
  let index = 0;
  let root;
  let rootFinished = false;
  let declarationSeen = false;
  let tokens = 0;
  const counts = { suites: 0, tests: 0, failures: 0, errors: 0, skipped: 0 };
  try {
    while (index < source.length) {
      const opening = source.indexOf('<', index);
      if (opening === -1) {
        validateXmlText(source.slice(index), stack.length > 0);
        index = source.length;
        break;
      }
      validateXmlText(source.slice(index, opening), stack.length > 0);
      index = opening;
      tokens += 1;
      if (tokens > MAX_XML_TOKENS) throw new RangeError('XML token limit exceeded');
      if (source.startsWith('<!--', index)) {
        const close = source.indexOf('-->', index + 4);
        const body = close < 0 ? '' : source.slice(index + 4, close);
        if (close < 0 || body.includes('--') || body.endsWith('-')) throw new SyntaxError('Invalid XML comment');
        validateXmlCharacters(body);
        index = close + 3;
        continue;
      }
      if (source.startsWith('<![CDATA[', index)) {
        if (stack.length === 0) throw new SyntaxError('CDATA outside root');
        const close = source.indexOf(']]>', index + 9);
        if (close < 0) throw new SyntaxError('Unterminated CDATA');
        validateXmlCharacters(source.slice(index + 9, close));
        index = close + 3;
        continue;
      }
      if (source.startsWith('<?', index)) {
        if (root !== undefined || declarationSeen || index !== 0) throw new SyntaxError('Processing instruction is not an XML declaration');
        const close = source.indexOf('?>', index + 2);
        if (close < 0) throw new SyntaxError('Unterminated processing instruction');
        const body = source.slice(index + 2, close);
        validateXmlCharacters(body);
        if (!/^xml[\u0009\u000a\u000d\u0020]+version[\u0009\u000a\u000d\u0020]*=[\u0009\u000a\u000d\u0020]*(?:"1\.[01]"|'1\.[01]')(?:[\u0009\u000a\u000d\u0020]+encoding[\u0009\u000a\u000d\u0020]*=[\u0009\u000a\u000d\u0020]*(?:"[Uu][Tt][Ff]-8"|'[Uu][Tt][Ff]-8'))?(?:[\u0009\u000a\u000d\u0020]+standalone[\u0009\u000a\u000d\u0020]*=[\u0009\u000a\u000d\u0020]*(?:"(?:yes|no)"|'(?:yes|no)'))?[\u0009\u000a\u000d\u0020]*$/u.test(body)) {
          throw new SyntaxError('Invalid XML declaration');
        }
        declarationSeen = true;
        index = close + 2;
        continue;
      }
      if (source.startsWith('<!', index)) throw new SyntaxError('Unsupported XML declaration');
      if (source.startsWith('</', index)) {
        const close = source.indexOf('>', index + 2);
        if (close < 0) throw new SyntaxError('Unterminated closing tag');
        const name = source.slice(index + 2, close).trim();
        if (!isXmlName(name) || stack.pop() !== name) throw new SyntaxError('Mismatched closing tag');
        if (stack.length === 0) rootFinished = true;
        index = close + 1;
        continue;
      }
      if (rootFinished) throw new SyntaxError('Multiple XML roots');
      const close = findXmlTagEnd(source, index + 1);
      const parsed = parseXmlStartTag(source.slice(index + 1, close));
      const parent = stack.at(-1);
      if (root === undefined) {
        if (!['testsuite', 'testsuites'].includes(parsed.name)) throw new SyntaxError('Unsupported XML root');
        root = parsed.name;
      }
      validateJunitPosition(parsed.name, parent, stack);
      if (parsed.name === 'testsuite') counts.suites += 1;
      if (parsed.name === 'testcase') counts.tests += 1;
      if (parsed.name === 'failure') counts.failures += 1;
      if (parsed.name === 'error') counts.errors += 1;
      if (parsed.name === 'skipped') counts.skipped += 1;
      if (!parsed.selfClosing) {
        stack.push(parsed.name);
        if (stack.length > MAX_XML_DEPTH) throw new RangeError('XML nesting limit exceeded');
      } else if (stack.length === 0) {
        rootFinished = true;
      }
      index = close + 1;
    }
    if (root === undefined || stack.length !== 0 || !rootFinished) throw new SyntaxError('Incomplete XML document');
    if (counts.suites === 0 && counts.tests === 0) throw new SyntaxError('JUnit document has no test cases or suites');
  } catch (error) {
    fail('EMALFORMED', `Evidence input ${id} is malformed JUnit XML`, error);
  }
  return inspected('test-report', 'application/junit+xml', 'junit', 'xml', 'STRUCTURE_FULL', {
    suiteCount: counts.suites,
    testCount: counts.tests,
    failureCount: counts.failures,
    errorCount: counts.errors,
    skippedCount: counts.skipped,
  });
}

function findXmlTagEnd(source, start) {
  let quote;
  for (let index = start; index < source.length; index += 1) {
    const character = source[index];
    if (quote) {
      if (character === quote) quote = undefined;
    } else if (character === '"' || character === "'") quote = character;
    else if (character === '>') return index;
    else if (character === '<') throw new SyntaxError('Nested tag opener');
  }
  throw new SyntaxError('Unterminated opening tag');
}

function parseXmlStartTag(raw) {
  let source = raw.trim();
  let selfClosing = false;
  if (source.endsWith('/')) {
    selfClosing = true;
    source = source.slice(0, -1).trimEnd();
  }
  const nameMatch = /^[A-Za-z_][A-Za-z0-9_.:-]*/u.exec(source);
  if (!nameMatch) throw new SyntaxError('Invalid tag name');
  const name = nameMatch[0];
  let index = name.length;
  const attributes = new Set();
  while (index < source.length) {
    const whitespace = /^[\u0009\u000a\u000d\u0020]+/u.exec(source.slice(index));
    if (!whitespace) throw new SyntaxError('Attribute separator expected');
    index += whitespace[0].length;
    if (index >= source.length) break;
    const attribute = /^[A-Za-z_][A-Za-z0-9_.:-]*/u.exec(source.slice(index));
    if (!attribute || attributes.has(attribute[0])) throw new SyntaxError('Invalid or duplicate attribute');
    attributes.add(attribute[0]);
    index += attribute[0].length;
    index += (/^[\u0009\u000a\u000d\u0020]*/u.exec(source.slice(index))?.[0].length ?? 0);
    if (source[index] !== '=') throw new SyntaxError('Attribute equals expected');
    index += 1;
    index += (/^[\u0009\u000a\u000d\u0020]*/u.exec(source.slice(index))?.[0].length ?? 0);
    const quote = source[index];
    if (quote !== '"' && quote !== "'") throw new SyntaxError('Quoted attribute expected');
    const close = source.indexOf(quote, index + 1);
    if (close < 0) throw new SyntaxError('Unterminated attribute');
    const value = source.slice(index + 1, close);
    if (value.includes('<')) throw new SyntaxError('Raw tag opener in attribute');
    validateXmlReferences(value);
    index = close + 1;
  }
  return { name, selfClosing };
}

function validateJunitPosition(name, parent, stack) {
  if (name === 'testsuites' && stack.length > 0) throw new SyntaxError('JUnit testsuites must be the root');
  if (name === 'testsuite' && parent !== undefined && parent !== 'testsuites' && parent !== 'testsuite') {
    throw new SyntaxError('JUnit suite has invalid parent');
  }
  if (name === 'testcase' && parent !== 'testsuite' && parent !== 'testsuites') throw new SyntaxError('JUnit testcase has invalid parent');
  if (['failure', 'error', 'skipped'].includes(name) && parent !== 'testcase') {
    throw new SyntaxError('JUnit outcome has invalid parent');
  }
  if (stack.length === 0 && !['testsuite', 'testsuites'].includes(name)) throw new SyntaxError('Invalid JUnit root');
}

function validateXmlText(value, insideRoot) {
  validateXmlCharacters(value);
  if (value.includes(']]>')) throw new SyntaxError('CDATA terminator in character data');
  if (!insideRoot && value.trim() !== '') throw new SyntaxError('Text outside XML root');
  validateXmlReferences(value);
}

function validateXmlCharacters(value) {
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\ufffe\uffff]/u.test(value)) throw new SyntaxError('Invalid XML character');
}

function validateXmlReferences(value) {
  validateXmlCharacters(value);
  for (let index = value.indexOf('&'); index >= 0; index = value.indexOf('&', index + 1)) {
    const close = value.indexOf(';', index + 1);
    if (close < 0) throw new SyntaxError('Unterminated XML reference');
    const reference = value.slice(index + 1, close);
    if (!['amp', 'lt', 'gt', 'apos', 'quot'].includes(reference) && !validNumericReference(reference)) {
      throw new SyntaxError('Unknown XML entity');
    }
    index = close;
  }
}

function validNumericReference(reference) {
  const hex = /^#x([A-Fa-f0-9]+)$/u.exec(reference);
  const decimal = /^#([0-9]+)$/u.exec(reference);
  if (!hex && !decimal) return false;
  const value = Number.parseInt((hex ?? decimal)[1], hex ? 16 : 10);
  return value === 0x9 || value === 0xa || value === 0xd
    || (value >= 0x20 && value <= 0xd7ff)
    || (value >= 0xe000 && value <= 0xfffd)
    || (value >= 0x10000 && value <= 0x10ffff);
}

function isXmlName(value) {
  return /^[A-Za-z_][A-Za-z0-9_.:-]*$/u.test(value);
}

function fail(code, message, cause) {
  throw new EvidenceCollectionError(code, message, cause ? { cause } : undefined);
}
