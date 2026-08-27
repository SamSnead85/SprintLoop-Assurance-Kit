import { lstat, realpath } from 'node:fs/promises';
import path from 'node:path';
import { readJson } from './read-json.mjs';

export const MCP_CONFIG_SCHEMA_VERSION = 'assurance.sprintloop.dev/mcp-server-config/v1';
export const DEFAULT_MCP_LIMITS = Object.freeze({
  maxMessageBytes: 1_048_576,
  maxJsonBytes: 1_048_576,
  maxDossierBytes: 67_108_864,
  maxToolCalls: 256,
});

const ROOT_KINDS = new Set(['bundle', 'receiver', 'dossier']);
const LIMIT_BOUNDS = Object.freeze({
  maxMessageBytes: [32_768, 4_194_304],
  maxJsonBytes: [1_024, 16_777_216],
  maxDossierBytes: [1_024, 134_217_728],
  maxToolCalls: [1, 10_000],
});

export class McpConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'McpConfigError';
  }
}

export class McpToolInputError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'McpToolInputError';
    this.code = code;
  }
}

export async function loadMcpConfig(file) {
  if (typeof file !== 'string' || !path.isAbsolute(file)) {
    throw new McpConfigError('MCP configuration path must be absolute');
  }
  let document;
  try {
    document = await readJson(file, { maxBytes: 131_072 });
  } catch (error) {
    throw new McpConfigError(configReadMessage(error));
  }
  const errors = validateMcpConfig(document);
  if (errors.length) throw new McpConfigError(`MCP configuration is invalid at ${errors.join(', ')}`);

  const roots = [];
  for (const grant of document.roots) {
    if (!path.isAbsolute(grant.path)) {
      throw new McpConfigError(`MCP root ${grant.id} must use an absolute path`);
    }
    if (path.resolve(grant.path) === path.parse(path.resolve(grant.path)).root) {
      throw new McpConfigError(`MCP root ${grant.id} cannot grant an entire filesystem root`);
    }
    let metadata;
    let resolved;
    try {
      metadata = await lstat(grant.path);
      if (metadata.isSymbolicLink()) throw new McpConfigError(`MCP root ${grant.id} cannot be a symbolic link`);
      if (!metadata.isDirectory()) throw new McpConfigError(`MCP root ${grant.id} must be a directory`);
      resolved = await realpath(grant.path);
      metadata = await lstat(resolved);
      if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
        throw new McpConfigError(`MCP root ${grant.id} must resolve to a directory`);
      }
    } catch (error) {
      if (error instanceof McpConfigError) throw error;
      throw new McpConfigError(`MCP root ${grant.id} is unavailable`);
    }
    roots.push(Object.freeze({
      id: grant.id,
      kind: grant.kind,
      path: resolved,
      identity: Object.freeze({ dev: metadata.dev, ino: metadata.ino }),
    }));
  }
  rejectOverlappingRoots(roots);
  return Object.freeze({
    schemaVersion: MCP_CONFIG_SCHEMA_VERSION,
    roots: Object.freeze(roots),
    limits: Object.freeze({ ...DEFAULT_MCP_LIMITS, ...(document.limits ?? {}) }),
  });
}

export function validateMcpConfig(value) {
  const errors = [];
  if (!isObject(value)) return ['$'];
  exactKeys(value, ['$schema', 'schemaVersion', 'roots', 'limits'], '$', errors);
  if (value.$schema !== undefined && !boundedString(value.$schema, 1, 2048)) errors.push('$.$schema');
  if (value.schemaVersion !== MCP_CONFIG_SCHEMA_VERSION) errors.push('$.schemaVersion');
  if (!Array.isArray(value.roots) || value.roots.length < 1 || value.roots.length > 16) {
    errors.push('$.roots');
  } else {
    const ids = new Set();
    value.roots.forEach((grant, index) => {
      const label = `$.roots[${index}]`;
      if (!isObject(grant)) {
        errors.push(label);
        return;
      }
      exactKeys(grant, ['id', 'kind', 'path'], label, errors);
      if (typeof grant.id !== 'string' || !/^[a-z][a-z0-9_-]{0,63}$/.test(grant.id)) errors.push(`${label}.id`);
      else if (ids.has(grant.id)) errors.push(`${label}.id(duplicate)`);
      else ids.add(grant.id);
      if (!ROOT_KINDS.has(grant.kind)) errors.push(`${label}.kind`);
      if (!boundedString(grant.path, 1, 4096)) errors.push(`${label}.path`);
    });
  }
  if (value.limits !== undefined) {
    if (!isObject(value.limits)) errors.push('$.limits');
    else {
      exactKeys(value.limits, Object.keys(LIMIT_BOUNDS), '$.limits', errors);
      for (const [name, [minimum, maximum]] of Object.entries(LIMIT_BOUNDS)) {
        const candidate = value.limits[name];
        if (candidate !== undefined && (!Number.isSafeInteger(candidate) || candidate < minimum || candidate > maximum)) {
          errors.push(`$.limits.${name}`);
        }
      }
    }
  }
  return [...new Set(errors)].sort();
}

export function publicMcpConfig(config) {
  return {
    roots: config.roots.map(({ id, kind }) => ({ id, kind })),
    limits: { ...config.limits },
  };
}

export async function resolveGrantedFile(config, rootId, kind, relative, { optional = false } = {}) {
  const binding = await resolveGrantedFileBinding(config, rootId, kind, relative, { optional });
  return binding.missing ? binding.requested : binding.resolved;
}

async function resolveGrantedFileBinding(config, rootId, kind, relative, { optional = false } = {}) {
  const grant = await requireGrant(config, rootId, kind);
  const segments = relativeSegments(relative, false);
  const candidate = path.resolve(grant.path, ...segments);
  if (!inside(grant.path, candidate)) throw new McpToolInputError('PATH_ESCAPE', 'Requested path escapes its configured root grant.');

  let cursor = grant.path;
  for (let index = 0; index < segments.length; index += 1) {
    cursor = path.join(cursor, segments[index]);
    let metadata;
    try {
      metadata = await lstat(cursor);
    } catch (error) {
      if (error?.code === 'ENOENT' && optional && index === segments.length - 1) {
        await assertGrantStable(grant);
        return { requested: candidate, missing: true };
      }
      if (error?.code === 'ENOENT') throw new McpToolInputError('FILE_NOT_FOUND', 'Requested file is unavailable within its configured root grant.');
      throw new McpToolInputError('FILE_UNAVAILABLE', 'Requested file cannot be inspected.');
    }
    if (metadata.isSymbolicLink()) throw new McpToolInputError('SYMLINK_REJECTED', 'Symbolic links are prohibited in configured document paths.');
    if (index < segments.length - 1 && !metadata.isDirectory()) {
      throw new McpToolInputError('PATH_INVALID', 'A configured document path crosses a non-directory entry.');
    }
    if (index === segments.length - 1 && !metadata.isFile()) {
      throw new McpToolInputError('FILE_NOT_REGULAR', 'Requested document is not a regular file.');
    }
  }
  const resolved = await realpath(candidate).catch(() => {
    throw new McpToolInputError('FILE_UNAVAILABLE', 'Requested file cannot be resolved.');
  });
  if (!inside(grant.path, resolved)) throw new McpToolInputError('PATH_ESCAPE', 'Requested path resolves outside its configured root grant.');
  const finalMetadata = await lstat(resolved).catch(() => {
    throw new McpToolInputError('FILE_UNAVAILABLE', 'Requested file cannot be inspected.');
  });
  if (!finalMetadata.isFile() || finalMetadata.isSymbolicLink()) {
    throw new McpToolInputError('FILE_NOT_REGULAR', 'Requested document is not a regular file.');
  }
  await assertGrantStable(grant);
  return {
    requested: candidate,
    resolved,
    missing: false,
    identity: { dev: finalMetadata.dev, ino: finalMetadata.ino },
  };
}

export async function resolveGrantedDirectory(config, rootId, kind, relative) {
  const grant = await requireGrant(config, rootId, kind);
  const segments = relativeSegments(relative, true);
  let cursor = grant.path;
  for (const segment of segments) {
    cursor = path.join(cursor, segment);
    let metadata;
    try {
      metadata = await lstat(cursor);
    } catch {
      throw new McpToolInputError('DIRECTORY_NOT_FOUND', 'Requested directory is unavailable within its configured root grant.');
    }
    if (metadata.isSymbolicLink()) throw new McpToolInputError('SYMLINK_REJECTED', 'Symbolic links are prohibited in configured directory paths.');
    if (!metadata.isDirectory()) throw new McpToolInputError('DIRECTORY_INVALID', 'Requested path is not a directory.');
  }
  const resolved = await realpath(cursor).catch(() => {
    throw new McpToolInputError('DIRECTORY_UNAVAILABLE', 'Requested directory cannot be resolved.');
  });
  if (!inside(grant.path, resolved)) throw new McpToolInputError('PATH_ESCAPE', 'Requested directory resolves outside its configured root grant.');
  await assertGrantStable(grant);
  return resolved;
}

export async function readGrantedJson(config, rootId, kind, relative, { optional = false, dossier = false } = {}) {
  const before = await resolveGrantedFileBinding(config, rootId, kind, relative, { optional });
  if (before.missing) return null;
  let document;
  try {
    document = await readJson(before.resolved, {
      maxBytes: dossier ? config.limits.maxDossierBytes : config.limits.maxJsonBytes,
      expectedIdentity: before.identity,
    });
  } catch (error) {
    if (optional && error?.code === 'ENOENT') return null;
    if (error instanceof SyntaxError) throw new McpToolInputError('JSON_INVALID', 'Requested document is not valid JSON.');
    if (error?.code === 'ETOOLARGE' || /exceeds \d+ bytes/.test(error?.message ?? '')) {
      throw new McpToolInputError('JSON_TOO_LARGE', 'Requested document exceeds the configured byte limit.');
    }
    if (error?.code === 'ESTALE') throw new McpToolInputError('PATH_CHANGED', 'Requested document path changed during inspection.');
    throw new McpToolInputError('DOCUMENT_READ_FAILED', 'Requested document could not be read safely.');
  }
  const after = await resolveGrantedFileBinding(config, rootId, kind, relative).catch((error) => {
    if (error instanceof McpToolInputError) throw new McpToolInputError('PATH_CHANGED', 'Requested document path changed during inspection.');
    throw error;
  });
  if (after.resolved !== before.resolved || after.identity.dev !== before.identity.dev || after.identity.ino !== before.identity.ino) {
    throw new McpToolInputError('PATH_CHANGED', 'Requested document path changed during inspection.');
  }
  return document;
}

async function requireGrant(config, rootId, kind) {
  if (typeof rootId !== 'string') throw new McpToolInputError('ROOT_REQUIRED', 'A configured root grant ID is required.');
  const grant = config.roots.find((entry) => entry.id === rootId);
  if (!grant) throw new McpToolInputError('ROOT_NOT_GRANTED', 'Requested root ID is not granted to this MCP server.');
  if (grant.kind !== kind) throw new McpToolInputError('ROOT_KIND_MISMATCH', `Requested root must have kind ${kind}.`);
  await assertGrantStable(grant);
  return grant;
}

async function assertGrantStable(grant) {
  let metadata;
  let resolved;
  try {
    metadata = await lstat(grant.path);
    resolved = await realpath(grant.path);
  } catch {
    throw new McpToolInputError('ROOT_CHANGED', 'Configured root grant changed or became unavailable after server startup.');
  }
  if (metadata.isSymbolicLink() || !metadata.isDirectory() || resolved !== grant.path
    || metadata.dev !== grant.identity.dev || metadata.ino !== grant.identity.ino) {
    throw new McpToolInputError('ROOT_CHANGED', 'Configured root grant changed or became unavailable after server startup.');
  }
}

function relativeSegments(value, allowDot) {
  if (allowDot && value === '.') return [];
  if (typeof value !== 'string' || value.length < 1 || value.length > 1024
    || /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u.test(value) || value.includes('\\')) {
    throw new McpToolInputError('PATH_INVALID', 'Document paths must be bounded forward-slash relative paths.');
  }
  if (path.posix.isAbsolute(value)) throw new McpToolInputError('PATH_INVALID', 'Absolute document paths are prohibited.');
  const segments = value.split('/');
  if (segments.some((segment) => !segment || segment === '.' || segment === '..')) {
    throw new McpToolInputError('PATH_INVALID', 'Empty, current-directory, and parent-directory path segments are prohibited.');
  }
  if (path.posix.normalize(value) !== value) throw new McpToolInputError('PATH_INVALID', 'Document path is not normalized.');
  return segments;
}

function rejectOverlappingRoots(roots) {
  for (let left = 0; left < roots.length; left += 1) {
    for (let right = left + 1; right < roots.length; right += 1) {
      if (inside(roots[left].path, roots[right].path) || inside(roots[right].path, roots[left].path)) {
        throw new McpConfigError(`MCP roots ${roots[left].id} and ${roots[right].id} must not overlap`);
      }
    }
  }
}

function configReadMessage(error) {
  if (error instanceof SyntaxError) return 'MCP configuration is not valid JSON';
  if (error?.code === 'ELOOP') return 'MCP configuration cannot be a symbolic link';
  if (error?.code === 'ENOENT') return 'MCP configuration is unavailable';
  if (error?.code === 'ETOOLARGE' || /exceeds \d+ bytes/.test(error?.message ?? '')) return 'MCP configuration exceeds 131072 bytes';
  return 'MCP configuration could not be read safely';
}

function inside(root, candidate) {
  return candidate === root || candidate.startsWith(`${root}${path.sep}`);
}

function exactKeys(value, allowed, label, errors) {
  const accepted = new Set(allowed);
  for (const key of Object.keys(value)) if (!accepted.has(key)) errors.push(`${label}(unexpected property)`);
}

function boundedString(value, minimum, maximum) {
  return typeof value === 'string' && value.length >= minimum && value.length <= maximum;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
