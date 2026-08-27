import { createHash } from 'node:crypto';

/**
 * Canonical JSON for assurance bindings.
 *
 * Objects are key-sorted, arrays retain order, and unsupported JSON values are
 * rejected rather than silently coerced. This is intentionally small and is
 * not a complete RFC 8785 implementation; the schemas disallow floating-point
 * values in signed documents.
 */
export function canonicalize(value) {
  return JSON.stringify(normalize(value));
}

function normalize(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return value;
  }

  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) {
      throw new TypeError('Canonical documents may contain only safe integers');
    }
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((entry) => normalize(entry));
  }

  if (typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    // Preserve prototype-named JSON keys as ordinary own properties instead
    // of invoking legacy Object.prototype setters such as __proto__.
    const result = Object.create(null);
    for (const key of Object.keys(value).sort()) {
      const entry = value[key];
      if (entry === undefined || typeof entry === 'function' || typeof entry === 'symbol') {
        throw new TypeError(`Unsupported JSON value at key ${key}`);
      }
      result[key] = normalize(entry);
    }
    return result;
  }

  throw new TypeError(`Unsupported canonical JSON value: ${typeof value}`);
}

export function sha256(value) {
  const bytes = Buffer.isBuffer(value) || value instanceof Uint8Array
    ? value
    : Buffer.from(typeof value === 'string' ? value : canonicalize(value), 'utf8');
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

export function documentDigest(document) {
  return sha256(canonicalize(document));
}

export function withoutSignature(document) {
  const { signature: _signature, ...unsigned } = document;
  return unsigned;
}

export function withoutDossierDigest(dossier) {
  const { dossierDigest: _dossierDigest, ...unsigned } = dossier;
  return unsigned;
}
