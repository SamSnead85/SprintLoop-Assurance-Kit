const MAX_DEPTH = 64;
const MAX_ERRORS = 128;

// Internal validator for the closed schema subset shipped by the Kit and its
// MCP catalog. It is deliberately not exported from the package root as a
// general JSON Schema implementation.
export function validateJsonSchema(schema, value) {
  const errors = [];
  visit(schema, value, '$', errors, 0, schema);
  return errors;
}

function visit(schema, value, path, errors, depth, rootSchema) {
  if (errors.length >= MAX_ERRORS) return;
  if (depth > MAX_DEPTH) {
    errors.push(`${path}: schema depth exceeds ${MAX_DEPTH}`);
    return;
  }
  if (schema === true) return;
  if (schema === false || !isObject(schema)) {
    errors.push(`${path}: invalid or rejecting schema`);
    return;
  }
  if (typeof schema.$ref === 'string') {
    const referenced = resolveLocalReference(rootSchema, schema.$ref);
    if (referenced === undefined) {
      errors.push(`${path}: schema reference is invalid or unsupported`);
      return;
    }
    visit(referenced, value, path, errors, depth + 1, rootSchema);
  }
  if (Array.isArray(schema.anyOf)) {
    const matches = schema.anyOf.some((branch) => validateBranch(branch, value, depth + 1, rootSchema));
    if (!matches) errors.push(`${path}: does not match any allowed schema`);
  }
  if (Array.isArray(schema.oneOf)) {
    const matches = schema.oneOf.filter((branch) => validateBranch(branch, value, depth + 1, rootSchema)).length;
    if (matches !== 1) errors.push(`${path}: does not match exactly one allowed schema`);
  }
  if (Object.hasOwn(schema, 'const') && !sameJson(value, schema.const)) {
    errors.push(`${path}: does not match const`);
    return;
  }
  if (Array.isArray(schema.enum) && !schema.enum.some((entry) => sameJson(value, entry))) {
    errors.push(`${path}: is not an allowed enum value`);
    return;
  }
  if (schema.type !== undefined && !matchesType(value, schema.type)) {
    errors.push(`${path}: has invalid type`);
    return;
  }
  if (typeof value === 'string') validateString(schema, value, path, errors);
  if (typeof value === 'number') validateNumber(schema, value, path, errors);
  if (Array.isArray(value)) validateArray(schema, value, path, errors, depth, rootSchema);
  else if (isObject(value)) validateObject(schema, value, path, errors, depth, rootSchema);
}

function validateString(schema, value, path, errors) {
  const characterLength = [...value].length;
  if (Number.isSafeInteger(schema.minLength) && characterLength < schema.minLength) errors.push(`${path}: is shorter than minLength`);
  if (Number.isSafeInteger(schema.maxLength) && characterLength > schema.maxLength) errors.push(`${path}: is longer than maxLength`);
  if (typeof schema.pattern === 'string') {
    let pattern;
    try {
      pattern = new RegExp(schema.pattern, 'u');
    } catch {
      errors.push(`${path}: schema pattern is invalid`);
      return;
    }
    if (!pattern.test(value)) errors.push(`${path}: does not match pattern`);
  }
  if (schema.format === 'date-time' && !Number.isFinite(Date.parse(value))) errors.push(`${path}: is not a date-time`);
}

function validateNumber(schema, value, path, errors) {
  if (typeof schema.minimum === 'number' && value < schema.minimum) errors.push(`${path}: is below minimum`);
  if (typeof schema.maximum === 'number' && value > schema.maximum) errors.push(`${path}: is above maximum`);
}

function validateArray(schema, value, path, errors, depth, rootSchema) {
  if (Number.isSafeInteger(schema.minItems) && value.length < schema.minItems) errors.push(`${path}: has too few items`);
  if (Number.isSafeInteger(schema.maxItems) && value.length > schema.maxItems) errors.push(`${path}: has too many items`);
  if (schema.uniqueItems === true) {
    const encoded = value.map((entry) => JSON.stringify(entry));
    if (new Set(encoded).size !== encoded.length) errors.push(`${path}: items are not unique`);
  }
  if (schema.items !== undefined) value.forEach((entry, index) => visit(schema.items, entry, `${path}[${index}]`, errors, depth + 1, rootSchema));
}

function validateObject(schema, value, path, errors, depth, rootSchema) {
  const properties = isObject(schema.properties) ? schema.properties : {};
  const propertyCount = Object.keys(value).length;
  if (Number.isSafeInteger(schema.minProperties) && propertyCount < schema.minProperties) errors.push(`${path}: has too few properties`);
  if (Number.isSafeInteger(schema.maxProperties) && propertyCount > schema.maxProperties) errors.push(`${path}: has too many properties`);
  if (Array.isArray(schema.required)) {
    for (const key of schema.required) if (!Object.hasOwn(value, key)) errors.push(`${path}.${key}: is required`);
  }
  for (const [key, child] of Object.entries(value)) {
    if (Object.hasOwn(properties, key)) visit(properties[key], child, `${path}.${key}`, errors, depth + 1, rootSchema);
    else if (schema.additionalProperties === false) errors.push(`${path}: contains an unexpected property`);
    else if (isObject(schema.additionalProperties)) visit(schema.additionalProperties, child, `${path}.${key}`, errors, depth + 1, rootSchema);
  }
}

function validateBranch(schema, value, depth, rootSchema) {
  const errors = [];
  visit(schema, value, '$', errors, depth, rootSchema);
  return errors.length === 0;
}

function resolveLocalReference(rootSchema, reference) {
  if (reference === '#') return rootSchema;
  if (!reference.startsWith('#/')) return undefined;
  let current = rootSchema;
  for (const rawSegment of reference.slice(2).split('/')) {
    const segment = rawSegment.replaceAll('~1', '/').replaceAll('~0', '~');
    if (!isObject(current) || !Object.hasOwn(current, segment)) return undefined;
    current = current[segment];
  }
  return current;
}

function matchesType(value, expected) {
  const types = Array.isArray(expected) ? expected : [expected];
  return types.some((type) => {
    if (type === 'null') return value === null;
    if (type === 'array') return Array.isArray(value);
    if (type === 'object') return isObject(value);
    if (type === 'integer') return Number.isSafeInteger(value);
    if (type === 'number') return typeof value === 'number' && Number.isFinite(value);
    return typeof value === type;
  });
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
