import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { createExampleBundle } from '../src/example.mjs';
import { isPortableRelativePath, PORTABLE_RELATIVE_PATH_PATTERN } from '../src/portable-path.mjs';
import { validateJsonSchema } from '../src/schema-check.mjs';
import { validateManifest } from '../src/validate.mjs';

const root = path.resolve(import.meta.dirname, '..');
const manifestSchema = JSON.parse(await readFile(path.join(root, 'schemas/manifest.v1.schema.json'), 'utf8'));
const schemaPattern = new RegExp(manifestSchema.$defs.relativePath.pattern, 'u');
const exportedPattern = new RegExp(PORTABLE_RELATIVE_PATH_PATTERN, 'u');

test('portable path runtime and published schema reject cross-platform aliases identically', () => {
  const cases = new Map([
    ['evidence/junit.xml', true],
    ['nested/report-1.sarif', true],
    ['C:report.json', false],
    ['file:stream', false],
    ['CON', false],
    ['nul.txt', false],
    ['COM¹.json', false],
    ['lpt³.txt', false],
    ['reports/name.', false],
    ['reports/name ', false],
    ['reports/a<b.json', false],
    ['reports/a>b.json', false],
    ['reports/a"b.json', false],
    ['reports/a|b.json', false],
    ['reports/a?b.json', false],
    ['reports/a*b.json', false],
    ['reports\\windows.json', false],
    ['../outside.json', false],
  ]);
  for (const [value, expected] of cases) {
    assert.equal(isPortableRelativePath(value), expected, `runtime ${value}`);
    assert.equal(schemaPattern.test(value), expected, `manifest schema ${value}`);
    assert.equal(exportedPattern.test(value), expected, `exported schema pattern ${value}`);

    const manifest = structuredClone(createExampleBundle().manifest);
    manifest.evidence[0].path = value;
    assert.equal(validateManifest(manifest).length === 0, expected, `runtime manifest ${value}`);
    assert.equal(validateJsonSchema(manifestSchema, manifest).length === 0, expected, `JSON Schema manifest ${value}`);
  }
});

test('portable path length uses Unicode code points like JSON Schema', () => {
  for (const [value, expected] of [
    ['😀'.repeat(600), true],
    ['😀'.repeat(1024), true],
    ['😀'.repeat(1025), false],
  ]) {
    assert.equal(isPortableRelativePath(value), expected);
    const codePointLength = [...value].length;
    assert.equal(schemaPattern.test(value)
      && codePointLength >= manifestSchema.$defs.relativePath.minLength
      && codePointLength <= manifestSchema.$defs.relativePath.maxLength, expected);
    assert.equal(exportedPattern.test(value), expected);

    const manifest = structuredClone(createExampleBundle().manifest);
    manifest.evidence[0].path = value;
    assert.equal(validateManifest(manifest).length === 0, expected);
    assert.equal(validateJsonSchema(manifestSchema, manifest).length === 0, expected);
  }
});
