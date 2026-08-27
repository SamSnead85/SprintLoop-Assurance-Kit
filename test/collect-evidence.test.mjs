import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { link, mkdir, mkdtemp, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  collectEvidence,
  collectEvidenceFile,
  EvidenceCollectionError,
  toManifestEvidence,
} from '../src/collect-evidence.mjs';
import { validateJsonSchema } from '../src/schema-check.mjs';

const kitRoot = path.resolve(import.meta.dirname, '..');
const collectionSchema = JSON.parse(
  await readFile(path.join(kitRoot, 'schemas/evidence-collection.v1.schema.json'), 'utf8'),
);

test('collects six CI formats in stable order from exact raw bytes without report content', async () => {
  await withWorkspace(async (root) => {
    const artifacts = validArtifacts();
    for (const [name, content] of Object.entries(artifacts)) await put(root, name, content);
    const inputs = [
      { id: 'evidence:sigstore', path: 'sigstore.json' },
      { id: 'evidence:junit', path: 'junit.xml' },
      { id: 'evidence:sarif', path: 'scan.sarif' },
      { id: 'evidence:spdx', path: 'sbom.spdx.json' },
      { id: 'evidence:cyclonedx', path: 'bom.cdx.json' },
      { id: 'evidence:provenance', path: 'provenance.json' },
    ];
    const result = await collectEvidence(inputs, { root });
    assert.equal(result.pathBase, '.');
    assert.deepEqual(validateJsonSchema(collectionSchema, result), []);

    assert.deepEqual(result.evidence.map((entry) => entry.id), [
      'evidence:cyclonedx',
      'evidence:junit',
      'evidence:provenance',
      'evidence:sarif',
      'evidence:sigstore',
      'evidence:spdx',
    ]);
    assert.deepEqual(result.totals, {
      itemCount: 6,
      byteCount: Object.values(artifacts).reduce((total, value) => total + Buffer.byteLength(value), 0),
      structureFullCount: 4,
      envelopeOnlyCount: 2,
    });
    for (const entry of result.evidence) {
      assert.equal(entry.claimsVerified, false);
      assert.match(entry.digest, /^sha256:[a-f0-9]{64}$/u);
    }
    const junit = result.evidence.find((entry) => entry.format === 'junit');
    assert.deepEqual(junit.summary, {
      suiteCount: 1,
      testCount: 3,
      failureCount: 1,
      errorCount: 0,
      skippedCount: 1,
    });
    const sarif = result.evidence.find((entry) => entry.format === 'sarif');
    assert.deepEqual(sarif.summary, {
      runCount: 1,
      resultCount: 3,
      errorCount: 1,
      warningCount: 1,
      noteCount: 0,
      noneCount: 0,
      unresolvedLevelCount: 1,
      suppressionRequestCount: 1,
    });
    const serialized = JSON.stringify(result);
    for (const secret of ['TOP_SECRET_TEST', 'TOP_SECRET_PATH', 'TOP_SECRET_PACKAGE', 'TOP_SECRET_SUBJECT', 'TOP_SECRET_PAYLOAD']) {
      assert.equal(serialized.includes(secret), false);
    }
    const raw = Buffer.from(artifacts['junit.xml']);
    assert.equal(junit.digest, `sha256:${createHash('sha256').update(raw).digest('hex')}`);
    assert.equal(junit.sizeBytes, raw.length);
  });
});

test('single-file API preserves explicit safe manifest metadata', async () => {
  await withWorkspace(async (root) => {
    const bytes = `${JSON.stringify(JSON.parse(validArtifacts()['scan.sarif']), null, 2)}\n`;
    await put(root, 'reports/scan.sarif', bytes);
    const result = await collectEvidenceFile({ id: 'evidence:scan', path: 'reports/scan.sarif', format: 'sarif' }, { root });
    assert.equal(result.id, 'evidence:scan');
    assert.equal(result.path, 'reports/scan.sarif');
    assert.equal(result.type, 'static-analysis');
    assert.equal(result.mediaType, 'application/sarif+json');
    assert.equal(result.inspectionLevel, 'STRUCTURE_FULL');
  });
});

test('SPDX 3.0.1 is identified but honestly remains envelope-only', async () => {
  await withWorkspace(async (root) => {
    await put(root, 'sbom.spdx3.json', JSON.stringify({
      '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
      '@graph': [
        { type: 'CreationInfo', '@id': '_:creation', specVersion: '3.0.1' },
        { type: 'SpdxDocument', spdxId: 'urn:spdx:document', creationInfo: '_:creation' },
        { type: 'software_Package', spdxId: 'urn:spdx:package', name: 'TOP_SECRET_PACKAGE' },
        { type: 'software_File', spdxId: 'urn:spdx:file' },
        { type: 'Relationship', spdxId: 'urn:spdx:relationship' },
      ],
    }));
    const result = await collectEvidenceFile({ id: 'spdx3', path: 'sbom.spdx3.json' }, { root });
    assert.equal(result.formatVersion, '3.0.1');
    assert.equal(result.inspectionLevel, 'ENVELOPE_ONLY');
    assert.deepEqual(result.summary, {
      documentCount: 1,
      graphElementCount: 5,
      packageCount: 1,
      fileCount: 1,
      relationshipCount: 1,
    });
    assert.equal(JSON.stringify(result).includes('TOP_SECRET_PACKAGE'), false);
  });
});

test('SLSA v1 statements expose counts, not subjects, builders, or parameters', async () => {
  await withWorkspace(async (root) => {
    await put(root, 'slsa.json', JSON.stringify({
      _type: 'https://in-toto.io/Statement/v1',
      subject: [{ name: 'TOP_SECRET_SUBJECT', digest: { sha256: 'a'.repeat(64) } }],
      predicateType: 'https://slsa.dev/provenance/v1',
      predicate: {
        buildDefinition: {
          buildType: 'https://example.test/build/private/v1',
          externalParameters: { tokenName: 'TOP_SECRET_PARAMETER' },
          resolvedDependencies: [{ uri: 'git+https://example.test/private' }],
        },
        runDetails: { builder: { id: 'https://example.test/private-builder' } },
      },
    }));
    const result = await collectEvidenceFile({ id: 'slsa', path: 'slsa.json' }, { root });
    assert.equal(result.inspectionLevel, 'ENVELOPE_ONLY');
    assert.deepEqual(result.summary, {
      predicateProfile: 'slsa-provenance-v1',
      subjectCount: 1,
      subjectDigestAlgorithmCount: 1,
      dependencyCount: 1,
    });
    assert.equal(JSON.stringify(result).includes('private'), false);
  });
});

test('fails closed on duplicate JSON object keys before JSON.parse can overwrite them', async () => {
  await withWorkspace(async (root) => {
    await put(root, 'duplicate.json', '{"version":"2.1.0","version":"2.1.0","runs":[]}');
    await rejectsCode(() => collectEvidenceFile({ id: 'duplicate', path: 'duplicate.json' }, { root }), 'EMALFORMED');
  });
});

test('fails closed when a JSON object advertises multiple evidence identities', async () => {
  await withWorkspace(async (root) => {
    await put(root, 'ambiguous.json', JSON.stringify({
      version: '2.1.0',
      runs: [],
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
    }));
    await rejectsCode(() => collectEvidenceFile({ id: 'ambiguous', path: 'ambiguous.json' }, { root }), 'EAMBIGUOUS');
  });
});

test('fails closed on declared-format mismatch and unknown JSON', async () => {
  await withWorkspace(async (root) => {
    await put(root, 'scan.json', validArtifacts()['scan.sarif']);
    await put(root, 'unknown.json', '{"hello":"world"}');
    await rejectsCode(() => collectEvidenceFile({ id: 'scan', path: 'scan.json', format: 'spdx' }, { root }), 'EFORMAT');
    await rejectsCode(() => collectEvidenceFile({ id: 'unknown', path: 'unknown.json' }, { root }), 'EFORMAT');
  });
});

test('fails closed on non-UTF-8 and non-finite JSON numbers', async () => {
  await withWorkspace(async (root) => {
    await put(root, 'invalid.sarif', Buffer.from([0xff, 0xfe, 0xfd]));
    await put(root, 'infinite.sarif', '{"version":"2.1.0","runs":[],"x":1e9999}');
    await rejectsCode(() => collectEvidenceFile({ id: 'utf8', path: 'invalid.sarif' }, { root }), 'EUTF8');
    await rejectsCode(() => collectEvidenceFile({ id: 'number', path: 'infinite.sarif' }, { root }), 'EMALFORMED');
  });
});

test('fails closed on per-file and aggregate byte limits', async () => {
  await withWorkspace(async (root) => {
    const one = validArtifacts()['scan.sarif'];
    const two = validArtifacts()['sbom.spdx.json'];
    const aggregateLimit = Math.max(Buffer.byteLength(one), Buffer.byteLength(two));
    await put(root, 'one.sarif', one);
    await put(root, 'two.spdx.json', two);
    await rejectsCode(() => collectEvidenceFile(
      { id: 'large', path: 'one.sarif' },
      { root, maxFileBytes: 8, maxTotalBytes: 8 },
    ), 'ETOOLARGE');
    await rejectsCode(() => collectEvidence([
      { id: 'one', path: 'one.sarif' },
      { id: 'two', path: 'two.spdx.json' },
    ], { root, maxFileBytes: aggregateLimit, maxTotalBytes: aggregateLimit }), 'ETOOLARGE');
  });
});

test('rejects traversal, platform aliases, duplicate ids, and duplicate paths', async () => {
  await withWorkspace(async (root) => {
    await put(root, 'scan.sarif', validArtifacts()['scan.sarif']);
    await rejectsCode(() => collectEvidenceFile({ id: 'escape', path: '../scan.sarif' }, { root }), 'EPATH');
    await rejectsCode(() => collectEvidenceFile({ id: 'portable', path: 'reports\\scan.sarif' }, { root }), 'EPATH');
    for (const unsafe of ['C:scan.sarif', 'file:stream', 'CON', 'nul.txt', 'COM¹.json', 'lpt³.txt', 'reports/name.', 'reports/name ',
      'reports/scan?.sarif', 'reports/a<b.xml', 'reports/a|b.json', 'reports/a*b.json']) {
      await rejectsCode(() => collectEvidenceFile({ id: 'portable', path: unsafe }, { root }), 'EPATH');
    }
    await rejectsCode(() => collectEvidence([
      { id: 'same', path: 'scan.sarif' },
      { id: 'same', path: 'other.sarif' },
    ], { root }), 'EDUPLICATE');
    await rejectsCode(() => collectEvidence([
      { id: 'one', path: 'scan.sarif' },
      { id: 'two', path: 'scan.sarif' },
    ], { root }), 'EDUPLICATE');
  });
});

test('rejects leaf and ancestor symlinks without following them', async (context) => {
  await withWorkspace(async (root) => {
    await put(root, 'real/scan.sarif', validArtifacts()['scan.sarif']);
    try {
      await symlink('real/scan.sarif', path.join(root, 'leaf.sarif'));
      await symlink('real', path.join(root, 'linked-directory'));
    } catch (error) {
      if (['EPERM', 'EACCES', 'ENOTSUP'].includes(error?.code)) {
        context.skip(`symlinks unavailable: ${error.code}`);
        return;
      }
      throw error;
    }
    await rejectsCode(() => collectEvidenceFile({ id: 'leaf', path: 'leaf.sarif' }, { root }), 'ESYMLINK');
    await rejectsCode(() => collectEvidenceFile({ id: 'ancestor', path: 'linked-directory/scan.sarif' }, { root }), 'ESYMLINK');
  });
});

test('binds the standalone collector root before canonical resolution', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'assurance-collector-root-race-'));
  const granted = path.join(root, 'granted');
  const displaced = path.join(root, 'displaced');
  const outside = path.join(root, 'outside');
  try {
    await Promise.all([mkdir(granted), mkdir(outside)]);
    await Promise.all([
      put(granted, 'junit.xml', '<testsuite/>\n'),
      put(outside, 'junit.xml', '<testsuite><testcase/></testsuite>\n'),
    ]);
    try {
      await symlink(outside, path.join(root, 'symlink-probe'), 'dir');
      await rm(path.join(root, 'symlink-probe'));
    } catch (error) {
      if (['EPERM', 'EACCES', 'ENOTSUP'].includes(error?.code)) {
        context.skip(`directory symlinks unavailable: ${error.code}`);
        return;
      }
      throw error;
    }
    await assert.rejects(
      collectEvidence(
        [{ id: 'tests', path: 'junit.xml', format: 'junit' }],
        { root: granted },
        {
          afterRootLeafLstat: async () => {
            await rename(granted, displaced);
            await symlink(outside, granted, 'dir');
          },
        },
      ),
      (error) => error instanceof EvidenceCollectionError && error.code === 'ESTALE',
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('rejects two hard-link paths to the same file as ambiguous duplicate evidence', async (context) => {
  await withWorkspace(async (root) => {
    await put(root, 'scan.sarif', validArtifacts()['scan.sarif']);
    try {
      await link(path.join(root, 'scan.sarif'), path.join(root, 'alias.sarif'));
    } catch (error) {
      if (['EPERM', 'EACCES', 'ENOTSUP'].includes(error?.code)) {
        context.skip(`hard links unavailable: ${error.code}`);
        return;
      }
      throw error;
    }
    await rejectsCode(() => collectEvidence([
      { id: 'original', path: 'scan.sarif' },
      { id: 'alias', path: 'alias.sarif' },
    ], { root }), 'EDUPLICATE');
  });
});

test('rejects malformed JUnit structure, DTDs, unknown entities, and duplicate attributes', async () => {
  await withWorkspace(async (root) => {
    const invalid = {
      mismatch: '<testsuite><testcase></testsuite>',
      dtd: '<!DOCTYPE testsuite [<!ENTITY x SYSTEM "file:///etc/passwd">]><testsuite/>',
      entity: '<testsuite><system-out>&exfiltrate;</system-out></testsuite>',
      attribute: '<testsuite name="one" name="two"/>',
      position: '<testsuite><failure/></testsuite>',
    };
    for (const [name, value] of Object.entries(invalid)) {
      await put(root, `${name}.xml`, value);
      await rejectsCode(() => collectEvidenceFile({ id: name, path: `${name}.xml` }, { root }), 'EMALFORMED');
    }
  });
});

test('rejects malformed XML characters, attribute openers, and CDATA terminators', async () => {
  await withWorkspace(async (root) => {
    const invalid = {
      attribute: '<testsuite name="bad<value"/>',
      characterData: '<testsuite>forbidden ]]&gt;</testsuite>'.replace('&gt;', '>'),
      commentControl: `<testsuite><!--bad${String.fromCharCode(1)}--></testsuite>`,
      processingInstruction: '<?unsafe data?><testsuite/>',
    };
    for (const [name, value] of Object.entries(invalid)) {
      await put(root, `${name}.xml`, value);
      await rejectsCode(() => collectEvidenceFile({ id: name, path: `${name}.xml` }, { root }), 'EMALFORMED');
    }
  });
});

test('accepts the lowercase UTF-8 declaration emitted by pytest JUnit XML', async () => {
  await withWorkspace(async (root) => {
    const pytestReport = '<?xml version="1.0" encoding="utf-8"?><testsuites name="pytest tests"><testsuite name="test_example.py" errors="0" failures="0" skipped="0" tests="1" time="0.001" timestamp="2030-01-01T00:00:00.000000+00:00" hostname="fixture"><testcase classname="test_example" name="test_passes" time="0.001" /></testsuite></testsuites>\n';
    await put(root, 'pytest.xml', pytestReport);
    const result = await collectEvidenceFile(
      { id: 'pytest', path: 'pytest.xml', format: 'junit' },
      { root },
    );
    assert.equal(result.format, 'junit');
    assert.deepEqual(result.summary, {
      suiteCount: 1,
      testCount: 1,
      failureCount: 0,
      errorCount: 0,
      skippedCount: 0,
    });
  });
});

test('accepts direct testcases emitted by the supported Node JUnit reporter', async () => {
  await withWorkspace(async (root) => {
    const nodeReport = '<!-- tests 1 -->\n<testsuites><testcase name="test passes" classname="test" time="0.001"></testcase></testsuites>\n';
    await put(root, 'node-junit.xml', nodeReport);
    const result = await collectEvidenceFile(
      { id: 'node-tests', path: 'node-junit.xml', format: 'junit' },
      { root },
    );
    assert.deepEqual(result.summary, {
      suiteCount: 0,
      testCount: 1,
      failureCount: 0,
      errorCount: 0,
      skippedCount: 0,
    });
  });
});

test('rejects duplicate identifiers inside SPDX, CycloneDX, and in-toto evidence', async () => {
  await withWorkspace(async (root) => {
    const spdx = JSON.parse(validArtifacts()['sbom.spdx.json']);
    spdx.files = [{ SPDXID: 'SPDXRef-Package' }];
    const cyclonedx = JSON.parse(validArtifacts()['bom.cdx.json']);
    cyclonedx.services = [{ name: 'service', 'bom-ref': 'component-a' }];
    const provenance = JSON.parse(validArtifacts()['provenance.json']);
    provenance.subject.push(structuredClone(provenance.subject[0]));
    for (const [name, value] of Object.entries({ spdx, cyclonedx, provenance })) await put(root, `${name}.json`, JSON.stringify(value));
    await rejectsCode(() => collectEvidenceFile({ id: 'spdx', path: 'spdx.json' }, { root }), 'EDUPLICATE');
    await rejectsCode(() => collectEvidenceFile({ id: 'cyclonedx', path: 'cyclonedx.json' }, { root }), 'EDUPLICATE');
    await rejectsCode(() => collectEvidenceFile({ id: 'provenance', path: 'provenance.json' }, { root }), 'EDUPLICATE');
  });
});

test('rejects Sigstore bundles with ambiguous content or multiple DSSE signatures', async () => {
  await withWorkspace(async (root) => {
    const both = JSON.parse(validArtifacts()['sigstore.json']);
    both.messageSignature = { messageDigest: {}, signature: 'c2ln' };
    const multiple = JSON.parse(validArtifacts()['sigstore.json']);
    multiple.dsseEnvelope.signatures.push({ sig: 'c2ln' });
    await put(root, 'both.json', JSON.stringify(both));
    await put(root, 'multiple.json', JSON.stringify(multiple));
    await rejectsCode(() => collectEvidenceFile({ id: 'both', path: 'both.json' }, { root }), 'EMALFORMED');
    await rejectsCode(() => collectEvidenceFile({ id: 'multiple', path: 'multiple.json' }, { root }), 'EMALFORMED');
  });
});

test('accepts bounded Sigstore JSONL emitted by GitHub artifact-attestation download', async () => {
  await withWorkspace(async (root) => {
    const bundle = validArtifacts()['sigstore.json'];
    await put(root, 'attestations.jsonl', `${bundle}\n${bundle}\n`);
    const result = await collectEvidenceFile(
      { id: 'attestations', path: 'attestations.jsonl', format: 'sigstore' },
      { root },
    );
    assert.equal(result.mediaType, 'application/vnd.dev.sigstore.bundle+jsonl');
    assert.equal(result.inspectionLevel, 'ENVELOPE_ONLY');
    assert.deepEqual(result.summary, {
      bundleCount: 2,
      contentType: 'dsse-envelope',
      keyMaterialType: 'certificate',
      transparencyLogEntryCount: 2,
      timestampCount: 2,
    });
  });
});

test('enforces one structural JSON budget across every Sigstore JSONL record', async () => {
  await withWorkspace(async (root) => {
    const bundle = JSON.parse(validArtifacts()['sigstore.json']);
    bundle.padding = Array.from({ length: 130_000 }, () => null);
    const line = JSON.stringify(bundle);
    await put(root, 'oversized-structure.jsonl', `${line}\n${line}\n`);
    await rejectsCode(
      () => collectEvidenceFile(
        { id: 'attestations', path: 'oversized-structure.jsonl', format: 'sigstore' },
        { root },
      ),
      'EMALFORMED',
    );
  });
});

function validArtifacts() {
  return {
    'junit.xml': '<?xml version="1.0" encoding="UTF-8"?><testsuites><testsuite name="private"><testcase name="passes"/><testcase name="TOP_SECRET_TEST"><failure message="TOP_SECRET_FAILURE"><![CDATA[private trace]]></failure></testcase><testcase name="skip"><skipped/></testcase><system-out>ignored &amp; minimized</system-out></testsuite></testsuites>\n',
    'scan.sarif': JSON.stringify({
      version: '2.1.0',
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      runs: [{
        tool: { driver: { name: 'Scanner' } },
        results: [
          { level: 'error', message: { text: 'TOP_SECRET_PATH' }, locations: [{ uri: 'TOP_SECRET_PATH' }] },
          { level: 'warning', suppressions: [{ kind: 'external' }] },
          {},
        ],
      }],
    }),
    'sbom.spdx.json': JSON.stringify({
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: 'private-sbom',
      documentNamespace: 'https://example.test/private/sbom',
      creationInfo: { created: '2030-01-01T00:00:00Z', creators: ['Tool: private'] },
      packages: [{ SPDXID: 'SPDXRef-Package', name: 'TOP_SECRET_PACKAGE' }],
      files: [],
      relationships: [{ spdxElementId: 'SPDXRef-DOCUMENT', relationshipType: 'DESCRIBES', relatedSpdxElement: 'SPDXRef-Package' }],
    }),
    'bom.cdx.json': JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      version: 1,
      components: [{ type: 'library', name: 'TOP_SECRET_PACKAGE', 'bom-ref': 'component-a' }],
      dependencies: [{ ref: 'component-a', dependsOn: [] }],
      vulnerabilities: [{ id: 'CVE-TEST' }],
    }),
    'provenance.json': JSON.stringify({
      _type: 'https://in-toto.io/Statement/v1',
      subject: [{ name: 'TOP_SECRET_SUBJECT', digest: { sha256: 'a'.repeat(64) } }],
      predicateType: 'https://example.test/attestation/private/v1',
      predicate: { confidential: 'TOP_SECRET_PREDICATE' },
    }),
    'sigstore.json': JSON.stringify({
      mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
      verificationMaterial: {
        certificate: { rawBytes: 'Y2VydA==' },
        tlogEntries: [{}],
        timestampVerificationData: { rfc3161Timestamps: [{ signedTimestamp: 'dGltZXN0YW1w' }] },
      },
      dsseEnvelope: {
        payload: Buffer.from('TOP_SECRET_PAYLOAD').toString('base64'),
        payloadType: 'application/vnd.in-toto+json',
        signatures: [{ sig: 'c2ln' }],
      },
    }),
  };
}

test('collection paths declare their externally established base', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'assurance-collector-base-'));
  try {
    await writeFile(path.join(root, 'junit.xml'), '<testsuite/>\n');
    const subjectDigest = `git:sha1:${'a'.repeat(40)}`;
    const result = await collectEvidence(
      [{ id: 'tests', path: 'junit.xml', format: 'junit' }],
      { root, pathBase: 'ci/evidence', subjectDigest },
    );
    assert.equal(result.pathBase, 'ci/evidence');
    assert.equal(result.evidence[0].path, 'junit.xml');
    assert.deepEqual(result.manifestEvidence, [{
      id: 'tests',
      type: 'test-report',
      path: 'ci/evidence/junit.xml',
      mediaType: 'application/junit+xml',
      digest: result.evidence[0].digest,
      subjectDigest,
    }]);
    assert.deepEqual(toManifestEvidence({ ...result, manifestEvidence: undefined }, subjectDigest), result.manifestEvidence);
    assert.deepEqual(validateJsonSchema(collectionSchema, result), []);
    await assert.rejects(
      collectEvidence([{ id: 'tests', path: 'junit.xml' }], { root, pathBase: '../outside' }),
      (error) => error instanceof EvidenceCollectionError && error.code === 'EINVAL',
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

async function withWorkspace(callback) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'assurance-collectors-'));
  try {
    await callback(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function put(root, relative, value) {
  const absolute = path.join(root, relative);
  await mkdir(path.dirname(absolute), { recursive: true });
  await writeFile(absolute, value);
}

async function rejectsCode(operation, code) {
  await assert.rejects(operation, (error) => {
    assert.ok(error instanceof EvidenceCollectionError);
    assert.equal(error.code, code);
    return true;
  });
}
