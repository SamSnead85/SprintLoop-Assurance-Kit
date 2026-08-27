import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';

const root = process.cwd();
const packageJson = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
const lock = JSON.parse(await readFile(path.join(root, 'package-lock.json'), 'utf8'));
const packages = [];

for (const [location, metadata] of Object.entries(lock.packages ?? {})) {
  if (location === '') continue;
  const name = metadata.name ?? location.replace(/^node_modules\//, '');
  packages.push({
    SPDXID: `SPDXRef-Package-${safe(`${name}-${metadata.version}`)}`,
    name,
    versionInfo: metadata.version ?? 'UNKNOWN',
    downloadLocation: metadata.resolved ?? 'NOASSERTION',
    filesAnalyzed: false,
    licenseConcluded: metadata.license ?? 'NOASSERTION',
    licenseDeclared: metadata.license ?? 'NOASSERTION',
    copyrightText: 'NOASSERTION',
  });
}

const sourceHash = createHash('sha256')
  .update(await readFile(path.join(root, 'package-lock.json')))
  .digest('hex');
const sbom = {
  spdxVersion: 'SPDX-2.3',
  dataLicense: 'CC0-1.0',
  SPDXID: 'SPDXRef-DOCUMENT',
  name: `${packageJson.name}-${packageJson.version}`,
  documentNamespace: `https://assurance.sprintloop.dev/sbom/${sourceHash}`,
  creationInfo: {
    created: new Date(0).toISOString(),
    creators: ['Tool: sprintloop-assurance-kit-sbom'],
    licenseListVersion: '3.24',
  },
  packages: [
    {
      SPDXID: 'SPDXRef-RootPackage',
      name: packageJson.name,
      versionInfo: packageJson.version,
      downloadLocation: 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: packageJson.license,
      licenseDeclared: packageJson.license,
      copyrightText: 'NOASSERTION',
      externalRefs: [{
        referenceCategory: 'PACKAGE-MANAGER',
        referenceType: 'purl',
        referenceLocator: `pkg:npm/${encodeURIComponent(packageJson.name)}@${packageJson.version}`,
      }],
    },
    ...packages,
  ],
  relationships: [
    {
      spdxElementId: 'SPDXRef-DOCUMENT',
      relationshipType: 'DESCRIBES',
      relatedSpdxElement: 'SPDXRef-RootPackage',
    },
    ...packages.map((entry) => ({
      spdxElementId: 'SPDXRef-RootPackage',
      relationshipType: 'DEPENDS_ON',
      relatedSpdxElement: entry.SPDXID,
    })),
  ],
};

await mkdir(path.join(root, 'artifacts'), { recursive: true });
await writeFile(path.join(root, 'artifacts/sbom.spdx.json'), `${JSON.stringify(sbom, null, 2)}\n`, 'utf8');
process.stdout.write(`SBOM: ${sbom.packages.length} package records written to artifacts/sbom.spdx.json\n`);

function safe(value) {
  return value.replace(/[^A-Za-z0-9.-]/g, '-');
}
