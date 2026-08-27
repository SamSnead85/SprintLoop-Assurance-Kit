import { spawnSync } from 'node:child_process';
import { access, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const root = process.cwd();
const temporary = await mkdtemp(path.join(os.tmpdir(), 'assurance-package-smoke-'));
const consumer = path.join(temporary, 'consumer');

try {
  const packed = run('npm', ['pack', '--json', '--pack-destination', temporary], root);
  const metadata = JSON.parse(packed.stdout)[0];
  const tarball = path.join(temporary, metadata.filename);
  await mkdir(consumer, { recursive: true });
  await writeFile(path.join(consumer, 'package.json'), `${JSON.stringify({ name: 'assurance-smoke-consumer', private: true }, null, 2)}\n`, 'utf8');
  run('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', '--no-package-lock', tarball], consumer);
  const executable = process.platform === 'win32'
    ? path.join(consumer, 'node_modules/.bin/sprintloop-assure.cmd')
    : path.join(consumer, 'node_modules/.bin/sprintloop-assure');
  const help = run(executable, ['help'], consumer);
  if (!help.stdout.includes('SprintLoop Assurance Kit')) throw new Error('Installed CLI did not execute its entrypoint');
  const library = run(process.execPath, [
    '--input-type=module',
    '--eval',
    "import('@sprintloop/assurance-kit').then((m)=>{if(typeof m.createDossier!=='function'||typeof m.verifyDossier!=='function'||typeof m.runMcpStdioServer!=='function'||m.listMcpTools().length!==6)process.exit(1)})",
  ], consumer);
  if (library.status !== 0) throw new Error('Installed library exports are unavailable');
  await access(path.join(consumer, 'node_modules/@sprintloop/assurance-kit/materialize-bundle/action.yml'));
  await access(path.join(consumer, 'node_modules/@sprintloop/assurance-kit/prepare-shadow-bundle/action.yml'));
  await access(path.join(consumer, 'node_modules/@sprintloop/assurance-kit/src/materialize-bundle.mjs'));
  await access(path.join(consumer, 'node_modules/@sprintloop/assurance-kit/src/prepare-shadow-bundle.mjs'));
  await access(path.join(consumer, 'node_modules/@sprintloop/assurance-kit/schemas/mcp-server-config.v1.schema.json'));
  await access(path.join(consumer, 'node_modules/@sprintloop/assurance-kit/schemas/release-subject.v1.schema.json'));

  const mcpRoot = path.join(temporary, 'mcp-roots');
  const bundleRoot = path.join(mcpRoot, 'bundle');
  const receiverRoot = path.join(mcpRoot, 'receiver');
  const dossierRoot = path.join(mcpRoot, 'dossiers');
  await Promise.all([
    mkdir(bundleRoot, { recursive: true }),
    mkdir(receiverRoot, { recursive: true }),
    mkdir(dossierRoot, { recursive: true }),
  ]);
  const mcpConfig = path.join(temporary, 'mcp-config.json');
  await writeFile(mcpConfig, `${JSON.stringify({
    schemaVersion: 'assurance.sprintloop.dev/mcp-server-config/v1',
    roots: [
      { id: 'bundle', kind: 'bundle', path: bundleRoot },
      { id: 'receiver', kind: 'receiver', path: receiverRoot },
      { id: 'dossiers', kind: 'dossier', path: dossierRoot },
    ],
  }, null, 2)}\n`, 'utf8');
  const request = {
    jsonrpc: '2.0',
    id: 'installed-smoke',
    method: 'tools/call',
    params: {
      _meta: {
        'io.modelcontextprotocol/protocolVersion': '2026-07-28',
        'io.modelcontextprotocol/clientCapabilities': {},
      },
      name: 'assurance_capabilities',
      arguments: {},
    },
  };
  const mcp = run(executable, ['mcp', '--config', mcpConfig], consumer, { input: `${JSON.stringify(request)}\n` });
  const lines = mcp.stdout.trim().split('\n');
  if (lines.length !== 1) throw new Error('Installed MCP emitted non-protocol stdout');
  const response = JSON.parse(lines[0]);
  if (response.result?.structuredContent?.securityBoundary?.filesystemWrites !== false
    || response.result?.structuredContent?.enforcementEligible !== false) {
    throw new Error('Installed MCP capability boundary is unavailable');
  }
  process.stdout.write(`Package smoke: installed ${metadata.name}@${metadata.version}; CLI, library, schema, and MCP stdio passed\n`);
} finally {
  await rm(temporary, { recursive: true, force: true });
}

function run(command, args, cwd, { input } = {}) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    input,
    env: {
      ...process.env,
      npm_config_cache: path.join(os.tmpdir(), 'sprintloop-assurance-kit-npm-cache'),
    },
  });
  if (result.status !== 0) {
    process.stderr.write(result.stdout ?? '');
    process.stderr.write(result.stderr ?? '');
    throw new Error(`${command} failed with status ${result.status}`);
  }
  return result;
}
