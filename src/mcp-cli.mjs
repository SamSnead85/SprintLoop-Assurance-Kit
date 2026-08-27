import path from 'node:path';
import process from 'node:process';
import { loadMcpConfig } from './mcp-config.mjs';
import { runMcpStdioServer } from './mcp-server.mjs';

const HELP = 'SprintLoop Assurance MCP\n\nUsage: sprintloop-assure mcp --config ABSOLUTE_FILE\n';

export async function runMcpCli(argv, { input = process.stdin, output = process.stdout, errorOutput = process.stderr } = {}) {
  const configPath = parseConfigPath(argv);
  if (configPath === null) {
    output.write(HELP);
    return 0;
  }
  const config = await loadMcpConfig(configPath);
  await runMcpStdioServer({ config, input, output, errorOutput });
  return 0;
}

export async function mainMcp(argv = process.argv.slice(3), streams) {
  try {
    return await runMcpCli(argv, streams);
  } catch (error) {
    (streams?.errorOutput ?? process.stderr).write(`Assurance MCP startup error: ${safeStartupMessage(error)}\n`);
    return 2;
  }
}

function parseConfigPath(argv) {
  if (!Array.isArray(argv)) throw new TypeError('MCP arguments must be an array');
  if (argv.length === 1 && (argv[0] === '--help' || argv[0] === '-h')) return null;
  let value;
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === '--config') {
      if (value !== undefined || index + 1 >= argv.length) throw new Error('exactly one --config ABSOLUTE_FILE is required');
      value = argv[index + 1];
      index += 1;
    } else if (typeof token === 'string' && token.startsWith('--config=')) {
      if (value !== undefined) throw new Error('exactly one --config ABSOLUTE_FILE is required');
      value = token.slice('--config='.length);
    } else {
      throw new Error('only --config ABSOLUTE_FILE is accepted');
    }
  }
  if (typeof value !== 'string' || value.length === 0) throw new Error('--config ABSOLUTE_FILE is required');
  if (!path.isAbsolute(value)) throw new Error('--config must use an absolute path');
  return value;
}

function safeStartupMessage(error) {
  const message = typeof error?.message === 'string' ? error.message : 'server could not start';
  return message.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/gu, ' ').replace(/\s+/gu, ' ').trim().slice(0, 512)
    || 'server could not start';
}
