#!/usr/bin/env node

import process from 'node:process';

const argv = process.argv.slice(2);
if (argv[0] === 'mcp') {
  const { mainMcp } = await import('../src/mcp-cli.mjs');
  process.exitCode = await mainMcp(argv.slice(1));
} else {
  const { main } = await import('../src/cli.mjs');
  process.exitCode = await main(argv);
}
