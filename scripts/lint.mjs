import { spawnSync } from 'node:child_process';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';

const root = process.cwd();
const files = await walk(root);
let checked = 0;

for (const file of files.filter((entry) => entry.endsWith('.mjs'))) {
  const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (result.status !== 0) {
    process.stderr.write(result.stderr || result.stdout);
    process.exit(1);
  }
  checked += 1;
}

for (const file of files.filter((entry) => entry.endsWith('.json'))) {
  try {
    JSON.parse(await readFile(file, 'utf8'));
  } catch (error) {
    throw new Error(`${path.relative(root, file)}: ${error.message}`);
  }
  checked += 1;
}

process.stdout.write(`Syntax gate: ${checked} JavaScript/JSON files valid\n`);

async function walk(directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (['.git', 'node_modules', 'artifacts'].includes(entry.name)) continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) output.push(...await walk(absolute));
    else output.push(absolute);
  }
  return output;
}
