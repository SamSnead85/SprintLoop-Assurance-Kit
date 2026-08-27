import { constants } from 'node:fs';
import { appendFile, mkdir, open, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { readHandleBounded } from './bounded.mjs';

export async function readJson(file, { maxBytes = 1_048_576 } = {}) {
  const handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const before = await handle.stat();
    if (!before.isFile()) throw new Error(`JSON input is not a regular file: ${file}`);
    if (before.size > maxBytes) throw new Error(`JSON input exceeds ${maxBytes} bytes: ${file}`);
    const bytes = await readHandleBounded(handle, maxBytes);
    const after = await handle.stat();
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs || bytes.length !== after.size) {
      throw new Error(`JSON input changed during read: ${file}`);
    }
    return JSON.parse(bytes.toString('utf8'));
  } finally {
    await handle.close();
  }
}

export async function readOptionalJson(file, options) {
  try {
    return await readJson(file, options);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

export async function writeJsonAtomic(file, value) {
  const absolute = path.resolve(file);
  await mkdir(path.dirname(absolute), { recursive: true });
  const temporary = `${absolute}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  await rename(temporary, absolute);
}

export async function writeTextExclusive(file, value) {
  const absolute = path.resolve(file);
  await mkdir(path.dirname(absolute), { recursive: true });
  await writeFile(absolute, value, { flag: 'wx', mode: 0o644 });
}

export async function appendGithubOutput(file, values) {
  const lines = Object.entries(values).map(([key, value]) => `${key}=${escapeWorkflowValue(String(value))}`);
  await appendFile(file, `${lines.join('\n')}\n`, 'utf8');
}

function escapeWorkflowValue(value) {
  return value.replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');
}
