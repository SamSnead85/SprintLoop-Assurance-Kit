import { appendFile, mkdir, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
export { readJson, readOptionalJson } from './read-json.mjs';

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

export function safeLogMessage(error, { maxLength = 4096 } = {}) {
  const message = error instanceof Error ? error.message : 'Unknown failure';
  return JSON.stringify(String(message).slice(0, maxLength))
    .replaceAll('%', '\\u0025')
    .replaceAll('::', '\\u003a\\u003a')
    .replaceAll('\u2028', '\\u2028')
    .replaceAll('\u2029', '\\u2029');
}

function escapeWorkflowValue(value) {
  return value.replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');
}
