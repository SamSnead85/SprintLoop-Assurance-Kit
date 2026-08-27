import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { readHandleBounded } from './bounded.mjs';
import { parseJsonStrictText } from './strict-json.mjs';

const utf8 = new TextDecoder('utf-8', { fatal: true });

export async function readJson(file, { maxBytes = 1_048_576, expectedIdentity } = {}) {
  const handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const before = await handle.stat();
    if (!before.isFile()) throw new Error(`JSON input is not a regular file: ${file}`);
    if (expectedIdentity && (before.dev !== expectedIdentity.dev || before.ino !== expectedIdentity.ino)) {
      const error = new Error(`JSON input path changed before open: ${file}`);
      error.code = 'ESTALE';
      throw error;
    }
    if (before.size > maxBytes) throw new Error(`JSON input exceeds ${maxBytes} bytes: ${file}`);
    const bytes = await readHandleBounded(handle, maxBytes);
    const after = await handle.stat();
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs || bytes.length !== after.size) {
      throw new Error(`JSON input changed during read: ${file}`);
    }
    let text;
    try {
      text = utf8.decode(bytes);
    } catch {
      throw new SyntaxError('JSON input is not valid UTF-8');
    }
    return parseJsonStrictText(text);
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
