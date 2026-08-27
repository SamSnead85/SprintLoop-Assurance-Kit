export async function readHandleBounded(handle, maxBytes) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) throw new TypeError('maxBytes must be a non-negative safe integer');
  const chunks = [];
  let total = 0;
  while (true) {
    const remainingWithSentinel = (maxBytes - total) + 1;
    const buffer = Buffer.allocUnsafe(Math.min(65_536, remainingWithSentinel));
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
    if (bytesRead === 0) break;
    total += bytesRead;
    if (total > maxBytes) {
      const error = new RangeError(`Input exceeds ${maxBytes} bytes`);
      error.code = 'ETOOLARGE';
      throw error;
    }
    chunks.push(buffer.subarray(0, bytesRead));
  }
  return Buffer.concat(chunks, total);
}
