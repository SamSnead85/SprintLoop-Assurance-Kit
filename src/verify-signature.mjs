import { createPublicKey, verify } from 'node:crypto';
import { canonicalize, withoutSignature } from './canonical.mjs';

export function verifyDocumentSignature(document, publicKeyPem) {
  if (!document?.signature || document.signature.algorithm !== 'Ed25519') return false;
  try {
    const signature = Buffer.from(document.signature.value, 'base64');
    if (signature.length !== 64) return false;
    const payload = Buffer.from(canonicalize(withoutSignature(document)), 'utf8');
    return verify(null, payload, createPublicKey(publicKeyPem), signature);
  } catch {
    return false;
  }
}
