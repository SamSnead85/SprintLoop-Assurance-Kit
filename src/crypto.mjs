import { sign } from 'node:crypto';
import { canonicalize, withoutSignature } from './canonical.mjs';
export { verifyDocumentSignature } from './verify-signature.mjs';

export function signDocument(document, privateKey, keyId) {
  const payload = Buffer.from(canonicalize(withoutSignature(document)), 'utf8');
  const signature = sign(null, payload, privateKey);
  return {
    ...withoutSignature(document),
    signature: {
      algorithm: 'Ed25519',
      keyId,
      value: signature.toString('base64'),
    },
  };
}
