export interface UpdateManifestSignatureRequest {
  manifestPayload: Record<string, unknown>;
  manifestSignature: string;
  manifestAlgorithm?: string;
  manifestKeyId?: string;
}

function normalizePem(pem: string): string {
  return pem.replace(/\\n/g, '\n').trim();
}

export function pemToArrayBuffer(pem: string): ArrayBuffer {
  const normalized = normalizePem(pem)
    .replace('-----BEGIN PUBLIC KEY-----', '')
    .replace('-----END PUBLIC KEY-----', '')
    .replace(/\s+/g, '');
  const binary = atob(normalized);
  const bytes = Uint8Array.from(binary, (_, index) => binary.charCodeAt(index));
  return bytes.buffer;
}

export function base64ToBytes(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value);
  const bytes: Uint8Array<ArrayBuffer> = new Uint8Array(new ArrayBuffer(binary.length));
  bytes.set(Array.from(binary, (character) => character.charCodeAt(0)));
  return bytes;
}

/**
 * Verify the canonical manifest payload using Web Crypto Ed25519.
 * JSON property insertion order is part of the signing contract.
 */
export async function verifyEd25519ManifestSignature(
  manifestPayload: Record<string, unknown>,
  manifestSignature: string,
  publicKeyPem: string
): Promise<boolean> {
  const publicKey = await crypto.subtle.importKey(
    'spki',
    pemToArrayBuffer(publicKeyPem),
    { name: 'Ed25519' },
    false,
    ['verify']
  );

  return crypto.subtle.verify(
    { name: 'Ed25519' },
    publicKey,
    base64ToBytes(manifestSignature),
    new TextEncoder().encode(JSON.stringify(manifestPayload))
  );
}
