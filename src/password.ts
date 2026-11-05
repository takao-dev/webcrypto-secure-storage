/**
 * Runtime-neutral client password stretching contract.
 *
 * This module intentionally has no Vite, DOM, IndexedDB, or HTTP client dependency
 * so browser clients, Edge Workers, and build-time tooling can use the
 * same derivation contract.
 */
export const CLIENT_PBKDF2_ROUNDS = 100000;

export async function deriveClientPasswordHash(
  password: string,
  loginId: string
): Promise<string> {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('Web Crypto is required to derive the client password hash.');
  }

  const salt = new TextEncoder().encode(loginId.toLowerCase());
  const passwordBuffer = new TextEncoder().encode(password);

  const baseKey = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const hashBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations: CLIENT_PBKDF2_ROUNDS,
      hash: 'SHA-512',
    },
    baseKey,
    64 * 8
  );

  return Array.from(new Uint8Array(hashBits), (byte) =>
    byte.toString(16).padStart(2, '0')
  ).join('');
}
