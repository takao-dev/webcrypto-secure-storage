import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import test from 'node:test';

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}

import {
  CLIENT_PBKDF2_ROUNDS,
  CryptoUnavailableError,
  deriveClientPasswordHash,
  hashPasswordClient,
  SharedSecureStorage,
  verifyUpdateManifestSignature,
} from '../dist/index.js';

class MemoryStorage {
  constructor() {
    this.values = new Map();
  }
  getItem(key) {
    return this.values.get(key) ?? null;
  }
  setItem(key, value) {
    this.values.set(key, value);
  }
  removeItem(key) {
    this.values.delete(key);
  }
}

test('SharedSecureStorage fails closed without IndexedDB unless legacy fallback is enabled', async () => {
  const localStorage = new MemoryStorage();
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: localStorage });
  Reflect.deleteProperty(globalThis, 'indexedDB');

  const strictStorage = new SharedSecureStorage('strict-key');
  await assert.rejects(() => strictStorage.encrypt('secret'), CryptoUnavailableError);

  const legacyStorage = new SharedSecureStorage('legacy-key', {
    allowLegacyLocalStorageKeyFallback: true,
  });
  await legacyStorage.setItem('profile', { name: 'Aoi', count: 3 });
  assert.deepEqual(await legacyStorage.getItem('profile'), { name: 'Aoi', count: 3 });
  await legacyStorage.removeItem('profile');
  assert.equal(await legacyStorage.getItem('profile'), null);
});

test('client password derivation uses PBKDF2-SHA512 and normalizes login ID salt', async () => {
  const hash1 = await deriveClientPasswordHash('correct horse battery staple', 'User.Name');
  const hash2 = await hashPasswordClient('correct horse battery staple', 'user.name');
  assert.equal(CLIENT_PBKDF2_ROUNDS, 100_000);
  assert.match(hash1, /^[0-9a-f]{128}$/);
  assert.equal(hash1, hash2);
});

test('verifyUpdateManifestSignature verifies Ed25519 signatures and key rotation maps', async () => {
  const payload = { product: 'staff', version: '1.2.3', channel: 'production' };
  const keyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ]);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
  const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...publicKey))}\n-----END PUBLIC KEY-----`;
  const signatureBytes = new Uint8Array(
    await crypto.subtle.sign(
      { name: 'Ed25519' },
      keyPair.privateKey,
      new TextEncoder().encode(JSON.stringify(payload))
    )
  );
  const signature = btoa(String.fromCharCode(...signatureBytes));

  const response = {
    product: 'staff',
    channel: 'production',
    currentVersion: '1.2.2',
    latestVersion: '1.2.3',
    updateAvailable: true,
    forceUpdate: false,
    downloadUrl: '/download',
    sha256: 'a'.repeat(64),
    publishedAt: '2026-09-20T00:00:00.000Z',
    manifestSigned: true,
    manifestPayload: payload,
    manifestSignature: signature,
    manifestKeyId: 'key-2026',
  };

  let postedPayload = null;
  const api = {
    async post(_url, body) {
      postedPayload = body;
      return { data: { verified: true } };
    },
  };

  await verifyUpdateManifestSignature(api, response, {
    requireSignedManifest: true,
    publicKeyMapJson: JSON.stringify({ 'key-2026': publicKeyPem }),
  });
  assert.ok(postedPayload);
});
