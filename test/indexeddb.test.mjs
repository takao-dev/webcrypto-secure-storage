import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { beforeEach, afterEach, describe, it } from 'node:test';

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}

import { CryptoUnavailableError, SharedSecureStorage, DEFAULT_KEY_DB_NAME, verifyUpdateManifestSignature } from '../dist/index.js';

class MemoryStorage {
  constructor() {
    this.values = new Map();
  }

  get length() {
    return this.values.size;
  }

  key(index) {
    return Array.from(this.values.keys())[index] ?? null;
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

  clear() {
    this.values.clear();
  }
}

const databases = new Map();
let nextOperationFailure = null;
let nextAddConflict = null;
let localStorage;

const makeRequest = () => ({
  result: undefined,
  error: null,
  onsuccess: null,
  onerror: null,
  onupgradeneeded: null,
});

const mockIndexedDB = {
  open: (databaseName, version) => {
    if (version !== 2) throw new Error(`Unexpected database version: ${version}`);
    const request = makeRequest();
    queueMicrotask(() => {
      let stores = databases.get(databaseName);
      const isNewDatabase = !stores;
      if (!stores) {
        stores = new Map();
        databases.set(databaseName, stores);
      }

      const database = {
        objectStoreNames: { contains: (name) => stores.has(name) },
        createObjectStore: (name) => {
          stores.set(name, new Map());
          return {};
        },
        close: () => {},
        transaction: (storeName, mode) => {
          if (mode !== 'readonly' && mode !== 'readwrite') {
            throw new Error(`Unexpected transaction mode: ${mode}`);
          }
          const transaction = {
            error: null,
            oncomplete: null,
            onerror: null,
            onabort: null,
            objectStore: (name) => {
              if (name !== storeName) throw new Error(`Unexpected object store: ${name}`);
              const rows = stores.get(name);
              if (!rows) throw new Error(`Object store does not exist: ${name}`);

              const run = (method, operation) => {
                const operationRequest = makeRequest();
                queueMicrotask(() => {
                  const operationFailure = nextOperationFailure;
                  if (
                    operationFailure &&
                    operationFailure.storeName === name &&
                    operationFailure.method === method
                  ) {
                    nextOperationFailure = null;
                    operationRequest.error = operationFailure.error;
                    transaction.error = Object.prototype.hasOwnProperty.call(
                      operationFailure,
                      'transactionError'
                    )
                      ? operationFailure.transactionError
                      : operationFailure.error;
                    operationRequest.onerror?.();
                    transaction.onerror?.();
                  } else {
                    try {
                      if (method === 'add' && nextAddConflict && nextAddConflict.storeName === name) {
                        if (nextAddConflict.winningKey) {
                          rows.set(nextAddConflict.key, nextAddConflict.winningKey);
                        }
                        nextAddConflict = null;
                        const conflict = new Error('The key already exists.');
                        conflict.name = 'ConstraintError';
                        throw conflict;
                      }
                      operationRequest.result = operation();
                      operationRequest.onsuccess?.();
                    } catch (error) {
                      operationRequest.error = error;
                      transaction.error = error;
                      operationRequest.onerror?.();
                      transaction.onerror?.();
                    }
                  }
                  queueMicrotask(() => transaction.oncomplete?.());
                });
                return operationRequest;
              };

              return {
                get: (key) => run('get', () => rows.get(String(key))),
                add: (value, key) =>
                  run('add', () => {
                    const normalizedKey = String(key);
                    if (rows.has(normalizedKey)) {
                      const conflict = new Error('The key already exists.');
                      conflict.name = 'ConstraintError';
                      throw conflict;
                    }
                    rows.set(normalizedKey, value);
                    return undefined;
                  }),
                put: (value, key) =>
                  run('put', () => {
                    rows.set(String(key), value);
                    return undefined;
                  }),
                delete: (key) =>
                  run('delete', () => {
                    rows.delete(String(key));
                    return undefined;
                  }),
                getAllKeys: () => run('getAllKeys', () => Array.from(rows.keys())),
                clear: () =>
                  run('clear', () => {
                    rows.clear();
                    return undefined;
                  }),
              };
            },
          };
          return transaction;
        },
      };

      request.result = database;
      if (isNewDatabase) request.onupgradeneeded?.();
      request.onsuccess?.();
    });
    return request;
  },
};

const rowsFor = (storeName, dbName = DEFAULT_KEY_DB_NAME) =>
  databases.get(dbName)?.get(storeName) ?? new Map();

const encodeBase64 = (bytes) =>
  btoa(String.fromCharCode(...bytes));

describe('SharedSecureStorage with IndexedDB', () => {
  const originalError = console.error;
  const originalWarn = console.warn;

  beforeEach(() => {
    console.error = () => {};
    console.warn = () => {};
    databases.clear();
    nextOperationFailure = null;
    nextAddConflict = null;
    localStorage = new MemoryStorage();
    Object.defineProperty(globalThis, 'indexedDB', { configurable: true, value: mockIndexedDB });
    Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: localStorage });
  });

  afterEach(() => {
    console.error = originalError;
    console.warn = originalWarn;
    Reflect.deleteProperty(globalThis, 'indexedDB');
    Reflect.deleteProperty(globalThis, 'localStorage');
  });

  it('creates a non-extractable key and round-trips encrypted values through IndexedDB', async () => {
    const storage = new SharedSecureStorage('profile-key');

    await storage.setItem('profile', { name: 'Aoi', count: 3 });
    const stored = await storage.getItem('profile');
    assert.deepEqual(stored, { name: 'Aoi', count: 3 });

    const key = rowsFor('keys').get('profile-key');
    assert.ok(key);
    assert.equal(key.extractable, false);

    const encrypted = rowsFor('secure_data').get('profile');
    assert.ok(typeof encrypted === 'string');
    assert.match(encrypted, /^[A-Za-z0-9+/=]+$/);
    assert.equal(localStorage.getItem('profile-key'), null);
    assert.equal(localStorage.getItem('s_profile'), null);
  });

  it('shares an in-flight master-key promise across concurrent operations', async () => {
    const storage = new SharedSecureStorage('shared-promise-key');
    const [left, right] = await Promise.all([
      storage.encrypt('left-data'),
      storage.encrypt('right-data'),
    ]);

    assert.equal(await storage.decrypt(left), 'left-data');
    assert.equal(await storage.decrypt(right), 'right-data');
    assert.equal(rowsFor('keys').size, 1);
  });

  it('shares one persisted master key across concurrently created storage instances', async () => {
    const storageA = new SharedSecureStorage('shared-instance-key');
    const storageB = new SharedSecureStorage('shared-instance-key');

    const [encryptedA, encryptedB] = await Promise.all([
      storageA.encrypt('data-from-a'),
      storageB.encrypt('data-from-b'),
    ]);

    assert.equal(await storageB.decrypt(encryptedA), 'data-from-a');
    assert.equal(await storageA.decrypt(encryptedB), 'data-from-b');
    assert.equal(rowsFor('keys').size, 1);
  });

  it('reuses a key persisted by an earlier storage instance', async () => {
    const storageA = new SharedSecureStorage('reused-key');
    const encrypted = await storageA.encrypt('persisted-payload');

    const storageB = new SharedSecureStorage('reused-key');
    assert.equal(await storageB.decrypt(encrypted), 'persisted-payload');
  });

  it('uses the key committed by another tab after an IndexedDB add conflict (First-key-wins)', async () => {
    const winningKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    nextAddConflict = { storeName: 'keys', key: 'raced-key', winningKey };
    const storage = new SharedSecureStorage('raced-key');

    const encrypted = await storage.encrypt('race-safe');
    assert.ok(encrypted);
    assert.equal(rowsFor('keys').get('raced-key'), winningKey);
    assert.equal(await storage.decrypt(await storage.encrypt('still-usable')), 'still-usable');
  });

  it('fails closed when an add conflict has no committed winner', async () => {
    nextAddConflict = { storeName: 'keys', key: 'orphaned-race-key', winningKey: null };
    const storage = new SharedSecureStorage('orphaned-race-key');

    await assert.rejects(
      () => storage.encrypt('retry-after-empty-race'),
      CryptoUnavailableError
    );
    assert.equal(rowsFor('keys').has('orphaned-race-key'), false);
  });

  it('migrates a legacy localStorage key and encrypted item into IndexedDB', async () => {
    const rawKey = crypto.getRandomValues(new Uint8Array(32));
    const legacyKey = await crypto.subtle.importKey(
      'raw',
      rawKey,
      'AES-GCM',
      true,
      ['encrypt', 'decrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      legacyKey,
      new TextEncoder().encode(JSON.stringify({ name: 'Sora' }))
    );
    const encryptedValue = encodeBase64(
      new Uint8Array([...iv, ...new Uint8Array(ciphertext)])
    );
    localStorage.setItem('legacy-key', encodeBase64(rawKey));
    localStorage.setItem('s_profile', encryptedValue);
    const storage = new SharedSecureStorage('legacy-key');

    assert.deepEqual(await storage.getItem('profile'), { name: 'Sora' });

    const migratedKey = rowsFor('keys').get('legacy-key');
    assert.equal(migratedKey.extractable, false);
    assert.equal(localStorage.getItem('legacy-key'), null);
    assert.equal(localStorage.getItem('s_profile'), null);
    assert.equal(rowsFor('secure_data').get('profile'), encryptedValue);
  });

  it('falls back to localStorage if IndexedDB data write fails', async () => {
    nextOperationFailure = {
      storeName: 'secure_data',
      method: 'put',
      error: new Error('disk is temporarily unavailable'),
    };
    const storage = new SharedSecureStorage('fallback-key');

    await storage.setItem('profile', { name: 'Mio' });
    assert.ok(localStorage.getItem('s_profile'));
    assert.deepEqual(await storage.getItem('profile'), { name: 'Mio' });
  });

  it('treats authenticated but corrupted non-JSON data as absent (null)', async () => {
    const storage = new SharedSecureStorage('corrupt-json-key');
    const encrypted = await storage.encrypt('not-json');
    rowsFor('secure_data').set('corrupt-json', encrypted);

    assert.equal(await storage.getItem('corrupt-json'), null);
  });

  it('supports TTL with automatic expiration and cleanup', async () => {
    const storage = new SharedSecureStorage('ttl-test-key');
    await storage.setItem('short_lived', { token: 'xyz' }, { ttlMs: 30 });
    await storage.setItem('long_lived', { token: 'abc' }, { ttlMs: 10000 });

    // Immediately available
    assert.deepEqual(await storage.getItem('short_lived'), { token: 'xyz' });
    const meta = await storage.getMetadata('short_lived');
    assert.ok(meta);
    assert.equal(meta.expired, false);
    assert.ok(meta.expiresAt && meta.expiresAt > Date.now());

    // Wait for TTL expiration
    await new Promise((r) => setTimeout(r, 45));

    // After expiration: returns null and cleans up
    assert.equal(await storage.getItem('short_lived'), null);
    // Long-lived item still present
    assert.deepEqual(await storage.getItem('long_lived'), { token: 'abc' });
  });

  it('lists keys, clears storage, and purges expired items', async () => {
    const storage = new SharedSecureStorage('mgmt-key');
    await storage.setItem('item1', 'v1');
    await storage.setItem('item2', 'v2', { ttlMs: 20 });
    await storage.setItem('item3', 'v3');

    const keyList = await storage.keys();
    assert.equal(keyList.length, 3);
    assert.ok(keyList.includes('item1'));
    assert.ok(keyList.includes('item2'));

    // Wait for item2 to expire
    await new Promise((r) => setTimeout(r, 35));

    const purgedCount = await storage.purgeExpired();
    assert.equal(purgedCount, 1);
    const keysAfterPurge = await storage.keys();
    assert.equal(keysAfterPurge.length, 2);
    assert.ok(!keysAfterPurge.includes('item2'));

    // Clear all
    await storage.clear();
    assert.equal((await storage.keys()).length, 0);
  });

  it('exports and imports encrypted backup bundles with passphrase', async () => {
    const storage = new SharedSecureStorage('bundle-key');
    await storage.setItem('setting1', 'alpha');
    await storage.setItem('setting2', { mode: 'dark', level: 42 });

    const bundle = await storage.exportEncryptedBundle('super-secret-passphrase');
    assert.ok(bundle.startsWith('v1_bundle.'));

    // Clear and restore into fresh instance
    await storage.clear();
    assert.equal(await storage.getItem('setting1'), null);

    const imported = await storage.importEncryptedBundle(bundle, 'super-secret-passphrase');
    assert.equal(imported, 2);
    assert.equal(await storage.getItem('setting1'), 'alpha');
    assert.deepEqual(await storage.getItem('setting2'), { mode: 'dark', level: 42 });

    // Wrong passphrase throws error
    await assert.rejects(
      () => storage.importEncryptedBundle(bundle, 'wrong-passphrase'),
      /operation failed|OperationError|decrypt/i
    );
  });

  it('executes callbacks safely within withLock', async () => {
    const storage = new SharedSecureStorage('lock-key');
    const result = await storage.withLock(async () => {
      await storage.setItem('locked_val', 'safe');
      return await storage.getItem('locked_val');
    });
    assert.equal(result, 'safe');
  });

  it('supports removeItem, direct encrypt/decrypt, and importEncryptedBundle validation', async () => {
    const storage = new SharedSecureStorage('ops-key');
    await storage.setItem('tempKey', 'tempValue');

    const allKeys = await storage.keys();
    assert.ok(allKeys.includes('tempKey'));

    await storage.removeItem('tempKey');
    assert.equal(await storage.getItem('tempKey'), null);

    // Direct encrypt and decrypt
    const cipher = await storage.encrypt('raw-secret-text');
    assert.ok(cipher);
    const decrypted = await storage.decrypt(cipher);
    assert.equal(decrypted, 'raw-secret-text');

    // Invalid bundle format rejection
    await assert.rejects(
      () => storage.importEncryptedBundle('invalid_prefix.salt.iv.data', 'passphrase'),
      /Invalid bundle format/i
    );

    // Missing passphrase or bundle
    await assert.rejects(
      () => storage.exportEncryptedBundle(''),
      /Passphrase is required/i
    );
    await assert.rejects(
      () => storage.importEncryptedBundle('', 'pass'),
      /Bundle string and passphrase are required/i
    );
    await assert.rejects(
      () => storage.importEncryptedBundle('v1_bundle.a.b.c', ''),
      /Bundle string and passphrase are required/i
    );

    // Corrupted Base64 in envelope
    await assert.rejects(
      () => storage.importEncryptedBundle('v1_bundle.???!!===.???!!===.???!!===', 'pass'),
      /Corrupted or invalid Base64/i
    );

    // Invalid envelope boundaries (too short)
    const shortSalt = Buffer.from('short').toString('base64');
    const shortIv = Buffer.from('short').toString('base64');
    const shortData = Buffer.from('short').toString('base64');
    await assert.rejects(
      () => storage.importEncryptedBundle(`v1_bundle.${shortSalt}.${shortIv}.${shortData}`, 'pass'),
      /Invalid cryptographic envelope boundaries/i
    );

    // Non-JSON decrypted payload throws Decrypted bundle payload is not valid JSON
    const enc = new TextEncoder();
    const salt16 = crypto.getRandomValues(new Uint8Array(16));
    const iv12 = crypto.getRandomValues(new Uint8Array(12));
    const bk = await crypto.subtle.importKey('raw', enc.encode('secret-pwd'), 'PBKDF2', false, ['deriveKey']);
    const dk = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: salt16, iterations: 100000, hash: 'SHA-512' }, bk, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    const nonJsonCt = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv12 }, dk, enc.encode('plain-text-not-json'));
    const nonJsonBundle = `v1_bundle.${Buffer.from(salt16).toString('base64')}.${Buffer.from(iv12).toString('base64')}.${Buffer.from(new Uint8Array(nonJsonCt)).toString('base64')}`;
    await assert.rejects(
      () => storage.importEncryptedBundle(nonJsonBundle, 'secret-pwd'),
      /Decrypted bundle payload is not valid JSON/i
    );

    // Decrypt corrupted ciphertext returns null
    const badDecrypted = await storage.decrypt(Buffer.from('corrupted-ciphertext-12345678901234567890').toString('base64'));
    assert.equal(badDecrypted, null);
  });

  it('handles importEncryptedBundle with overwrite: false skipping existing keys', async () => {
    const storage = new SharedSecureStorage('overwrite-test-key', { databaseName: 'db_target' });
    await storage.setItem('keepMe', 'original-value');

    // Create a bundle from an instance with new values in an isolated database
    const bundleStorage = new SharedSecureStorage('bundle-gen-key', { databaseName: 'db_bundle_source' });
    await bundleStorage.setItem('keepMe', 'new-ignored-value');
    await bundleStorage.setItem('newItem', 'fresh-value');
    const bundle = await bundleStorage.exportEncryptedBundle('pwd123');

    // Import with overwrite: false
    const count = await storage.importEncryptedBundle(bundle, 'pwd123', { overwrite: false });
    assert.equal(count, 1); // only newItem was imported
    assert.equal(await storage.getItem('keepMe'), 'original-value');
    assert.equal(await storage.getItem('newItem'), 'fresh-value');
  });

  it('handles localStorage keys() and clear() with s_ prefix', async () => {
    const storage = new SharedSecureStorage('ls-key');
    localStorage.setItem('s_pref1', 'val1');
    localStorage.setItem('s_pref2', 'val2');
    localStorage.setItem('other_key', 'unrelated');

    const keys = await storage.keys();
    assert.ok(keys.includes('pref1'));
    assert.ok(keys.includes('pref2'));

    await storage.clear();
    assert.equal(localStorage.getItem('s_pref1'), null);
    assert.equal(localStorage.getItem('s_pref2'), null);
    assert.equal(localStorage.getItem('other_key'), 'unrelated');
  });

  it('handles withLock fallback when navigator.locks is unavailable', async () => {
    const originalNavigator = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
    try {
      Object.defineProperty(globalThis, 'navigator', {
        configurable: true,
        value: undefined,
      });
      const storage = new SharedSecureStorage('nolock-key');
      const val = await storage.withLock(async () => 'nolock-result');
      assert.equal(val, 'nolock-result');
    } finally {
      if (originalNavigator) {
        Object.defineProperty(globalThis, 'navigator', originalNavigator);
      } else {
        Reflect.deleteProperty(globalThis, 'navigator');
      }
    }
  });
});

describe('verifyUpdateManifestSignature comprehensive error cases', () => {
  const dummyPayload = {
    version: '1.0.0',
    latestVersion: '1.0.0',
    product: 'app',
    channel: 'stable',
    downloadUrl: 'https://example.com/dl',
    sha256: 'a'.repeat(64),
    publishedAt: '2026-01-01T00:00:00Z',
  };
  const dummySig = Buffer.from(new Uint8Array(64)).toString('base64');

  it('throws when public key map contains invalid JSON', async () => {
    await assert.rejects(
      () => verifyUpdateManifestSignature({}, {
        manifestSigned: true,
        manifestPayload: dummyPayload,
        manifestSignature: dummySig,
      }, {
        publicKeyMapJson: 'invalid-json{{{',
      }),
      /VITE_UPDATE_SIGNING_PUBLIC_KEYS must be valid JSON map/i
    );
  });

  it('throws when keyId is not found and no fallback key provided', async () => {
    await assert.rejects(
      () => verifyUpdateManifestSignature({}, {
        manifestSigned: true,
        manifestKeyId: 'unknown-key-id',
        manifestPayload: dummyPayload,
        manifestSignature: dummySig,
      }, {
        publicKeyMapJson: '{"known-key": "pk"}',
      }),
      /No public key configured for manifest keyId/i
    );
  });

  it('throws when no key is configured at all', async () => {
    await assert.rejects(
      () => verifyUpdateManifestSignature({}, {
        manifestSigned: true,
        manifestPayload: dummyPayload,
        manifestSignature: dummySig,
      }, {}),
      /Update signing public key is not configured/i
    );
  });

  it('throws when requireSignedManifest is true but manifest is unsigned', async () => {
    await assert.rejects(
      () => verifyUpdateManifestSignature({}, {
        manifestSigned: false,
      }, { requireSignedManifest: true }),
      /Unsigned update manifest is not allowed/i
    );
  });

  it('passes silently when manifest is unsigned and requireSignedManifest is false', async () => {
    await verifyUpdateManifestSignature({}, {
      manifestSigned: false,
    }, { requireSignedManifest: false, enableServerVerification: false });
  });

  it('throws when signed manifest is missing payload or signature', async () => {
    await assert.rejects(
      () => verifyUpdateManifestSignature({}, {
        manifestSigned: true,
        manifestPayload: null,
        manifestSignature: 'sig',
      }, { fallbackPublicKey: 'pk' }),
      /Signed manifest is missing payload or signature/i
    );
  });

  it('throws when signature verification fails', async () => {
    const dummyKey = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEANkF5Aom7J35l1b8V3n0P1xW+k5mJk4r7lY9y2z6K3sQ=\n-----END PUBLIC KEY-----';
    await assert.rejects(
      () => verifyUpdateManifestSignature({}, {
        manifestSigned: true,
        manifestPayload: dummyPayload,
        manifestSignature: dummySig,
      }, { fallbackPublicKey: dummyKey, enableServerVerification: false }),
      /Update manifest signature verification failed|signature/i
    );
  });

  it('skips server verification when manifest is unsigned', async () => {
    const mockApi = {
      post: async () => ({ data: { verified: false } }),
    };
    const res = await verifyUpdateManifestSignature(mockApi, {
      manifestSigned: false,
    }, { requireSignedManifest: false, enableServerVerification: true });
    assert.equal(res, undefined);
  });
});
