import { deriveClientPasswordHash } from './password.js';
import { verifyEd25519ManifestSignature, base64ToBytes } from './update-signature.js';

export { CLIENT_PBKDF2_ROUNDS, deriveClientPasswordHash } from './password.js';
export {
  base64ToBytes,
  pemToArrayBuffer,
  verifyEd25519ManifestSignature,
  type UpdateManifestSignatureRequest,
} from './update-signature.js';

export interface UpdateVerifyHttpClient {
  post(url: string, payload: unknown): Promise<{ data?: { verified?: boolean } }>;
}

/**
 * Configurable SecureStorage helper using Web Crypto API and non-extractable
 * AES-256-GCM keys persisted in IndexedDB.
 */
export const DEFAULT_KEY_DB_NAME = 'webcrypto_secure_key_db';
const KEY_STORE_NAME = 'keys';
const DATA_STORE_NAME = 'secure_data';
const BASE64_CHUNK_SIZE = 0x8000;

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += BASE64_CHUNK_SIZE) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + BASE64_CHUNK_SIZE));
  }
  return btoa(binary);
}

function openKeyDB(dbName = DEFAULT_KEY_DB_NAME): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined') {
      return reject(new Error('IndexedDB is not supported in this environment'));
    }
    const request = indexedDB.open(dbName, 2);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(KEY_STORE_NAME)) {
        db.createObjectStore(KEY_STORE_NAME);
      }
      if (!db.objectStoreNames.contains(DATA_STORE_NAME)) {
        db.createObjectStore(DATA_STORE_NAME);
      }
    };
    request.onsuccess = () => {
      request.result.onversionchange = () => request.result.close();
      resolve(request.result);
    };
    request.onerror = () => reject(request.error);
  });
}

function waitForRequestAndTransaction<T>(
  request: IDBRequest<T>,
  transaction: IDBTransaction
): Promise<T> {
  return new Promise((resolve, reject) => {
    let requestComplete = false;
    let transactionComplete = false;
    let result: T;
    let settled = false;

    const fail = (error: unknown) => {
      if (settled) return;
      settled = true;
      reject(error instanceof Error ? error : new Error('IndexedDB transaction failed'));
    };

    const complete = () => {
      if (settled || !requestComplete || !transactionComplete) return;
      settled = true;
      resolve(result);
    };

    request.onsuccess = () => {
      result = request.result;
      requestComplete = true;
      complete();
    };
    request.onerror = () => fail(request.error ?? new Error('IndexedDB request failed'));
    transaction.oncomplete = () => {
      transactionComplete = true;
      complete();
    };
    transaction.onerror = () =>
      fail(transaction.error ?? new Error('IndexedDB transaction failed'));
    transaction.onabort = () =>
      fail(transaction.error ?? new Error('IndexedDB transaction aborted'));
  });
}

async function getStoredData(key: string, dbName: string): Promise<string | null> {
  try {
    const db = await openKeyDB(dbName);
    return new Promise((resolve) => {
      const transaction = db.transaction(DATA_STORE_NAME, 'readonly');
      const store = transaction.objectStore(DATA_STORE_NAME);
      const request = store.get(key);
      waitForRequestAndTransaction(request, transaction).then(
        (value) => resolve(value || null),
        () => resolve(null)
      );
    });
  } catch {
    return null;
  }
}

async function storeData(key: string, value: string, dbName: string): Promise<void> {
  const db = await openKeyDB(dbName);
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(DATA_STORE_NAME, 'readwrite');
    const store = transaction.objectStore(DATA_STORE_NAME);
    const request = store.put(value, key);
    waitForRequestAndTransaction(request, transaction).then(() => resolve(), reject);
  });
}

async function removeStoredData(key: string, dbName: string): Promise<void> {
  try {
    const db = await openKeyDB(dbName);
    return new Promise((resolve) => {
      const transaction = db.transaction(DATA_STORE_NAME, 'readwrite');
      const store = transaction.objectStore(DATA_STORE_NAME);
      const request = store.delete(key);
      waitForRequestAndTransaction(request, transaction).then(
        () => resolve(),
        () => resolve()
      );
    });
  } catch {
    return;
  }
}

async function getAllStoredDataKeys(dbName: string): Promise<string[]> {
  try {
    const db = await openKeyDB(dbName);
    return new Promise((resolve) => {
      const transaction = db.transaction(DATA_STORE_NAME, 'readonly');
      const store = transaction.objectStore(DATA_STORE_NAME);
      const request = store.getAllKeys();
      waitForRequestAndTransaction(request, transaction).then(
        (keys) => resolve(((keys as unknown[]) || []).map((k) => String(k))),
        () => resolve([])
      );
    });
  } catch {
    return [];
  }
}

async function clearStoredData(dbName: string): Promise<void> {
  try {
    const db = await openKeyDB(dbName);
    return new Promise((resolve) => {
      const transaction = db.transaction(DATA_STORE_NAME, 'readwrite');
      const store = transaction.objectStore(DATA_STORE_NAME);
      const request = store.clear();
      waitForRequestAndTransaction(request, transaction).then(
        () => resolve(),
        () => resolve()
      );
    });
  } catch {
    return;
  }
}

async function getStoredCryptoKey(keyName: string, dbName: string): Promise<CryptoKey | null> {
  try {
    const db = await openKeyDB(dbName);
    return new Promise((resolve) => {
      const transaction = db.transaction(KEY_STORE_NAME, 'readonly');
      const store = transaction.objectStore(KEY_STORE_NAME);
      const request = store.get(keyName);
      waitForRequestAndTransaction(request, transaction).then(
        (value) => resolve(value || null),
        () => resolve(null)
      );
    });
  } catch {
    return null;
  }
}

async function storeCryptoKeyIfAbsent(
  keyName: string,
  key: CryptoKey,
  dbName: string
): Promise<CryptoKey> {
  const db = await openKeyDB(dbName);
  try {
    await new Promise<void>((resolve, reject) => {
      const transaction = db.transaction(KEY_STORE_NAME, 'readwrite');
      const store = transaction.objectStore(KEY_STORE_NAME);
      const request = store.add(key, keyName);
      waitForRequestAndTransaction(request, transaction).then(() => resolve(), reject);
    });
    return key;
  } catch (error) {
    // Another tab may have won the first-key race. Use its committed key
    // rather than overwriting it with a different key.
    const errorName =
      error && typeof error === 'object' && 'name' in error
        ? String((error as { name?: unknown }).name)
        : '';
    if (errorName === 'ConstraintError') {
      const stored = await getStoredCryptoKey(keyName, dbName);
      if (stored) return stored;
    }
    throw error;
  }
}

const masterKeyPromises = new Map<string, Promise<CryptoKey>>();

/**
 * Raised when a caller attempts to use a security-sensitive operation in a
 * browser/runtime without Web Crypto. Falling back to encoding would make
 * values that callers believe are encrypted readable by anyone with storage
 * access, so this is intentionally a hard failure.
 */
export class CryptoUnavailableError extends Error {
  public readonly code = 'CRYPTO_UNAVAILABLE';

  constructor(message = 'Web Crypto is required for secure client storage and password hashing.') {
    super(message);
    this.name = 'CryptoUnavailableError';
  }
}

export interface SetItemOptions {
  /**
   * Time-to-live in milliseconds. After this duration has passed,
   * getItem() will automatically remove the item and return null.
   */
  ttlMs?: number;
}

export interface StorageItemMetadata<T> {
  value: T;
  expiresAt: number | null;
  expired: boolean;
}

interface StorageEnvelope<T = unknown> {
  __v: 1;
  d: T;
  exp?: number;
}

export interface SharedSecureStorageOptions {
  /**
   * Temporary compatibility switch for migrating an old localStorage-only
   * installation. Production callers should leave this disabled.
   */
  allowLegacyLocalStorageKeyFallback?: boolean;
  /**
   * Custom IndexedDB database name (defaults to 'webcrypto_secure_key_db').
   */
  databaseName?: string;
}

export interface ImportBundleOptions {
  overwrite?: boolean;
}

export class SharedSecureStorage {
  private readonly keyName: string;
  private readonly databaseName: string;
  private readonly allowLegacyLocalStorageKeyFallback: boolean;
  private cachedKey: CryptoKey | null = null;
  private masterKeyPromise: Promise<CryptoKey> | null = null;
  private readonly cryptoAvailable: boolean;

  constructor(keyName: string, options: SharedSecureStorageOptions = {}) {
    this.keyName = keyName;
    this.databaseName = options.databaseName || DEFAULT_KEY_DB_NAME;
    this.allowLegacyLocalStorageKeyFallback = options.allowLegacyLocalStorageKeyFallback === true;
    this.cryptoAvailable = typeof crypto !== 'undefined' && Boolean(crypto.subtle);
  }

  private get promiseKey(): string {
    return `${this.databaseName}:${this.keyName}`;
  }

  private async getMasterKey(): Promise<CryptoKey> {
    if (!this.cryptoAvailable) {
      throw new CryptoUnavailableError();
    }
    if (this.cachedKey) return this.cachedKey;

    const existingPromise = masterKeyPromises.get(this.promiseKey) ?? this.masterKeyPromise;
    if (existingPromise) return existingPromise;

    const pending = this.loadOrCreateMasterKey();
    this.masterKeyPromise = pending;
    masterKeyPromises.set(this.promiseKey, pending);
    try {
      const key = await pending;
      this.cachedKey = key;
      return key;
    } finally {
      masterKeyPromises.delete(this.promiseKey);
      this.masterKeyPromise = null;
    }
  }

  private async loadOrCreateMasterKey(): Promise<CryptoKey> {
    const hasIndexedDB = typeof indexedDB !== 'undefined';

    if (hasIndexedDB) {
      const stored = await getStoredCryptoKey(this.keyName, this.databaseName);
      if (stored) {
        this.cachedKey = stored;
        return stored;
      }
    }

    // Check localStorage fallback
    const storedKey =
      typeof localStorage !== 'undefined' ? localStorage.getItem(this.keyName) : null;
    if (storedKey) {
      try {
        const keyData = Uint8Array.from(atob(storedKey), (c) => c.charCodeAt(0));

        if (hasIndexedDB) {
          // Import as non-extractable for IndexedDB
          const importedKey = await crypto.subtle.importKey('raw', keyData, 'AES-GCM', false, [
            'encrypt',
            'decrypt',
          ]);
          try {
            const persistedKey = await storeCryptoKeyIfAbsent(
              this.keyName,
              importedKey,
              this.databaseName
            );
            localStorage.removeItem(this.keyName); // Safe to delete after migration
            this.cachedKey = persistedKey;
            return persistedKey;
          } catch (e) {
            console.error('[SecureStorage] Failed to store migrated key in IndexedDB:', e);
            throw new CryptoUnavailableError(
              'The existing secure storage key could not be safely migrated to IndexedDB.'
            );
          }
        } else {
          if (!this.allowLegacyLocalStorageKeyFallback) {
            throw new CryptoUnavailableError(
              'IndexedDB is required to persist secure storage keys in this application.'
            );
          }

          // Legacy compatibility only. New callers must not persist an
          // extractable encryption key in localStorage.
          const importedKey = await crypto.subtle.importKey('raw', keyData, 'AES-GCM', true, [
            'encrypt',
            'decrypt',
          ]);
          this.cachedKey = importedKey;
          return importedKey;
        }
      } catch (e) {
        console.error('[SecureStorage] Master key restoration/migration failed, regenerating', e);
        if (e instanceof CryptoUnavailableError) throw e;
      }
    }

    // Generate new key
    if (hasIndexedDB) {
      try {
        const newKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
          'encrypt',
          'decrypt',
        ]);
        const persistedKey = await storeCryptoKeyIfAbsent(
          this.keyName,
          newKey,
          this.databaseName
        );
        this.cachedKey = persistedKey;
        return persistedKey;
      } catch (e) {
        console.error('[SecureStorage] Failed to create non-extractable key in IndexedDB:', e);
      }
    }

    if (!this.allowLegacyLocalStorageKeyFallback) {
      throw new CryptoUnavailableError(
        'IndexedDB is required to persist secure storage keys in this application.'
      );
    }

    // Legacy compatibility only. This path is intentionally opt-in so normal
    // application instances never write a reusable key to localStorage.
    const newKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
      'encrypt',
      'decrypt',
    ]);
    if (typeof localStorage !== 'undefined') {
      const exported = await crypto.subtle.exportKey('raw', newKey);
      localStorage.setItem(this.keyName, bytesToBase64(new Uint8Array(exported)));
    }
    this.cachedKey = newKey;
    return newKey;
  }

  public async encrypt(data: string): Promise<string> {
    if (!this.cryptoAvailable) {
      throw new CryptoUnavailableError();
    }
    const key = await this.getMasterKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(data);

    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);

    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);

    return bytesToBase64(combined);
  }

  public async decrypt(encryptedBase64: string): Promise<string | null> {
    try {
      if (!this.cryptoAvailable) {
        return null;
      }
      const key = await this.getMasterKey();
      const combined = Uint8Array.from(atob(encryptedBase64), (c) => c.charCodeAt(0));
      const iv = combined.slice(0, 12);
      const data = combined.slice(12);

      const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);

      return new TextDecoder().decode(decrypted);
    } catch (e) {
      console.error('[SecureStorage] Decryption failed', e);
      return null;
    }
  }

  public async setItem(key: string, value: unknown, options?: SetItemOptions): Promise<void> {
    const envelope: StorageEnvelope = {
      __v: 1,
      d: value,
      ...(options?.ttlMs && options.ttlMs > 0 ? { exp: Date.now() + options.ttlMs } : {}),
    };
    const json = JSON.stringify(envelope);
    const encrypted = await this.encrypt(json);

    if (typeof indexedDB !== 'undefined') {
      try {
        await storeData(key, encrypted, this.databaseName);
        if (typeof localStorage !== 'undefined') {
          localStorage.removeItem(`s_${key}`);
        }
        return;
      } catch (e) {
        console.warn('[SecureStorage] Failed to store in IndexedDB, falling back to localStorage:', e);
      }
    }

    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(`s_${key}`, encrypted);
    }
  }

  public async getItem<T>(key: string): Promise<T | null> {
    const meta = await this.getMetadata<T>(key);
    if (!meta) return null;
    if (meta.expired) {
      await this.removeItem(key);
      return null;
    }
    return meta.value;
  }

  public async getMetadata<T>(key: string): Promise<StorageItemMetadata<T> | null> {
    let encrypted: string | null = null;

    if (typeof indexedDB !== 'undefined') {
      encrypted = await getStoredData(key, this.databaseName);
    }

    // Migration path: check localStorage fallback
    if (!encrypted && typeof localStorage !== 'undefined') {
      const localValue = localStorage.getItem(`s_${key}`);
      if (localValue) {
        encrypted = localValue;
        if (typeof indexedDB !== 'undefined') {
          try {
            await storeData(key, localValue, this.databaseName);
            localStorage.removeItem(`s_${key}`);
          } catch (e) {
            console.error('[SecureStorage] Failed to migrate local storage item to IndexedDB:', e);
          }
        }
      }
    }

    if (!encrypted) return null;
    const decrypted = await this.decrypt(encrypted);
    if (!decrypted) return null;
    try {
      const parsed = JSON.parse(decrypted) as unknown;
      // Check if wrapped in StorageEnvelope
      if (parsed && typeof parsed === 'object' && '__v' in parsed && 'd' in parsed) {
        const env = parsed as StorageEnvelope<T>;
        const expiresAt = typeof env.exp === 'number' ? env.exp : null;
        const expired = Boolean(expiresAt && Date.now() > expiresAt);
        return {
          value: env.d,
          expiresAt,
          expired,
        };
      }
      // Backward-compatible for raw stored JSON
      return {
        value: parsed as T,
        expiresAt: null,
        expired: false,
      };
    } catch (error) {
      console.warn(`[SecureStorage] Ignoring corrupted value for ${key}`, error);
      return null;
    }
  }

  public async removeItem(key: string): Promise<void> {
    if (typeof indexedDB !== 'undefined') {
      await removeStoredData(key, this.databaseName);
    }
    if (typeof localStorage !== 'undefined') {
      localStorage.removeItem(`s_${key}`);
    }
  }

  public async clear(): Promise<void> {
    if (typeof indexedDB !== 'undefined') {
      await clearStoredData(this.databaseName);
    }
    if (typeof localStorage !== 'undefined') {
      const keysToRemove: string[] = [];
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k?.startsWith('s_')) keysToRemove.push(k);
      }
      for (const k of keysToRemove) {
        localStorage.removeItem(k);
      }
    }
  }

  public async keys(): Promise<string[]> {
    const keySet = new Set<string>();
    if (typeof indexedDB !== 'undefined') {
      const idbKeys = await getAllStoredDataKeys(this.databaseName);
      for (const k of idbKeys) keySet.add(k);
    }
    if (typeof localStorage !== 'undefined') {
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k?.startsWith('s_')) {
          keySet.add(k.slice(2));
        }
      }
    }
    return Array.from(keySet);
  }

  public async purgeExpired(): Promise<number> {
    const allKeys = await this.keys();
    let purged = 0;
    for (const key of allKeys) {
      const meta = await this.getMetadata(key);
      if (meta?.expired) {
        await this.removeItem(key);
        purged++;
      }
    }
    return purged;
  }

  public async withLock<T>(fn: () => Promise<T>): Promise<T> {
    const lockName = `webcrypto_secure_storage:${this.databaseName}`;
    const nav = typeof navigator !== 'undefined' ? (navigator as unknown as { locks?: { request?: (name: string, cb: () => Promise<T>) => Promise<T> } }) : undefined;
    if (nav?.locks?.request) {
      return nav.locks.request(lockName, () => fn());
    }
    return fn();
  }

  public async exportEncryptedBundle(passphrase: string): Promise<string> {
    if (!passphrase) throw new Error('Passphrase is required to export bundle');
    const allKeys = await this.keys();
    const bundleData: Record<string, unknown> = {};
    for (const k of allKeys) {
      const val = await this.getItem(k);
      if (val !== null) bundleData[k] = val;
    }

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    const derivedKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-512' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const payloadBytes = enc.encode(JSON.stringify(bundleData));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, derivedKey, payloadBytes);

    return `v1_bundle.${bytesToBase64(salt)}.${bytesToBase64(iv)}.${bytesToBase64(new Uint8Array(ciphertext))}`;
  }

  public async importEncryptedBundle(
    bundleString: string,
    passphrase: string,
    options?: ImportBundleOptions
  ): Promise<number> {
    if (!bundleString || !passphrase) throw new Error('Bundle string and passphrase are required');
    const parts = bundleString.split('.');
    if (parts.length !== 4 || parts[0] !== 'v1_bundle') {
      throw new Error('Invalid bundle format or unsupported version');
    }
    let salt: Uint8Array<ArrayBuffer>;
    let iv: Uint8Array<ArrayBuffer>;
    let ciphertext: Uint8Array<ArrayBuffer>;
    try {
      salt = base64ToBytes(parts[1]);
      iv = base64ToBytes(parts[2]);
      ciphertext = base64ToBytes(parts[3]);
    } catch {
      throw new Error('Corrupted or invalid Base64 in bundle envelope');
    }

    if (salt.length < 16 || iv.length !== 12 || ciphertext.length < 16) {
      throw new Error('Invalid cryptographic envelope boundaries');
    }

    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    const derivedKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-512' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, derivedKey, ciphertext);
    let data: Record<string, unknown>;
    try {
      data = JSON.parse(new TextDecoder().decode(decrypted)) as Record<string, unknown>;
    } catch {
      throw new Error('Decrypted bundle payload is not valid JSON');
    }

    let imported = 0;
    const overwrite = options?.overwrite !== false;
    for (const [key, val] of Object.entries(data)) {
      if (!overwrite) {
        const existing = await this.getItem(key);
        if (existing !== null) continue;
      }
      await this.setItem(key, val);
      imported++;
    }
    return imported;
  }
}

export { SharedSecureStorage as SecureStorage };

export interface UpdateCheckResponse {
  product: string;
  channel: string;
  currentVersion: string;
  latestVersion: string;
  minSupportedVersion?: string;
  graceUntil?: string | null;
  updateAvailable: boolean;
  forceUpdate: boolean;
  mustUpdateNow?: boolean;
  downloadUrl: string;
  sha256: string;
  publishedAt: string;
  notes?: string;
  releaseNotes?: string;
  manifestPayload?: Record<string, unknown>;
  manifestSigned?: boolean;
  manifestSignature?: string;
  manifestAlgorithm?: string;
  manifestKeyId?: string;
}

export type VerifyManifestOptions = {
  requireSignedManifest: boolean;
  fallbackPublicKey?: string;
  publicKeyMapJson?: string;
  enableServerVerification?: boolean;
};

function parsePublicKeyMap(raw?: string): Record<string, string> {
  if (!raw) {
    return {};
  }

  try {
    const parsed = JSON.parse(raw) as Record<string, string>;
    return Object.fromEntries(
      Object.entries(parsed).filter(
        (entry): entry is [string, string] =>
          typeof entry[0] === 'string' && typeof entry[1] === 'string'
      )
    );
  } catch {
    throw new Error('VITE_UPDATE_SIGNING_PUBLIC_KEYS must be valid JSON map.');
  }
}

function resolvePublicKey(response: UpdateCheckResponse, options: VerifyManifestOptions): string {
  const keyMap = new Map(Object.entries(parsePublicKeyMap(options.publicKeyMapJson)));
  if (response.manifestKeyId && keyMap.has(response.manifestKeyId)) {
    return keyMap.get(response.manifestKeyId)!;
  }

  if (options.fallbackPublicKey) {
    return options.fallbackPublicKey;
  }

  if (response.manifestKeyId) {
    throw new Error(`No public key configured for manifest keyId: ${response.manifestKeyId}`);
  }

  throw new Error('Update signing public key is not configured.');
}

async function verifyLocally(
  response: UpdateCheckResponse,
  options: VerifyManifestOptions
): Promise<void> {
  if (!response.manifestSigned && options.requireSignedManifest) {
    throw new Error('Unsigned update manifest is not allowed.');
  }

  if (!response.manifestSigned) {
    return;
  }

  if (!response.manifestPayload || !response.manifestSignature) {
    throw new Error('Signed manifest is missing payload or signature.');
  }

  const verified = await verifyEd25519ManifestSignature(
    response.manifestPayload,
    response.manifestSignature,
    resolvePublicKey(response, options)
  );

  if (!verified) {
    throw new Error('Update manifest signature verification failed.');
  }
}

async function verifyWithServer(
  updateApi: UpdateVerifyHttpClient,
  response: UpdateCheckResponse
): Promise<void> {
  if (!response.manifestSigned || !response.manifestPayload || !response.manifestSignature) {
    return;
  }

  const verifyResponse = await updateApi.post('/verify-signature', {
    manifestPayload: response.manifestPayload,
    manifestSignature: response.manifestSignature,
    manifestAlgorithm: response.manifestAlgorithm,
    manifestKeyId: response.manifestKeyId,
  });

  if (!verifyResponse.data?.verified) {
    throw new Error('Server-side update manifest verification failed.');
  }
}

export async function verifyUpdateManifestSignature(
  updateApi: UpdateVerifyHttpClient,
  response: UpdateCheckResponse,
  options: VerifyManifestOptions
): Promise<void> {
  await verifyLocally(response, options);

  if (options.enableServerVerification !== false) {
    await verifyWithServer(updateApi, response);
  }
}

export async function hashPasswordClient(password: string, loginId: string): Promise<string> {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new CryptoUnavailableError(
      'Web Crypto is required to hash a password. Enable HTTPS or a secure local origin and retry.'
    );
  }
  return deriveClientPasswordHash(password, loginId);
}
