# webcrypto-secure-storage

[![npm version](https://img.shields.io/npm/v/webcrypto-secure-storage.svg)](https://www.npmjs.com/package/webcrypto-secure-storage)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)]()

Zero-dependency, production-grade browser encrypted storage using **non-extractable Web Crypto `AES-256-GCM` `CryptoKey`s** persisted in `IndexedDB`.

Features **multi-tab first-key race arbitration**, **zero-downtime migration from `localStorage`**, **PBKDF2-SHA512 client password stretching**, and **Ed25519 update manifest signature verification**.

---

## 🔒 Why `webcrypto-secure-storage`?

Most "encrypted `localStorage`" packages on npm suffer from critical architectural flaws:
- They keep the secret key or passphrase as a plaintext string in JavaScript memory, environment variables, or directly inside `localStorage`.
- In the event of a Cross-Site Scripting (XSS) attack, an attacker can trivially extract the key and decrypt all customer data offline.
- When multiple browser tabs open simultaneously for the first time, naive key generation causes a race condition where tabs overwrite each other's keys, permanently corrupting saved data.

`webcrypto-secure-storage` addresses these issues from the ground up:

1. **Non-Extractable Master Keys (`extractable: false`)**:
   Keys are generated natively via the Web Crypto API (`AES-256-GCM`, 256-bit) and stored directly in `IndexedDB` as structured cloneable `CryptoKey` objects. Because `extractable: false` is enforced by the browser engine, **the raw key bytes cannot be extracted even if arbitrary JavaScript is injected via XSS**.
2. **Multi-Tab First-Key Race Arbitration**:
   Uses `IDBObjectStore.add()` with atomic `ConstraintError` handling. If two tabs initialize the key store at the exact same millisecond, the losing tab catches the conflict, discards its tentative key, and loads the committed winner's key.
3. **Fail-Closed Security**:
   Never silently falls back to Base64 or unencrypted storage. If Web Crypto or IndexedDB is unavailable, it throws a strict `CryptoUnavailableError` (unless legacy migration fallback is explicitly configured).
4. **Seamless Migration from Legacy `localStorage`**:
   Automatically detects and decrypts legacy `localStorage` keys, securely migrates both key and payload to IndexedDB with non-extractable flags, and purges the plaintext key from `localStorage`.
5. **Zero External Dependencies**:
   Built exclusively on modern Web APIs (`crypto.subtle` and `indexedDB`). Tiny footprint (~17 kB tarball).

---

## 📦 Installation

```bash
npm install webcrypto-secure-storage
```

---

## 🚀 Quick Start

### 1. Encrypted Storage (`SecureStorage`)

```typescript
import { SecureStorage } from 'webcrypto-secure-storage';

// Initialize storage with a master key name
const storage = new SecureStorage('my-app-auth-key');

// Store sensitive user profile or credentials
await storage.setItem('auth_session', {
  userId: 'usr_98124',
  token: 'secret-auth-token',
  role: 'admin',
});

// Retrieve typed data (returns null if absent or corrupted)
interface Session {
  userId: string;
  token: string;
  role: string;
}
const session = await storage.getItem<Session>('auth_session');
console.log(session?.userId); // 'usr_98124'

// Remove item
await storage.removeItem('auth_session');
```

### 2. Direct Encryption / Decryption

You can also use the storage instance for direct string encryption:

```typescript
const storage = new SecureStorage('my-master-key');

const cipherText = await storage.encrypt('Confidential Data');
const plainText = await storage.decrypt(cipherText);
console.log(plainText); // 'Confidential Data'
```

### 3. Client Password Stretching (`PBKDF2-SHA512`)

Strengthens user passwords on the client side before transmission, preventing plaintext password leakage and protecting server-side databases:

```typescript
import { hashPasswordClient, deriveClientPasswordHash } from 'webcrypto-secure-storage/password';

// Uses 100,000 PBKDF2 rounds with SHA-512 and normalized loginId as salt
const clientHash = await hashPasswordClient('userPassword123', 'User@Example.com');
console.log(clientHash); // 128-character hex string
```

### 4. Ed25519 Manifest Signature Verification

Verify software update manifests or remote configurations using Ed25519 public keys:

```typescript
import { verifyEd25519ManifestSignature } from 'webcrypto-secure-storage/signature';

const isValid = await verifyEd25519ManifestSignature(
  { version: '2.0.0', sha256: '...' },
  manifestSignatureBase64,
  publicKeyPem
);
```

---

## ⚙️ Configuration Options

```typescript
export interface SharedSecureStorageOptions {
  /**
   * Custom IndexedDB database name.
   * Default: 'webcrypto_secure_key_db'
   */
  databaseName?: string;

  /**
   * Temporary migration switch for legacy environments without IndexedDB.
   * WARNING: Setting this to true stores extractable keys in localStorage.
   * Default: false
   */
  allowLegacyLocalStorageKeyFallback?: boolean;
}
```

Example:

```typescript
const storage = new SecureStorage('custom-key', {
  databaseName: 'my_custom_db',
});
```

---

## 🛡️ Security Architecture

```
┌────────────────────────────────────────────────────────┐
│                      Browser App                       │
├────────────────────────────────────────────────────────┤
│  setItem('data', value)                                │
│       │                                                │
│       ▼                                                │
│  [Web Crypto API] ─── AES-256-GCM                      │
│       │               IV (12 bytes) + Tag (16 bytes)   │
│       │                                                │
│  [CryptoKey] ◄─── extractable: false                   │
│       │           (JS cannot inspect raw key bytes)    │
│       ▼                                                │
│  [IndexedDB Store] ── Structured Clone Storage         │
│       ▲                                                │
│  Multi-Tab Race    ── First-key-wins atomic arbitration│
└────────────────────────────────────────────────────────┘
```

---

## 🧪 Testing

The test suite runs with Node.js built-in test runner without external dependencies:

```bash
npm test
```

---

## 📄 License

MIT License © 2026 takaodev
