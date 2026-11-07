# webcrypto-secure-storage

[![codecov](https://codecov.io/gh/takao-dev/webcrypto-secure-storage/branch/main/graph/badge.svg)](https://codecov.io/gh/takao-dev/webcrypto-secure-storage)
[![npm version](https://img.shields.io/npm/v/webcrypto-secure-storage.svg)](https://www.npmjs.com/package/webcrypto-secure-storage)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)]()

> **ブラウザの Web Crypto API（非抽出 AES-256-GCM 鍵）と IndexedDB を用いた、ゼロ依存・本番水準の暗号化クライアントストレージ。**

マルチタブ起動時の初回鍵生成レースの調停、`localStorage` からのゼロダウンタイム暗号化移行、TTL（有効期限）による自動失効、Web Locks API による排他制御、暗号化バックアップのエクスポート/インポート、PBKDF2-SHA512 クライアントパスワードハッシュ導出、Ed25519 アップデートマニフェスト署名検証を標準搭載しています。

[English README is available here](./README.md)

---

## 🔒 なぜ `webcrypto-secure-storage` なのか？

npm に存在する多くの「暗号化 localStorage」ライブラリには深刻なセキュリティ・設計上の欠陥があります：

1. **秘密鍵の平文保持**: 暗号鍵やパスフレーズを JavaScript のメモリ、環境変数、あるいは `localStorage` 内に平文文字列として保存している。XSS（クロスサイトスクリプティング）攻撃が発生した際、攻撃者は即座に鍵を窃取して全データをオフラインで復号できてしまいます。
2. **初回起動時のマルチタブ競合破壊**: ユーザーがブラウザで同時に複数タブを開いた場合、各タブが別々の鍵を生成・上書きし合い、他方のタブで保存したデータが永久に復号不能になる。
3. **安全ではないフォールバック**: 暗号化に失敗した際に、警告なく平文や Base64 エンコードだけで保存してしまう。

`webcrypto-secure-storage` はこれらの問題を根本から解決します：

- **非抽出マスターキー (`extractable: false`)**:
  鍵は Web Crypto API でネイティブ生成され、`extractable: false` の構造化クローン可能な `CryptoKey` オブジェクトとして `IndexedDB` に直接保管されます。ブラウザエンジンにより保護されるため、**仮に XSS で悪意あるスクリプトが注入されても生の秘密鍵バイト列を外部に持ち出すことは不可能**です。
- **マルチタブ初回キー生成レース調停**:
  `IDBObjectStore.add()` と `ConstraintError` を活用し、2つのタブがミリ秒単位で同時に初期化されても、競合に敗れたタブが生成中の鍵を破棄し、コミットに成功した勝者の鍵を透過的にロードします。
- **Fail-Closed（安全側に倒す設計）**:
  Web Crypto や IndexedDB が利用できない環境で、暗号化されていないデータを暗黙に保存することは絶対にありません（安全な `CryptoUnavailableError` をスロー）。
- **TTL による自動失効と一括パージ**:
  キャッシュトークンや一時セッションに有効期限（ミリ秒）を設定可能。期限切れのアイテムは次回アクセス時に自動で安全に削除されます。
- **Web Locks API によるマルチタブ排他制御**:
  ブラウザの `navigator.locks` を通じて、複数タブ間での重複処理や書き込みの競合をアトミックに排他制御します。
- **外部依存ゼロ（Zero Runtime Dependencies）**:
  最新の Web 標準 API のみで構築されており、パッケージサイズは約 18 kB。サプライチェーン攻撃のリスクを排除しています。

---

## 📦 インストール

```bash
npm install webcrypto-secure-storage
```

---

## 🚀 クイックスタート

### 1. 暗号化ストレージの基本利用

```typescript
import { SecureStorage } from 'webcrypto-secure-storage';

// マスターキー名を指定してストレージを初期化
const storage = new SecureStorage('my-app-auth-key');

// 1. 機密データ（セッション情報等）を安全に保存（TTLオプション対応）
await storage.setItem('auth_session', {
  userId: 'usr_98124',
  token: 'secret-auth-token',
  role: 'admin',
}, { ttlMs: 1000 * 60 * 60 }); // 1時間後に自動失効

// 2. 型安全な取得（期限切れや破損時は自動で null を返却してクリーンアップ）
interface Session {
  userId: string;
  token: string;
  role: string;
}
const session = await storage.getItem<Session>('auth_session');
console.log(session?.userId); // "usr_98124"

// 3. メタデータ（有効期限や失効状態）の確認
const meta = await storage.getMetadata<Session>('auth_session');
console.log(meta?.expiresAt, meta?.expired);

// 4. キー一覧・期限切れアイテムの一括パージ
const allKeys = await storage.keys();
const purgedCount = await storage.purgeExpired();

// 5. 削除
await storage.removeItem('auth_session');
```

---

### 2. マルチタブ排他制御（Web Locks API）

```typescript
// 複数タブが開かれていても、安全に1つのタブずつアトミックに処理
await storage.withLock(async () => {
  const currentCount = (await storage.getItem<number>('login_attempts')) ?? 0;
  await storage.setItem('login_attempts', currentCount + 1);
});
```

---

### 3. 暗号化バックアップのエクスポートとインポート

ユーザーの全保存データを、ユーザー自身が指定したパスフレーズ（PBKDF2-SHA512 + AES-256-GCM）で暗号化してファイルや文字列としてエクスポート・リストアできます。

```typescript
// パスフレーズを指定して暗号化バンドルを出力
const backupBundle = await storage.exportEncryptedBundle('user-secure-passphrase');
// -> "v1_bundle.<salt_b64>.<iv_b64>.<ciphertext_b64>"

// 別端末や別ブラウザでリストア
const importedCount = await storage.importEncryptedBundle(
  backupBundle,
  'user-secure-passphrase',
  { overwrite: true }
);
console.log(`リストア成功: ${importedCount} 件のアイテムを復元しました`);
```

---

### 4. クライアント側パスワードハッシュ導出 (`deriveClientPasswordHash`)

サーバーへ平文パスワードを送信する前に、クライアント側で PBKDF2-SHA512 ストレッチングを実行し、ネットワーク経路やログでの漏洩を防止します。

```typescript
import { deriveClientPasswordHash } from 'webcrypto-secure-storage';

// ログインIDをソルトとして正規化し、280,000回の PBKDF2-SHA512 でハッシュ化
const clientHash = await deriveClientPasswordHash('MySecretPassword123!', 'user@example.com');
// -> サーバーにはこのハッシュ文字列を送信
```

---

### 5. Ed25519 マニフェスト電子署名検証 (`verifyEd25519ManifestSignature`)

アプリケーションの自動アップデート時、改ざんされた悪意あるマニフェストが実行されないよう、公開鍵（PEM）で署名を高速検証します。

```typescript
import { verifyEd25519ManifestSignature } from 'webcrypto-secure-storage';

const isValid = await verifyEd25519ManifestSignature(
  manifestPayload,
  signatureBase64,
  publicKeyPem
);

if (!isValid) {
  throw new Error('アップデートマニフェストの電子署名が不正です！更新を中止します。');
}
```

---

## 🛡️ セキュリティモデル

- **暗号アルゴリズム**: AES-256-GCM（256ビット鍵長、12バイトのランダムIV、16バイトの認証タグ）。
- **IVの再利用防止**: 暗号化ごとに `crypto.getRandomValues(new Uint8Array(12))` を生成。IVの使い回しによる脆弱性を完全に排除。
- **鍵の導出**: PBKDF2-SHA512（OWASP 推奨基準を満たす十分な反復回数と16バイト以上のクリプトソルト）。
- **完全性検証**: GCM 認証タグにより、保存データが1ビットでも改ざんされた場合は復号が拒否され、`null` またはエラーとして安全に処理されます。

---

## 📄 ライセンス

MIT License © 2026 takao-dev
