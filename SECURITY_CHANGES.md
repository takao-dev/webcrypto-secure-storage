# Update manifest verification migration

verifyUpdateManifestSignature keeps its Promise<void> API but now rejects signed update responses whose effective artifact fields differ from the signed payload.

Required signed fields: product, channel, downloadUrl, sha256, publishedAt, and latestVersion (version is accepted as an alias; both must agree if present). Include forceUpdate and any supplied minSupportedVersion, graceUntil, mustUpdateNow, notes or releaseNotes exactly as returned. Partial signatures over only product/version/channel are intentionally rejected.

currentVersion and updateAvailable describe client/request context and are not authenticated release claims. Consumers must independently enforce product/channel policy, anti-rollback/freshness, and the downloaded artifact's SHA-256 before installation. The verifier detects mutation during asynchronous verification; callers must not mutate verified data afterward.

The low-level verifyEd25519ManifestSignature authenticates exactly its payload argument. It does not authenticate sibling fields in a separate object. No network installation or publication was performed.
