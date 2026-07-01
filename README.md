# MOURN E2EE Core

This module isolates the core MOURN desktop end-to-end encryption messaging primitives into a standalone TypeScript package.
It is intended as a pure cryptographic engine for secure message ratcheting, key generation, and authenticated AEAD payload encryption.

## Protocol Overview

The extracted architecture mirrors a Signal-style Double Ratchet with the following layers:

1. **Key generation and identity binding**
   - Long-term identity keys are generated as Ed25519 key pairs.
   - Device keys are generated as X25519-compatible key pairs used for ECDH.
   - Identity public keys can be converted to X25519 public keys for encryption interoperability.

2. **Initial shared secret derivation**
   - The initial shared secret `SK` is computed as `DH(myDevicePriv, theirDevicePub)`.
   - Initiator/responder role is derived deterministically using a shared HMAC over user IDs when available, with a fallback to device public key ordering.

3. **Signal Double Ratchet state**
   - A root key `RK` and sending/receiving chain keys `CKs`/`CKr` are maintained.
   - Sending consumes `CKs` via `KDF_CK`, producing per-message keys.
   - Receiving advances `CKr` and performs a Diffie-Hellman ratchet step whenever the sender's ratchet public key changes.
   - Skipped message keys are cached for out-of-order delivery up to a fixed window.

4. **Authenticated encryption**
   - Message payloads are padded to fixed-size buckets before encryption to mitigate size leakage.
   - Payloads are encrypted with `XChaCha20-Poly1305` using libsodium.
   - Additional authenticated data (AD) covers the sender's ratchet public key, message index, and previous chain length.

5. **Identity key verification and mismatch detection**
   - Optional sender identity key binding is supported.
   - If a previously bound identity key differs from a received identity key, the engine flags the link as compromised.

## File & API Reference

### `src/keys.ts`

- `KeyManager`
  - `init(): Promise<void>`
  - `generateIdentityKeyPair(): KeyPair`
  - `generateDeviceKeyPair(): KeyPair`
  - `convertIdentityPubToDevicePub(identityPub: Uint8Array): Uint8Array`
  - `convertIdentityPrivToDevicePriv(identityPriv: Uint8Array): Uint8Array`
  - `static generateSafetyNumber(myIdentityPub: Uint8Array, theirIdentityPub: Uint8Array): string`

### `src/ratchet.ts`

- `KDF`
  - `static deriveRoot(rk: Uint8Array, dhOut: Uint8Array)` → `{ rootKey, chainKey }`
  - `static deriveChain(ck: Uint8Array)` → `{ chainKey, messageKey }`

- `DoubleRatchet`
  - `init(): Promise<void>`
  - `setDevicePrivKey(_priv: Uint8Array): void`
  - `static preInitChain(SK: Uint8Array): Uint8Array`
  - `initSender(SK: Uint8Array, theirRatchetPub: Uint8Array): void`
  - `initReceiver(SK: Uint8Array, myInitialKeyPair: { publicKey: Uint8Array; privateKey: Uint8Array }): void`
  - `ratchetForSend()` → `{ messageKey, senderDHRPub, messageIndex, PN }`
  - `processRatchetStep(senderDHRPub: Uint8Array, messageIndex: number, PN: number)` → `{ messageKey, messageIndex }`
  - `exportState(): RatchetState`
  - `importState(state: RatchetState): void`

### `src/padding.ts`

- `PaddingLayer`
  - `static applyPadding(payload: string): Uint8Array`
  - `static stripPadding(paddedArray: Uint8Array): string`

### `src/engine.ts`

- `CipherEngine`
  - `init(myDevicePriv: Uint8Array, theirDevicePub: Uint8Array, myUserId?: string, theirUserId?: string): Promise<void>`
  - `exportRatchetState(): RatchetState`
  - `importRatchetState(state: RatchetState): Promise<void>`
  - `bindIdentityKey(identityKey: Uint8Array): void`
  - `getLinkSecurityState(): LinkSecurityState`
  - `encryptFrame(plaintext: string): Promise<EncryptedMessage>`
  - `decryptFrame(cipherPkg: EncryptedMessage, opts?: { senderIdentityKey?: Uint8Array }): Promise<string>`
  - `onIdentityMismatch?: (details: { storedIdentityKey: Uint8Array; receivedIdentityKey: Uint8Array }) => void`

### `src/index.ts`

Re-exports the package public surface:
- `KeyManager`
- `CipherEngine`
- `DoubleRatchet`
- `KDF`
- `PaddingLayer`
- `KeyPair`, `EncryptedMessage`, `LinkSecurityState`, `RatchetState`

## Dependency Manifest

Dependencies are intentionally minimal and focused on audited cryptographic primitives:

- `libsodium-wrappers`
  - Provides X25519/ECDH keypair generation, Ed25519 key conversion, XChaCha20-Poly1305 AEAD, and BLAKE2b generic hashing.
- WebCrypto primitives (browser / Node-compatible runtime):
  - `crypto.subtle.sign`
  - `crypto.subtle.importKey`
  - `TextEncoder` / `TextDecoder`
  - `crypto.getRandomValues`

## Build & Validation

Run the following in `mourn-e2e`:

```bash
npm install
npm run typecheck
npm run build
```
