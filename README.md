# MOURN E2EE Core

This module isolates the core MOURN desktop end-to-end encryption messaging primitives into a standalone TypeScript package.
It is intended as a pure cryptographic engine for secure message ratcheting, key generation, and authenticated AEAD payload encryption.

This repository is published for transparency. It intentionally shows how message keys, device keys, identity keys, padding, and ratchet state work without including our operational secrets.

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

## Public Security Boundary

Included here:

- Ed25519 identity key generation.
- X25519 device key generation.
- Initial shared-secret derivation with X25519 ECDH.
- Signal-style Double Ratchet state transitions.
- XChaCha20-Poly1305 authenticated encryption.
- Padded plaintext buckets to reduce message-size leakage.
- Optional identity-key TOFU / mismatch detection.

## Device IDs vs Device Keys

This package has **device keys**, instead of our DeviceID system. For security purposes.


## Ratchet State Warning

`exportRatchetState()` returns sensitive local client state. It contains live ratchet secrets, including root keys, chain keys, skipped message keys, and the current ratchet private key.

Do not log, publish, transmit, or expose exported `RatchetState`. In an application, it should only be stored in local client-controlled storage appropriate for the platform.

## Identity Verification Note

Identity mismatch detection only works when callers consistently bind or provide identity public keys:

- Call `bindIdentityKey()` after an out-of-band trust decision, or
- Pass `senderIdentityKey` to `decryptFrame()` for every received message.

If no identity key is supplied, the engine still decrypts authenticated ciphertext but cannot detect identity-key substitution for that frame.

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

Run the following in `mourn-e2ee`:

```bash
npm install
npm run typecheck
npm run build
```
