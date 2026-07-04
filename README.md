# MOURN E2EE Core

MOURN E2EE Core is a standalone TypeScript extraction of the cryptographic primitives used by the MOURN desktop messaging system.

This repository exists for transparency and security review. It shows how our client-side end-to-end encryption works at the cryptographic layer without publishing production transport code, backend authorization logic, service infrastructure, operational secrets, or deployment details.

## License

This repository is **source-available for transparency and security review only**. It is not open source and may not be used commercially, redistributed, incorporated into another product, or used in production without prior written permission.

See [`LICENSE`](./LICENSE).

## Permission Requests

If you want to use, modify, redistribute, integrate, commercialize, or build upon this code in any way not expressly allowed by the license, contact us first.

**Discord:** https://discord.gg/sGp8A3nfKj

Please include:

- who you are or what organization you represent;
- how you want to use the software;
- whether the use is commercial, research, educational, or personal;
- whether you plan to modify, redistribute, host, or integrate it;
- any relevant links, repositories, product details, or audit context.

MOURN may approve, deny, or negotiate separate licensing terms at its sole discretion.

## What This Repository Is

This package is the cryptographic core only. It is intended to make the message-encryption design understandable and reviewable.

Included here:

- Ed25519 identity key generation.
- X25519 device key generation.
- Initial shared-secret derivation with X25519 ECDH.
- Signal-style Double Ratchet state transitions.
- XChaCha20-Poly1305 authenticated encryption.
- Authenticated message headers through AEAD additional data.
- Padded plaintext buckets to reduce message-size leakage.
- Skipped message-key caching for out-of-order delivery.
- Optional identity-key TOFU / mismatch detection.
- Safety-number generation for out-of-band identity comparison.

## What This Repository Is Not

This is not the full production MOURN E2EE service.

Intentionally omitted:

- Backend `Device.id` creation and persistence.
- Vault WebSocket authentication tokens.
- Tauri attestation handling.
- API routes and backend authorization checks.
- Message routing, ACK/NACK handling, offline delivery, and delete tombstones.
- Server-side rate limiting, replay controls, and abuse controls.
- Production hostnames, endpoint paths, deployment configuration, and secrets.

The omission is deliberate. These operational layers are not required to audit the encrypted message format and would expose unnecessary service details.

## Protocol Overview

The extracted architecture mirrors a Signal-style Double Ratchet with the following layers.

### 1. Key Generation and Identity Binding

- Long-term identity keys are generated as Ed25519 key pairs.
- Device keys are generated as X25519-compatible key pairs used for ECDH.
- Identity public keys can be converted to X25519 public keys if an integration needs encryption interoperability.

### 2. Initial Shared Secret Derivation

The initial shared secret `SK` is computed as:

```text
DH(myDevicePriv, theirDevicePub)
```

Initiator/responder role is derived deterministically using a shared HMAC over user IDs when available, with a fallback to device public key ordering.

### 3. Double Ratchet State

The ratchet maintains:

- `RK` — root key.
- `DHs` — local sending ratchet keypair.
- `DHr` — remote party's latest ratchet public key.
- `CKs` — sending chain key.
- `CKr` — receiving chain key.
- `Ns` / `Nr` — sending and receiving message counters.
- `PN` — length of the previous sending chain.
- `MKSKIPPED` — cached skipped message keys for out-of-order delivery.

Sending consumes `CKs` through `KDF_CK`, producing per-message keys. Receiving advances `CKr` and performs a Diffie-Hellman ratchet step whenever the sender's ratchet public key changes.

### 4. Authenticated Encryption

Message payloads are padded to fixed-size buckets before encryption to reduce size leakage.

Payloads are encrypted with `XChaCha20-Poly1305` using libsodium.

Additional authenticated data covers:

```text
senderDHRPub || messageIndex || PN
```

This means tampering with the ratchet public key, message index, or previous-chain length causes AEAD authentication failure before plaintext is released.

### 5. Identity Verification

Optional sender identity-key binding is supported.

If a previously bound identity key differs from a received identity key, the engine flags the link as compromised and rejects the frame.

Identity mismatch detection only works when callers consistently bind or provide identity public keys:

- Call `bindIdentityKey()` after an out-of-band trust decision, or
- Pass `senderIdentityKey` to `decryptFrame()` for every received message.

If no identity key is supplied, the engine still decrypts authenticated ciphertext but cannot detect identity-key substitution for that frame.

## Device IDs vs Device Keys

This package has **device keys**, not production **device IDs**.

- `generateDeviceKeyPair()` creates the local X25519 keypair used for ECDH.
- A production `deviceId` is a backend database identifier assigned after authenticated device registration.
- The production `deviceId` is used for routing encrypted frames to the correct online/offline device.
- The production `deviceId` is not a cryptographic secret, but it is part of the service transport layer and is intentionally omitted here.

For transparency without increasing attack surface, this package demonstrates the cryptographic device key material while excluding server-issued device IDs, vault tokens, and transport routing.

## Ratchet State Warning

`exportRatchetState()` returns sensitive local client state.

It contains live ratchet secrets, including:

- root keys;
- sending and receiving chain keys;
- skipped message keys;
- the current ratchet private key.

Do not log, publish, transmit, or expose exported `RatchetState`. In an application, it should only be stored in local client-controlled storage appropriate for the platform.

## File & API Reference

### `src/keys.ts`

`KeyManager`

- `init(): Promise<void>`
- `generateIdentityKeyPair(): KeyPair`
- `generateDeviceKeyPair(): KeyPair`
- `convertIdentityPubToDevicePub(identityPub: Uint8Array): Uint8Array`
- `convertIdentityPrivToDevicePriv(identityPriv: Uint8Array): Uint8Array`
- `static generateSafetyNumber(myIdentityPub: Uint8Array, theirIdentityPub: Uint8Array): string`

### `src/ratchet.ts`

`KDF`

- `static deriveRoot(rk: Uint8Array, dhOut: Uint8Array)` → `{ rootKey, chainKey }`
- `static deriveChain(ck: Uint8Array)` → `{ chainKey, messageKey }`

`DoubleRatchet`

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

`PaddingLayer`

- `static applyPadding(payload: string): Uint8Array`
- `static stripPadding(paddedArray: Uint8Array): string`

### `src/engine.ts`

`CipherEngine`

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
- WebCrypto primitives from the runtime:
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

If you are reviewing the repository from a fresh checkout, prefer reproducible installs:

```bash
npm ci
npm run typecheck
npm run build
```

## Security Research

Security researchers may reference this repository in responsible disclosure reports, audits, articles, or discussions. Please do not publish exploitable operational details, production secrets, or modified copies of the software.

For permission requests or security discussion, contact us on Discord:

https://discord.gg/sGp8A3nfKj
