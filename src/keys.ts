import sodium from 'libsodium-wrappers';
import type { KeyPair } from './types';

export class KeyManager {
  private inited = false;

  async init(): Promise<void> {
    if (!this.inited) {
      await sodium.ready;
      this.inited = true;
    }
  }

  generateIdentityKeyPair(): KeyPair {
    const keyPair = sodium.crypto_sign_keypair();
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
    };
  }

  generateDeviceKeyPair(): KeyPair {
    const keyPair = sodium.crypto_kx_keypair();
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
    };
  }

  convertIdentityPubToDevicePub(identityPub: Uint8Array): Uint8Array {
    return sodium.crypto_sign_ed25519_pk_to_curve25519(identityPub);
  }

  convertIdentityPrivToDevicePriv(identityPriv: Uint8Array): Uint8Array {
    return sodium.crypto_sign_ed25519_sk_to_curve25519(identityPriv);
  }

  static generateSafetyNumber(
    myIdentityPub: Uint8Array,
    theirIdentityPub: Uint8Array,
  ): string {
    const cmp = sodium.compare(myIdentityPub, theirIdentityPub);
    const first = cmp <= 0 ? myIdentityPub : theirIdentityPub;
    const second = cmp <= 0 ? theirIdentityPub : myIdentityPub;

    const combined = new Uint8Array(first.length + second.length);
    combined.set(first, 0);
    combined.set(second, first.length);

    let hash = sodium.crypto_generichash(64, combined, null);
    for (let i = 0; i < 4; i++) {
      hash = sodium.crypto_generichash(64, hash, null);
    }

    const digits: string[] = [];
    for (let i = 0; i < 30; i++) {
      digits.push(String(hash[i] % 100).padStart(2, '0'));
    }

    const raw = digits.join('');
    const blocks: string[] = [];
    for (let i = 0; i < 60; i += 5) {
      blocks.push(raw.slice(i, i + 5));
    }
    return blocks.join(' ');
  }
}
