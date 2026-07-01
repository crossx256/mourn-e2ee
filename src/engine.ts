import sodium from 'libsodium-wrappers';
import type { EncryptedMessage, LinkSecurityState, RatchetState } from './types';
import { PaddingLayer } from './padding';
import { DoubleRatchet } from './ratchet';

export class CipherEngine {
  private inited = false;
  private ratchet: DoubleRatchet | null = null;
  private storedIdentityKey?: Uint8Array;
  private isCompromised = false;

  public onIdentityMismatch?: (details: {
    storedIdentityKey: Uint8Array;
    receivedIdentityKey: Uint8Array;
  }) => void;

  async init(
    myDevicePriv: Uint8Array,
    theirDevicePub: Uint8Array,
    myUserId?: string,
    theirUserId?: string,
  ): Promise<void> {
    if (!this.inited) {
      await sodium.ready;
      this.inited = true;
    }

    const myDevicePub = sodium.crypto_scalarmult_base(myDevicePriv);
    const SK = sodium.crypto_scalarmult(myDevicePriv, theirDevicePub);

    const ratchet = new DoubleRatchet();
    await ratchet.init();

    let iAmInitiator: boolean;

    if (myUserId && theirUserId) {
      const userIdString = [myUserId, theirUserId].sort().join('||');
      const hmacHash = await crypto.subtle.sign(
        'HMAC',
        await crypto.subtle.importKey(
          'raw',
          new Uint8Array(SK),
          { name: 'HMAC', hash: 'SHA-256' },
          false,
          ['sign'],
        ),
        new TextEncoder().encode(userIdString),
      );
      const hmacArray = new Uint8Array(hmacHash);
      const roleValue = hmacArray[0] ?? 0;
      const myUserIdFirst = myUserId < theirUserId;
      const thisPartyIsInitiator = roleValue < 128;
      iAmInitiator = myUserIdFirst ? thisPartyIsInitiator : !thisPartyIsInitiator;
    } else {
      iAmInitiator = sodium.compare(myDevicePub, theirDevicePub) < 0;
    }

    if (iAmInitiator) {
      ratchet.initSender(SK, theirDevicePub);
    } else {
      ratchet.initReceiver(SK, { publicKey: myDevicePub, privateKey: myDevicePriv });
    }

    this.ratchet = ratchet;
  }

  exportRatchetState(): RatchetState {
    if (!this.ratchet) throw new Error('Engine not initialized');
    return this.ratchet.exportState();
  }

  async importRatchetState(state: RatchetState): Promise<void> {
    if (!this.ratchet) {
      const ratchet = new DoubleRatchet();
      await ratchet.init();
      this.ratchet = ratchet;
    }
    await sodium.ready;
    this.ratchet.importState(state);
  }

  bindIdentityKey(identityKey: Uint8Array): void {
    this.storedIdentityKey = identityKey;
    this.isCompromised = false;
  }

  getLinkSecurityState(): LinkSecurityState {
    return {
      storedIdentityKey: this.storedIdentityKey ? sodium.to_hex(this.storedIdentityKey) : undefined,
      isCompromised: this.isCompromised,
    };
  }

  async encryptFrame(plaintext: string): Promise<EncryptedMessage> {
    if (!this.ratchet) throw new Error('Engine not initialized');

    const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const paddedMsg = PaddingLayer.applyPadding(plaintext);

    const { messageKey, senderDHRPub, messageIndex, PN } = this.ratchet.ratchetForSend();
    const ad = buildAD(senderDHRPub, messageIndex, PN);

    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      paddedMsg,
      ad,
      null,
      nonce,
      messageKey,
    );

    messageKey.fill(0);

    return { ciphertext, nonce, messageIndex, senderDHRPub, PN };
  }

  async decryptFrame(
    cipherPkg: EncryptedMessage,
    opts?: { senderIdentityKey?: Uint8Array },
  ): Promise<string> {
    if (!this.ratchet) throw new Error('Engine not initialized');
    if (!cipherPkg.senderDHRPub) throw new Error('Missing senderDHRPub in packet');

    this.assertIdentityKey(opts?.senderIdentityKey);

    const msgIndex = cipherPkg.messageIndex ?? 0;
    const pn = cipherPkg.PN ?? 0;

    const { messageKey } = this.ratchet.processRatchetStep(
      cipherPkg.senderDHRPub,
      msgIndex,
      pn,
    );

    const ad = buildAD(cipherPkg.senderDHRPub, msgIndex, pn);

    try {
      const paddedMsg = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        cipherPkg.ciphertext,
        ad,
        cipherPkg.nonce,
        messageKey,
      );

      messageKey.fill(0);
      return PaddingLayer.stripPadding(paddedMsg);
    } catch (decryptErr) {
      const ratchetState = this.exportRatchetState();
      console.error('[Engine] Decryption failed - AEAD authentication mismatch', {
        reason: (decryptErr as Error).message,
        ad_values: {
          messageIndex: msgIndex,
          PN: pn,
          senderDHRPub_head: sodium.to_hex(cipherPkg.senderDHRPub).slice(0, 16),
        },
        packet_fields: {
          messageIndex: cipherPkg.messageIndex,
          PN: cipherPkg.PN,
          has_nonce: !!cipherPkg.nonce,
          has_ciphertext: !!cipherPkg.ciphertext,
        },
        ratchetState: {
          Ns: ratchetState.Ns,
          Nr: ratchetState.Nr,
          PN: ratchetState.PN,
          CKr_exists: !!ratchetState.CKr_hex,
        },
      });
      throw decryptErr;
    }
  }

  async advanceRatchetAndDropKey(_msgIndex: number): Promise<void> {
    return;
  }

  private assertIdentityKey(senderIdentityKey?: Uint8Array): void {
    if (!senderIdentityKey) return;
    if (!this.storedIdentityKey) {
      this.storedIdentityKey = senderIdentityKey;
      return;
    }
    if (!sodium.memcmp(this.storedIdentityKey, senderIdentityKey)) {
      this.isCompromised = true;
      if (this.onIdentityMismatch) {
        this.onIdentityMismatch({
          storedIdentityKey: this.storedIdentityKey,
          receivedIdentityKey: senderIdentityKey,
        });
      }
      throw new Error('Identity key mismatch detected for this link.');
    }
  }
}

function buildAD(senderDHRPub: Uint8Array, messageIndex: number, PN: number): Uint8Array {
  const ad = new Uint8Array(32 + 4 + 4);
  ad.set(senderDHRPub, 0);
  new DataView(ad.buffer).setUint32(32, messageIndex, true);
  new DataView(ad.buffer).setUint32(36, PN, true);
  return ad;
}
