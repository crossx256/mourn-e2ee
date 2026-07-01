import sodium from 'libsodium-wrappers';
import type { RatchetState } from './types';

type SodiumKeyPair = { publicKey: Uint8Array; privateKey: Uint8Array };

const MAX_SKIP = 1000;

export class KDF {
  static deriveRoot(rk: Uint8Array, dhOut: Uint8Array): { rootKey: Uint8Array; chainKey: Uint8Array } {
    const out = sodium.crypto_generichash(64, dhOut, rk);
    return { rootKey: out.slice(0, 32), chainKey: out.slice(32, 64) };
  }

  static deriveChain(ck: Uint8Array): { chainKey: Uint8Array; messageKey: Uint8Array } {
    const chainKey = sodium.crypto_generichash(32, new Uint8Array([0x01]), ck);
    const messageKey = sodium.crypto_generichash(32, new Uint8Array([0x02]), ck);
    return { chainKey, messageKey };
  }
}

export class DoubleRatchet {
  private RK: Uint8Array | null = null;
  private DHs: SodiumKeyPair | null = null;
  private DHr: Uint8Array | null = null;
  private CKs: Uint8Array | null = null;
  private CKr: Uint8Array | null = null;
  private Ns = 0;
  private Nr = 0;
  private PN = 0;
  private MKSKIPPED = new Map<string, Uint8Array>();

  public isInitialized = false;

  async init(): Promise<void> {
    await sodium.ready;
  }

  setDevicePrivKey(_priv: Uint8Array) {}

  static preInitChain(SK: Uint8Array): Uint8Array {
    return KDF.deriveChain(SK).chainKey;
  }

  initSender(SK: Uint8Array, theirRatchetPub: Uint8Array): void {
    this.DHs = sodium.crypto_kx_keypair();
    this.DHr = theirRatchetPub;
    const DHs = this.DHs!;
    const DHr = this.DHr!;
    const dh = sodium.crypto_scalarmult(DHs.privateKey, DHr);
    const { rootKey, chainKey } = KDF.deriveRoot(SK, dh);
    this.RK = rootKey;
    this.CKs = chainKey;
    this.CKr = DoubleRatchet.preInitChain(SK);
    this.Ns = 0;
    this.Nr = 0;
    this.PN = 0;
    this.MKSKIPPED.clear();
    this.isInitialized = true;
  }

  initReceiver(SK: Uint8Array, myInitialKeyPair: SodiumKeyPair): void {
    this.RK = SK;
    this.DHs = myInitialKeyPair;
    this.DHr = null;
    this.CKs = DoubleRatchet.preInitChain(SK);
    this.CKr = DoubleRatchet.preInitChain(SK);
    this.Ns = 0;
    this.Nr = 0;
    this.PN = 0;
    this.MKSKIPPED.clear();
    this.isInitialized = true;
  }

  ratchetForSend(): {
    messageKey: Uint8Array;
    senderDHRPub: Uint8Array;
    messageIndex: number;
    PN: number;
  } {
    if (!this.RK || !this.DHs || !this.CKs) {
      throw new Error(
        'Ratchet not ready for sending — CKs is null. The responder must receive at least one message before sending.',
      );
    }

    const { chainKey, messageKey } = KDF.deriveChain(this.CKs);
    this.CKs = chainKey;
    const messageIndex = this.Ns;
    this.Ns += 1;
    return { messageKey, senderDHRPub: this.DHs.publicKey, messageIndex, PN: this.PN };
  }

  processRatchetStep(senderDHRPub: Uint8Array, messageIndex: number, PN: number): {
    messageKey: Uint8Array;
    messageIndex: number;
  } {
    if (!this.RK || !this.DHs) throw new Error('Ratchet not initialized');

    const cacheId = `${sodium.to_hex(senderDHRPub)}:${messageIndex}`;
    const cached = this.MKSKIPPED.get(cacheId);
    if (cached) {
      this.MKSKIPPED.delete(cacheId);
      return { messageKey: cached, messageIndex };
    }

    const theirHex = sodium.to_hex(senderDHRPub);
    const ourDHrHex = this.DHr ? sodium.to_hex(this.DHr) : null;

    if (theirHex !== ourDHrHex && ourDHrHex !== null && PN < this.Nr) {
      throw new Error(`Stale previous-chain message key not available (PN ${PN} < Nr ${this.Nr})`);
    }

    if (theirHex !== ourDHrHex) {
      this.skipMessageKeys(PN);
      this.dhRatchetStep(senderDHRPub);
    }

    if (messageIndex < this.Nr) {
      throw new Error(`Stale message key not available (messageIndex ${messageIndex} < Nr ${this.Nr})`);
    }

    this.skipMessageKeys(messageIndex);

    if (!this.CKr) throw new Error('CKr is null — no receiving chain established yet');
    const { chainKey, messageKey } = KDF.deriveChain(this.CKr);
    this.CKr = chainKey;
    this.Nr += 1;

    return { messageKey, messageIndex };
  }

  private dhRatchetStep(theirNewDHRPub: Uint8Array): void {
    if (!this.RK || !this.DHs) throw new Error('Ratchet not initialized');

    this.PN = this.Ns;
    this.Ns = 0;
    this.Nr = 0;
    this.DHr = theirNewDHRPub;

    const DHs = this.DHs;
    const DHr = this.DHr;
    if (!DHr) throw new Error('Ratchet not initialized');

    const dh1 = sodium.crypto_scalarmult(DHs.privateKey, DHr);
    const s1 = KDF.deriveRoot(this.RK, dh1);
    this.RK = s1.rootKey;
    this.CKr = s1.chainKey;
    DHs.privateKey.fill(0);

    this.DHs = sodium.crypto_kx_keypair();
    const dh2 = sodium.crypto_scalarmult(this.DHs!.privateKey, DHr);
    const s2 = KDF.deriveRoot(this.RK, dh2);
    this.RK = s2.rootKey;
    this.CKs = s2.chainKey;
  }

  private skipMessageKeys(until: number): void {
    if (this.Nr >= until) return;
    if (!this.CKr || !this.DHr) return;
    if (this.Nr + MAX_SKIP < until) {
      throw new Error(`Too many skipped messages (${until - this.Nr} > ${MAX_SKIP})`);
    }
    while (this.Nr < until) {
      const { chainKey, messageKey } = KDF.deriveChain(this.CKr);
      this.CKr = chainKey;
      const id = `${sodium.to_hex(this.DHr)}:${this.Nr}`;
      this.MKSKIPPED.set(id, messageKey);
      if (this.MKSKIPPED.size > MAX_SKIP) {
        const first = this.MKSKIPPED.keys().next().value;
        if (first) this.MKSKIPPED.delete(first);
      }
      this.Nr += 1;
    }
  }

  exportState(): RatchetState {
    if (!this.RK || !this.DHs) throw new Error('Ratchet not initialized');
    return {
      version: 4,
      RK_hex: sodium.to_hex(this.RK),
      DHs_pubHex: sodium.to_hex(this.DHs.publicKey),
      DHs_privHex: sodium.to_hex(this.DHs.privateKey),
      DHr_pubHex: this.DHr ? sodium.to_hex(this.DHr) : null,
      CKs_hex: this.CKs ? sodium.to_hex(this.CKs) : null,
      CKr_hex: this.CKr ? sodium.to_hex(this.CKr) : null,
      Ns: this.Ns,
      Nr: this.Nr,
      PN: this.PN,
      MKSKIPPED: Array.from(this.MKSKIPPED.entries()).map(([id, key]) => ({
        id,
        keyHex: sodium.to_hex(key),
      })),
    };
  }

  importState(state: RatchetState): void {
    if (!state.version || state.version < 4) {
      throw new Error('Ratchet state version incompatible (need v4) — starting fresh');
    }
    this.RK = sodium.from_hex(state.RK_hex);
    this.DHs = {
      publicKey: sodium.from_hex(state.DHs_pubHex),
      privateKey: sodium.from_hex(state.DHs_privHex),
    };
    this.DHr = state.DHr_pubHex ? sodium.from_hex(state.DHr_pubHex) : null;
    this.CKs = state.CKs_hex ? sodium.from_hex(state.CKs_hex) : null;
    this.CKr = state.CKr_hex ? sodium.from_hex(state.CKr_hex) : null;
    this.Ns = state.Ns;
    this.Nr = state.Nr;
    this.PN = state.PN;
    this.MKSKIPPED.clear();
    for (const { id, keyHex } of state.MKSKIPPED ?? []) {
      this.MKSKIPPED.set(id, sodium.from_hex(keyHex));
    }
    this.isInitialized = true;
  }
}
