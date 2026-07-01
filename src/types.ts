export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface EncryptedMessage {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  messageIndex: number;
  senderDHRPub: Uint8Array;
  PN: number;
}

export interface LinkSecurityState {
  storedIdentityKey?: string;
  isCompromised: boolean;
}

export interface RatchetState {
  version: number;
  RK_hex: string;
  DHs_pubHex: string;
  DHs_privHex: string;
  DHr_pubHex: string | null;
  CKs_hex: string | null;
  CKr_hex: string | null;
  Ns: number;
  Nr: number;
  PN: number;
  MKSKIPPED: Array<{ id: string; keyHex: string }>;
  devicePubBinding?: {
    myDevicePubHex: string;
    theirDevicePubHex: string;
    bindingTime: number;
  };
}
