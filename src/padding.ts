export class PaddingLayer {
  private static readonly BUCKETS = [256, 512, 1024, 2048, 4096, 8192];

  static applyPadding(payload: string): Uint8Array {
    const encoder = new TextEncoder();
    const rawBytes = encoder.encode(payload);
    const lengthPrefix = new ArrayBuffer(4);
    new DataView(lengthPrefix).setUint32(0, rawBytes.length, false);

    const minRequiredSize = 4 + rawBytes.length;
    let targetSize = this.BUCKETS.find((size) => size >= minRequiredSize);
    if (!targetSize) {
      targetSize = Math.ceil(minRequiredSize / 1024) * 1024;
    }

    const paddedArray = new Uint8Array(targetSize);
    paddedArray.set(new Uint8Array(lengthPrefix), 0);
    paddedArray.set(rawBytes, 4);

    if (targetSize > minRequiredSize) {
      const paddingBytes = new Uint8Array(targetSize - minRequiredSize);
      globalThis.crypto.getRandomValues(paddingBytes);
      paddedArray.set(paddingBytes, minRequiredSize);
    }

    return paddedArray;
  }

  static stripPadding(paddedArray: Uint8Array): string {
    const dataView = new DataView(paddedArray.buffer, paddedArray.byteOffset, paddedArray.byteLength);
    const actualLength = dataView.getUint32(0, false);
    const rawPayload = paddedArray.slice(4, 4 + actualLength);
    return new TextDecoder().decode(rawPayload);
  }
}
