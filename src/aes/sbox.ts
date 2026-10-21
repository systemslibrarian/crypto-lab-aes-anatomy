import { inv } from "../gf/gf256";
export function affineOnly(x: number): number {
  let y = x ^ 0x63;
  for (let n = 1; n <= 4; n++) y ^= ((x << n) | (x >>> (8 - n))) & 255;
  return y;
}
export function buildSbox(): Uint8Array {
  return Uint8Array.from({ length: 256 }, (_, x) => affineOnly(inv(x).value ?? 0));
}
export function buildInvSbox(box = buildSbox()): Uint8Array {
  const out = new Uint8Array(256);
  box.forEach((y, x) => (out[y] = x));
  return out;
}
export const SBOX = buildSbox(),
  INV_SBOX = buildInvSbox(SBOX),
  AFFINE = Uint8Array.from({ length: 256 }, (_, x) => affineOnly(x));
export function ddt(box = SBOX) {
  const rows = Array.from({ length: 256 }, () => new Uint16Array(256));
  for (let a = 0; a < 256; a++) for (let x = 0; x < 256; x++) rows[a][box[x] ^ box[x ^ a]]++;
  return { rows, max: Math.max(...rows.slice(1).map((r) => Math.max(...r))) };
}
const parity = (x: number) => {
  x ^= x >>> 4;
  x ^= x >>> 2;
  x ^= x >>> 1;
  return x & 1;
};
/** Walsh-Hadamard transform computes all masked sums exactly; LAT = (256+Walsh)/2. */
export function lat(box = SBOX) {
  const rows = Array.from({ length: 256 }, () => new Int16Array(256));
  let maxBias = 0;
  for (let b = 0; b < 256; b++) {
    const w = Int16Array.from(box, (y) => (parity(b & y) ? -1 : 1));
    for (let span = 1; span < 256; span *= 2)
      for (let i = 0; i < 256; i += 2 * span)
        for (let j = 0; j < span; j++) {
          const x = w[i + j],
            y = w[i + j + span];
          w[i + j] = x + y;
          w[i + j + span] = x - y;
        }
    for (let a = 0; a < 256; a++) {
      rows[a][b] = (256 + w[a]) / 2;
      if (a !== 0 && b !== 0) maxBias = Math.max(maxBias, Math.abs(rows[a][b] - 128));
    }
  }
  return { rows, maxBias };
}
export function affineIdentity(box: Uint8Array) {
  let passed = 0;
  for (let x = 0; x < 256; x++)
    for (let y = 0; y < 256; y++) if ((box[x ^ y] ^ box[x] ^ box[y] ^ box[0]) === 0) passed++;
  return { passed, total: 65536, affine: passed === 65536 };
}
