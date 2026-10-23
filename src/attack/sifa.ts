import { SBOX } from "../aes/sbox";

export interface SifaCandidate {
  keyByte: number;
  zeros: number;
  ones: number;
  sei: number;
}

/**
 * Rank all 256 candidates for one first-round AES key byte using only the
 * plaintext bytes belonging to outputs that survived the fault filter.
 *
 * For candidate k, the targeted intermediate bit is:
 *
 *   b = bit(SBOX[plaintextByte XOR k])
 *
 * SEI is the squared Euclidean imbalance of the predicted bit distribution
 * from uniform. The attack receives no victim key and no per-attempt fault
 * outcome beyond membership in acceptedPlaintextBytes.
 */
export function rankSifaKeyByte(
  acceptedPlaintextBytes: readonly number[],
  targetBit: number,
): SifaCandidate[] {
  if (!Number.isInteger(targetBit) || targetBit < 0 || targetBit > 7)
    throw new RangeError("targetBit must be an integer from 0 through 7");
  if (acceptedPlaintextBytes.length === 0)
    throw new Error("at least one accepted sample is required");

  const n = acceptedPlaintextBytes.length;
  const histogram = new Uint16Array(256);
  for (const value of acceptedPlaintextBytes) {
    if (!Number.isInteger(value) || value < 0 || value > 255)
      throw new RangeError("plaintext bytes must be integers from 0 through 255");
    histogram[value]++;
  }
  const candidates: SifaCandidate[] = [];

  for (let keyByte = 0; keyByte < 256; keyByte++) {
    let zeros = 0;
    for (let value = 0; value < 256; value++) {
      if (histogram[value] === 0) continue;
      const bit = (SBOX[(value ^ keyByte) & 0xff]! >>> targetBit) & 1;
      if (bit === 0) zeros += histogram[value]!;
    }
    const ones = n - zeros;
    const p0 = zeros / n;
    const p1 = ones / n;
    const sei = (p0 - 0.5) ** 2 + (p1 - 0.5) ** 2;
    candidates.push({ keyByte, zeros, ones, sei });
  }

  return candidates.sort((a, b) => b.sei - a.sei || a.keyByte - b.keyByte);
}

export function rankOf(candidates: readonly SifaCandidate[], keyByte: number): number {
  const index = candidates.findIndex((candidate) => candidate.keyByte === keyByte);
  if (index < 0) throw new Error("key byte is not present in the candidate list");
  return index + 1;
}
