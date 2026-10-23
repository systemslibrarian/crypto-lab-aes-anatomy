import { INV_SBOX, SBOX } from "../aes/sbox";
import { MC, type Block } from "../aes/state";

export interface FaultPair {
  correct: Block;
  faulty: Block;
}

export interface QuartetCandidate {
  bytes: [number, number, number, number];
}

function gfMul(a: number, b: number): number {
  let out = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) out ^= a;
    a = ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;
    b >>>= 1;
  }
  return out;
}

/**
 * A byte in row r of column c immediately before round-9 MixColumns affects
 * row r of that column after MixColumns, then ShiftRows in round 10 moves it
 * to ciphertext position r + 4 * (c-r mod 4).
 */
export function affectedCipherPositions(column: number): [number, number, number, number] {
  if (!Number.isInteger(column) || column < 0 || column > 3)
    throw Error("Fault column must be 0…3.");
  return [0, 1, 2, 3].map(
    (row) => row + 4 * ((column - row + 4) % 4),
  ) as [number, number, number, number];
}

function pack(bytes: readonly number[]): number {
  return (
    ((bytes[0]! << 24) | (bytes[1]! << 16) | (bytes[2]! << 8) | bytes[3]!) >>>
    0
  );
}

function unpack(value: number): [number, number, number, number] {
  return [
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ];
}

/**
 * Recover candidates for four bytes of the AES-128 round-10 key from one
 * correct/faulty ciphertext pair. The attacker is told only the injected byte
 * location (column,row), not the victim key and not the nonzero fault value.
 * It enumerates all 255 possible fault values and keeps key quartets consistent
 * with the AES inverse-S-box differential and the published MixColumns matrix.
 */
export function recoverRound10Quartets(
  pair: FaultPair,
  column: number,
  faultRow: number,
): QuartetCandidate[] {
  if (pair.correct.length !== 16 || pair.faulty.length !== 16)
    throw Error("DFA needs two 16-byte ciphertexts.");
  if (!Number.isInteger(faultRow) || faultRow < 0 || faultRow > 3)
    throw Error("Fault row must be 0…3.");

  const positions = affectedCipherPositions(column);
  const packed = new Set<number>();

  for (let fault = 1; fault < 256; fault++) {
    const choices: number[][] = [];
    let viable = true;

    for (let row = 0; row < 4; row++) {
      const expected = gfMul(MC[row]![faultRow]!, fault);
      const position = positions[row]!;
      const keys: number[] = [];
      for (let keyByte = 0; keyByte < 256; keyByte++) {
        const difference =
          INV_SBOX[pair.correct[position]! ^ keyByte]! ^
          INV_SBOX[pair.faulty[position]! ^ keyByte]!;
        if (difference === expected) keys.push(keyByte);
      }
      if (!keys.length) {
        viable = false;
        break;
      }
      choices.push(keys);
    }
    if (!viable) continue;

    for (const a of choices[0]!)
      for (const b of choices[1]!)
        for (const c of choices[2]!)
          for (const d of choices[3]!) packed.add(pack([a, b, c, d]));
  }

  return [...packed]
    .sort((a, b) => a - b)
    .map((value) => ({ bytes: unpack(value) }));
}

export function intersectQuartets(
  first: readonly QuartetCandidate[],
  second: readonly QuartetCandidate[],
): QuartetCandidate[] {
  const right = new Set(second.map((candidate) => pack(candidate.bytes)));
  return first.filter((candidate) => right.has(pack(candidate.bytes)));
}

export function installQuartet(
  round10Key: Block,
  column: number,
  quartet: QuartetCandidate,
): void {
  if (round10Key.length !== 16) throw Error("Round-10 key must be 16 bytes.");
  const positions = affectedCipherPositions(column);
  positions.forEach((position, row) => {
    round10Key[position] = quartet.bytes[row]!;
  });
}

function rcon(round: number): number {
  if (!Number.isInteger(round) || round < 1 || round > 10)
    throw Error("AES-128 Rcon round must be 1…10.");
  let value = 1;
  for (let i = 1; i < round; i++)
    value = ((value << 1) ^ (value & 0x80 ? 0x1b : 0)) & 0xff;
  return value;
}

function scheduleTransform(word: Uint8Array, round: number): Uint8Array {
  const rotated = Uint8Array.from([word[1]!, word[2]!, word[3]!, word[0]!]);
  const substituted = rotated.map((byte) => SBOX[byte]!);
  substituted[0] ^= rcon(round);
  return substituted;
}

/** Reverse the AES-128 key schedule from round key 10 back to the 16-byte key. */
export function invertAes128Round10Key(round10Key: Block): Block {
  if (round10Key.length !== 16) throw Error("AES-128 round-10 key must be 16 bytes.");
  const words: Array<Uint8Array | undefined> = Array(44);
  for (let i = 40; i < 44; i++) words[i] = round10Key.slice(4 * (i - 40), 4 * (i - 39));

  for (let i = 43; i >= 4; i--) {
    const previous = words[i - 1];
    const current = words[i];
    if (!previous || !current) throw Error("Incomplete reverse key schedule.");
    const transformed = i % 4 === 0 ? scheduleTransform(previous, i / 4) : previous;
    words[i - 4] = Uint8Array.from(current, (byte, j) => byte ^ transformed[j]!);
  }
  return Uint8Array.from(words.slice(0, 4).flatMap((word) => Array.from(word!)));
}
