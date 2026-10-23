import { expect, it } from "vitest";
import fips from "./data/fips197.json";
import { cipher } from "./aes/cipher";
import { expand } from "./aes/keyExpansion";
import { equal, hex, parseHex, type Block } from "./aes/state";
import { injectRound9MixColumnsFault } from "./dfa-fixture";
import {
  affectedCipherPositions,
  installQuartet,
  intersectQuartets,
  invertAes128Round10Key,
  recoverRound10Quartets,
  type QuartetCandidate,
} from "./attack/dfa";

const bytes = (s: string) => parseHex(s.replaceAll(" ", ""), [s.replaceAll(" ", "").length]);
const key = () => bytes(fips.appendixB.key);
const plaintext = () => bytes(fips.appendixB.plaintext);

function trueQuartet(round10: Block, column: number): QuartetCandidate {
  return {
    bytes: affectedCipherPositions(column).map((position) => round10[position]!) as [
      number,
      number,
      number,
      number,
    ],
  };
}

function sameQuartet(a: QuartetCandidate, b: QuartetCandidate): boolean {
  return a.bytes.every((value, i) => value === b.bytes[i]);
}

it("DFA fault before round-9 MixColumns changes exactly the expected four ciphertext bytes", () => {
  for (let column = 0; column < 4; column++) {
    const pair = injectRound9MixColumnsFault(key(), plaintext(), column, 0, 1);
    const changed = Array.from({ length: 16 }, (_, i) => i).filter(
      (i) => pair.correct[i] !== pair.faulty[i],
    );
    expect(changed.sort((a, b) => a - b)).toEqual(
      [...affectedCipherPositions(column)].sort((a, b) => a - b),
    );
  }
});

it("One DFA pair narrows each 32-bit round-key quartet while retaining the true quartet", () => {
  const round10 = expand(key()).roundKeys[10]!;
  const expectedCounts = [496, 240, 256, 528];
  for (let column = 0; column < 4; column++) {
    const pair = injectRound9MixColumnsFault(key(), plaintext(), column, 0, 1);
    const candidates = recoverRound10Quartets(pair, column, 0);
    expect(candidates).toHaveLength(expectedCounts[column]!);
    expect(candidates.some((candidate) => sameQuartet(candidate, trueQuartet(round10, column)))).toBe(
      true,
    );
    expect(candidates.length).toBeLessThan(2 ** 10);
  }
});

it("A second independent fault pair isolates every round-10 key quartet", () => {
  const round10 = expand(key()).roundKeys[10]!;
  for (let column = 0; column < 4; column++) {
    const first = injectRound9MixColumnsFault(key(), plaintext(), column, 0, 1);
    const second = injectRound9MixColumnsFault(key(), plaintext(), column, 0, 2);
    const survivors = intersectQuartets(
      recoverRound10Quartets(first, column, 0),
      recoverRound10Quartets(second, column, 0),
    );
    expect(survivors).toHaveLength(1);
    expect(survivors[0]).toEqual(trueQuartet(round10, column));
  }
});

it("Eight well-located faulty ciphertexts recover round key 10 and the AES-128 master key", () => {
  const recoveredRound10 = new Uint8Array(16);
  for (let column = 0; column < 4; column++) {
    const first = injectRound9MixColumnsFault(key(), plaintext(), column, 0, 1);
    const second = injectRound9MixColumnsFault(key(), plaintext(), column, 0, 2);
    const survivors = intersectQuartets(
      recoverRound10Quartets(first, column, 0),
      recoverRound10Quartets(second, column, 0),
    );
    expect(survivors).toHaveLength(1);
    installQuartet(recoveredRound10, column, survivors[0]!);
  }

  const schedule = expand(key()).roundKeys;
  expect(recoveredRound10).toEqual(schedule[10]);

  const recoveredMaster = invertAes128Round10Key(recoveredRound10);
  expect(recoveredMaster).toEqual(key());
  expect(expand(recoveredMaster).roundKeys[10]).toEqual(recoveredRound10);
  expect(cipher(plaintext(), expand(recoveredMaster).roundKeys)).toEqual(
    cipher(plaintext(), schedule),
  );

  const heldout = plaintext();
  heldout[0] ^= 0x80;
  expect(cipher(heldout, expand(recoveredMaster).roundKeys)).toEqual(cipher(heldout, schedule));
});

it("The attacker API receives ciphertext pairs and location metadata, never the fault value or victim key", () => {
  expect(recoverRound10Quartets.length).toBe(3);
  expect(intersectQuartets.length).toBe(2);
  expect(invertAes128Round10Key.length).toBe(1);

  const sourcePair = injectRound9MixColumnsFault(key(), plaintext(), 0, 0, 0x5a);
  const attackerPair = { correct: sourcePair.correct, faulty: sourcePair.faulty };
  const candidates = recoverRound10Quartets(attackerPair, 0, 0);
  const truth = trueQuartet(expand(key()).roundKeys[10]!, 0);
  expect(candidates.some((candidate) => sameQuartet(candidate, truth))).toBe(true);
});

it("Wrong fault-location assumptions do not falsely recover the true quartet", () => {
  const pair = injectRound9MixColumnsFault(key(), plaintext(), 0, 0, 1);
  const trueKey = trueQuartet(expand(key()).roundKeys[10]!, 0);
  const wrongRow = recoverRound10Quartets(pair, 0, 1);
  expect(wrongRow.some((candidate) => sameQuartet(candidate, trueKey))).toBe(false);
});

it("AES-128 round-10 key inversion matches both FIPS examples used by the lab", () => {
  const examples = [
    { key: bytes(fips.appendixB.key), plaintext: bytes(fips.appendixB.plaintext) },
    {
      key: Uint8Array.from({ length: 16 }, (_, i) => i),
      plaintext: bytes("00112233445566778899aabbccddeeff"),
    },
  ];
  for (const example of examples) {
    const schedule = expand(example.key).roundKeys;
    const recovered = invertAes128Round10Key(schedule[10]!);
    expect(hex(recovered)).toBe(hex(example.key));
    expect(equal(cipher(example.plaintext, expand(recovered).roundKeys), cipher(example.plaintext, schedule))).toBe(
      true,
    );
  }
});


it("Simple recomputation detects a one-sided transient fault but not an identical common-mode fault", () => {
  const victimKey = key();
  const pt = plaintext();
  const schedule = expand(victimKey).roundKeys;
  const pair = injectRound9MixColumnsFault(victimKey, pt, 0, 0, 1);
  const recomputed = cipher(pt, schedule);
  expect(equal(pair.faulty, recomputed)).toBe(false);
  const commonModeFirst = injectRound9MixColumnsFault(victimKey, pt, 0, 0, 1);
  const commonModeSecond = injectRound9MixColumnsFault(victimKey, pt, 0, 0, 1);
  expect(commonModeFirst.faulty).not.toBe(commonModeSecond.faulty);
  expect(equal(commonModeFirst.faulty, commonModeSecond.faulty)).toBe(true);
});
