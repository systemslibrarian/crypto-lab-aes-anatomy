import { describe, expect, it } from "vitest";
import { cipher, REAL } from "./aes/cipher";
import { expand } from "./aes/keyExpansion";
import { SBOX } from "./aes/sbox";
import { equal, parseHex, xor } from "./aes/state";
import { rankOf, rankSifaKeyByte } from "./attack/sifa";
import {
  buildSifaWitnesses,
  collectSifaSamples,
  executeSifaTrial,
  injectFirstRoundSboxStuckAtZero,
  sampleSifaPrefixes,
} from "./sifa-fixture";

const key = parseHex("2b7e151628aed2a6abf7158809cf4f3c", [32]);
const plaintext = parseHex("3243f6a8885a308d313198a2e0370734", [32]);

describe("accepted-output statistical ineffective fault model", () => {
  it("uses the real first-round AES S-box relation", () => {
    const plaintextByte = 0x19;
    expect(SBOX[plaintextByte ^ key[0]!]).toBe(SBOX[0x32]);
  });

  it("applies a real first-round stuck-at-zero fault and classifies full AES outputs", () => {
    const witnesses = buildSifaWitnesses(key, plaintext, 3, "reject");
    expect((witnesses.ineffective.correctSboxByte >>> 3) & 1).toBe(0);
    expect(witnesses.ineffective.faultedSboxByte).toBe(
      witnesses.ineffective.correctSboxByte,
    );
    expect(equal(witnesses.ineffective.correctCiphertext, witnesses.ineffective.faultyCiphertext)).toBe(
      true,
    );
    expect(witnesses.ineffective.detectorAlert).toBe(false);
    expect(witnesses.ineffective.returnedKind).toBe("correct");

    expect((witnesses.effective.correctSboxByte >>> 3) & 1).toBe(1);
    expect((witnesses.effective.faultedSboxByte >>> 3) & 1).toBe(0);
    expect(equal(witnesses.effective.correctCiphertext, witnesses.effective.faultyCiphertext)).toBe(
      false,
    );
    expect(witnesses.effective.detectorAlert).toBe(true);
    expect(witnesses.effective.returnedKind).toBe("suppressed");
    expect(witnesses.effective.returnedCiphertext).toBeNull();

    expect(witnesses.control.correctSboxByte).not.toBe(witnesses.control.faultedSboxByte);
    expect(equal(witnesses.control.correctCiphertext, witnesses.control.faultyCiphertext)).toBe(
      false,
    );
    expect(witnesses.control.detectorAlert).toBe(true);
  });

  it("derives every landed/missed trial label from full ciphertext equality", () => {
    for (let bit = 0; bit < 8; bit++) {
      for (let firstByte = 0; firstByte < 256; firstByte += 17) {
        const pt = plaintext.slice();
        pt[0] = firstByte;
        const stuck = executeSifaTrial(key, pt, bit, "noisy-stuck-at-zero", true);
        const predictedBit = (SBOX[firstByte ^ key[0]!]! >>> bit) & 1;
        expect(stuck.unchanged).toBe(predictedBit === 0);
        expect(equal(stuck.correctCiphertext, stuck.faultyCiphertext)).toBe(stuck.unchanged);

        const flip = executeSifaTrial(key, pt, bit, "secret-independent", true);
        expect(flip.unchanged).toBe(false);
        expect(equal(flip.correctCiphertext, flip.faultyCiphertext)).toBe(false);

        const miss = executeSifaTrial(key, pt, bit, "noisy-stuck-at-zero", false);
        expect(miss.unchanged).toBe(true);
        expect(equal(miss.correctCiphertext, miss.faultyCiphertext)).toBe(true);
      }
    }
  });

  it("computes an infected output on detected mismatch", () => {
    const hidden = buildSifaWitnesses(key, plaintext, 5, "infect-hidden");
    const withOracle = buildSifaWitnesses(key, plaintext, 5, "infect-with-validity");
    expect(hidden.effective.returnedKind).toBe("infected");
    expect(hidden.effective.returnedCiphertext).not.toBeNull();
    expect(equal(hidden.effective.returnedCiphertext!, hidden.effective.faultyCiphertext)).toBe(
      false,
    );
    expect(equal(hidden.effective.returnedCiphertext!, hidden.effective.correctCiphertext)).toBe(
      false,
    );
    const roundKeys = expand(key.slice()).roundKeys;
    const difference = xor(
      hidden.effective.correctCiphertext,
      hidden.effective.faultyCiphertext,
    );
    const expectedMask = xor(
      cipher(difference, roundKeys, REAL),
      cipher(new Uint8Array(16), roundKeys, REAL),
    );
    expect(hidden.effective.returnedCiphertext).toEqual(
      xor(hidden.effective.correctCiphertext, expectedMask),
    );
    expect(hidden.effective.returnedCiphertext).toEqual(withOracle.effective.returnedCiphertext);
  });

  it("separates landed, missed, ineffective, and effective attempts", () => {
    const biased = collectSifaSamples(key[0]!, 0, "noisy-stuck-at-zero");
    const control = collectSifaSamples(key[0]!, 0, "secret-independent");
    expect(biased.attempts).toBe(2048);
    expect(biased.induced).toBe(1536);
    expect(biased.missed).toBe(512);
    expect(biased.ineffective).toBe(768);
    expect(biased.effective).toBe(768);
    expect(biased.accepted).toBe(1280);
    expect(control.accepted).toBe(1280);
    expect(biased.rejected).toBe(768);
    expect(control.rejected).toBe(768);
    expect(control.induced).toBe(768);
    expect(control.missed).toBe(1280);
    expect(control.ineffective).toBe(0);
    expect(control.effective).toBe(768);
  });

  it("the noisy accepted set uniquely ranks the actual key byte first", () => {
    const samples = collectSifaSamples(key[0]!, 0, "noisy-stuck-at-zero");
    const ranking = rankSifaKeyByte(samples.selectedPlaintextBytes, 0);
    expect(ranking[0]?.keyByte).toBe(key[0]);
    expect(rankOf(ranking, key[0]!)).toBe(1);
    expect(ranking[0]?.zeros).toBe(1024);
    expect(ranking[0]?.ones).toBe(256);
    expect(ranking[0]?.sei).toBeCloseTo(0.18, 12);
    expect(ranking[1]?.sei ?? 1).toBeLessThan(0.01);
  });

  it("the equal-count secret-independent control contains no candidate imbalance", () => {
    const samples = collectSifaSamples(key[0]!, 0, "secret-independent");
    const ranking = rankSifaKeyByte(samples.selectedPlaintextBytes, 0);
    for (const candidate of ranking) {
      expect(candidate.zeros).toBe(640);
      expect(candidate.ones).toBe(640);
      expect(candidate.sei).toBe(0);
    }
  });

  it("hidden infection closes this selection channel when no validity oracle is granted", () => {
    const samples = collectSifaSamples(
      key[0]!,
      4,
      "noisy-stuck-at-zero",
      "infect-hidden",
    );
    const ranking = rankSifaKeyByte(samples.selectedPlaintextBytes, 4);
    expect(samples.outputsReturned).toBe(2048);
    expect(samples.selected).toBe(2048);
    expect(ranking.every((candidate) => candidate.zeros === 1024)).toBe(true);
    expect(ranking.every((candidate) => candidate.ones === 1024)).toBe(true);
    expect(ranking.every((candidate) => candidate.sei === 0)).toBe(true);
  });

  it("a reference or validity oracle recreates the leaking accepted subset", () => {
    const rejected = collectSifaSamples(key[0]!, 3, "noisy-stuck-at-zero", "reject");
    const infected = collectSifaSamples(
      key[0]!,
      3,
      "noisy-stuck-at-zero",
      "infect-with-validity",
    );
    expect(rejected.outputsReturned).toBe(1280);
    expect(infected.outputsReturned).toBe(2048);
    expect(infected.externallyValid).toBe(rejected.accepted);
    expect(infected.selectedPlaintextBytes).toEqual(rejected.selectedPlaintextBytes);
    expect(rankSifaKeyByte(infected.selectedPlaintextBytes, 3)[0]?.keyByte).toBe(key[0]);
  });

  it("a finite-sample experiment shows noisy convergence and a noisy null", () => {
    const prefixes = sampleSifaPrefixes(key, plaintext, 0, 0x197197, [64, 256, 1024]);
    expect(prefixes.map((prefix) => prefix.sampleSize)).toEqual([64, 256, 1024]);
    expect(prefixes.map((prefix) => prefix.noisyAttempts)).toEqual([107, 400, 1634]);
    expect(prefixes.map((prefix) => prefix.controlAttempts)).toEqual([111, 411, 1653]);
    for (const prefix of prefixes) {
      expect(prefix.allInputs).toHaveLength(prefix.sampleSize);
      expect(prefix.noisySelected).toHaveLength(prefix.sampleSize);
      expect(prefix.controlSelected).toHaveLength(prefix.sampleSize);
      expect(prefix.noisyAttempts).toBeGreaterThanOrEqual(prefix.sampleSize);
      expect(prefix.controlAttempts).toBeGreaterThanOrEqual(prefix.sampleSize);
    }
    const final = prefixes.at(-1)!;
    const noisyRanking = rankSifaKeyByte(final.noisySelected, 0);
    const controlRanking = rankSifaKeyByte(final.controlSelected, 0);
    expect(noisyRanking[0]?.keyByte).toBe(key[0]);
    expect(noisyRanking[0]!.sei).toBeGreaterThan(noisyRanking[1]!.sei);
    expect(controlRanking[0]!.sei).toBeGreaterThan(0);
  });

  it("the key ranking holds for every AES key byte and every S-box bit", () => {
    for (let keyByte = 0; keyByte < 256; keyByte++) {
      for (let bit = 0; bit < 8; bit++) {
        const samples = collectSifaSamples(keyByte, bit, "noisy-stuck-at-zero");
        const ranking = rankSifaKeyByte(samples.selectedPlaintextBytes, bit);
        expect(ranking[0]?.keyByte).toBe(keyByte);
      }
    }
  });

  it("rejects invalid attack and fixture inputs instead of inventing a verdict", () => {
    expect(() => rankSifaKeyByte([], 0)).toThrow(/selected sample/);
    expect(() => rankSifaKeyByte([0], 8)).toThrow(/targetBit/);
    expect(() => rankSifaKeyByte([256], 0)).toThrow(/plaintext bytes/);
    expect(() => collectSifaSamples(256, 0, "noisy-stuck-at-zero")).toThrow(/keyByte/);
    expect(() => injectFirstRoundSboxStuckAtZero(key, plaintext, 8)).toThrow(/targetBit/);
    expect(() => injectFirstRoundSboxStuckAtZero(new Uint8Array(24), plaintext, 0)).toThrow(
      /AES-128/,
    );
    expect(() => sampleSifaPrefixes(key, plaintext, 0, -1)).toThrow(/seed/);
    expect(() => sampleSifaPrefixes(key, plaintext, 0, 1, [64, 64])).toThrow(/sample sizes/);
  });
});
