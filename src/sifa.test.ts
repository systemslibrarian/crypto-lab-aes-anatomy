import { describe, expect, it } from "vitest";
import { SBOX } from "./aes/sbox";
import { rankOf, rankSifaKeyByte } from "./attack/sifa";
import { collectSifaSamples } from "./sifa-fixture";

describe("accepted-output statistical ineffective fault model", () => {
  it("uses the real first-round AES S-box relation", () => {
    const keyByte = 0x2b;
    const plaintextByte = 0x19;
    expect(SBOX[plaintextByte ^ keyByte]).toBe(SBOX[0x32]);
  });

  it("keeps the biased and secret-independent experiments at the same sample count", () => {
    const biased = collectSifaSamples(0x2b, 0, "biased-ineffective");
    const control = collectSifaSamples(0x2b, 0, "secret-independent");
    expect(biased.attempts).toBe(2048);
    expect(biased.accepted).toBe(1280);
    expect(control.accepted).toBe(1280);
    expect(biased.rejected).toBe(768);
    expect(control.rejected).toBe(768);
  });

  it("the biased accepted set uniquely ranks the actual key byte first", () => {
    const keyByte = 0x2b;
    const samples = collectSifaSamples(keyByte, 0, "biased-ineffective");
    const ranking = rankSifaKeyByte(samples.acceptedPlaintextBytes, 0);
    expect(ranking[0]?.keyByte).toBe(keyByte);
    expect(rankOf(ranking, keyByte)).toBe(1);
    expect(ranking[0]?.zeros).toBe(1024);
    expect(ranking[0]?.ones).toBe(256);
    expect(ranking[0]?.sei).toBeCloseTo(0.18, 12);
    expect(ranking[1]?.sei ?? 1).toBeLessThan(0.01);
  });

  it("the secret-independent control contains no candidate imbalance", () => {
    const samples = collectSifaSamples(0x2b, 0, "secret-independent");
    const ranking = rankSifaKeyByte(samples.acceptedPlaintextBytes, 0);
    for (const candidate of ranking) {
      expect(candidate.zeros).toBe(640);
      expect(candidate.ones).toBe(640);
      expect(candidate.sei).toBe(0);
    }
  });

  it("the key ranking holds for every AES key byte and every S-box bit", () => {
    for (let keyByte = 0; keyByte < 256; keyByte++) {
      for (let bit = 0; bit < 8; bit++) {
        const samples = collectSifaSamples(keyByte, bit, "biased-ineffective");
        const ranking = rankSifaKeyByte(samples.acceptedPlaintextBytes, bit);
        expect(ranking[0]?.keyByte).toBe(keyByte);
      }
    }
  });

  it("infection does not remove the leak when an external validity oracle re-filters outputs", () => {
    const rejected = collectSifaSamples(0x7a, 3, "biased-ineffective", "reject");
    const infected = collectSifaSamples(
      0x7a,
      3,
      "biased-ineffective",
      "infect-with-validity",
    );
    expect(rejected.outputsReturned).toBe(1280);
    expect(infected.outputsReturned).toBe(2048);
    expect(infected.externallyValid).toBe(rejected.accepted);
    expect(infected.acceptedPlaintextBytes).toEqual(rejected.acceptedPlaintextBytes);
    expect(rankSifaKeyByte(infected.acceptedPlaintextBytes, 3)[0]?.keyByte).toBe(0x7a);
  });

  it("rejects invalid attack inputs instead of inventing a verdict", () => {
    expect(() => rankSifaKeyByte([], 0)).toThrow(/accepted sample/);
    expect(() => rankSifaKeyByte([0], 8)).toThrow(/targetBit/);
    expect(() => rankSifaKeyByte([256], 0)).toThrow(/plaintext bytes/);
    expect(() => collectSifaSamples(256, 0, "biased-ineffective")).toThrow(/keyByte/);
  });
});
