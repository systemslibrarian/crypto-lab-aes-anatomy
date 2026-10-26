import { describe, expect, it } from 'vitest';
import fips from './data/fips197.json';
import { parseHex, hex, xor } from './aes/state';
import { expand } from './aes/keyExpansion';
import { reducedAes, lambdaSet, classify, filterIntegral, integralAttack, recoverIntegralKey } from './integral';
import { dispersesColumns, columnDispersion } from './wide-trail';
const key = parseHex(fips.appendixB.key, [32]);
const base = parseHex(fips.appendixB.plaintext, [32]);
describe('reduced-round integral', () => {
  it('matches independent FIPS intermediate values with the declared final-round omission', () => {
    const trace: Uint8Array[] = [];
    const output = reducedAes(base, key, trace);
    for (let r = 1; r <= 3; r++) expect(hex(trace[r])).toBe(fips.appendixB.rounds[r - 1].output);
    const fourth = fips.appendixB.rounds[3];
    expect(output).toEqual(xor(parseHex(fourth.shift, [32]), parseHex(fourth.key, [32])));
  });
  it('retains the real byte in every first-set candidate list and balances round three', () => {
    const plaintexts = lambdaSet(base);
    expect(new Set(plaintexts.map(hex)).size).toBe(256);
    const traces = plaintexts.map(p => { const t: Uint8Array[] = []; reducedAes(p, key, t); return t; });
    for (let byte = 0; byte < 16; byte++) expect(traces.reduce((a, t) => a ^ t[3][byte], 0)).toBe(0);
    const candidates = filterIntegral(plaintexts.map(p => reducedAes(p, key)));
    candidates.forEach((c, i) => expect(c).toContain(expand(key).roundKeys[4][i]));
    expect(candidates.some(c => c.length > 1)).toBe(true);
  });
  it('filters multiple disjoint sets using only an oracle and reverses the schedule', () => {
    for (const k of [key, new Uint8Array(16), Uint8Array.from({length: 16}, (_, i) => i * 17)]) {
      const observed = new Set<string>();
      const result = integralAttack(p => { expect(observed.has(hex(p))).toBe(false); observed.add(hex(p)); return reducedAes(p, k); }, base);
      expect(result.candidates.every(c => c.length === 1)).toBe(true);
      expect(recoverIntegralKey(Uint8Array.from(result.candidates, c => c[0]))).toEqual(k);
      expect(observed.size).toBe(result.queries);
    }
  });
  it('rejects incomplete or repeated sets rather than silently treating zero XOR as evidence', () => {
    expect(() => filterIntegral(Array.from({length: 256}, () => base))).toThrow(/distinct/);
    expect(() => filterIntegral([base])).toThrow(/complete/);
    expect(() => classify([0])).toThrow(/complete/);
  });
  it('checks every source column and detects removal of ShiftRows', () => {
    expect(dispersesColumns()).toBe(true);
    expect(dispersesColumns(true)).toBe(false);
    columnDispersion().forEach(columns => expect([...columns].sort()).toEqual([0, 1, 2, 3]));
  });
});
