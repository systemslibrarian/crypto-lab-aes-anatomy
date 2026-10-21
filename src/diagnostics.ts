import { cipher, invCipher, VARIANTS, type Config, type Round } from "./aes/cipher";
import { expand } from "./aes/keyExpansion";
import { xor, type Block, dependencies } from "./aes/state";
import { seeded } from "./random";
const weight = (x: number) => {
  let n = 0;
  while (x) {
    n += x & 1;
    x >>>= 1;
  }
  return n;
};
export function avalanche(key: Block, plaintext: Block, config: Config) {
  const w = expand(key).roundKeys,
    ct = cipher(plaintext, w, config),
    counts: number[] = [],
    outputDependencies = Array(128).fill(0) as number[];
  for (let i = 0; i < 128; i++) {
    const p = plaintext.slice();
    p[i >> 3] ^= 1 << (i & 7);
    const d = xor(ct, cipher(p, w, config));
    counts.push([...d].reduce((n, x) => n + weight(x), 0));
    for (let j = 0; j < 128; j++) if ((d[j >> 3] >> (j & 7)) & 1) outputDependencies[j]++;
  }
  return {
    counts,
    mean: counts.reduce((a, b) => a + b) / 128,
    min: Math.min(...counts),
    max: Math.max(...counts),
    outputDependencies,
    fullByteDependencies: dependencies(2, config.shiftRows, config.mixColumns).every(
      (x) => x.length === 16,
    ),
    roundTrip: invCipher(ct, w, undefined, config).every((b, i) => b === plaintext[i]),
  };
}

/** Byte dependencies of the actual keyed 7b cipher, not a structural wiring map. */
export function affineByteDependencies(key: Block, rounds = 2): number[][] {
  const w = expand(key).roundKeys;
  const atRound = (p: Block) => {
    const trace: Round[] = [];
    cipher(p, w, VARIANTS.affine, trace);
    return trace[rounds].output;
  };
  const base = atRound(new Uint8Array(16));
  const columns = Array.from({ length: 128 }, (_, bit) => {
    const basis = new Uint8Array(16);
    basis[bit >> 3] = 1 << (bit & 7);
    return xor(atRound(basis), base);
  });
  // Each input-byte/output-byte block is 8 × 8 bits: any set bit is dependence.
  return Array.from({ length: 16 }, (_, output) =>
    Array.from({ length: 16 }, (_, input) => input).filter((input) =>
      columns.slice(input * 8, input * 8 + 8).some((column) => column[output] !== 0),
    ),
  );
}

export function largerKeyAvalanche(plaintext: Block, config: Config) {
  return [192, 256].map((size) => ({
    size,
    ...avalanche(seeded(0x197197)(size / 8), plaintext, config),
  }));
}
