/** Verifier-only stream. Attack modules may not import this module or receive its instances. */
import { seeded } from "./random";
import { equal, type Block } from "./aes/state";
import type { KnownPair } from "./attack/types";

/** SplitMix-style avalanche, domain separated from both attacker input streams.
 * Reproducible teaching data only; this is not a cryptographic KDF or RNG.
 */
export function heldoutSeed(seed: number): number {
  const HELDOUT_DOMAIN = 0x68656c64; // "held", the heldout stream's domain tag
  let mixed = (seed + HELDOUT_DOMAIN + 0x9e3779b9) >>> 0;
  mixed = Math.imul(mixed ^ (mixed >>> 16), 0x21f0aaad);
  mixed = Math.imul(mixed ^ (mixed >>> 15), 0x735a2d97);
  return (mixed ^ (mixed >>> 15)) >>> 0;
}
export class HeldoutGenerator {
  private next: ReturnType<typeof seeded>;
  constructor(seed: number) {
    this.next = seeded(seed);
  }
  block(): Block {
    return this.next();
  }
  splice(pairs: KnownPair[]): Block {
    for (let retry = 0; retry < 10000; retry++) {
      const choices = this.next(4).map((x) => x % pairs.length);
      if (new Set(choices).size < 2) continue;
      const target = new Uint8Array(16);
      for (let c = 0; c < 4; c++)
        target.set(pairs[choices[c]].plaintext.slice(c * 4, c * 4 + 4), c * 4);
      if (pairs.every((p) => !equal(p.plaintext, target))) return target;
    }
    throw Error("Could not construct a fresh splice target.");
  }
}
