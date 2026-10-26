import { SBOX, INV_SBOX } from './aes/sbox';
import { shiftRows, mixColumns, xor, type Block } from './aes/state';
import { expand } from './aes/keyExpansion';

/** Four AES rounds; rounds 1–3 include MC, round 4 uses final-round shape. */
export function reducedAes(input: Block, key: Block, trace?: Block[]): Block {
  if (key.length !== 16 || input.length !== 16) throw Error('Reduced exercise requires AES-128 blocks and keys.');
  const keys = expand(key).roundKeys;
  let state = xor(input, keys[0]);
  trace?.push(state.slice());
  for (let round = 1; round <= 4; round++) {
    state = shiftRows(state.map(x => SBOX[x]));
    if (round < 4) state = mixColumns(state);
    state = xor(state, keys[round]);
    trace?.push(state.slice());
  }
  return state;
}
export function lambdaSet(base: Block, active = 0): Block[] {
  if (base.length !== 16 || !Number.isInteger(active) || active < 0 || active > 15) throw Error('Invalid Lambda-set.');
  return Array.from({length: 256}, (_, value) => { const p = base.slice(); p[active] = value; return p; });
}
export function classify(values: number[]): string {
  if (values.length !== 256) throw Error('Classification requires a complete 256-element set.');
  const count = new Set(values).size;
  if (count === 1) return 'constant';
  if (count === 256) return 'active';
  return values.reduce((a, b) => a ^ b, 0) === 0 ? 'balanced' : 'unknown';
}
export function filterIntegral(ciphertexts: Block[], candidates?: number[][]): number[][] {
  if (ciphertexts.length !== 256 || ciphertexts.some(c => c.length !== 16) || new Set(ciphertexts.map(c => Array.from(c).join(','))).size !== 256)
    throw Error('A complete distinct 256-ciphertext Lambda-set is required.');
  return Array.from({length: 16}, (_, byte) =>
    (candidates?.[byte] ?? Array.from({length: 256}, (_, k) => k))
      .filter(k => ciphertexts.reduce((sum, c) => sum ^ INV_SBOX[c[byte] ^ k], 0) === 0));
}
/** Attacker receives an encryption oracle, never a key or intermediate state. */
export function integralAttack(encrypt: (p: Block) => Block, base: Block, maxSets = 6) {
  if (!Number.isInteger(maxSets) || maxSets < 1 || maxSets > 6) throw Error('Budget must be 1–6 sets.');
  let candidates: number[][] | undefined;
  const history: number[][] = [];
  for (let set = 0; set < maxSets; set++) {
    const next = base.slice(); next[15] = (base[15] + set) & 255;
    candidates = filterIntegral(lambdaSet(next).map(encrypt), candidates);
    history.push(candidates.map(c => c.length));
    if (candidates.every(c => c.length === 1) || candidates.some(c => c.length === 0)) break;
  }
  return { candidates: candidates!, history, queries: history.length * 256 };
}
/** Reverse the AES-128 schedule from round 4, not round 10. */
export function recoverIntegralKey(round4: Block): Block {
  if (round4.length !== 16) throw Error('Round-4 key must have 16 bytes.');
  const words: Block[] = Array.from({length: 20}, () => new Uint8Array(4));
  for (let i = 16; i < 20; i++) words[i] = round4.slice((i - 16) * 4, (i - 15) * 4);
  for (let i = 19; i >= 4; i--) {
    let t = words[i - 1].slice();
    if (i % 4 === 0) { t = Uint8Array.from([t[1], t[2], t[3], t[0]], x => SBOX[x]); t[0] ^= 1 << (i / 4 - 1); }
    words[i - 4] = xor(words[i], t);
  }
  return Uint8Array.from(words.slice(0, 4).flatMap(w => Array.from(w)));
}
