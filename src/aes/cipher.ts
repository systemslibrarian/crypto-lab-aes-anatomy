import { SBOX, INV_SBOX, AFFINE, buildInvSbox } from "./sbox";
import { shiftRows, invShiftRows, mixColumns, invMixColumns, xor, type Block } from "./state";
export interface Config {
  shiftRows: boolean;
  mixColumns: boolean;
  sbox: "real" | "affineOnly" | "identity";
}
export const REAL: Config = { shiftRows: true, mixColumns: true, sbox: "real" };
export const VARIANTS: Record<string, Config> = {
  real: REAL,
  noSub: { ...REAL, sbox: "identity" },
  affine: { ...REAL, sbox: "affineOnly" },
  noShift: { ...REAL, shiftRows: false },
  noMix: { ...REAL, mixColumns: false },
};
export interface Round {
  round: number;
  input: Block;
  sub: Block;
  shift: Block;
  mix: Block | null;
  beforeKey: Block;
  key: Block;
  output: Block;
}
export function cipher(
  input: Block,
  roundKeys: Block[],
  config: Config = REAL,
  trace?: Round[],
): Block {
  if (input.length !== 16) throw Error("AES block must be exactly 16 bytes.");
  const Nr = roundKeys.length - 1;
  if (![10, 12, 14].includes(Nr)) throw Error("Invalid round-key count.");
  let state = xor(input, roundKeys[0]);
  trace?.push({
    round: 0,
    input: input.slice(),
    sub: input.slice(),
    shift: input.slice(),
    mix: null,
    beforeKey: input.slice(),
    key: roundKeys[0],
    output: state,
  });
  for (let round = 1; round <= Nr; round++) {
    const start = state.slice(),
      sub = state.map((x) =>
        config.sbox === "real" ? SBOX[x] : config.sbox === "affineOnly" ? AFFINE[x] : x,
      ),
      shift = config.shiftRows ? shiftRows(sub) : sub.slice(),
      mix = config.mixColumns && round < Nr ? mixColumns(shift) : null,
      beforeKey = mix ?? shift;
    state = xor(beforeKey, roundKeys[round]);
    trace?.push({
      round,
      input: start,
      sub,
      shift,
      mix,
      beforeKey,
      key: roundKeys[round],
      output: state,
    });
  }
  return state;
}
const INV_AFFINE = buildInvSbox(AFFINE);
export interface InverseStep {
  round: number;
  layer: string;
  state: Block;
  key?: Block;
}
export function invCipher(
  input: Block,
  roundKeys: Block[],
  trace?: InverseStep[],
  config: Config = REAL,
  fault: "none" | "forwardKeys" | "wrongMix" = "none",
): Block {
  if (input.length !== 16) throw Error("AES block must be exactly 16 bytes.");
  const keys = fault === "forwardKeys" ? roundKeys : roundKeys.slice().reverse();
  let state = xor(input, keys[0]);
  trace?.push({ round: 0, layer: "AddRoundKey", state: state.slice(), key: keys[0] });
  for (let round = 1; round < keys.length; round++) {
    if (config.shiftRows) state = invShiftRows(state);
    trace?.push({ round, layer: "InvShiftRows", state: state.slice() });
    state = state.map((x) =>
      config.sbox === "real" ? INV_SBOX[x] : config.sbox === "affineOnly" ? INV_AFFINE[x] : x,
    );
    trace?.push({ round, layer: "InvSubBytes", state: state.slice() });
    state = xor(state, keys[round]);
    trace?.push({ round, layer: "AddRoundKey", state: state.slice(), key: keys[round] });
    if (config.mixColumns && round < keys.length - 1) {
      state = fault === "wrongMix" ? mixColumns(state) : invMixColumns(state);
      trace?.push({
        round,
        layer: fault === "wrongMix" ? "Wrong MixColumns" : "InvMixColumns",
        state: state.slice(),
      });
    }
  }
  return state;
}
// [extension] point: reduced rounds for a future square/integral exhibit, not implemented.
