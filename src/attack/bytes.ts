import { noMixPosition, type Block } from "../aes/state";
import type { EncryptionOracle, Recovery } from "./types";
export async function recoverBytes(oracle: EncryptionOracle, count = 256): Promise<Recovery> {
  if (!Number.isInteger(count) || count < 1 || count > 256)
    throw Error("Choose 1…256 uniform plaintexts.");
  const tables = Array.from({ length: 16 }, () => new Map<number, number>());
  for (let v = 0; v < count; v++) {
    const ct = await oracle(new Uint8Array(16).fill(v));
    for (let input = 0; input < 16; input++) tables[input].set(ct[noMixPosition(input)], v);
  }
  return {
    kind: "decrypt",
    known: [],
    partial: count < 256,
    candidate: (ct: Block) => {
      const p = new Uint8Array(16);
      let missing = false;
      for (let input = 0; input < 16; input++) {
        const value = tables[input].get(ct[noMixPosition(input)]);
        if (value === undefined) {
          missing = true;
          p[input] = 0;
        } else p[input] = value;
      }
      return missing ? null : p;
    },
    decodePartial: (ct: Block) =>
      Array.from({ length: 16 }, (_, input) => tables[input].get(ct[noMixPosition(input)]) ?? null),
  } as Recovery & { decodePartial: (ct: Block) => (number | null)[] };
}
