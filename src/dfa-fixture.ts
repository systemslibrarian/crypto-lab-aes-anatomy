import { SBOX } from "./aes/sbox";
import { cipher, REAL, type Round } from "./aes/cipher";
import { expand } from "./aes/keyExpansion";
import { mixColumns, shiftRows, xor, type Block } from "./aes/state";
import type { FaultPair } from "./attack/dfa";

export interface InjectedFaultPair extends FaultPair {
  column: number;
  row: number;
  fault: number;
}

/**
 * Teaching fault harness. It owns the victim key and simulates one nonzero byte
 * XOR immediately before AES-128 round-9 MixColumns. The attack module never
 * imports or receives this function, the key, the round keys, or the fault value.
 */
export function injectRound9MixColumnsFault(
  key: Block,
  plaintext: Block,
  column: number,
  row: number,
  fault: number,
): InjectedFaultPair {
  if (key.length !== 16) throw Error("This DFA fixture is AES-128 only.");
  if (plaintext.length !== 16) throw Error("AES block must be exactly 16 bytes.");
  if (!Number.isInteger(column) || column < 0 || column > 3) throw Error("Fault column must be 0…3.");
  if (!Number.isInteger(row) || row < 0 || row > 3) throw Error("Fault row must be 0…3.");
  if (!Number.isInteger(fault) || fault < 1 || fault > 255) throw Error("Fault byte must be nonzero.");

  const roundKeys = expand(key).roundKeys;
  const trace: Round[] = [];
  const correct = cipher(plaintext, roundKeys, REAL, trace);
  const beforeMix = trace[9]!.shift.slice();
  beforeMix[row + 4 * column] ^= fault;

  const round9 = xor(mixColumns(beforeMix), roundKeys[9]!);
  const round10Sub = round9.map((byte) => SBOX[byte]!);
  const round10Shift = shiftRows(round10Sub);
  const faulty = xor(round10Shift, roundKeys[10]!);

  return { correct, faulty, column, row, fault };
}
