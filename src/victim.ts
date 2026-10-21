import { cipher, type Config } from "./aes/cipher";
import { expand } from "./aes/keyExpansion";
import type { EncryptionOracle } from "./attack/types";
/** The returned capability exposes encryption only; no key property or schedule getter. */
export function createVictim(key: Uint8Array, config: Config): EncryptionOracle {
  const roundKeys = expand(key.slice()).roundKeys;
  return async (p) => cipher(p, roundKeys, config);
}
