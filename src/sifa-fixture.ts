import { SBOX } from "./aes/sbox";

export type SifaFaultModel = "biased-ineffective" | "secret-independent";

export interface SifaCollection {
  acceptedPlaintextBytes: number[];
  attempts: number;
  accepted: number;
  rejected: number;
  targetBit: number;
  faultModel: SifaFaultModel;
  defense: "reject" | "infect-with-validity";
  outputsReturned: number;
  externallyValid: number;
}

/**
 * Collect the inputs whose faulted execution is classified as unchanged.
 *
 * Each possible plaintext byte is tried exactly eight times. In the biased
 * ineffective model, a stuck-at-zero-like induction is ineffective on all
 * eight trials when the selected first-round S-box bit is already 0, and on
 * two of eight trials when that bit is 1. The secret-independent control
 * accepts five of eight trials for every plaintext byte. Both therefore retain
 * exactly 1,280 samples, so sample count alone cannot explain the key signal.
 *
 * "infect-with-validity" returns an output on every attempt but models an
 * external application validity oracle that lets the attacker keep the same
 * unchanged executions. This makes the countermeasure boundary explicit.
 */
export function collectSifaSamples(
  keyByte: number,
  targetBit: number,
  faultModel: SifaFaultModel,
  defense: "reject" | "infect-with-validity" = "reject",
): SifaCollection {
  if (!Number.isInteger(keyByte) || keyByte < 0 || keyByte > 255)
    throw new RangeError("keyByte must be an integer from 0 through 255");
  if (!Number.isInteger(targetBit) || targetBit < 0 || targetBit > 7)
    throw new RangeError("targetBit must be an integer from 0 through 7");

  const acceptedPlaintextBytes: number[] = [];
  const repeats = 8;

  for (let plaintextByte = 0; plaintextByte < 256; plaintextByte++) {
    const intermediate = SBOX[(plaintextByte ^ keyByte) & 0xff]!;
    const secretBit = (intermediate >>> targetBit) & 1;

    for (let repetition = 0; repetition < repeats; repetition++) {
      const accepted =
        faultModel === "biased-ineffective"
          ? secretBit === 0 || repetition < 2
          : repetition < 5;
      if (accepted) acceptedPlaintextBytes.push(plaintextByte);
    }
  }

  const attempts = 256 * repeats;
  const accepted = acceptedPlaintextBytes.length;
  return {
    acceptedPlaintextBytes,
    attempts,
    accepted,
    rejected: attempts - accepted,
    targetBit,
    faultModel,
    defense,
    outputsReturned: defense === "reject" ? accepted : attempts,
    externallyValid: accepted,
  };
}
