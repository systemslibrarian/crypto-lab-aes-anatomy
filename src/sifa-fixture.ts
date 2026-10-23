import { cipher, REAL, type Round } from "./aes/cipher";
import { expand } from "./aes/keyExpansion";
import { SBOX } from "./aes/sbox";
import { equal, mixColumns, shiftRows, xor, type Block } from "./aes/state";
import { seeded } from "./random";

export type SifaFaultModel = "noisy-stuck-at-zero" | "secret-independent";
export type SifaDefense = "reject" | "infect-hidden" | "infect-with-validity";

export interface SifaFaultWitness {
  plaintext: Block;
  correctSboxByte: number;
  faultedSboxByte: number;
  correctCiphertext: Block;
  faultyCiphertext: Block;
  detectorAlert: boolean;
  returnedCiphertext: Block | null;
  returnedKind: "correct" | "suppressed" | "infected";
}

export interface SifaWitnessPair {
  ineffective: SifaFaultWitness;
  effective: SifaFaultWitness;
  control: SifaFaultWitness;
}

export interface SifaTrial {
  plaintext: Block;
  faultModel: SifaFaultModel;
  faultLanded: boolean;
  correctSboxByte: number;
  faultedSboxByte: number;
  correctCiphertext: Block;
  faultyCiphertext: Block;
  unchanged: boolean;
}

export interface SifaSamplePrefix {
  sampleSize: number;
  allInputs: number[];
  noisySelected: number[];
  controlSelected: number[];
  noisyAttempts: number;
  controlAttempts: number;
}

export interface SifaCollection {
  acceptedPlaintextBytes: number[];
  selectedPlaintextBytes: number[];
  attempts: number;
  accepted: number;
  rejected: number;
  selected: number;
  targetBit: number;
  faultModel: SifaFaultModel;
  defense: SifaDefense;
  outputsReturned: number;
  externallyValid: number;
  induced: number;
  missed: number;
  ineffective: number;
  effective: number;
}

function validateBit(targetBit: number): void {
  if (!Number.isInteger(targetBit) || targetBit < 0 || targetBit > 7)
    throw new RangeError("targetBit must be an integer from 0 through 7");
}

/** Continue genuine AES-128 after the first round's SubBytes output. */
function finishAfterRound1SubBytes(firstRoundSub: Block, roundKeys: Block[]): Block {
  let state = xor(mixColumns(shiftRows(firstRoundSub)), roundKeys[1]!);
  for (let round = 2; round < roundKeys.length; round++) {
    const sub = state.map((byte) => SBOX[byte]!);
    const shifted = shiftRows(sub);
    state = xor(round < roundKeys.length - 1 ? mixColumns(shifted) : shifted, roundKeys[round]!);
  }
  return state;
}

/**
 * A deterministic teaching infection transform, not a hardened countermeasure.
 * A detected mismatch derives a nonzero mask from real AES-128; a zero mismatch
 * derives the all-zero mask. The selection experiment never treats this output
 * value as proof of a general infective construction.
 */
function infectionMask(correct: Block, faulty: Block, roundKeys: Block[]): Block {
  const difference = xor(correct, faulty);
  return xor(
    cipher(difference, roundKeys, REAL),
    cipher(new Uint8Array(16), roundKeys, REAL),
  );
}

function executeWithRoundKeys(
  roundKeys: Block[],
  plaintext: Block,
  targetBit: number,
  fault: "miss" | "stuck-at-zero" | "bit-flip",
): Omit<SifaTrial, "plaintext" | "faultModel" | "faultLanded"> {
  const trace: Round[] = [];
  const correctCiphertext = cipher(plaintext, roundKeys, REAL, trace);
  const correctSub = trace[1]!.sub.slice();
  const faultedSub = correctSub.slice();
  if (fault === "stuck-at-zero") faultedSub[0] &= ~(1 << targetBit);
  else if (fault === "bit-flip") faultedSub[0] ^= 1 << targetBit;
  const faultyCiphertext =
    fault === "miss"
      ? correctCiphertext.slice()
      : finishAfterRound1SubBytes(faultedSub, roundKeys);
  return {
    correctSboxByte: correctSub[0]!,
    faultedSboxByte: faultedSub[0]!,
    correctCiphertext,
    faultyCiphertext,
    unchanged: equal(correctCiphertext, faultyCiphertext),
  };
}

/** Execute one full AES-128 trial for the statistical experiment. */
export function executeSifaTrial(
  key: Block,
  plaintext: Block,
  targetBit: number,
  faultModel: SifaFaultModel,
  faultLanded: boolean,
): SifaTrial {
  if (key.length !== 16) throw new Error("This accepted-output fixture is AES-128 only.");
  if (plaintext.length !== 16) throw new Error("AES block must be exactly 16 bytes.");
  validateBit(targetBit);
  const executed = executeWithRoundKeys(
    expand(key.slice()).roundKeys,
    plaintext,
    targetBit,
    faultLanded
      ? faultModel === "noisy-stuck-at-zero"
        ? "stuck-at-zero"
        : "bit-flip"
      : "miss",
  );
  return {
    plaintext: plaintext.slice(),
    faultModel,
    faultLanded,
    ...executed,
  };
}

/**
 * Reliably alter one bit of state byte 0 immediately after the first AES-128
 * SubBytes. The fixture then finishes real AES, compares the duplicated outputs,
 * and applies the selected output-handling policy.
 */
function injectFirstRoundSboxFault(
  key: Block,
  plaintext: Block,
  targetBit: number,
  defense: SifaDefense,
  fault: "stuck-at-zero" | "bit-flip",
): SifaFaultWitness {
  if (key.length !== 16) throw new Error("This accepted-output fixture is AES-128 only.");
  if (plaintext.length !== 16) throw new Error("AES block must be exactly 16 bytes.");
  validateBit(targetBit);

  const roundKeys = expand(key.slice()).roundKeys;
  const executed = executeWithRoundKeys(roundKeys, plaintext, targetBit, fault);
  const detectorAlert = !executed.unchanged;

  if (!detectorAlert)
    return {
      plaintext: plaintext.slice(),
      correctSboxByte: executed.correctSboxByte,
      faultedSboxByte: executed.faultedSboxByte,
      correctCiphertext: executed.correctCiphertext,
      faultyCiphertext: executed.faultyCiphertext,
      detectorAlert,
      returnedCiphertext: executed.correctCiphertext.slice(),
      returnedKind: "correct",
    };

  if (defense === "reject")
    return {
      plaintext: plaintext.slice(),
      correctSboxByte: executed.correctSboxByte,
      faultedSboxByte: executed.faultedSboxByte,
      correctCiphertext: executed.correctCiphertext,
      faultyCiphertext: executed.faultyCiphertext,
      detectorAlert,
      returnedCiphertext: null,
      returnedKind: "suppressed",
    };

  return {
    plaintext: plaintext.slice(),
    correctSboxByte: executed.correctSboxByte,
    faultedSboxByte: executed.faultedSboxByte,
    correctCiphertext: executed.correctCiphertext,
    faultyCiphertext: executed.faultyCiphertext,
    detectorAlert,
    returnedCiphertext: xor(
      executed.correctCiphertext,
      infectionMask(executed.correctCiphertext, executed.faultyCiphertext, roundKeys),
    ),
    returnedKind: "infected",
  };
}

export function injectFirstRoundSboxStuckAtZero(
  key: Block,
  plaintext: Block,
  targetBit: number,
  defense: SifaDefense = "reject",
): SifaFaultWitness {
  return injectFirstRoundSboxFault(
    key,
    plaintext,
    targetBit,
    defense,
    "stuck-at-zero",
  );
}

export function buildSifaWitnesses(
  key: Block,
  basePlaintext: Block,
  targetBit: number,
  defense: SifaDefense,
): SifaWitnessPair {
  if (key.length !== 16) throw new Error("This accepted-output fixture is AES-128 only.");
  if (basePlaintext.length !== 16) throw new Error("AES block must be exactly 16 bytes.");
  validateBit(targetBit);

  const findPlaintextByte = (wantedBit: number) => {
    for (let value = 0; value < 256; value++)
      if (((SBOX[value ^ key[0]!]! >>> targetBit) & 1) === wantedBit) return value;
    throw new Error("AES S-box did not provide both target-bit values");
  };
  const ineffectivePlaintext = basePlaintext.slice();
  ineffectivePlaintext[0] = findPlaintextByte(0);
  const effectivePlaintext = basePlaintext.slice();
  effectivePlaintext[0] = findPlaintextByte(1);

  return {
    ineffective: injectFirstRoundSboxStuckAtZero(
      key,
      ineffectivePlaintext,
      targetBit,
      defense,
    ),
    effective: injectFirstRoundSboxStuckAtZero(key, effectivePlaintext, targetBit, defense),
    control: injectFirstRoundSboxFault(
      key,
      basePlaintext,
      targetBit,
      defense,
      "bit-flip",
    ),
  };
}

/**
 * Build the selected-input distribution used by the bounded SIFA lesson.
 *
 * In the noisy stuck-at-zero model, each possible first plaintext byte is tried
 * eight times. The fault lands on six attempts and misses on two. A landed
 * stuck-at-zero fault is ineffective exactly when the selected first-round
 * S-box output bit is already zero. The attacker sees which calls return under
 * rejection, but is not told whether a returned call was a true ineffective
 * induction or a miss.
 *
 * The secret-independent control applies an always-effective bit flip on three
 * of eight attempts and misses on five. It therefore retains the same 1,280
 * unchanged samples without secret-dependent selection. The infect-hidden
 * control returns every output and grants no reference/validity oracle, so its
 * selection-only ranker must use all attempts.
 */
export function collectSifaSamples(
  keyByte: number,
  targetBit: number,
  faultModel: SifaFaultModel,
  defense: SifaDefense = "reject",
): SifaCollection {
  if (!Number.isInteger(keyByte) || keyByte < 0 || keyByte > 255)
    throw new RangeError("keyByte must be an integer from 0 through 255");
  validateBit(targetBit);

  const acceptedPlaintextBytes: number[] = [];
  const selectedPlaintextBytes: number[] = [];
  const repeats = 8;
  let induced = 0;
  let missed = 0;
  let ineffective = 0;
  let effective = 0;

  for (let plaintextByte = 0; plaintextByte < 256; plaintextByte++) {
    const intermediate = SBOX[(plaintextByte ^ keyByte) & 0xff]!;
    const secretBit = (intermediate >>> targetBit) & 1;

    for (let repetition = 0; repetition < repeats; repetition++) {
      let unchanged: boolean;
      if (faultModel === "noisy-stuck-at-zero") {
        const faultLanded = repetition >= 2;
        unchanged = !faultLanded || secretBit === 0;
        if (faultLanded) {
          induced++;
          if (unchanged) ineffective++;
          else effective++;
        } else missed++;
      } else {
        const faultLanded = repetition >= 5;
        unchanged = !faultLanded;
        if (faultLanded) {
          induced++;
          effective++;
        } else missed++;
      }

      if (unchanged) acceptedPlaintextBytes.push(plaintextByte);
      if (defense === "infect-hidden" || unchanged)
        selectedPlaintextBytes.push(plaintextByte);
    }
  }

  const attempts = 256 * repeats;
  const accepted = acceptedPlaintextBytes.length;
  return {
    acceptedPlaintextBytes,
    selectedPlaintextBytes,
    attempts,
    accepted,
    rejected: attempts - accepted,
    selected: selectedPlaintextBytes.length,
    targetBit,
    faultModel,
    defense,
    outputsReturned: defense === "reject" ? accepted : attempts,
    externallyValid: accepted,
    induced,
    missed,
    ineffective,
    effective,
  };
}

/**
 * A finite-sample experiment distinct from the analytic balanced census above.
 * Plaintext bytes and fault misses come from the lab's reproducible teaching
 * generator. Every trial computes a correct AES-128 ciphertext, finishes AES
 * from the faulted first-round state, and classifies equality from those blocks.
 * Prefixes therefore exhibit ordinary sampling noise, including a nonzero
 * null/control SEI, while remaining independently reproducible.
 */
export function sampleSifaPrefixes(
  key: Block,
  basePlaintext: Block,
  targetBit: number,
  seed: number,
  sampleSizes: readonly number[] = [64, 256, 1024],
): SifaSamplePrefix[] {
  if (key.length !== 16) throw new Error("This accepted-output fixture is AES-128 only.");
  if (basePlaintext.length !== 16) throw new Error("AES block must be exactly 16 bytes.");
  validateBit(targetBit);
  if (!Number.isInteger(seed) || seed < 0 || seed > 0xffffffff)
    throw new RangeError("seed must be an unsigned 32-bit integer");
  if (
    sampleSizes.length === 0 ||
    sampleSizes.some((size, index) =>
      !Number.isInteger(size) || size < 1 || (index > 0 && size <= sampleSizes[index - 1]!)
    )
  )
    throw new RangeError("sample sizes must be positive, strictly increasing integers");

  const draw = seeded(seed);
  const max = sampleSizes.at(-1)!;
  const noisySelected: number[] = [];
  const controlSelected: number[] = [];
  const allInputs: number[] = [];
  const noisyAttempts = new Map<number, number>();
  const controlAttempts = new Map<number, number>();
  const roundKeys = expand(key.slice()).roundKeys;
  let attempts = 0;

  while (noisySelected.length < max || controlSelected.length < max) {
    const random = draw(2);
    const plaintextByte = random[0]!;
    const bucket = random[1]! & 7;
    const plaintext = basePlaintext.slice();
    plaintext[0] = plaintextByte;
    attempts++;
    allInputs.push(plaintextByte);

    const noisy = executeWithRoundKeys(
      roundKeys,
      plaintext,
      targetBit,
      bucket < 2 ? "miss" : "stuck-at-zero",
    );
    if (noisySelected.length < max && noisy.unchanged) {
      noisySelected.push(plaintextByte);
      if (sampleSizes.includes(noisySelected.length))
        noisyAttempts.set(noisySelected.length, attempts);
    }

    const control = executeWithRoundKeys(
      roundKeys,
      plaintext,
      targetBit,
      bucket < 5 ? "miss" : "bit-flip",
    );
    if (controlSelected.length < max && control.unchanged) {
      controlSelected.push(plaintextByte);
      if (sampleSizes.includes(controlSelected.length))
        controlAttempts.set(controlSelected.length, attempts);
    }
  }

  return sampleSizes.map((sampleSize) => ({
    sampleSize,
    allInputs: allInputs.slice(0, sampleSize),
    noisySelected: noisySelected.slice(0, sampleSize),
    controlSelected: controlSelected.slice(0, sampleSize),
    noisyAttempts: noisyAttempts.get(sampleSize)!,
    controlAttempts: controlAttempts.get(sampleSize)!,
  }));
}
