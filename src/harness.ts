import { recoverAffine } from "./attack/affine";
import { recoverColumns } from "./attack/columns";
import { recoverBytes } from "./attack/bytes";
import { HeldoutGenerator } from "./attack/heldout";
import type { Recovery } from "./attack/types";
import { createVictim } from "./victim";
import { seeded } from "./random";
import { VARIANTS, REAL } from "./aes/cipher";
import { equal, type Block } from "./aes/state";
export interface HeldoutRow {
  plaintext: Block;
  ciphertext: Block;
  candidate: Block | null;
  candidateCiphertext: Block | null;
  matches: boolean;
  partial?: (number | null)[];
}
export function singularVerdict(control: boolean) {
  return control
    ? {
        kind: "control-fails",
        message: "No linear model exists; this is expected against real AES.",
      }
    : {
        kind: "implementation-error",
        message: "Singular L in an affine ablation: implementation error.",
      };
}
export async function runBreak(
  variant: string,
  victimKey: Block,
  seed: number,
  count = variant === "noShift" ? 3 : 256,
  hooks: {
    afterAttack?: () => void;
    generator?: (seed: number) => HeldoutGenerator;
    injectColumns?: bigint[];
  } = {},
) {
  if (!["noSub", "affine", "noShift", "noMix"].includes(variant))
    throw Error("Choose a deliberately broken layer first.");
  if (victimKey.length !== 16) throw Error("Attack acts run at AES-128 only.");
  const run = async (control: boolean) => {
    const config = control ? REAL : VARIANTS[variant],
      victim = createVictim(victimKey, config),
      ownSource = seeded(seed ^ 0x6c8e9cf5),
      makeOwnKey = () => ownSource(16);
    const choose = seeded(seed ^ 0x45d9f3b);
    let queries = 0;
    const oracle = async (p: Block) => {
      queries++;
      return victim(p);
    };
    let recovered: Recovery;
    if (variant === "noSub" || variant === "affine")
      recovered = await recoverAffine(oracle, makeOwnKey, config, hooks.injectColumns);
    else if (variant === "noShift") recovered = await recoverColumns(oracle, () => choose(), count);
    else recovered = await recoverBytes(oracle, count);
    // The promise has resolved; only now may the verifier construct its separate stream.
    hooks.afterAttack?.();
    const heldout = hooks.generator
        ? hooks.generator(seed ^ 0xa341316c)
        : new HeldoutGenerator(seed ^ 0xa341316c),
      rows: HeldoutRow[] = [];
    for (let i = 0; i < 32; i++) {
      const plaintext =
          recovered.kind === "forge" ? heldout.splice(recovered.known) : heldout.block(),
        ciphertext = await victim(plaintext),
        candidate = recovered.candidate(recovered.kind === "forge" ? plaintext : ciphertext),
        fallback = candidate ?? new Uint8Array(16),
        candidateCiphertext = recovered.kind === "forge" ? fallback : await victim(fallback),
        matches =
          recovered.kind === "forge"
            ? equal(fallback, ciphertext)
            : equal(candidateCiphertext, ciphertext);
      const decode = (recovered as Recovery & { decodePartial?: (ct: Block) => (number | null)[] })
        .decodePartial;
      rows.push({
        plaintext,
        ciphertext,
        candidate: fallback,
        candidateCiphertext,
        matches,
        partial: decode?.(ciphertext),
      });
    }
    const successes = rows.filter((x) => x.matches).length;
    return {
      control,
      queries,
      rows,
      successes,
      known: recovered.known,
      columns: recovered.columns,
      inverse: recovered.inverse,
      rank: recovered.rank,
      operations: recovered.operations,
      partial: recovered.partial,
      singular: recovered.inverse === null ? singularVerdict(control) : null,
    };
  };
  return { broken: await run(false), control: await run(true) };
}
