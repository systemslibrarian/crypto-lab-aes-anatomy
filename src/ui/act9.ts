import { equal, hex, type Block } from "../aes/state";
import { rankOf, rankSifaKeyByte } from "../attack/sifa";
import {
  buildSifaWitnesses,
  collectSifaSamples,
  sampleSifaPrefixes,
  type SifaDefense,
  type SifaFaultModel,
  type SifaFaultWitness,
} from "../sifa-fixture";
import { check, table } from "./common";

const byteHex = (value: number) => value.toString(16).padStart(2, "0");

function handledOutput(witness: SifaFaultWitness): string {
  if (witness.returnedKind === "suppressed") return "suppressed";
  return `${witness.returnedKind}: ${hex(witness.returnedCiphertext!)}`;
}

export function act9(
  key: Block,
  plaintext: Block,
  targetBit: number,
  faultModel: SifaFaultModel,
  defense: SifaDefense,
  seed: number,
): string {
  if (key.length !== 16)
    return '<p class="alarm" data-verdict="wrong-key-size">⚠ Accepted-output fault analysis in this exhibit is AES-128 only. Select a 128-bit key.</p>';

  const actual = key[0]!;
  const collection = collectSifaSamples(actual, targetBit, faultModel, defense);
  const matchingControl = collectSifaSamples(actual, targetBit, "secret-independent", defense);
  const ranking = rankSifaKeyByte(collection.selectedPlaintextBytes, targetBit);
  const actualRank = rankOf(ranking, actual);
  const top = ranking[0]!;
  const allZero = ranking.every((candidate) => candidate.sei === 0);
  const uniqueTop = ranking.length > 1 && top.sei > ranking[1]!.sei;
  const selectionVisible = defense !== "infect-hidden";
  const recovered =
    faultModel === "noisy-stuck-at-zero" &&
    selectionVisible &&
    uniqueTop &&
    top.keyByte === actual;
  const witnesses = buildSifaWitnesses(key, plaintext, targetBit, defense);

  const topRows = ranking.slice(0, 8).map((candidate, index) => [
    String(index + 1),
    byteHex(candidate.keyByte),
    String(candidate.zeros),
    String(candidate.ones),
    candidate.sei.toFixed(6),
    candidate.keyByte === actual ? "actual byte" : "",
  ]);

  const witnessRows = [
    ["stuck-at-0, bit was 0", witnesses.ineffective],
    ["stuck-at-0, bit was 1", witnesses.effective],
    ["bit-flip control", witnesses.control],
  ] as const;
  const witnessTable = table(
    "Actual first-round AES fault witnesses",
    [
      "Fault case",
      "P₀",
      "S-box byte before → after",
      "Correct ciphertext",
      "Fault-path ciphertext",
      "Detector",
      "Returned output",
    ],
    witnessRows.map(([label, witness]) => [
      label,
      byteHex(witness.plaintext[0]!),
      `${byteHex(witness.correctSboxByte)} → ${byteHex(witness.faultedSboxByte)}`,
      hex(witness.correctCiphertext),
      hex(witness.faultyCiphertext),
      witness.detectorAlert ? "alert" : "no alert",
      handledOutput(witness),
    ]),
    "sifa-witnesses",
  );

  const witnessCorrect =
    !witnesses.ineffective.detectorAlert &&
    equal(witnesses.ineffective.correctCiphertext, witnesses.ineffective.faultyCiphertext) &&
    witnesses.effective.detectorAlert &&
    !equal(witnesses.effective.correctCiphertext, witnesses.effective.faultyCiphertext) &&
    witnesses.control.detectorAlert;
  const handlingCorrect =
    defense === "reject"
      ? witnesses.effective.returnedKind === "suppressed"
      : witnesses.effective.returnedKind === "infected" &&
        witnesses.effective.returnedCiphertext !== null &&
        !equal(
          witnesses.effective.returnedCiphertext,
          witnesses.effective.correctCiphertext,
        );

  const prefixes = sampleSifaPrefixes(key, plaintext, targetBit, seed);
  const prefixRows = prefixes.map((prefix) => {
    const selected =
      defense === "infect-hidden"
        ? prefix.allInputs
        : faultModel === "noisy-stuck-at-zero"
          ? prefix.noisySelected
          : prefix.controlSelected;
    const selectedAttempts =
      defense === "infect-hidden"
        ? prefix.sampleSize
        : faultModel === "noisy-stuck-at-zero"
          ? prefix.noisyAttempts
          : prefix.controlAttempts;
    const controlInputs =
      defense === "infect-hidden" || faultModel === "secret-independent"
        ? selected
        : prefix.controlSelected;
    const experiment = rankSifaKeyByte(selected, targetBit);
    const control = rankSifaKeyByte(controlInputs, targetBit);
    const actualExperiment = experiment.find((candidate) => candidate.keyByte === actual)!;
    const actualControl = control.find((candidate) => candidate.keyByte === actual)!;
    return [
      String(prefix.sampleSize),
      String(selectedAttempts),
      String(rankOf(experiment, actual)),
      actualExperiment.sei.toFixed(6),
      String(
        defense === "infect-hidden" || faultModel === "secret-independent"
          ? selectedAttempts
          : prefix.controlAttempts,
      ),
      String(rankOf(control, actual)),
      actualControl.sei.toFixed(6),
      control[0]!.sei.toFixed(6),
    ];
  });
  const finalPrefix = prefixes.at(-1)!;
  const finalSelected =
    defense === "infect-hidden"
      ? finalPrefix.allInputs
      : faultModel === "noisy-stuck-at-zero"
        ? finalPrefix.noisySelected
        : finalPrefix.controlSelected;
  const finalControl =
    defense === "infect-hidden" || faultModel === "secret-independent"
      ? finalSelected
      : finalPrefix.controlSelected;
  const finalRanking = rankSifaKeyByte(finalSelected, targetBit);
  const finalControlRanking = rankSifaKeyByte(finalControl, targetBit);
  const statisticalCheck =
    faultModel === "noisy-stuck-at-zero" && selectionVisible
      ? finalRanking[0]!.keyByte === actual
      : finalRanking.every(
          (candidate, index) =>
            candidate.keyByte === finalControlRanking[index]!.keyByte &&
            candidate.sei === finalControlRanking[index]!.sei,
        );

  const modelText =
    faultModel === "noisy-stuck-at-zero"
      ? `The stuck-at-zero induction lands ${collection.induced} times and misses ${collection.missed} times. Of the landed faults, ${collection.ineffective} are genuinely ineffective and ${collection.effective} change the AES output and trigger the detector.`
      : `The control bit flip lands ${collection.induced} times and misses ${collection.missed} times. Every landed flip changes the AES output, so the ${collection.accepted} unchanged executions are all misses and are independent of the S-box bit.`;

  const defenseText =
    defense === "reject"
      ? `Reject-on-detection returns ${collection.outputsReturned} unchanged outputs and suppresses ${collection.rejected}. Output absence exposes the selected ${collection.selected}-input set to the ranker.`
      : defense === "infect-hidden"
        ? `The scoped infective transform returns all ${collection.outputsReturned} outputs and computes an infected block on each detected mismatch. With no reference or validity oracle, this selection-only attacker cannot label which ${collection.externallyValid} outputs were unchanged, so it must rank all ${collection.selected} attempts.`
        : `The scoped infective transform returns all ${collection.outputsReturned} outputs, but this experiment explicitly grants the clean reference ciphertext for the same plaintext and fixed context. Exact equality re-identifies the ${collection.externallyValid} unchanged executions and recreates the same ${collection.selected}-input selection channel as rejection.`;

  const verdict =
    faultModel === "secret-independent"
      ? check(
          "sifa-control",
          allZero,
          allZero
            ? "The equal-count bit-flip control gives every key candidate zero imbalance in the exact balanced census. There is no key ranking to claim."
            : "The secret-independent control unexpectedly produced a candidate imbalance; the control failed.",
        )
      : defense === "infect-hidden"
        ? check(
            "sifa-infect-hidden",
            allZero,
            allZero
              ? "Without a reference or validity oracle, all attempts enter this selection-only ranker and every candidate ties at zero imbalance. This closes only the modeled selection channel."
              : "The no-oracle infective control unexpectedly retained a selection imbalance.",
          )
        : check(
            "sifa-biased",
            recovered,
            recovered
              ? `The noisy ineffective-fault selection uniquely ranks key byte ${byteHex(actual)} first. This recovers one AES-128 master-key byte in this bounded model, not the whole key.`
              : "The noisy model did not uniquely rank the actual key byte; no recovery is asserted.",
          );

  return (
    `<h3>Reliable induction: an IFA-style AES witness</h3>` +
    `<p>The declared fault clears bit ${targetBit} (least-significant bit is bit 0) of state byte 0 immediately after the first AES-128 SubBytes. The fixture computes a correct encryption, applies the fault, finishes the remaining real AES rounds, and compares the two ciphertexts. A reliable landed fault is ineffective when that bit was already 0; when it was 1, clearing it changes the final ciphertext.</p>` +
    witnessTable +
    check(
      "sifa-real-fault",
      witnessCorrect,
      witnessCorrect
        ? "Actual AES propagation classifies the bit-0 witness as unchanged and the bit-1 and bit-flip witnesses as changed."
        : "The real-AES fault witness did not match its declared stuck-at-zero model.",
    ) +
    check(
      "sifa-defense-executed",
      handlingCorrect,
      handlingCorrect
        ? `The selected ${defense === "reject" ? "rejection" : "infection"} policy was executed on the changed AES witness.`
        : "The selected output-handling policy did not execute as declared.",
    ) +
    `<h3>Analytic population check for the noisy model</h3>` +
    `<p>This exact census derives the expected population from all 256 possible P₀ values and the declared eight-trial profile; it is not presented as sampled SIFA evidence. In the noisy stuck-at-zero model the fault lands six times and misses twice; the attacker is not told whether an unchanged output came from a miss or a genuinely ineffective induction. The equal-count control instead uses a bit flip that always changes the state when it lands on three of eight attempts and misses five.</p>` +
    `<p>Fault model: <strong id="sifa-model-result">${faultModel}</strong>; output handling: <strong id="sifa-defense-result">${defense}</strong>.</p>` +
    `<p>Attempts <strong id="sifa-attempts">${collection.attempts}</strong>; unchanged/admitted <strong id="sifa-accepted">${collection.accepted}</strong>; changed/rejected <strong id="sifa-rejected">${collection.rejected}</strong>; outputs returned <strong id="sifa-returned">${collection.outputsReturned}</strong>; inputs available to the ranker <strong id="sifa-selected">${collection.selected}</strong>.</p>` +
    `<p id="sifa-fault-counts">${modelText}</p>` +
    `<p>${defenseText}</p>` +
    table(
      "Top selected-output key-byte candidates",
      ["Rank", "K₀ guess", "predicted bit 0", "predicted bit 1", "SEI", "Verifier note"],
      topRows,
      "sifa-ranking",
    ) +
    `<p>Actual key-byte rank: <strong id="sifa-actual-rank">${allZero ? "all 256 tied" : actualRank}</strong>; top-candidate SEI: <strong id="sifa-top-sei">${top.sei.toFixed(6)}</strong>.</p>` +
    verdict +
    check(
      "sifa-same-count",
      collection.selected === matchingControl.selected,
      collection.selected === matchingControl.selected
        ? `For this output policy, the attack and secret-independent control give the ranker the same ${collection.selected}-sample count. Count alone is not the signal.`
        : "The attack and control sample counts differ; this comparison is not valid.",
    ) +
    `<h3>Finite-sample convergence</h3>` +
    `<p>The table below uses the reproducible seed to draw P₀ values and fault misses rather than enumerating a perfectly balanced census. Every trial runs a correct AES-128 encryption, continues AES from the injected or missed first-round state, and classifies the two resulting ciphertexts by exact equality. The experiment columns obey the selected fault and output policy; hidden infection uses every input, and the secret-independent model is compared with itself rather than relabeled as an attack. The control therefore has ordinary finite-sample SEI noise instead of an artificial zero-variance null. A rank is evidence from this run, not a guaranteed sample bound.</p>` +
    table(
      "Finite-sample SIFA and null-control convergence",
      [
        "Selected N",
        "Experiment attempts",
        "Experiment true-key rank",
        "Experiment true-key SEI",
        "Control attempts",
        "Control true-key rank",
        "Control true-key SEI",
        "Max control SEI",
      ],
      prefixRows,
      "sifa-convergence",
    ) +
    check(
      "sifa-statistical",
      statisticalCheck,
      statisticalCheck
        ? faultModel === "noisy-stuck-at-zero" && selectionVisible
          ? `At ${finalPrefix.sampleSize} selected outputs, this seeded noisy run ranks the true key byte first.`
          : `At ${finalPrefix.sampleSize} inputs, the selected experiment is identical to its secret-independent control, so no key recovery is claimed.`
        : faultModel === "noisy-stuck-at-zero" && selectionVisible
          ? `At ${finalPrefix.sampleSize} selected outputs, this seeded run does not rank the true byte first, so it makes no recovery claim.`
          : "The no-selection/control experiment diverged from its matched control; the control failed.",
    ) +
    `<details><summary>What the SEI ranker knows</summary><p>For each candidate byte k, the ranker recomputes bit ${targetBit} of <code>SBOX[P₀ XOR k]</code> for only the inputs its output policy lets it select. It receives neither the victim key nor the fault outcome for an individual returned call. Squared Euclidean imbalance measures distance from the predicted 50/50 bit distribution.</p></details>` +
    `<p><strong>Boundary.</strong> This is a chosen-input, one-byte teaching adaptation with a declared first-round bit fault, an exact six-of-eight profiled landing rate, and reproducible pseudorandom sampling. It is not a physical injection measurement, does not reproduce the papers’ full multi-byte AES attacks, and assumes the attacker knows this simplified selection model. The deterministic infection mask is a bounded comparison case, not the fine-grained circuit protections analyzed by Daemen et al.; it is not a hardened or universal SIFA countermeasure, and output-value, common-mode, multi-fault and physical-oracle attacks remain outside this result.</p>` +
    `<p class="scope">Sources: Dobraunig et al., <em>SIFA: Exploiting Ineffective Fault Inductions on Symmetric Cryptography</em> (TCHES 2018; ePrint 2018/071), and Daemen et al., <em>Protecting against Statistical Ineffective Fault Attacks</em> (TCHES 2020; ePrint 2019/536).</p>`
  );
}
