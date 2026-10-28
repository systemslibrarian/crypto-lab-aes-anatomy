import { cipher } from "../aes/cipher";
import { expand } from "../aes/keyExpansion";
import { equal, hex, type Block } from "../aes/state";
import { injectRound9MixColumnsFault } from "../dfa-fixture";
import {
  affectedCipherPositions,
  installQuartet,
  intersectQuartets,
  invertAes128Round10Key,
  recoverRound10Quartets,
  type QuartetCandidate,
} from "../attack/dfa";
import { check, table } from "./common";

function changedPositions(correct: Block, faulty: Block): string {
  return Array.from({ length: 16 }, (_, i) => i)
    .filter((i) => correct[i] !== faulty[i])
    .join(", ");
}

function quartetHex(candidate: QuartetCandidate | undefined): string {
  return candidate ? candidate.bytes.map((b) => b.toString(16).padStart(2, "0")).join(" ") : "—";
}

export function act8(key: Block, plaintext: Block): string {
  if (key.length !== 16)
    return '<p class="alarm" data-verdict="wrong-key-size">⚠ Differential fault recovery in this exhibit is AES-128 only. Select a 128-bit key.</p>';

  const schedule = expand(key).roundKeys;
  const recoveredRound10 = new Uint8Array(16);
  const rows: string[][] = [];
  const faultValues = [1, 2, 4, 8, 16, 32, 64, 128];
  let allUnique = true;
  let totalFaults = 0;
  let referenceCorrect: Block | null = null;

  for (let column = 0; column < 4; column++) {
    let survivors: QuartetCandidate[] | null = null;
    let firstCount = 0;
    let secondCount = 0;
    let used = 0;
    let firstChanged = "";

    for (const fault of faultValues) {
      const pair = injectRound9MixColumnsFault(key, plaintext, column, 0, fault);
      referenceCorrect ??= pair.correct;
      if (!firstChanged) firstChanged = changedPositions(pair.correct, pair.faulty);
      const candidates = recoverRound10Quartets(
        { correct: pair.correct, faulty: pair.faulty },
        column,
        0,
      );
      used++;
      if (used === 1) firstCount = candidates.length;
      survivors = survivors ? intersectQuartets(survivors, candidates) : candidates;
      if (used === 2) secondCount = survivors.length;
      if (survivors.length === 1) break;
    }

    totalFaults += used;
    if (survivors?.length === 1) installQuartet(recoveredRound10, column, survivors[0]);
    else allUnique = false;

    rows.push([
      String(column),
      affectedCipherPositions(column).join(", "),
      firstChanged,
      String(firstCount),
      used >= 2 ? String(secondCount) : "—",
      String(survivors?.length ?? 0),
      String(used),
      quartetHex(survivors?.length === 1 ? survivors[0] : undefined),
    ]);
  }

  const actualRound10 = schedule[10]!;
  const round10Matches = allUnique && equal(recoveredRound10, actualRound10);
  let recoveredMaster: Block | null = null;
  let masterMatches = false;
  let reencryptionMatches = false;
  let heldoutMatches = false;
  const heldoutPlaintext = plaintext.slice();
  heldoutPlaintext[0] ^= 0x80;
  const heldoutVictim = cipher(heldoutPlaintext, schedule);

  if (allUnique) {
    recoveredMaster = invertAes128Round10Key(recoveredRound10);
    masterMatches = equal(recoveredMaster, key);
    const recoveredSchedule = expand(recoveredMaster).roundKeys;
    reencryptionMatches =
      referenceCorrect !== null &&
      equal(cipher(plaintext, recoveredSchedule), referenceCorrect);
    heldoutMatches = equal(cipher(heldoutPlaintext, recoveredSchedule), heldoutVictim);
  }

  const defensePair = injectRound9MixColumnsFault(key, plaintext, 0, 0, 1);
  const recomputed = cipher(plaintext, schedule);
  const oneSidedDetected = !equal(defensePair.faulty, recomputed);

  const changedModelFirst = injectRound9MixColumnsFault(key, plaintext, 0, 1, 1);
  const changedModelSecond = injectRound9MixColumnsFault(key, plaintext, 0, 1, 2);
  const wrongModelSurvivors = intersectQuartets(
    recoverRound10Quartets(
      { correct: changedModelFirst.correct, faulty: changedModelFirst.faulty },
      0,
      0,
    ),
    recoverRound10Quartets(
      { correct: changedModelSecond.correct, faulty: changedModelSecond.faulty },
      0,
      0,
    ),
  );
  const trueColumnZero = affectedCipherPositions(0).map((position) => actualRound10[position]!);
  const wrongModelContainsTruth = wrongModelSurvivors.some((candidate) =>
    candidate.bytes.every((byte, i) => byte === trueColumnZero[i]),
  );

  const correctHex = referenceCorrect ? hex(referenceCorrect) : "—";

  return (
    `<p><strong>Fault model.</strong> One nonzero byte is XORed at a known row/column immediately before round-9 MixColumns. The simulator owns the injected value; the recovery function receives only the correct/faulty ciphertexts and the known byte location. It enumerates all 255 possible nonzero fault values.</p>
<p>Correct ciphertext: <code id="dfa-correct">${correctHex}</code></p>` +
    table(
      "DFA key-candidate narrowing by affected column",
      [
        "Fault column",
        "Expected ciphertext positions",
        "Observed changed positions",
        "After fault #1",
        "After fault #2",
        "Final survivors",
        "Fault pairs used",
        "Recovered round-10 bytes",
      ],
      rows,
      "dfa-table",
    ) +
    check(
      "dfa-unique",
      allUnique,
      allUnique
        ? `Each of the four last-round key quartets was isolated after ${totalFaults} well-located faulty ciphertexts total.`
        : "The bounded fault set did not isolate every quartet; no full-key recovery is asserted.",
    ) +
    `<p>Recovered round-10 key: <code id="dfa-round10">${allUnique ? hex(recoveredRound10) : "not uniquely recovered"}</code></p>` +
    check(
      "dfa-round10",
      round10Matches,
      round10Matches
        ? "Recovered round key 10 equals the key schedule used by the victim."
        : "Recovered round key 10 does not match; stop before claiming master-key recovery.",
    ) +
    `<p>Reverse the AES-128 key schedule: <code id="dfa-master">${recoveredMaster ? hex(recoveredMaster) : "not attempted"}</code></p>` +
    check(
      "dfa-master",
      masterMatches,
      masterMatches
        ? "Reversing round key 10 recovers the exact 128-bit master key."
        : "Master-key recovery is not established.",
    ) +
    check(
      "dfa-reencrypt",
      reencryptionMatches,
      reencryptionMatches
        ? "Independent verification: re-expanding the recovered master key and encrypting the current plaintext reproduces the correct ciphertext."
        : "Recovered-key re-encryption did not reproduce the correct ciphertext.",
    ) +
    `<p>Held-out plaintext: <code id="dfa-heldout-plaintext">${hex(heldoutPlaintext)}</code>; victim ciphertext: <code id="dfa-heldout-correct">${hex(heldoutVictim)}</code></p>` +
    check(
      "dfa-heldout",
      heldoutMatches,
      heldoutMatches
        ? "Held-out verification: the recovered key also encrypts a different plaintext to the victim's exact ciphertext."
        : "Held-out verification failed; the recovered key is not accepted.",
    ) +
    check(
      "dfa-recompute",
      oneSidedDetected,
      oneSidedDetected
        ? "Simple recomputation detects a one-sided transient fault because the faulty ciphertext differs from a clean second execution."
        : "Recomputation did not detect the one-sided transient fault.",
    ) +
    // Stated, not scored: a common-mode fault corrupts both executions
    // identically, so two equal faulty ciphertexts pass the same comparison.
    // Two identical deterministic injections cannot disagree, so there is no
    // control here that could fail, and a green check would have claimed one.
    `<p data-note="dfa-common-mode">The same comparison would miss a common-mode fault that corrupts both executions identically: two equal faulty ciphertexts pass a recomputation check. That limit is stated here rather than scored, because two identical injections of the same fault cannot disagree and a check that cannot fail is not a control.</p>` +
    check(
      "dfa-wrong-model",
      !wrongModelContainsTruth,
      !wrongModelContainsTruth
        ? `Changed fault model: injecting row 1 while solving as row 0 leaves ${wrongModelSurvivors.length} surviving quartets and does not recover the true last-round bytes.`
        : "The wrong fault model unexpectedly retained the true quartet; no failure claim is made.",
    ) +
    `<details><summary>Why four ciphertext bytes change</summary><p>A single pre-MixColumns byte spreads down one column. Round 10 has no MixColumns, so its ShiftRows moves those four byte differences onto one ciphertext diagonal. For fault column 0 the affected positions are <code>0, 13, 10, 7</code>; the other columns rotate that pattern. The inverse-S-box equations let the attacker test last-round key bytes against the MixColumns differential without knowing the injected byte value.</p></details>
<p><strong>Boundary:</strong> this is a chosen-location transient-fault model, not a claim that arbitrary real hardware faults land at this exact point. The attack is AES-128 only here. The recomputation check is a scoped temporal-redundancy example, not a universal fault defense; ineffective-fault leakage is a separate next lesson.</p>`
  );
}
