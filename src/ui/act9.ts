import { type Block } from "../aes/state";
import { collectSifaSamples, type SifaFaultModel } from "../sifa-fixture";
import { rankOf, rankSifaKeyByte } from "../attack/sifa";
import { check, table } from "./common";

type Defense = "reject" | "infect-with-validity";

export function act9(
  key: Block,
  targetBit: number,
  faultModel: SifaFaultModel,
  defense: Defense,
): string {
  if (key.length !== 16)
    return '<p class="alarm" data-verdict="wrong-key-size">⚠ Accepted-output fault analysis in this exhibit is AES-128 only. Select a 128-bit key.</p>';

  const actual = key[0]!;
  const collection = collectSifaSamples(actual, targetBit, faultModel, defense);
  const ranking = rankSifaKeyByte(collection.acceptedPlaintextBytes, targetBit);
  const actualRank = rankOf(ranking, actual);
  const top = ranking[0]!;
  const allZero = ranking.every((candidate) => candidate.sei === 0);
  const uniqueTop = ranking.length > 1 && top.sei > ranking[1]!.sei;
  const recovered = faultModel === "biased-ineffective" && uniqueTop && top.keyByte === actual;

  const topRows = ranking.slice(0, 8).map((candidate, i) => [
    String(i + 1),
    candidate.keyByte.toString(16).padStart(2, "0"),
    String(candidate.zeros),
    String(candidate.ones),
    candidate.sei.toFixed(6),
    candidate.keyByte === actual ? "actual byte" : "",
  ]);

  const defenseText =
    defense === "reject"
      ? `The detector returned only ${collection.accepted} of ${collection.attempts} executions. The attacker ranks the plaintext bytes belonging to those accepted outputs; no faulty ciphertext value is used by the ranker.`
      : `The infective mode returned all ${collection.outputsReturned} outputs, but this scoped experiment gives the attacker an external validity oracle that identifies the same ${collection.externallyValid} unchanged executions. Under that explicit oracle, infection alone does not remove the selection channel.`;

  const verdict =
    faultModel === "biased-ineffective"
      ? check(
          "sifa-biased",
          recovered,
          recovered
            ? `The biased ineffective-fault selection uniquely ranks key byte ${actual.toString(16).padStart(2, "0")} first. This recovers one AES-128 master-key byte in this bounded model, not the whole key.`
            : "The biased model did not uniquely rank the actual key byte; no recovery is asserted.",
        )
      : check(
          "sifa-control",
          allZero,
          allZero
            ? `Secret-independent acceptance keeps the same ${collection.accepted} samples but every candidate has zero imbalance. There is no key ranking to claim.`
            : "The secret-independent control unexpectedly produced a candidate imbalance; the control failed.",
        );

  return (
    `<p><strong>Accepted-output model.</strong> The targeted intermediate is bit ${targetBit} of <code>SBOX[P₀ XOR K₀]</code>, using AES\'s real S-box. For every possible first plaintext byte, the fixture runs eight attempts. The attacker receives only the plaintext bytes whose outputs were classified as unchanged, plus the selected bit index.</p>` +
    `<p>Actual first key byte for verifier only: <code id="sifa-actual">${actual.toString(16).padStart(2, "0")}</code>. The ranking function is not passed this byte.</p>` +
    `<p>Fault model: <strong id="sifa-model">${faultModel}</strong>; defense: <strong id="sifa-defense">${defense}</strong>.</p>` +
    `<p>Attempts <strong id="sifa-attempts">${collection.attempts}</strong>; accepted/externally valid <strong id="sifa-accepted">${collection.accepted}</strong>; rejected <strong id="sifa-rejected">${collection.rejected}</strong>; outputs returned <strong id="sifa-returned">${collection.outputsReturned}</strong>.</p>` +
    defenseText +
    table(
      "Top accepted-output key-byte candidates",
      ["Rank", "K₀ guess", "predicted bit 0", "predicted bit 1", "SEI", "Verifier note"],
      topRows,
      "sifa-ranking",
    ) +
    `<p>Actual key-byte rank: <strong id="sifa-actual-rank">${actualRank}</strong>; top-candidate SEI: <strong id="sifa-top-sei">${top.sei.toFixed(6)}</strong>.</p>` +
    verdict +
    check(
      "sifa-same-count",
      collection.accepted === 1280,
      collection.accepted === 1280
        ? "This model retains exactly 1,280 of 2,048 attempts. The secret-independent control is constructed to retain the same number, so sample count alone is not the signal."
        : "The fixture did not produce its declared sample count.",
    ) +
    `<details><summary>Why the bias ranks a key guess</summary><p>For each candidate byte k, the learner recomputes the selected bit of <code>SBOX[P₀ XOR k]</code> for every accepted plaintext. The score is squared Euclidean imbalance from a 50/50 bit distribution. In the biased model, ineffective faults select executions according to the true intermediate bit, so the correct key guess makes that selection visible. In the secret-independent control, acceptance is uniform over P₀ and every candidate remains exactly balanced.</p></details>` +
    `<p><strong>Boundary.</strong> This is a profiled, chosen-input, one-byte mechanism demonstration with an exact eight-trial teaching distribution. It is not a physical fault-injection measurement or a reproduction of a full multi-byte AES SIFA. Reject-on-detection and infection are not universal defenses: the guarantee depends on whether the accept/validity decision itself is independent of secret-dependent intermediate state.</p>` +
    `<p class="scope">Sources: Dobraunig et al., <em>SIFA: Exploiting Ineffective Fault Inductions on Symmetric Cryptography</em> (ePrint 2018/071), and Dobraunig et al., <em>Protecting against Statistical Ineffective Fault Attacks</em> (ePrint 2019/536).</p>`
  );
}
