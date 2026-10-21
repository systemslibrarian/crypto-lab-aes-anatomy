import { runBreak } from "../harness";
import { avalanche, affineByteDependencies, largerKeyAvalanche } from "../diagnostics";
import { VARIANTS, cipher } from "../aes/cipher";
import { expand } from "../aes/keyExpansion";
import { linearOrder, shiftRows, mixColumns, xor, hex, equal, type Block } from "../aes/state";
import { pack, apply } from "../linalg/gf2";
import { table, check } from "./common";
type Result = Awaited<ReturnType<typeof runBreak>>;
function bitRows(columns: bigint[]) {
  return Array.from({ length: 128 }, (_, r) =>
    columns
      .map((c) => String(Number((c >> BigInt(r)) & 1n)))
      .join("")
      .match(/.{8}/g)!
      .join(" "),
  );
}
export function act7(result: Result, variant: string, key: Block, plaintext: Block) {
  const { broken, control } = result,
    stats = avalanche(key, plaintext, VARIANTS[variant]);
  let html = `<p id="attack-query-count">Attack-phase victim-oracle queries: <strong>${broken.queries}</strong>. Held-out generation and verification queries are excluded. Control attack queries: ${control.queries}.</p>`;
  if (variant === "noSub" || variant === "affine") {
    const larger = largerKeyAvalanche(plaintext, VARIANTS[variant]),
      order = linearOrder(),
      zero = new Uint8Array(16),
      w = expand(key).roundKeys,
      linear = xor(cipher(plaintext, w, VARIANTS.noSub), cipher(zero, w, VARIANTS.noSub)),
      collapsed = shiftRows(mixColumns(shiftRows(plaintext)));
    html += `<p>Build L using an attacker-chosen key, then obtain c = C ⊕ L(P) from one known pair. Decrypt C′ as L⁻¹(C′ ⊕ c).</p><p>128 × 128 GF(2) elimination: rank ${broken.rank}, ${broken.operations} row XORs.</p>`;
    if (broken.columns && broken.inverse) {
      const inverse = broken.inverse,
        columns = broken.columns,
        inverseRows = bitRows(inverse);
      html +=
        check(
          "matrix-inverse",
          columns.every((c, i) => apply(inverse, c) === 1n << BigInt(i)),
          "Computed L⁻¹ · L is identity on all 128 basis vectors.",
        ) +
        `<details><summary>Inspect the 128 × 128 matrix and its computed inverse</summary>${table(
          "Linear map and inverse, bits grouped by byte",
          ["Row", "L row: 128 bits", "L inverse row: 128 bits"],
          bitRows(columns).map((x, i) => [String(i), x, inverseRows[i]]),
        )}</details>`;
    }
    if (variant === "noSub")
      html +=
        check(
          "linear-order",
          order.length === 8 && order[7].identity && order.slice(0, 7).every((x) => !x.identity),
          `(MC∘SR) powers: ${order.map((x) => x.power + ": " + (x.identity ? "identity" : "not identity")).join("; ")}. Every power is checked on all 128 basis vectors.`,
        ) +
        check(
          "collapse",
          equal(linear, collapsed),
          `SR∘(MC∘SR)⁹(P) = SR∘MC∘SR(P) = ${hex(collapsed)}.`,
        );
    html += `<p>Mean avalanche ${stats.mean.toFixed(2)} bits; range ${stats.min}…${stats.max} over all 128 input-bit flips.</p><details><summary>All avalanche counts and bit-level dependencies</summary><p>${stats.counts.join(", ")}</p><p>Each output bit depends on ${Math.min(...stats.outputDependencies)}…${Math.max(...stats.outputDependencies)} input bits for this affine map. A given bit flips with probability exactly zero or one; the strict avalanche criterion fails even if the mean looks good.</p><p>${variant === "affine" ? "7b affine-only" : "7a no SubBytes"}, seeded keys (0x197197) with this same plaintext: ${larger.map((x) => `AES-${x.size} mean ${x.mean.toFixed(1)} bits (${x.min}–${x.max})`).join("; ")}. This attack exhibit runs only AES-128. The real S-box remains in every key schedule.</p></details>`;
  }
  if (variant === "affine") {
    html +=
      '<div id="affine-fixture-checks">' +
      check(
        "mean-avalanche",
        Math.abs(stats.mean - 64) <= 8,
        `Mean avalanche ${stats.mean} is within 64 ± 8.`,
      ) +
      check(
        "byte-dependencies",
        affineByteDependencies(key, 2).every((x) => x.length === 16),
        "All 256 input/output byte pairs depend after round 2 of the keyed affine-only cipher (computed from 128 basis columns).",
      ) +
      check(
        "keyed-roundtrip",
        stats.roundTrip,
        "The keyed inverse recovers the original plaintext.",
      ) +
      '</div><p class="alarm" id="affine-negative">FULL AVALANCHE (MEAN) — AND BROKEN BY ONE KNOWN PAIR. A good-looking avalanche is not security. This affine-only AES — where every output byte depends on every input byte and about half the output bits flip per input-bit flip on average — is still broken by one known plaintext.</p>';
  }
  if (variant === "noShift")
    html +=
      "<p>Four independent 32-bit column ciphers permit cut-and-paste from at least three known pairs. Each fresh target below uses at least two source pairs and equals none of the known plaintexts. This is a transplant attack, not an infeasible 2³²-entry codebook for every column.</p>";
  if (variant === "noMix")
    html +=
      "<p>Sixteen independent byte permutations remain. At AES-128, ten ShiftRows steps move rows 1 and 3 two columns over. The same occurs after fourteen rounds at AES-256; twelve rounds at AES-192 return every position. Uniform chosen plaintexts build the per-input-position codebooks.</p>";
  if (broken.known.length)
    html += table(
      "Attack known pairs",
      ["Plaintext", "Ciphertext"],
      broken.known.map((p) => [hex(p.plaintext), hex(p.ciphertext)]),
      "known-pairs",
    );
  if (variant === "noShift")
    html +=
      '<label>Try a target block (32 hex characters)<input id="splice-target" value="00000000000000000000000000000000" title="Every four-byte column must occur in a known pair at the same position."></label><button id="try-splice">Try splice target</button><p id="splice-result" role="status" aria-live="polite"></p>';
  const matrixBroken = broken.singular?.kind === "implementation-error";
  const attackSummary = matrixBroken
    ? "⚠ " + broken.singular!.message
    : broken.partial
      ? "ⓘ Partial codebook: missing bytes remain unknown."
      : "⚠ " + (broken.successes === 32 ? "BROKEN" : "Incomplete break");
  html += `<p id="attack-verdict" data-verdict="${matrixBroken ? "implementation-error" : broken.partial ? "partial" : broken.successes === 32 ? "broken" : "incomplete"}" class="${matrixBroken || broken.successes === 32 ? "alarm" : "info"}">${attackSummary} — ${broken.successes}/${broken.rows.length} held-out items without the key</p>`;
  const rows = (r: Result["broken"], prefix: string) =>
    table(
      `${prefix} held-out verification`,
      [
        "#",
        "Held-out plaintext",
        "Ciphertext",
        "Attack candidate " + (variant === "noShift" ? "ciphertext" : "plaintext"),
        "Candidate encryption / forgery",
        "Result",
      ],
      r.rows.map((x, i) => [
        String(i + 1),
        `<code data-plain="${hex(x.plaintext)}">${hex(x.plaintext)}</code>`,
        `<code data-cipher="${hex(x.ciphertext)}">${hex(x.ciphertext)}</code>`,
        `<code data-candidate="${hex(x.candidate!)}">${r.partial && x.partial ? x.partial.map((b) => (b === null ? "·" : b.toString(16).padStart(2, "0"))).join(" ") : hex(x.candidate!)}</code>`,
        hex(x.candidateCiphertext!),
        `<span data-match="${x.matches}">${x.matches ? "matches" : "fails"}</span>${r.partial && x.partial ? "; " + x.partial.filter((b) => b === null).length + " unknown bytes" : ""}`,
      ]),
      prefix + "-rows",
    );
  html +=
    rows(broken, "broken") +
    `<p id="control-verdict" data-verdict="${control.successes === 0 ? "control-fails" : "control-success"}" class="${control.successes === 0 ? "ok" : "alarm"}">${control.successes === 0 ? "✓ ATTACK FAILS ON REAL AES" : "⚠ Control unexpectedly succeeded"} — ${control.successes}/${control.rows.length}. ${control.singular ? "No linear model exists; zero plaintext candidates are shown below and independently fail verification." : ""}</p>` +
    rows(control, "control") +
    "<p>None of these is an attack on AES. They show why AES has each layer. Reduced-round and related-key cryptanalysis is outside this lab. AddRoundKey has no ablation: without the key there is no cipher to break.</p>";
  return html;
}
export function fixtureFingerprint(key: Block) {
  return pack(key).toString(16);
}
