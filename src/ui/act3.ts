import { columnDispersion, dispersesColumns } from '../wide-trail';
import {
  MC,
  IMC,
  matrixProduct,
  mdsMinors,
  dependencies,
  xor,
  type Block,
  hex,
} from "../aes/state";
import { cipher, type Round } from "../aes/cipher";
import { expand } from "../aes/keyExpansion";
import { table, check } from "./common";
export function act3(key: Block, plaintext: Block) {
  const product = matrixProduct(MC, IMC),
    minors = mdsMinors(),
    a: Round[] = [],
    b: Round[] = [],
    changed = plaintext.slice();
  changed[0] ^= 1;
  cipher(plaintext, expand(key).roundKeys, undefined, a);
  cipher(changed, expand(key).roundKeys, undefined, b);
  let html =
    table(
      "MixColumns matrix",
      ["row", "c0", "c1", "c2", "c3"],
      MC.map((r, i) => [String(i), ...r.map((x) => x.toString(16).padStart(2, "0"))]),
    ) +
    table(
      "InvMixColumns matrix",
      ["row", "c0", "c1", "c2", "c3"],
      IMC.map((r, i) => [String(i), ...r.map((x) => x.toString(16).padStart(2, "0"))]),
    ) +
    table(
      "Computed matrix product",
      ["row", "c0", "c1", "c2", "c3"],
      product.map((r, i) => [String(i), ...r.map(String)]),
    ) +
    check(
      "matrix-product",
      product.every((row, r) => row.every((x, c) => x === (r === c ? 1 : 0))),
      "MC · IMC = identity.",
    ) +
    check(
      "mds",
      minors.nonzero === 69 && minors.total === 69,
      `${minors.nonzero}/${minors.total} square minors are nonsingular: 16 + 36 + 16 + 1. This gives branch number 5.`,
    ) +
    `<details><summary>Inspect all 69 determinants</summary>${table(
      "Every MixColumns square minor",
      ["Size", "Rows", "Columns", "Determinant"],
      minors.rows.map((x) => [
        String(x.size),
        x.rows.join(","),
        x.columns.join(","),
        x.det.toString(16),
      ]),
    )}</details><p>Legend: ◆ means structural dependency; ● means an observed changed byte; ○ means an observed unchanged byte. An unchanged observation does not remove a dependency.</p>`;
  for (const round of [1, 2]) {
    const d = dependencies(round),
      difference = xor(a[round].output, b[round].output);
    html += `<h3>Round ${round}</h3>${check(
      "dependencies-" + round,
      d.every((x) => x.length === (round === 1 ? 4 : 16)),
      `Structural dependency count per byte: ${d.map((x) => x.length).join(", ")}.`,
    )}${table(
      `Round ${round} structural dependencies and observed differences`,
      ["Byte index", "◆ Depends on input bytes", "Observed difference"],
      d.map((x, i) => [
        String(i),
        "◆ " + x.join(","),
        `${difference[i] ? "●" : "○"} ${hex(difference.slice(i, i + 1))}`,
      ]),
    )}`;
  }
  html += '<h3>From local branch number to four-round trails</h3>' +
    table('Executable ShiftRows column dispersion', ['Input column', 'Destination columns: ShiftRows', 'Identity permutation'],
      columnDispersion().map((destinations, column) => [String(column), destinations.join(', '), columnDispersion(true)[column].join(', ')])) +
    check('wide-trail-dispersion', dispersesColumns(), 'Every input column sends one byte to each output column.') +
    check('weakened-dispersion', !dispersesColumns(true), 'The weakened identity permutation fails the dispersion hypothesis.') +
    '<p>MixColumns branch number 5 plus this column dispersion are hypotheses of the four-round wide-trail argument: at least 25 active S-boxes in any nonzero four-round differential or linear trail. The theorem supplies the bound; this program checks these structural hypotheses, not all trails.</p>' +
    table('Observed four-round differential trail', ['Round', 'Observed active S-box inputs'],
      [1, 2, 3, 4].map(round => [String(round), String(xor(a[round].input, b[round].input).filter(x => x !== 0).length)])) +
    '<p>This trace is one fixed-key observation, not a proof. With AES maximum S-box differential probability 2<sup>−6</sup> and maximum absolute linear correlation 2<sup>−3</sup>, the usual trail model gives 2<sup>−150</sup> for a four-round differential trail and 2<sup>−75</sup> for absolute linear-trail correlation. A differential or linear hull combines trails; these are not whole-cipher security bounds.</p>' +
    '<p>Source: Joan Daemen and Vincent Rijmen, <cite>The Design of Rijndael: The Advanced Encryption Standard (AES)</cite>, second edition (2020), Theorem 9.5.1 and surrounding proof, printed pp. 140–143 / supplied PDF pp. 160–163.</p>';
  return (
    html +
    '<p><a href="https://systemslibrarian.github.io/crypto-lab-aegis-gate/">AEGIS Gate</a> already steps a genuine AES round inside another construction.</p>'
  );
}
