import { reducedAes, lambdaSet, classify, integralAttack, recoverIntegralKey } from '../integral';
import { hex, type Block } from '../aes/state';
import { table } from './common';

export function act10(key: Block, base: Block): string {
  if (key.length !== 16) throw Error('Choose AES-128 for this reduced-round exercise.');
  // Teaching trace remains separate from the oracle-only attack API.
  const traces = lambdaSet(base).map(p => { const trace: Block[] = []; reducedAes(p, key, trace); return trace; });
  const result = integralAttack(p => reducedAes(p, key), base);
  const unique = result.candidates.every(c => c.length === 1);
  let verification = 'Candidates remain ambiguous or empty; no key recovery asserted.';
  if (unique) {
    const recovered = recoverIntegralKey(Uint8Array.from(result.candidates, c => c[0]));
    // Held-out plaintexts are chosen only after filtering, outside all six training sets.
    const checks = [127, 128, 129].map(offset => { const p = base.slice(); p[15] = (base[15] + offset) & 255; p[0] ^= offset; return hex(reducedAes(p, recovered)) === hex(reducedAes(p, key)); });
    verification = `Candidate master key ${hex(recovered)}. Separate held-out checks: ${checks.filter(Boolean).length}/3 match. These three queries were not supplied to candidate filtering.`;
  }
  return '<h3>Observe a complete Lambda-set</h3><p>Vary byte 0 through all 256 values; hold every other byte constant. Constant means one value; active means every byte value exactly once; balanced means XOR zero without the stronger active property; unknown means none of these checks holds. Classification here describes this observed set.</p>' +
    table('Observed integral propagation', ['After round', ...Array.from({length: 16}, (_, i) => `Byte ${i}`)],
      [0, 1, 2, 3].map(round => [String(round), ...Array.from({length: 16}, (_, byte) => classify(traces.map(t => t[round][byte])))])) +
    '<p>After three rounds every byte XOR is zero. Guess each round-4 key byte, undo the final SubBytes and require zero XOR over the whole set. ShiftRows only relocates these bytewise conditions. Extra sets remove false candidates; a zero sum alone is not verification.</p>' +
    table('Round-4 key candidate counts', ['Sets', ...Array.from({length: 16}, (_, i) => `Byte ${i}`)], result.history.map((counts, i) => [String(i + 1), ...counts.map(String)])) +
    `<p id="integral-query-count">${result.queries} chosen-plaintext queries; ${result.history.length} disjoint sets of 256. Maximum budget: six sets.</p><p id="integral-verification">${verification}</p>` +
    '<p>This runs four reduced AES rounds with no MixColumns in round 4. It is not an attack on full AES-128 (10 rounds). The final-round shape permits direct byte guessing; adding final MixColumns would require an equivalent transformed round key.</p>' +
    '<p>Source: Joan Daemen and Vincent Rijmen, <cite>The Design of Rijndael: The Advanced Encryption Standard (AES)</cite>, second edition (2020), integral attack discussion, printed pp. 150–152 / supplied PDF pp. 170–172.</p>';
}
