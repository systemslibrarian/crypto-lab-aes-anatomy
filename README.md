# AES Anatomy

## What It Is

A ten-act, inspectable implementation of AES-128, AES-192 and AES-256. Build finite-field arithmetic and the S-box, trace every round and inverse, then remove one layer and run an oracle-only attack beside the same attack on full AES. Real AES is the default; broken variants are opt-in teaching experiments.

## Exhibits

1. **Bytes are polynomials:** XOR, xtime, polynomial multiplication and extended Euclid; zero has no multiplicative inverse.
2. **Build the S-box:** derive all 256 entries and inverse entries; compute exhaustive DDT, LAT and affine-identity checks.
3. **Move and mix:** inspect both column matrices, all 69 square minors, structural byte dependencies and separately observed differences.
4. **Expand the key:** all 44/52/60 words, intermediate word operations, AES-256’s extra SubWord, and a one-bit key-change prediction.
5. **The whole cipher:** every round’s intermediate states, the omitted final MixColumns, and independent browser WebCrypto checks.
6. **Reverse the cipher:** step the inverse, then deliberately use forward keys or the wrong column matrix and observe the mismatch.
7. **Remove a layer:** affine inversion from one known pair, known-column transplantation, or a 256-query byte codebook. All four attacks show 32 fresh held-out successes and 32 failing control rows for full AES.
8. **Inject a fault, recover the key:** inject a declared one-byte fault before AES-128 round-9 MixColumns, compare correct/faulty ciphertexts, filter last-round-key quartets with inverse-S-box differentials, recover round key 10 from eight well-located faulty ciphertexts, reverse the key schedule, and verify the master key on a held-out plaintext. A recomputation example catches a one-sided fault but explicitly shows its common-mode limit; a wrong fault-location model fails without a recovery claim.
9. **Keep only accepted outputs, recover a byte:** clear a declared bit immediately after first-round SubBytes, continue the existing real AES-128 implementation, and classify the correct and fault-path ciphertexts by equality. A reproducible noisy experiment ranks all 256 first-key-byte guesses over increasing sample budgets, while an analytic population check and a secret-independent bit-flip control isolate the selection bias. Executable reject and infective cases show both when output selection is visible and how an exact clean-reference oracle recreates it.

## When to Use It

Use this lab to understand what each AES layer contributes and to distinguish invertibility, diffusion and avalanche from security. Use the traces to check your own learning implementation. Do not use this JavaScript implementation to protect real data: it is neither constant-time nor a hardened cryptographic library.

## Live Demo

[Open AES Anatomy](https://systemslibrarian.github.io/crypto-lab-aes-anatomy/). Load the published FIPS keys or a reproducible seeded example. The shared state grid uses column-major indexing r + 4c. Changes retire derived state; cancelling or changing inputs terminates pending attack work.

## What Can Go Wrong

Wrong byte order, a missing AES-256 key-schedule operation, retaining MixColumns in the last round, using the wrong inverse, or assuming the wrong fault location can produce plausible-looking bytes. Independent published vectors and browser recomputation catch those errors. A singular linear map in an affine ablation is an implementation alarm, while failure to find a linear model for full AES is an expected control outcome.

The affine-only fixture has mean avalanche 61.5 bits, complete byte dependency computed from the keyed cipher’s 128 basis columns after two rounds, and a working keyed inverse. It is nevertheless broken by one known pair. Every displayed control row is computed and checked; a green-looking average is not a security argument. Partial byte codebooks retain unknown bytes as dots, and an absent splice column is refused.

## Real-World Usage

AES is specified by [FIPS 197-upd1 (2023)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf). In the absence of an application-profile standard specifying otherwise, [RFC 9846 §9.1](https://www.rfc-editor.org/rfc/rfc9846.html#section-9.1) requires a TLS-compliant application to support TLS_AES_128_GCM_SHA256; this is a support requirement, not a claim about measured HTTPS traffic. RFC 9846 obsoletes RFC 8446. Modes and authenticated encryption are separate from the block primitive taught here.

The DFA exercise follows the classic late-round AES fault equations described by Dusart, Letourneux & Vivolo, *Differential Fault Analysis on A.E.S.* (ePrint 2003/010): a one-byte fault before the penultimate-round MixColumns spreads to four bytes, and inverse-S-box relations constrain the last-round key. This browser model uses a known logical fault location and unknown nonzero fault value; it is not a physical fault-injection claim.

The accepted-output exercise distinguishes reliable ineffective fault analysis from statistical ineffective fault analysis. It clears one LSB-numbered bit of state byte 0 immediately after first-round SubBytes, continues real AES-128, and calls an execution unchanged only when the correct and fault-path ciphertexts are equal. The noisy model has a declared six-of-eight landing profile; misses and genuinely ineffective inductions are verifier-distinct but attacker-indistinguishable. Its finite-sample run draws plaintext bytes and landing events from the visible reproducible seed, while the separate 2,048-row census is labeled an analytic population check rather than sampled evidence. The ranker receives only selected plaintext bytes and the target bit, not the key, internal state, or per-attempt fault labels.

This mechanism follows [Clavier’s ineffective-fault analysis](https://doi.org/10.1007/978-3-540-74735-2_13) and Dobraunig et al., [*SIFA: Exploiting Ineffective Fault Inductions on Symmetric Cryptography*](https://eprint.iacr.org/2018/071). The protection boundary is informed by Daemen et al., [*Protecting against Statistical Ineffective Fault Attacks*](https://eprint.iacr.org/2019/536). Reject-on-detection visibly suppresses changed outputs. The bounded infective comparison returns a concretely transformed block on a detected mismatch: without a classifier, all attempts reach this selection-only ranker; with the correct clean ciphertext for the same plaintext, equality recovers the unchanged subset. That deterministic transform is not timing- or latency-oblivious, not a hardened countermeasure, and not an implementation of the 2020 paper’s circuit protections. The lesson recovers one AES-128 key byte in its declared model and makes no physical-injection, full multi-byte AES SIFA, timing, common-mode, or universal-defense claim.

Source data in `src/data/fips197.json` was transcribed from the standard’s S-box tables, all Appendix A expanded words, and Appendix B intermediate states. Appendix C vectors come from the superseded [FIPS 197 (2001)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf); the 2023 Appendix C instead points to online examples. No textbook figures, exercises or prose are reproduced.

## How to Run Locally

```bash
npm ci
npm run dev
```

## Related Demos

- [Clock Arithmetic](https://systemslibrarian.github.io/crypto-lab-clock-arithmetic/) — integer modular arithmetic beside polynomial arithmetic.
- [AES Modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) — build encryption schemes from a block cipher.
- [AEGIS Gate](https://systemslibrarian.github.io/crypto-lab-aegis-gate/) — one genuine AES round inside another construction.
- [Glass Box](https://systemslibrarian.github.io/crypto-lab-glass-box/) — white-box implementation attacks and key-schedule inversion.
- [Sleeve Check](https://systemslibrarian.github.io/crypto-lab-sleeve-check/) — the S-box’s construction choices.
- [Biham Lens](https://systemslibrarian.github.io/crypto-lab-biham-lens/) and [Matsui Line](https://systemslibrarian.github.io/crypto-lab-matsui-line/) — how differential and linear biases support attacks.
- [Power Trace](https://systemslibrarian.github.io/crypto-lab-power-trace/) and [Masked Core](https://systemslibrarian.github.io/crypto-lab-masked-core/) — implementation leakage and countermeasures.

## Build & Verify

```bash
npm test
npm run build
npx playwright install chromium
npx playwright test --retries=0
node scripts/check-mutations.mjs
node scripts/measure-performance.mjs
```

Unit cases check all FIPS words and intermediate states, 400 seeded WebCrypto comparisons, 200 AES-192 round trips, exhaustive finite-field facts, all 69 minors, 200 seeded ablation-property cases, oracle import/arity and victim-key independence boundaries, held-out ordering/transcript separation, a memorising-attack canary, independently reconstructed invertible controls, singular and partial-codebook refusals, DFA recovery, and the IFA/SIFA mechanisms. Tenteen browser claims independently recompute attack/control rows, fault witnesses and SIFA rankings, inspect all key words and both S-box tables (including fixed SHA-256 digests), verify every AddRoundKey XOR and field computation, and check verdict classes, score denominators, hidden panels and complete retirement. Two accessibility drives scan all ten acts and expanded results at desktop and 320px: axe A/AA and landmarks, measured visible/hidden text and nontext contrast, keyboard scrollers, focus and reflow. The nontext baseline is empty.

Forty-four scripted mutations cover the original cases, every test-honesty survivor, the DFA mechanism, and the SIFA ranker, real fault application, equality classifier, landing distribution, control, hidden-selection boundary and infection transform. Each must build into a different artifact, fail a named assertion with retries disabled, restore byte-for-byte, and pass its owning test again. `mutation-evidence.json` records executed results and named owning tests; [AUDIT_VERIFICATION.md](AUDIT_VERIFICATION.md) maps the added cases to their owners. The AES-256-only mutant also runs AES-128 controls to prove those paths still pass. GitHub Pages deployment depends on the complete unit/build/browser/mutation gate; grouped Dependabot changes use that same gate and explicitly dispatch deployment after merge.

## Performance

`performance-evidence.json` measures the same production modules compiled by Vite as a minified browser bundle. On Chromium 153, DDT/LAT/MDS/linear-order checks took at most 7.5 ms unthrottled and 36.9 ms with a 4× CPU slowdown. They remain on the main thread. Attack, verification and result preparation took up to 34.8 ms unthrottled and 180.5 ms under that slowdown, so the shared attack harness runs in a cancellable Worker. The slowdown is a simulation, not a physical-phone benchmark. Matrix rows are prepared once; wide matrices and traces are labelled keyboard-scrollable regions.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*

## Wide trails and reduced-round integrals

Act 3 checks ShiftRows column dispersion alongside all 69 MixColumns minors. It connects those hypotheses to the four-round, 25-active-S-box theorem, shows an observed trace separately, and makes the identity-permutation counterexample visible. Differential-trail probability and linear-trail correlation bounds are not differential/hull or full-cipher security bounds.

Act 10 runs a four-round AES-128 reduction: three ordinary rounds and a final round without MixColumns. An oracle-only attacker filters all 256 key-byte candidates using complete, disjoint Lambda-sets (up to six), reverses the round-4 schedule only when every byte is unique, and checks three separate held-out plaintexts afterward. It exposes ambiguous results rather than claiming unconditional recovery.

Source: Joan Daemen and Vincent Rijmen, *The Design of Rijndael: The Advanced Encryption Standard (AES)*, second edition, 2020. Theorem 9.5.1: printed pp. 140–143 / supplied PDF pp. 160–163. Integral attack: printed pp. 150–152 / supplied PDF pp. 170–172.
