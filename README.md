# AES Anatomy

## What It Is

A seven-act, inspectable implementation of AES-128, AES-192 and AES-256. Build finite-field arithmetic and the S-box, trace every round and inverse, then remove one layer and run an oracle-only attack beside the same attack on full AES. Real AES is the default; broken variants are opt-in teaching experiments.

## Exhibits

1. **Bytes are polynomials:** XOR, xtime, polynomial multiplication and extended Euclid; zero has no multiplicative inverse.
2. **Build the S-box:** derive all 256 entries and inverse entries; compute exhaustive DDT, LAT and affine-identity checks.
3. **Move and mix:** inspect both column matrices, all 69 square minors, structural byte dependencies and separately observed differences.
4. **Expand the key:** all 44/52/60 words, intermediate word operations, AES-256’s extra SubWord, and a one-bit key-change prediction.
5. **The whole cipher:** every round’s intermediate states, the omitted final MixColumns, and independent browser WebCrypto checks.
6. **Reverse the cipher:** step the inverse, then deliberately use forward keys or the wrong column matrix and observe the mismatch.
7. **Remove a layer:** affine inversion from one known pair, known-column transplantation, or a 256-query byte codebook. All four attacks show 32 fresh held-out successes and 32 failing control rows for full AES.

## When to Use It

Use this lab to understand what each AES layer contributes and to distinguish invertibility, diffusion and avalanche from security. Use the traces to check your own learning implementation. Do not use this JavaScript implementation to protect real data: it is neither constant-time nor a hardened cryptographic library.

## Live Demo

[Open AES Anatomy](https://systemslibrarian.github.io/crypto-lab-aes-anatomy/). Load the published FIPS keys or a reproducible seeded example. The shared state grid uses column-major indexing r + 4c. Changes retire derived state; cancelling or changing inputs terminates pending attack work.

## What Can Go Wrong

Wrong byte order, a missing AES-256 key-schedule operation, retaining MixColumns in the last round, or using the wrong inverse can produce plausible-looking bytes. Independent published vectors and browser recomputation catch those errors. A singular linear map in an affine ablation is an implementation alarm, while failure to find a linear model for full AES is an expected control outcome.

The affine-only fixture has mean avalanche 61.5 bits, complete structural byte dependency after two rounds, and a working keyed inverse. It is nevertheless broken by one known pair. Every displayed control row is computed and checked; a green-looking average is not a security argument. Partial byte codebooks retain unknown bytes as dots, and an absent splice column is refused.

## Real-World Usage

AES is specified by [FIPS 197-upd1 (2023)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf). [RFC 8446 §9.1](https://www.rfc-editor.org/rfc/rfc8446.html#section-9.1) requires TLS 1.3 implementations to support TLS_AES_128_GCM_SHA256; this is a support requirement, not a claim about measured HTTPS traffic. Modes and authenticated encryption are separate from the block primitive taught here.

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
npm run test:e2e
npm run test:mutations
node scripts/measure-performance.mjs
```

Twenty-five unit cases check all FIPS words and intermediate states, 400 seeded WebCrypto comparisons, 200 AES-192 round trips, exhaustive finite-field facts, all 69 minors, 200 seeded ablation-property cases, oracle capability boundaries, held-out ordering, singular and partial-codebook refusals, and the negative fixture. Twelve browser claims independently recompute all attack/control rows inside `page.evaluate`, inspect all key words and both S-box tables, and verify every AddRoundKey XOR. Two accessibility drives scan all seven acts and expanded results at desktop and 320px: axe A/AA and landmarks, measured visible/hidden text and nontext contrast, keyboard scrollers, focus and reflow. The nontext baseline is empty.

Twenty scripted mutations cover the nineteen requested defects plus a broken avalanche computation. Each must build into a different artifact, fail a named assertion with retries disabled, restore byte-for-byte, and pass its owning test again. `mutation-evidence.json` records the executed results. The AES-256-only mutant also runs AES-128 controls to prove those paths still pass. GitHub Pages deployment depends on the complete unit/build/browser gate; grouped Dependabot changes use that same gate and explicitly dispatch deployment after merge.

## Performance

`performance-evidence.json` measures the same production modules compiled by Vite as a minified browser bundle. On Chromium 153, DDT/LAT/MDS/linear-order checks took at most 7.5 ms unthrottled and 36.9 ms with a 4× CPU slowdown. They remain on the main thread. Attack, verification and result preparation took up to 34.8 ms unthrottled and 180.5 ms under that slowdown, so the shared attack harness runs in a cancellable Worker. The slowdown is a simulation, not a physical-phone benchmark. Matrix rows are prepared once; wide matrices and traces are labelled keyboard-scrollable regions.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
