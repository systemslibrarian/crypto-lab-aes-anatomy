# Build brief — `crypto-lab-aes-anatomy`

**2026-10-21. Brief only; no repository exists yet.** Written against
`audits/_MASTER-TEMPLATE.md` and `audits/kickoff.md` at catalog `88f75e7edc6f`. Paste this
file into the new repo as `./brief.md`.

Source of the gap:

- Paar & Pelzl, *Understanding Cryptography*, ch. 4 (AES). In the 1st ed. (2010), §§4.3–4.5
  were checked against the book's text.
- The chapter number is the same in the 2nd ed. (Paar, Pelzl, Güneysu, 2024), per the chapter
  map on catalog branch `draft/understanding-cryptography-2e`.
- That branch's gap check ranks this lab #1.

**Verdict: new repository.**

```
NEW DEMO BRIEF
- Repo name:         crypto-lab-aes-anatomy
- Short name (H1):   AES Anatomy
- Subtitle:          FIPS 197 · GF(2⁸) · Key Expansion · Inverse Cipher
- One-liner:         Builds AES-128/192/256 up from GF(2⁸) byte arithmetic — S-box,
                     ShiftRows, MixColumns, key expansion, the cipher and its inverse —
                     then removes one layer at a time and breaks what is left.
- Concept to teach:  AES is four simple layers repeated, and the three keyless ones are each
                     load-bearing. Take out the S-box's inversion, ShiftRows or MixColumns,
                     and an attack you can run in the page decrypts or forges without ever
                     learning the key.
- Primitives/spec:   FIPS 197-upd1 (May 2023) §§3–5, Tables 4 and 6, Appendices A and B;
                     FIPS 197 (2001) Appendix C.1–C.3; WebCrypto AES-CBC as an independent
                     single-block cross-check (128/256 only)
- Accent (--accent): #4cc9f0  (lab identity colour; the CARD accent is picked from the
                     CLAUDE.md four-colour rotation when the lab is carded)
- Favicon emoji:     U+1F9F1 BRICK
- In scope:          GF(2⁸) addition, xtime, multiplication and inversion; S-box and inverse
                     S-box built from field arithmetic; ShiftRows and MixColumns with an
                     exhaustive MDS check; KeyExpansion for Nk = 4, 6, 8; Cipher with a full
                     round trace; InvCipher; four data-path ablations, each with a live break —
                     no SubBytes, affine-only S-box, no ShiftRows, no MixColumns
- Non-goals:         modes of operation (AES Modes); side channels, T-tables and masking
                     (Power Trace, Masked Core, Timing Oracle); white-box (Glass Box);
                     cryptanalysis of reduced-round REAL AES (square/integral, impossible
                     differential, biclique, related-key); where the S-box came from
                     (Sleeve Check); AES-NI, bitslicing and performance; EqInvCipher beyond
                     one disclosure
```

Supplementary fields, as in the catalog's `audits/BRIEF-*.md` files, are PROVISIONAL per
kickoff, and the catalog pass decides them:

- **Category:** `ENCRYPTION`.
- **Level:** Intermediate.

Give every non-goal its one-line "what this isn't" note in the UI (template §1 SCOPE).

## Overlap check — what I read, and what I found

Read at the commits shown. Repeat this from source before building (kickoff: "FIRST, THE
OVERLAP CHECK").

- **AEGIS Gate** `96c9e52`. `src/aes-round-vis.ts` traces **one genuine AES round**
  (SubBytes, ShiftRows, MixColumns, XOR) as AEGIS's state update. It has no key expansion, no
  last round and no inverse.
- **Glass Box** `5c9781f`:
  - a full AES-128 reference (`src/aes/aes-ref.ts`, with the FIPS 197 C.1 KAT);
  - `src/aes/gf.ts`, which builds the S-box from inverse + affine and exports `INV_SBOX`;
  - a 128×128-capable GF(2) `invertMatrix` in `src/math/gf2.ts`;
  - a live `invertKeySchedule` at `src/lab.worker.ts:346`;
  - a diagram of one column of round 1.

  All of it sits in white-box context.
- **Masked Core** `6196c04`: a hand-rolled AES-128 whose tests step the Appendix B round-1
  trace, plus an S-box derivation (`src/aes/aes.ts:79`). It teaches masking.
- **Power Trace** `9fd17c9`: a JS AES with an S-box derivation (`src/aes/aes.ts:4`), used for
  CPA.
- **Sleeve Check** `0ddd088`: the AES S-box from inversion and the affine map, as the control
  for GOST's π.
- **AES Modes** `882ed58`: modes over WebCrypto and `@noble/ciphers`.
- I grepped those repos, plus kerberos, rsa-educational, prime-witness, log-forge,
  iron-serpent and ec-point-arithmetic, for
  `invMixColumns|InvSubBytes|InvShiftRows|inverseCipher`. An independent reviewer widened the
  grep. **Neither found a stepped InvCipher or a stepped key expansion.** Key expansion exists
  as internal code, and Glass Box inverts it in a Worker, but no lab makes it a surface the
  learner steps through.

**Correction carried into this brief.** An earlier gap note said no lab steps an AES round.
That is false: AEGIS Gate does, for one round. The gap is the **sequence** — field
arithmetic, S-box construction, MixColumns, key expansion, the last round, and decryption.
Link AEGIS Gate, and link Glass Box's `invertKeySchedule` from act 4. Don't restate either.

## SCOPE — seven acts

This is progressive disclosure: acts 1–6 are the learner route, and act 7 is the payoff. Every
number on screen is computed live.

1. **Bytes are polynomials (GF(2⁸)).**
   - **Plain intro first.** A byte is eight coefficients. Adding is XOR. Multiplying wraps
     around m(x) = x⁸ + x⁴ + x³ + x + 1 (FIPS 197-upd1 §4.2, Eq. 4.3).
   - **Predict, then reveal:** "Will multiplying this byte by {02} need a reduction?" It does
     exactly when the top bit is set.
   - **Multiply through the xtime chain** (upd1 Eqs. 4.6–4.7, {57}·{13} = {fe}).
   - **Find an inverse** by extended Euclid over GF(2)[x] modulo m(x), one row per step, and
     check a·a⁻¹ = {01}. {00} has no inverse: upd1 §4.4 defines inverses only for b ≠ {00},
     and §5.1.1 (Eq. 5.2) maps {00} to {00} before the affine step.
2. **The S-box is built, not memorised.**
   - Compute all 256 entries as affine(inverse(x)), and compare each cell with upd1 Table 4.
     Do the same for InvSbox against Table 6.
   - Prove two facts exhaustively on the spot:
     - the max DDT entry over **non-zero input differences** is **4**;
     - the max |LAT − 128| over **non-zero masks** is **16**.
   - **Break it.** Remove the inversion and keep only the affine step. The page proves the box
     is now affine: S(x⊕y) ⊕ S(x) ⊕ S(y) ⊕ S(0) = 0 for all 65,536 pairs. The real box fails
     that test. This sets up act 7b.
   - Link Sleeve Check for *why this field and this affine map*.
3. **ShiftRows moves, MixColumns mixes.**
   - Draw the 4×4 state grid with the byte index **r + 4c** on it (upd1 §3.4). The
     column-major index is the most common implementation bug, so show it rather than assume
     it.
   - Show MixColumns as the matrix [02 03 01 01 / …] over GF(2⁸) and InvMixColumns as
     [0e 0b 0d 09 / …], and compute their product to the identity.
   - **MDS, exhaustively.** All **69** square submatrices of the MixColumns matrix
     (16 + 36 + 16 + 1) are non-singular. That is what gives branch number 5.
   - **Dependency map.** Structurally, each byte after round 1 depends on exactly **4** input
     bytes, and after round 2 on all **16**. Beside it, draw one real run's observed
     difference, labelled as an observation: a byte can come out unchanged by chance. The
     dependency map is the claim; the run is the illustration.
4. **Key expansion.**
   - Step the words w[i] through RotWord, SubWord and Rcon for Nk = 4, 6 and 8, showing the
     Nk = 8 extra SubWord at i mod 8 = 4.
   - Check every word against upd1 Appendix A.1–A.3.
   - **Predict, then reveal:** "Change one key byte. Which round-key words change, and from
     which round on?" Highlight them.
   - Link Glass Box's `invertKeySchedule` for the reverse direction.
5. **The whole cipher.**
   - Show the Appendix B trace, round by round and layer by layer. Make the **last round's
     missing MixColumns** a visible gap in the row, not a footnote.
   - Then encrypt a random key and plaintext and check it against WebCrypto, computed live
     (128/256).
6. **Decryption.**
   - InvCipher (upd1 §5.3): InvShiftRows, InvSubBytes, AddRoundKey with the round keys in
     **reverse** order, and InvMixColumns.
   - **Break it.** Decrypt with the round keys in forward order, or with MixColumns in place of
     InvMixColumns, and show the mismatch against the original plaintext.
   - EqInvCipher (upd1 §5.3.5) gets one disclosure only.
7. **Take a layer out, and break what is left.** This is the headline. There are four mutually
   exclusive ablations. Each runs a real attack, and **the same attack code also runs against
   full AES as the control** (see INVARIANTS). **Act 7 runs at AES-128.** The numbers below
   are AES-128's; other key sizes behave differently, as noted.
   - **7a. No SubBytes.** The cipher becomes affine: E(P) = L(P) ⊕ E(0), with L independent of
     the key.
     - **Ten rounds collapse.** (MC∘SR)⁸ is the identity, checked live on all 128 bit-basis
       vectors, and no smaller power is. So AES-128's linear part is
       SR∘(MC∘SR)⁹ = SR∘MC∘SR; show that equality on a random state. As a consequence,
       avalanche is poor: about 6 of 128 bits flip per input-bit flip.
     - **Attack.** The attacker builds L with **a key of their own choosing** and makes **one**
       victim query for a known pair (P, C). They compute c = C ⊕ L(P), then decrypt fresh
       victim ciphertexts with L⁻¹, a 128×128 GF(2) matrix inverted on screen.
   - **7b. Affine-only S-box** (inversion removed, affine step kept). This is the §4.1d
     fixture.
     - The avalanche meter passes. One-bit plaintext flips change on average **61.5** of 128
       output bits (minimum 57, maximum 71) at AES-128. These are brief-time values. They are
       exact, and independent of key and plaintext, because the cipher is affine.
     - Every output **byte** depends on every input byte after round 2.
     - The 7a attack still decrypts everything from one known pair.
     - **Expert disclosure:** at the bit level each output bit depends on only 51–73 of the 128
       input bits, and flips with probability exactly 0 or 1. The strict avalanche criterion
       fails outright; only the *mean* looks right.
     - Contrast with 7a. **The inversion, not the affine step, is the nonlinear part.**
   - **7c. No ShiftRows.** The cipher becomes four independent 32-bit column ciphers. Change one
     plaintext column and exactly that ciphertext column changes, and no other.
     - **Transplant.** From h ≥ 3 known pairs, splice columns to produce a valid ciphertext for
       any spliced plaintext, without the key.
     - The held-out check is **32 splice targets the verifier chooses after the attack**. Each
       target draws its columns from **at least two distinct known pairs** and is **not equal
       to any known plaintext**. Each forged ciphertext is confirmed with the victim oracle.
     - Be honest that a full per-column codebook (2³² entries per column) is out of browser
       reach. The break is cut-and-paste, not a codebook.
   - **7d. No MixColumns.** The cipher becomes sixteen independent byte ciphers with a fixed
     position map.
     - For AES-128 and AES-256, rows 1 and 3 land two columns over, because SR¹⁰ = SR¹⁴ = SR².
       For AES-192 every byte stays put, because SR¹² = id.
     - The 256 chosen plaintexts (v, v, …, v) give the full codebook, and the page decrypts
       fresh ciphertexts with it.
   - In-page honesty (keep this in spirit): *"None of these is an attack on AES. They show why
     AES has each layer. Published attacks on real AES reach only reduced rounds or related
     keys, and are out of scope here. AddRoundKey has no ablation: without the key there is no
     cipher to break."*

## SECURITY / CORRECTNESS INVARIANTS

1. **The real cipher is the default.** Every ablation is opt-in, marked "deliberately broken",
   and retired when switched off.
2. **One implementation, configured.** Every variant goes through the same
   `cipher(state, roundKeys, config)` entry point. `config` has three flags: `shiftRows`,
   `mixColumns`, and `sbox: 'real' | 'affineOnly' | 'identity'`. These are not separate
   copies. A test asserts the default config reproduces every KAT through that entry point.
3. **Attacks never read the victim key.** Attack modules receive an encryption oracle and, for
   7a/7b, a function to make the attacker's *own* key — never the victim key. Enforce this by
   type and by an import test: no attack module imports the victim key store.
4. **Every break is checked on held-out data the attack could not see.**
   - The attack function returns its decryptor (or forger) and finishes **before** the
     held-out generator is created.
   - That generator is a separate seeded stream that is never passed to, or importable by, the
     attack module.
   - A break counts only if it handles N = 32 held-out items. For 7a, 7b and 7d these are
     fresh victim ciphertexts; for 7c they are the splice targets defined above.
5. **The control is an attack failure, never an implementation alarm.** Against full AES, the
   7a/7b attack's L is usually singular: a random 128×128 GF(2) matrix is invertible only about
   29% of the time, and the reviewer saw 20 of 60 runs invertible. **Under the control, a
   singular L means "no linear model exists".** Score it 0/32 and render it OK. The
   "L not invertible — implementation error" ALARM applies **only** to ablations 7a/7b, where L
   must be invertible.
6. **The control draws all 32 rows**, showing the attack's candidate plaintext (or forgery) for
   each held-out item. Each row visibly fails, so "0/32" is computed from drawn rows, not
   asserted.
7. **The key schedule is untouched by ablations.** The ablations act on the data path only.
   SubWord keeps the real S-box in every variant, and the page says so.
8. **Key sizes are 128/192/256** for the hand-rolled cipher. The WebCrypto cross-check covers
   128 and 256 only, because Chromium's WebCrypto has no 192-bit AES (as AES Modes' extension
   brief documents). Say so beside the check.
9. **Every verdict path is seeded.** Random keys, plaintexts and held-out sets come from seeded
   generators shown on screen, so a test can replay a run.

## ARCHITECTURE

- `src/gf/gf256.ts`: `add`, `xtime`, `mul`, `inv` (extended Euclid over GF(2)[x], returning
  its step rows), and `pow254` as an independent route used only in tests.
- `src/aes/sbox.ts`: `buildSbox()`, `buildInvSbox()`, `affineOnly()`, `ddt()` (non-zero
  differences), `lat()` (non-zero masks).
- `src/aes/state.ts`: the r + 4c layout, `shiftRows`, `invShiftRows`, `mixColumns`,
  `invMixColumns`, `MC`, `IMC`, `mdsMinors()`.
- `src/aes/keyExpansion.ts`: `expand(key)`, returning the words with per-step annotations.
- `src/aes/cipher.ts`: `cipher(input, w, config, trace?)` and `invCipher(input, w, trace?)`.
- Attack modules, plus the held-out harness (invariant 4) and the attack-phase query counter:
  - `src/attack/affine.ts` (7a/7b);
  - `src/attack/columns.ts` (7c);
  - `src/attack/bytes.ts` (7d);
  - `src/attack/heldout.ts`.
- `src/linalg/gf2.ts`: build, invert and apply 128×128 bit matrices.
- `src/ui/act1.ts` … `src/ui/act7.ts`.
- Move heavy loops into a Worker (exhaustive LAT, MDS, 128×128 inversion) only if they block
  for more than 50 ms in the built bundle. Measure; don't guess.
- `// [extension] point` markers:
  - in `cipher.ts`, a reduced-round switch;
  - in `keyExpansion.ts`, a key-schedule ablation.

## UI

- **Stepper.** A seven-act stepper. Every act opens with a 2–4 sentence plain-language card
  before any hex.
- **State grid.** The persistent element is the **4×4 state grid**.
  - Bytes animate only when a layer acts on them, driven by a step button.
  - Nothing moves when the learner isn't stepping.
- **Act 7 controls.**
  - A five-option radio group: "Remove: nothing · SubBytes · the inversion · ShiftRows ·
    MixColumns".
  - A "Run attack" button. It reports the **attack-phase victim-oracle queries**, counted by
    the oracle wrapper, then the held-out verdict, then the control.
- **Predict prompts** on acts 1, 4 and 7, using AES Modes' `.predict-prompt` pattern.
- **Tooltips.** Each edge case below gets a tooltip that teaches it (template §1).
- **Layout.** Stacks below 640px. At 320px the 16 cells must stay at least 2.75rem; if they
  can't, wrap the grid in a labelled scroll region per §4.2.

## VISUAL SEMANTICS

- **KAT matches** read OK: a check icon, "matches FIPS 197 Appendix B", and colour.
- **A break in 7a–7d** is ALARM: `data-verdict="broken"` with an alarm class, reading "⚠ BROKEN
  — 32/32 held-out items without the key".
- **The control** reads OK, with the attack visibly failing: `data-verdict="control-fails"`,
  reading "✓ ATTACK FAILS ON REAL AES — 0/32". When L was singular, add "no linear model
  exists".
- **7b's fixture** reads as success and failure at once: **`FULL AVALANCHE (MEAN) — AND BROKEN
  BY ONE KNOWN PAIR`**.
- **Act 3** uses different glyphs for the structural dependency map and the observed
  difference, with a legend. Never draw an observed unchanged byte as "no dependency".
- **Never colour alone.** Check in grayscale and deuteranopia.

## EDGE CASES

- A key that is not exactly 32, 48 or 64 hex characters is refused, naming the length found.
  Never pad or truncate.
- A plaintext that is not 32 hex characters is refused the same way.
- Inverting {00} in act 1 shows "no inverse — AES maps {00} to {00} by convention". This is not
  an error.
- Act 4 with Nk = 6 or 8 shows the right number of words (52 or 60) and labels the Nk = 8 extra
  SubWord.
- Act 7c with fewer than 3 known pairs is refused ("collect at least three pairs").
- A 7c splice target whose column appears in no known pair is refused. Never guess.
- Act 7d with fewer than 256 chosen plaintexts gives a partial codebook. Undecryptable bytes
  are shown as `·` and counted, with no claim of full recovery.
- Switching ablation or key size mid-attack retires the attack state and says why. Re-selecting
  the same option is a no-op (§4.1b no-op guard).
- **A singular L under 7a/7b** is impossible for a correct implementation, so it shows the
  implementation ALARM. A test drives this path by injecting a singular matrix. Under the
  control, a singular L is the expected "no linear model exists" (invariant 5).

## EXTENSION SEAMS

1. A reduced-round switch (`cipher.ts`) for a future square/integral exhibit on 4-round AES.
   Not built.
2. A key-schedule ablation (`keyExpansion.ts`): remove Rcon. A primary source is needed before
   any slide-attack claim. Not built.
3. EqInvCipher as a full act. Not built.

## Acceptance checks (write these as tests; expected values come from the spec, not the code)

**Spec known answers (unit, Vitest).** Cite the section in a comment. The brief author checked
each value against the source named, and an independent reviewer re-checked it.

| Check | Expected | Source |
|---|---|---|
| xtime chain {57}·{02},{04},{08},{10},{20},{40},{80} | ae, 47, 8e, 07, 0e, 1c, 38 | FIPS 197-upd1 §4.2, Eq. 4.6 |
| {57}·{13} | fe | upd1 Eq. 4.7; also FIPS 197 (2001) §4.2.1 |
| {57}·{83} | c1 | FIPS 197 (2001) §4.2 only |
| S-box, all 256 entries | upd1 Table 4 (spot: S(53) = ed, S(00) = 63) | upd1 Table 4, §5.1.1 |
| Inverse S-box, all 256 | upd1 Table 6 | upd1 Table 6 |
| A.1 w[4..7] | a0fafe17 88542cb1 23a33939 2a6c7605 | upd1 App. A.1 |
| A.1 w[40..43] | d014f9a8 c9ee2589 e13f0cc8 b6630ca6 | upd1 App. A.1 |
| A.2 w[51] | 01002202 | FIPS 197 App. A.2 |
| A.3 w[56], w[59] | fe4890d1, 706c631e | FIPS 197 App. A.3 |
| App. B output | 3925841d02dc09fbdc118597196a0b32 | upd1 App. B |
| App. B every round's state | the full Appendix B table | upd1 App. B |
| C.1 AES-128 | 69c4e0d86a7b0430d8cdb78070b4c55a | FIPS 197 (2001) App. C.1 |
| C.2 AES-192 | dda97ca4864cdfe06eaf70a0ec0d7191 | FIPS 197 (2001) App. C.2 |
| C.3 AES-256 | 8ea2b7ca516745bfeafc49904b496089 | FIPS 197 (2001) App. C.3 |

**Citation caveats.**

- The fetch tool garbled upd1's A.2/A.3 table rows. The values above agree with the 2001
  edition and with two independent references. Confirm the row labels against the PDF.
- upd1's Appendix C points to NIST CSRC's "Examples with Intermediate Values" page
  (`AES_Core128/192/256.pdf`) rather than printing C.1–C.3. Cite the 2001 edition for those, as
  `crypto-lab-aes-modes/src/ecb.test.ts` already does.
- C.1 matches the sibling labs' pinned copies. Confirm C.2/C.3 against the PDF or the CSRC
  files before citing them.

**Exhaustive facts (unit):**

- The max DDT entry over input differences ≠ 0 is 4.
- The max |LAT − 128| over masks (a, b) ≠ (0, 0) is 16.
- The affine-only box passes the affine identity on all 65,536 pairs, and the real box fails
  it.
- 69 of 69 MixColumns minors are non-zero.
- MC·IMC = I.
- (MC∘SR)⁸ = id on all 128 basis vectors, and no smaller power is.
- The dependency sets after rounds 1 and 2 have sizes {4} and {16}.

**Independent routes (unit):**

- `inv` against `pow254` on all 255 non-zero bytes.
- The hand-rolled cipher against WebCrypto AES-CBC (zero IV, first block) on ≥ 200 seeded
  random key/plaintext pairs at 128 and 256.
- InvCipher(Cipher(x)) = x at all three key sizes.

**Brief-time cross-check values for the ablations.** These are **not** published vectors. They
come from the brief author's independent Python reference, which reproduces every value in the
table above and matches pycryptodome on 600 random blocks. An independent reviewer reproduced
them with their own implementation. Label them as cross-checks in the test, and never cite them
as FIPS.

They use the Appendix B key and input, and **the key schedule always uses the real S-box**
(invariant 7):

| Ablation | Output |
|---|---|
| no SubBytes | c022b95a1b4dd59121f4a86a78af00ca |
| affine-only S-box | d23dc7d597d16a855a3d6eada80db1a8 |
| no ShiftRows | de4a19166aca3b22ca14c57c6af0c504 |
| no MixColumns | a2cc0db4d67dfcbe494b63e006448124 |

If SubWord also used the affine-only box, 7b would give `0fe928ad8cc1838d72e882f1fc39efcc`.
That is not the specified variant, so don't use it.

**Properties (unit).** These are the real acceptance checks for act 7, derived from the
algebra rather than from the code:

- **7a/7b:** E(a) ⊕ E(b) ⊕ E(c) = E(a ⊕ b ⊕ c) on ≥ 200 seeded triples. This fails for full
  AES.
- **7c:** a single-column change leaves the other three columns of C unchanged. This fails for
  full AES.
- **7d:** a single-byte change changes exactly one output byte, at the stated position map.
  This fails for full AES.
- **Every break handles 32/32 held-out items, and the same code under the control handles
  0/32.**

**Avalanche numbers by key size.** The reviewer measured these. Pin the fixture at AES-128 and
show the others only as a disclosure:

| Variant | AES-128 | AES-192 | AES-256 |
|---|---|---|---|
| 7b mean | 61.5 | 62.0 (range 55–71) | 66.0 (range 61–75) |
| 7a mean | about 5.75 | 37.0 | 37.0 |

**Claims (`e2e/claims.spec.ts`, §4.1b):**

- Recompute xtime from the printed byte by a different route — a polynomial multiply by x, then
  subtract m(x) — and assert the printed result.
- Parse the printed S-box grid and compare it with Table 4, hard-coded in the test from the
  standard.
- Parts sum to whole in act 5: the printed round-k output ⊕ printed round key k equals the
  printed round-k state before AddRoundKey.
- **Act 7 attack-phase query count:** for 7a/7b it is exactly **1**, as counted by the oracle
  wrapper. It excludes held-out generation, 7c forgery confirmations, and the test's own
  re-encryptions.
- **Act 7 held-out table:** the denominator equals the number of drawn rows (32). Each "broken"
  row's plaintext re-encrypts under the victim oracle (in `page.evaluate`) to its
  ciphertext.
- **The control table:** 32 drawn rows, and every candidate fails to re-encrypt to its
  ciphertext.
- **Verdict attributes:** every verdict asserts both `data-verdict` and its class.
- **Retirement:** change the key and every derived panel says it was retired. Re-selecting the
  same ablation retires nothing.
- **The `[hidden]` probe (§4.1b):** no element carrying `hidden` is actually rendered.

**§4.1c mutations — one per rendered verdict.** Each must break the MECHANISM behind its
verdict, never a display flag.

- Record each as a concrete patch (file, unique anchor, replacement) in
  `scripts/check-mutations.mjs`, in the shape of
  `crypto-lab-aes-modes/scripts/check-ofb-mutations.mjs`.
- Have the script write `mutation-evidence.json`, including the names of the tests that failed.
- Every kill meets the four §4.1c rules.

| # | Mutation | Killed by |
|---|---|---|
| 1 | `xtime` reduces by 0x1B unconditionally | act-1 KATs and the S-box table |
| 2 | ShiftRows shifts right instead of left | Appendix B |
| 3 | the last round keeps MixColumns | Appendix B and C.1–C.3 |
| 4 | key expansion skips the Nk = 8 extra SubWord | A.3 and C.3. Record which tests failed; A.1/C.1 should still pass |
| 5 | InvCipher walks round keys forward | the round-trip test and act 6's mismatch claim |
| 6 | the 7a attack obtains c through a **second** victim query E(0) instead of computing C ⊕ L(P) | the attack-phase query-count claim, which reads 2 |
| 6b | the 7a attack reads the victim key | the invariant-3 import/type test |
| 7 | the attack module is handed the held-out generator, or the held-out set is created before the attack resolves | the invariant-4 test. Spy on the held-out generator's constructor and assert it runs after the attack promise resolves, and assert that the attack's signature has no generator parameter |
| 8 | the "no ShiftRows" switch also disables MixColumns | the no-ShiftRows cross-check value. The mutant outputs `a2498aa1d6dfa63f499cac0d06609707`. The 7c property test alone would **not** kill this |
| 9 | the control run is skipped and "0/32" is hard-coded | the control-table claim (32 drawn rows, each failing) |
| 10 | the WebCrypto cross-check imports the key with its bytes reversed | its claims test, which recomputes WebCrypto from the printed key in `page.evaluate` and asserts that the page's match verdict equals that comparison. Don't use "compare with itself": that mutation is equivalent while the cipher is correct, so nothing can kill it |
| 11 | `mdsMinors` skips the 3×3 minors | the 69-count fact |
| 12 | `ddt` includes the zero difference | the "= 4" fact |
| 13 | the affine-identity check tests only x = y | the "real box fails" fact |
| 14 | the (MC∘SR)ⁿ check stops at n = 4 | the order-8 and no-smaller-power fact |
| 15 | the 7d codebook indexes by output position instead of input position | the 7d held-out claim |
| 16 | the singular-L path under 7a reports OK | the injected-singular test |
| 17 | the InvMixColumns failure path uses IMC anyway | act 6's mismatch claim |
| 18 | delete the 7b negative-claim sentence | §4.1d assertion 3 |

**§4.1d negative claim:** *"A good-looking avalanche is not security. This affine-only AES —
where every output byte depends on every input byte and about half the output bits flip per
input-bit flip on average — is still broken by one known plaintext."*

- **Fixture:** act 7b at AES-128, with the seeded key shown. Every check the page renders in
  that state reports success:
  - the mean-avalanche check: the average over the 128 single-bit flips lies within 64 ± 8.
    The variant measures exactly 61.5. Real AES-128 stays within about ±1.7 of 64 over 400
    seeded runs, so the band is not flaky.
  - a full **byte-level** dependency map after round 2;
  - a round trip with the key.
- **Do not add a per-flip "every byte changed" check.** In 400 of 400 seeded real-AES runs, some
  flip left at least one byte unchanged; the minimum was 13 changed bytes. The 7b fixture
  itself always has such a flip. That check would fail the real cipher and teach the wrong
  thing.
- **And the property is violated:** the one-pair attack handles 32/32 held-out ciphertexts.
- Assert all three §4.1d points:
  - break the avalanche check inside the fixture, and assertion 2 must fail;
  - delete the sentence, and assertion 3 must fail.

**Fail-closed paths.** Each needs a NAMED test:

- wrong key length;
- wrong block length;
- inverse of {00};
- singular L under 7a (implementation ALARM);
- singular L under the control (expected, 0/32);
- fewer than 3 pairs for 7c;
- a splice column missing;
- partial codebook;
- switching mid-attack;
- decrypting with forward key order;
- decrypting with MixColumns instead of InvMixColumns.

## Hero copy (keep the three roles distinct)

- **Subtitle:** `FIPS 197 · GF(2⁸) · Key Expansion · Inverse Cipher`.
- **Description:** "Build AES from byte arithmetic up — S-box, ShiftRows, MixColumns, key
  expansion and decryption — then pull out the S-box's inversion, ShiftRows or MixColumns and
  break what is left."
- **Why it matters:** "In the absence of an application-profile standard specifying otherwise,
  TLS 1.3 requires a TLS-compliant application to support TLS_AES_128_GCM_SHA256 (RFC 9846
  §9.1). Understanding why each AES layer exists helps distinguish a correct construction from
  one that merely looks scrambled."
- This wording was checked against the RFC Editor's RFC 9846 §9.1 text on 2026-10-23. It records
  a mandatory-to-implement requirement and makes no claim about measured HTTPS deployment.

## README, card and links

- README per §5, including **Exhibits** numbered 1–7 to match the acts.
- **Catalog handoff (do not edit `../crypto-lab`).**
  - Proposed chips, implemented only: `AES-128/192/256` · `GF(2⁸)` · `Key Expansion` ·
    `Inverse Cipher`.
  - Check each against `tools/catalog-vocab.js`, and propose terms the catalog lacks.
  - Concept-coverage placement: item 4 (confusion, diffusion and cipher structure) in
    `concept-coverage.md`.
  - Propose card copy in the handoff.
- **Links out:**
  - AEGIS Gate: one round inside another construction.
  - Glass Box: implementation attacks on exactly this cipher, and its key-schedule
    inversion.
  - Sleeve Check: where the S-box came from.
  - Biham Lens and Matsui Line: what DDT and LAT entries buy an attacker.
  - AES Modes: what to do with a block cipher.
  - Power Trace and Masked Core: implementation attacks on exactly this cipher.
  - **Clock Arithmetic** (same batch): the integer side of the same arithmetic.

## Sources (each checked by the brief author, and re-checked by an independent reviewer)

- NIST FIPS 197-upd1, *Advanced Encryption Standard (AES)*, May 9 2023,
  doi:10.6028/NIST.FIPS.197-upd1.
  - Read: the table of contents; §3.4; §4.2 (Eqs. 4.3, 4.6, 4.7); §4.4; §5.1.1 (Eq. 5.2);
    §5.3; §5.3.5; Tables 4 and 6; App. A.1; App. B.
  - App. C is a pointer to the CSRC page.
  - Note that **§4.3 is "Multiplication of Words by a Fixed Matrix"**; m(x) is Eq. 4.3 in
    §4.2.
- NIST FIPS 197 (2001), withdrawn and superseded by upd1. Read: §4.2 ({57}·{83} = {c1}),
  §4.2.1 ({57}·{13} = {fe}), App. A.2 w[51], App. A.3 w[59]. App. C was not readable through
  the fetch tool.
- NIST CSRC, "Examples with Intermediate Values" (`AES_Core128.pdf` etc.).
- J. Daemen and V. Rijmen, *The Design of Rijndael*, Springer. Used for branch number and
  wide-trail vocabulary, in a disclosure only. Cite the edition you actually open.
- RFC 9846 §9.1. See the hero note.
- Paar & Pelzl, *Understanding Cryptography* (1st ed., 2010), ch. 4. Teaching context only;
  reproduce no text, figures or exercises.
