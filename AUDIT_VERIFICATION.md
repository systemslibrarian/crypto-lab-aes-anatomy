# AES Anatomy test-honesty verification

Requested audit follow-up, 2026-10-21. Base commit: `7abf61f7fdcef076c5f536c81ec0e1b729b05118`. Work is on `fix/aes-anatomy-test-honesty`; this change is for PR review, without merge or deployment.

## Executed gates

| Gate | Passed / total | Skipped |
| --- | --- | --- |
| Unit | 31 / 31 | 0 |
| Browser claims | 17 / 17 | 0 |
| Accessibility, desktop and 320px | 2 / 2 | 0 |
| Mutations | **33 of 33 killed** | 0 cases omitted |

`npm ci`, `npm test`, `npm run build`, all Playwright specs with `--retries=0`, and `node scripts/check-mutations.mjs` completed successfully. The formatting-only commit `5039649` first passed the unchanged 25 unit and 12 claims tests. The final unit run used JSON reporting; the final Playwright run used JSON reporting with retries disabled.

Local browser environment: Chromium **153.0.8010.0**. `npx playwright install chromium` attempted the lockfile's Chromium 156 download, which returned an invalid ZIP in this environment. All browser runs therefore used the existing Chromium 153 executable via the ignored `playwright.local.config.ts` (launch path `/tmp/crypto-lab-chromium`, two workers). No assertion or baseline was changed to accommodate it. CI retains the standard Playwright browser installation. The exact local final browser command was:

```bash
npx playwright test --retries=0 --config=playwright.local.config.ts --reporter=json
PLAYWRIGHT_CONFIG=playwright.local.config.ts node scripts/check-mutations.mjs
```

The accessibility baseline remains empty and byte-identical to the original. The select chevron uses `#edf6ef` against `#1c3026`, approximately **12.69:1** contrast (above 3:1). The gate changes are comments only; the original accessibility logic and assertions remain intact.

## Audit survivors and new mutation ownership

Each row below is an executed concrete source patch. `mutation-evidence.json` contains its diff, baseline and mutant artifact hashes, failing assertion/test names, and restored-green result. The key-leak row replaces the former name-based 6b mutation; the remaining 13 rows are additions.

| Mutation | Owning test(s) | Result |
| --- | --- | --- |
| Attack receives victim key | **Invariant 3: attacker inputs are independent of the victim key** | Killed |
| Heldout reseed replays the attacker stream | **Invariant 4: held-out items never appeared in the attack transcript**; **Invariant 4 canary: a memorising attack scores 0/32** | Killed |
| Control discards real candidates | **Invertible L under the control: real candidates, all fail** | Killed |
| Control singular explanation deleted | **Singular L under the control is the expected attack failure (0/32, OK)** | Killed |
| xtime uses 0x1d modulus | **Every field operation and 512 computed S-box entries match FIPS** | Killed |
| Attack verdict alarm class becomes ok | **Independent browser recomputation: noSub 32 heldout successes and 32 realAES failures** | Killed |
| Hidden tabpanel paints | **Hidden elements never paint in all seven acts and after an attack** | Killed |
| Fixture dependency check uses one round | **Seeded affine fixture computes every check and the full negative claim** | Killed |
| LAT includes the zero-zero mask | **FIPS all256 S-box and inverse entries, exhaustive DDT LAT affine facts** | Killed |
| Inverse MixColumns swaps 11 and 13 | **MDS all69 minors, inverse matrix, dependencies and exact order8** | Killed |
| Collapse uses MC SR SR | **Independent browser recomputation: noSub 32 heldout successes and 32 realAES failures** | Killed |
| Keyed round trip omits the ablation config | **Seeded affine fixture computes every check and the full negative claim** | Killed |
| 7c splice always copies pair zero | **Independent browser recomputation: noShift 32 heldout successes and 32 realAES failures** | Killed |
| 7a larger keys display 7b statistics | **Larger-key avalanche diagnostics compute each variant with the same plaintext** | Killed |

Thus all six specifically named survivors are killed: **own key = victim key**, **held-out reseed**, **control discards candidates**, **alarm → ok**, **deleted “No linear model exists” text**, and **xtime 0x1d**. The xtime mutant fails the Act 1 independent polynomial computation, before the S-box checks.

All four kill requirements remain enforced: a concrete source diff; a successful build producing a different artifact; an owning-test assertion failure with retries disabled; and byte-for-byte restoration followed by the original artifact hash and a green owning test. Each owner also passes before mutation. The original empty-control mutant needed an explicit `HeldoutRow[]` type annotation after the new tests made `never[]` inference a build error; compilation failure was not counted as a kill. The corrected, type-valid mutant then failed its browser assertion in the complete 33-case run. A preliminary run also correctly rejected stale hashed files left in `dist` during the last restoration. The runner now clears that generated directory before every baseline/mutant/restore build. The complete rerun retained the identical baseline artifact hash `88e7b843c4cc77c6b289ff5d3f45024116fe09c2e6484f31bf364cd68dd50630`; the restore-hash requirement was not relaxed.

## Control-check clarification

Real AES is nonlinear. For a general block `x`, `E_own(x) XOR E_own(0)` is **not** the attack's fitted linear map. Asserting that equality for arbitrary candidate blocks would encode a false cryptographic claim.

The new invertible-control test independently derives each basis column with Node's `aes-128-ecb` and `setAutoPadding(false)`:

```text
column[j] = E_own(e_j) XOR E_own(0)
L(x) = XOR of column[j] for each set bit j of x
L(candidate) XOR L(P_known) = C_row XOR C_known
```

It uses a separate byte/XOR implementation, not the production matrix routines. For both noSub and affine at seed 1 it checks rank 128, no singular verdict, all 32 nonzero candidates, that linear equation, the victim's encryption of each held-out plaintext, the candidate re-encryption bytes, and all 32 failures under the victim key. The default-seed singular path separately checks the 32 failing rows and the exact explanatory verdict.

## Preservation and scope

- No pinned expected value changed: FIPS KATs, ablation cross-checks, 61.5/57/71, 51–73, 5.75, 62.0/66.0, and 37.0 remain intact. New assertions also pin the requested larger-key ranges and S-box hashes.
- `src/data/fips197.json`, the package lockfile, and `e2e/nontext-baseline.ts` are unchanged from the base commit.
- AES, key expansion, field arithmetic and attack algorithms have formatting-only changes. Functional changes are limited to the harness/verifier separation, computed diagnostics and their display, and the requested styling/hygiene.
- The verifier-only generator moved to `src/heldout.ts`, so every file left in `src/attack/` can obey the requested import whitelist. Test hooks receive copies and are not exposed in the learner UI or worker messages.
- The fixture now checks the actual keyed 7b round-2 linear part, and larger-key means are computed for the selected variant and same plaintext. Structural wiring remains in Act 3.
- README counts and the catalog handoff are updated. Catalog category, accent and favicon proposals remain marked PROVISIONAL; no catalog repository was edited. The existing performance evidence is retained as the earlier measurement, not presented as a new benchmark.
