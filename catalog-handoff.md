# AES Anatomy — catalog handoff

This is a reviewable handoff for the catalog maintainer. This PR changes only this lab; it does not publish catalog changes. Source call sites below use the expanded, readable files in this branch.

## Card and placement

| Field | Proposed value |
| --- | --- |
| Title | AES Anatomy |
| Kicker | Build AES, Then Remove a Layer |
| One-sentence copy | Build and trace AES, break removed layers, recover a key from late-round faults, then expose accepted-output leakage with real faulted AES executions and controls. |
| Exactly four chips | AES-128/192/256 · GF(2⁸) · Key Expansion · Inverse Cipher |
| `data-category` | `ENCRYPTION \| ATTACKS` — **PROVISIONAL** |
| `TITLE_TO_SECTION` | `'AES Anatomy': 'symmetric'` (section id `symmetric`) — **PROVISIONAL** |
| `FOUNDATIONS_TITLES` | Include `'AES Anatomy'`: it teaches the block primitive's internal building blocks — **PROVISIONAL** |
| `REAL_WORLD_TITLES` | Do not include: TLS is context; the lab does not implement a TLS system — **PROVISIONAL** |
| `data-level` | `intermediate` — Learners follow byte algebra, key schedules and oracle-only attacks, with visible intermediate steps. |
| Accent | `#4cc9f0` — **PROVISIONAL**, confirm against the catalog's final category accent |
| Favicon | 🧱, Unicode `U+1F9F1` — **PROVISIONAL** |
| Start Here badge | No |

The copy contains fewer than 36 words. The three concept chips after AES do not introduce additional named cipher algorithms. Do not add vocabulary entries merely to force a chip match.

## Executed algorithm evidence

| Algorithm or component | Implementation | Executed call sites and scope |
| --- | --- | --- |
| AES-128, AES-192, AES-256 encryption | `src/aes/cipher.ts:26` | `src/ui/act5.ts:8` invokes the full cipher with the selected key; `src/victim.ts:7` supplies the encryption-only capability. |
| AES InvCipher | `src/aes/cipher.ts:75` | `src/ui/act6.ts:9` runs the keyed inverse; `src/diagnostics.ts:34` checks the selected ablation's inverse. EqInvCipher is described, not implemented. |
| AES KeyExpansion (all three sizes) | `src/aes/keyExpansion.ts:14` | `src/ui/act4.ts:6` expands the learner's key; `src/ui/act4.ts:11` checks the published key; `src/ui/act5.ts:8` supplies the encryption schedule. |
| GF(2⁸) multiplication / polynomial extended Euclid | `src/gf/gf256.ts:6`, `src/gf/gf256.ts:35` | `src/ui/act1.ts:17` computes the inverse; `src/ui/act1.ts:18` computes displayed products; `src/aes/state.ts:44` uses field multiplication in the column transform. |
| AES S-box and inverse S-box | `src/aes/sbox.ts:7`, `src/aes/sbox.ts:10` | `src/aes/sbox.ts:15` constructs the tables; `src/aes/cipher.ts:49` uses the data-path S-box; `src/aes/keyExpansion.ts:37` and `src/aes/keyExpansion.ts:44` keep the real S-box in every key schedule. |
| ShiftRows / MixColumns and their inverses | `src/aes/state.ts:29`, `src/aes/state.ts:34`, `src/aes/state.ts:47` | `src/aes/cipher.ts:51`, `src/aes/cipher.ts:52` execute the forward layers; `src/aes/cipher.ts:87`, `src/aes/cipher.ts:96` execute the inverse layers. |
| GF(2) matrix elimination and affine recovery | `src/linalg/gf2.ts:11`, `src/attack/affine.ts:7` | `src/attack/affine.ts:26` inverts the fitted 128-column map; `src/harness.ts:74` invokes the attack with an oracle and attacker-owned key factory. |
| Known-column transplantation (7c) | `src/attack/columns.ts:3`, `src/attack/columns.ts:15` | `src/harness.ts:75` recovers known pairs; `src/attack/columns.ts:27` supplies the splice candidate function. |
| Chosen-plaintext byte codebook (7d) | `src/attack/bytes.ts:3` | `src/harness.ts:76` builds byte tables; `src/harness.ts:87` queries candidates on held-out data. |
| DDT / LAT and MDS diagnostics | `src/aes/sbox.ts:18`, `src/aes/sbox.ts:30`, `src/aes/state.ts:74` | `src/ui/act2.ts:7` and `src/ui/act2.ts:8` compute exhaustive tables; `src/ui/act3.ts:16` computes all 69 minors. These are analyses, not additional ciphers. |
| Classical AES-128 DFA | `src/dfa-fixture.ts`, `src/attack/dfa.ts` | Act 8 injects a specified round-9 byte fault into real AES, intersects last-round-key candidates, reverses the key schedule and verifies the recovered key on a held-out block. |
| IFA/SIFA accepted-output model | `src/sifa-fixture.ts`, `src/attack/sifa.ts` | Act 9 executes correct and first-round-faulted AES-128, classifies ciphertext equality, ranks one key byte from selected inputs, and runs secret-independent plus scoped infective controls. The analytic census and finite sampled experiment are visibly distinct. |
| AES-CBC (independent oracle wrapper only) | Browser WebCrypto | `src/crosscheck.ts:12` imports the key; `src/crosscheck.ts:16` encrypts with zero IV and uses only the first block. Do not credit a modes teaching exhibit. |

The `data-implements` evidence anchor for AES can be `AES@src/aes/cipher.ts:26`, with the executed call sites above. Known-plaintext and chosen-plaintext attack claims refer only to deliberately weakened AES-128 variants. SHA-256 is used in the claims tests to pin the displayed S-box strings, not as an implemented page algorithm.

## GitHub About and topics

**About (under 350 characters):** Inspect AES-128/192/256 from field arithmetic through decryption. Break removed layers, recover AES-128 key material from declared late-round faults, and study accepted-output leakage from real faulted executions. A nine-act browser lab with FIPS vectors and mutation-tested claims.

**Topics:** `aes`, `aes-128`, `aes-192`, `aes-256`, `cryptography`, `cryptography-education`, `fips-197`, `finite-fields`, `s-box`, `key-expansion`, `typescript`, `vite`, `educational`, `browser-lab`.

## Integration notes and limits

- Suggested progression: Clock Arithmetic → AES Anatomy → AES Modes → Biham Lens / Matsui Line. Concept coverage: confusion, diffusion and cipher structure.
- Exact inspected neighbor revisions are in `overlap-review.md`. AEGIS Gate already shows a genuine AES round; this lab adds the full primitive, schedule, inverse and removal attacks.
- Port 4746 was selected from the fleet registry. Preserve existing registry entries when incorporating this lab.
- Attacks run at AES-128; schedule and whole-cipher traces cover 128/192/256. AES-192 uses FIPS vectors because Chromium WebCrypto does not support it. Act 9 recovers one byte in a logical chosen-input model, not a full key or a physical SIFA result; its teaching infection is not timing- or latency-oblivious.
- No EqInvCipher implementation, real-AES reduced-round attack, related-key attack, modes tutorial, timing attack or constant-time implementation is claimed.
- Generate catalog evidence from the reviewed source revision. `mutation-evidence.json` records this branch's executed mutation checks; `performance-evidence.json` is the earlier timing measurement, not a new benchmark of this PR.
