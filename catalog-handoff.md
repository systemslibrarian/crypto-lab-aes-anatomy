# AES Anatomy — catalog handoff

The brief expressly reserves catalog changes for a later pass. No files in `../crypto-lab` were changed.

- **Title:** AES Anatomy. **Level:** Intermediate. **Section:** symmetric. **Categories:** ENCRYPTION | ATTACKS; foundational building-block placement is appropriate. No Start Here badge.
- **Copy:** Build AES from field arithmetic to full encryption and decryption, then remove one layer and run four concrete attacks beside independently verified real-AES controls.
- **Chips:** AES-128/192/256 · GF(2⁸) · Key Expansion · Inverse Cipher.
- **Vocabulary review:** `tools/catalog-vocab.js` already has AES (FIPS 197). The other three chips describe concepts or implementation components, not additional named algorithms; do not add them as algorithms merely to satisfy chip matching. A combined AES-128/192/256 chip maps to AES.
- **Concept coverage:** item 4, confusion, diffusion and cipher structure. This closes the primitive-internals teaching gap without duplicating implementation-attack labs. Suggested progression: Clock Arithmetic → AES Anatomy → AES Modes → Biham Lens / Matsui Line.
- **Evidence anchors:** `src/gf/gf256.ts`, `src/aes/sbox.ts`, `src/aes/state.ts`, `src/aes/keyExpansion.ts`, `src/aes/cipher.ts`, `src/attack/affine.ts`, `src/attack/columns.ts`, `src/attack/bytes.ts`. Real S-box use in the key schedule is unchanged in every ablation. `src/crosscheck.ts` uses AES-CBC only as an independent single-block oracle; do not credit this as an AES-CBC teaching exhibit.
- **Source inspection:** exact neighbor revisions and scope corrections are in `overlap-review.md`. AEGIS Gate already shows a real AES round; the new contribution is the full primitive, schedule, inverse and removal attacks.
- **Port:** 4746, chosen after checking the committed fleet port registry (through 4745). The fleet-wide regeneration refuses a partial local census; preserve its existing records when registering this lab.
- **Limits:** attacks are AES-128; whole-cipher and key-schedule traces cover 128/192/256. AES-192 uses FIPS vectors because Chromium WebCrypto does not support it. No EqInvCipher, reduced-round attack, related-key claim, modes tutorial, timing attack, or constant-time implementation is claimed.
- **Validation:** `mutation-evidence.json`, `performance-evidence.json`, unit tests and browser tests are committed with the lab. Catalog evidence should be generated from the final published source revision, not hand-written or copied from this proposal.
