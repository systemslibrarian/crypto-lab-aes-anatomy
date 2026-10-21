# Source overlap review

- `aegis-gate` at `96c9e52024915148f967a8d0c9b57feaa6eb4d9b`.
- `glass-box` at `5c9781fb7a98dfae9422e74b604936180b585cad`.
- `masked-core` at `6196c042b3cc46b9f0c6c47acf4b4b35b008f4cc`.
- `power-trace` at `9fd17c9b1b12931eb9786cefd5647b70033f537e`.
- `sleeve-check` at `0ddd088ace6a3c12d285ee9d27d7ae3f96215c13`.
- `aes-modes` at `4d6fdf6498e7d58967d88ee65b9347dd3d3b875a`.

Read AEGIS Gate aes-round-vis.ts, Glass Box aes-ref.ts/gf.ts/math/gf2.ts, Masked Core and Power Trace src/aes/aes.ts, Sleeve Check gost/aes.ts, and AES Modes CFB/ECB/mode code. AEGIS already steps one genuine AES round. Glass Box implements full AES-128 and round-key inversion in its white-box context. Masked Core and Power Trace derive the S-box for side-channel lessons. Sleeve Check compares the published construction with GOST. AES Anatomy supplies the missing sequence of arithmetic, all key sizes, stepped key expansion, the final round, inverse cipher and deliberately removed-layer attacks; it does not claim the one-round visualization is new.
