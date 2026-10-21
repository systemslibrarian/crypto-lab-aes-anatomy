import { it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { createCipheriv } from "node:crypto";
import { runBreak, singularVerdict } from "./harness";
import { HeldoutGenerator } from "./heldout";
import { splice, recoverColumns } from "./attack/columns";
import { recoverAffine } from "./attack/affine";
import { recoverBytes } from "./attack/bytes";
import { seeded } from "./random";
import { avalanche, affineByteDependencies, largerKeyAvalanche } from "./diagnostics";
import { VARIANTS, cipher, invCipher } from "./aes/cipher";
import { expand } from "./aes/keyExpansion";
import { equal, parseHex, hex, type Block } from "./aes/state";
import { act7 } from "./ui/act7";
it("Capability boundary: attack signatures and imports cannot receive the victim key or heldout stream", () => {
  const allowed = (path: string) =>
    path === "./types" || /^\.\.\/(aes|linalg)\/[\w-]+(?:\.ts)?$/.test(path);
  for (const file of readdirSync("src/attack").filter((file) => file.endsWith(".ts"))) {
    const source = readFileSync(`src/attack/${file}`, "utf8");
    expect(source).not.toMatch(/victimKey|heldout|harness/);
    // Attack modules use static literal imports only; reject alternate loaders.
    expect(source).not.toMatch(/\b(?:import|require)\s*\(/);
    const imports = [...source.matchAll(/\b(?:from|import)\s*["']([^"']+)["']/g)];
    expect(imports.length).toBeGreaterThan(0);
    for (const [, specifier] of imports)
      expect(allowed(specifier), `${file}: ${specifier} must be on the import whitelist`).toBe(
        true,
      );
  }
  // JS arity counts parameters before the first default; optional TS parameters still count.
  expect(recoverAffine.length).toBe(4);
  expect(recoverColumns.length).toBe(2);
  expect(recoverBytes.length).toBe(1);
});
it("Heldout stream is constructed only after attack promise resolves, for both runs", async () => {
  const events: string[] = [];
  await runBreak("affine", seeded(1)(), 1, 256, {
    afterAttack: () => events.push("attack resolved"),
    generator: (s) => {
      events.push("heldout constructed");
      return new HeldoutGenerator(s);
    },
  });
  expect(events).toEqual([
    "attack resolved",
    "heldout constructed",
    "attack resolved",
    "heldout constructed",
  ]);
  const source = readFileSync("src/harness.ts", "utf8");
  expect(source.indexOf("new HeldoutGenerator")).toBeGreaterThan(
    source.indexOf("await recoverBytes"),
  );
});
it("Affine fixture healthy diagnostics and alarm are independently computed", async () => {
  const key = seeded(0x197197)(),
    p = seeded(0x197198)(),
    stats = avalanche(key, p, VARIANTS.affine);
  expect([stats.mean, stats.min, stats.max, stats.roundTrip]).toEqual([61.5, 57, 71, true]);
  expect([Math.min(...stats.outputDependencies), Math.max(...stats.outputDependencies)]).toEqual([
    51, 73,
  ]);
  expect(avalanche(key, p, VARIANTS.noSub).mean).toBe(5.75);
  expect(affineByteDependencies(key, 2)).toEqual(
    Array.from({ length: 16 }, () => Array.from({ length: 16 }, (_, i) => i)),
  );
  const r = await runBreak("affine", key, 0x197197),
    html = act7(r, "affine", key, p);
  expect(
    html.match(
      /data-check="(?:mean-avalanche|byte-dependencies|keyed-roundtrip)" data-verdict="pass" class="ok"/g,
    ),
  ).toHaveLength(3);
  expect(html).toContain("A good-looking avalanche is not security.");
  expect(html).toContain('data-verdict="broken" class="alarm"');
  expect(html).toContain('data-verdict="control-fails" class="ok"');
});
it("Singular affine matrix fails closed, while singular realAES is expected", async () => {
  expect(singularVerdict(false).kind).toBe("implementation-error");
  expect(singularVerdict(true).kind).toBe("control-fails");
  const key = seeded(3)(),
    r = await runBreak("affine", key, 3, 256, { injectColumns: Array(128).fill(0n) });
  expect(r.broken.successes).toBe(0);
  expect(r.broken.singular?.kind).toBe("implementation-error");
  expect(act7(r, "affine", key, new Uint8Array(16))).toContain(
    'data-verdict="implementation-error"',
  );
});
it("Column target freshness, multiple sources, and missing-column refusal", async () => {
  const r = await runBreak("noShift", seeded(5)(), 5);
  for (const row of r.broken.rows) {
    expect(r.broken.known.some((k) => equal(k.plaintext, row.plaintext))).toBe(false);
    const sources = new Set<number>();
    for (let col = 0; col < 4; col++)
      sources.add(
        r.broken.known.findIndex((k) =>
          equal(k.plaintext.slice(col * 4, col * 4 + 4), row.plaintext.slice(col * 4, col * 4 + 4)),
        ),
      );
    expect(sources.size).toBeGreaterThanOrEqual(2);
    expect(sources.has(-1)).toBe(false);
  }
  expect(() => splice(r.broken.known, new Uint8Array(16))).toThrow("appears in no known pair");
  await expect(runBreak("noShift", seeded(5)(), 5, 2)).rejects.toThrow("at least three");
});
it("Partial byte codebooks keep missing bytes unknown and never assert full recovery", async () => {
  const key = seeded(9)(),
    r = await runBreak("noMix", key, 9, 16);
  expect(r.broken.partial).toBe(true);
  expect(r.broken.rows.every((x) => x.partial?.some((v) => v === null))).toBe(true);
  const html = act7(r, "noMix", key, new Uint8Array(16));
  expect(html).toContain('data-verdict="partial"');
  expect(html).toContain("unknown bytes");
  expect(html).toContain("·");
  expect(html).not.toContain('data-verdict="broken"');
});
it("Wrong inverse modes visibly disagree, including wrong MixColumns", () => {
  const key = seeded(2)(),
    p = seeded(4)(),
    w = expand(key).roundKeys,
    ct = cipher(p, w);
  expect(invCipher(ct, w)).toEqual(p);
  for (const mode of ["forwardKeys", "wrongMix"] as const)
    expect(equal(invCipher(ct, w, undefined, undefined, mode), p)).toBe(false);
});
it("Input lengths are refused without truncation and zero seed is valid", () => {
  expect(() => parseHex("aa", [32])).toThrow("No padding or truncation");
  expect(() => expand(new Uint8Array(15))).toThrow();
  expect(() => cipher(new Uint8Array(15), expand(seeded(0)()).roundKeys)).toThrow();
  expect(seeded(0)()).toHaveLength(16);
});

it("Invariant 3: attacker inputs are independent of the victim key", async () => {
  const k1 = seeded(81)(),
    k2 = seeded(82)();
  expect(k1).not.toEqual(k2);
  for (const variant of ["noSub", "affine"]) {
    const capture = async (key: Block) => {
      const own: Block[] = [];
      const result = await runBreak(variant, key, 1, 256, { onOwnKey: (b) => own.push(b) });
      return { own, result };
    };
    const first = await capture(k1),
      second = await capture(k2);
    expect(first.own).toHaveLength(4); // Two draws for each of broken/control.
    expect(first.own).toEqual(second.own);
    for (const own of [...first.own, ...second.own]) {
      expect(own).not.toEqual(k1);
      expect(own).not.toEqual(k2);
    }
    expect(first.result.broken.known[0].plaintext).toEqual(second.result.broken.known[0].plaintext);
    expect(first.result.control.columns).toHaveLength(128);
    expect(first.result.control.columns).toEqual(second.result.control.columns);
  }
});

it("Invariant 4: held-out items never appeared in the attack transcript", async () => {
  for (const variant of ["noSub", "affine", "noShift", "noMix"]) {
    for (const seed of [0x197197, 1, 0]) {
      const queries: Block[] = [],
        own: Block[] = [];
      const r = await runBreak(variant, seeded(31)(), seed, undefined, {
        onAttackQuery: (p) => queries.push(p),
        onOwnKey: (k) => own.push(k),
      });
      expect(queries).toHaveLength(r.broken.queries + r.control.queries);
      expect(queries.length).toBeGreaterThan(0);
      expect(own).toHaveLength(variant === "noSub" || variant === "affine" ? 4 : 0);
      const transcript = new Set([...queries, ...own].map(hex));
      for (const run of [r.broken, r.control]) {
        expect(run.rows).toHaveLength(32);
        for (const row of run.rows) expect(transcript.has(hex(row.plaintext))).toBe(false);
      }
    }
  }
});

it("Invariant 4 canary: a memorising attack scores 0/32", async () => {
  for (const variant of ["noSub", "noMix"]) {
    const r = await runBreak(variant, seeded(47)(), 0x197197, undefined, {
      recoverOverride: async (oracle, makeOwnKey, config, count) => {
        const seen = new Map<string, Block>();
        const record = async (p: Block) => {
          const ct = await oracle(p);
          seen.set(hex(ct), p.slice());
          return ct;
        };
        const recovery =
          variant === "noSub"
            ? await recoverAffine(record, makeOwnKey, config)
            : await recoverBytes(record, count);
        expect(seen.size).toBe(variant === "noSub" ? 1 : 256);
        return { ...recovery, candidate: (ct: Block) => seen.get(hex(ct)) ?? null };
      },
    });
    expect(r.broken.queries).toBe(variant === "noSub" ? 1 : 256);
    expect(r.broken.rows).toHaveLength(32);
    expect(r.broken.successes).toBe(0);
  }
});

it("Singular L under the control is the expected attack failure (0/32, OK)", async () => {
  const key = seeded(0x197197)();
  const r = await runBreak("noSub", key, 0x197197);
  expect(r.control.rank).toBeLessThan(128);
  expect(r.control.singular?.kind).toBe("control-fails");
  expect(r.control.successes).toBe(0);
  expect(r.control.rows).toHaveLength(32);
  const html = act7(r, "noSub", key, seeded(0x197198)());
  expect(html).toMatch(
    /id="control-verdict" data-verdict="control-fails" class="ok"[^>]*>[^<]*0\/32[^<]*No linear model exists/,
  );
});

it("Invertible L under the control: real candidates, all fail", async () => {
  const key = seeded(0x197197)();
  const aes = (key: Block, plaintext: Block): Block => {
    const encryptor = createCipheriv("aes-128-ecb", key, null);
    encryptor.setAutoPadding(false);
    return Uint8Array.from(Buffer.concat([encryptor.update(plaintext), encryptor.final()]));
  };
  const xorBytes = (a: Block, b: Block) => Uint8Array.from(a, (v, i) => v ^ b[i]);
  for (const variant of ["noSub", "affine"]) {
    const own: Block[] = [];
    const { control } = await runBreak(variant, key, 1, 256, { onOwnKey: (k) => own.push(k) });
    expect(own).toHaveLength(4);
    expect(control.rank).toBe(128);
    expect(control.singular).toBeNull();
    expect(control.successes).toBe(0);
    expect(control.rows).toHaveLength(32);
    // Real AES is nonlinear: L is the linear extension of its 128 basis differences,
    // NOT E_own(x) XOR E_own(0) for arbitrary x. Rebuild it without production helpers.
    const zero = aes(own[2], new Uint8Array(16));
    const columns = Array.from({ length: 128 }, (_, bit) => {
      const basis = new Uint8Array(16);
      basis[bit >> 3] = 1 << (bit & 7);
      return xorBytes(aes(own[2], basis), zero);
    });
    const linear = (p: Block) => {
      const out = new Uint8Array(16);
      for (let bit = 0; bit < 128; bit++)
        if (p[bit >> 3] & (1 << (bit & 7))) for (let j = 0; j < 16; j++) out[j] ^= columns[bit][j];
      return out;
    };
    const known = control.known[0];
    expect(aes(key, known.plaintext)).toEqual(known.ciphertext);
    for (const row of control.rows) {
      expect(row.candidate).not.toBeNull();
      expect(row.candidate!.some((x) => x !== 0)).toBe(true);
      expect(xorBytes(linear(row.candidate!), linear(known.plaintext))).toEqual(
        xorBytes(row.ciphertext, known.ciphertext),
      );
      expect(aes(key, row.plaintext)).toEqual(row.ciphertext);
      expect(aes(key, row.candidate!)).not.toEqual(row.ciphertext);
      expect(aes(key, row.candidate!)).toEqual(row.candidateCiphertext);
      expect(row.matches).toBe(false);
    }
  }
});

it("Larger-key avalanche diagnostics compute each variant with the same plaintext", async () => {
  const plaintext = seeded(0x197198)();
  expect(
    largerKeyAvalanche(plaintext, VARIANTS.affine).map((s) => [s.size, s.mean, s.min, s.max]),
  ).toEqual([
    [192, 62.0, 55, 71],
    [256, 66.0, 61, 75],
  ]);
  expect(largerKeyAvalanche(plaintext, VARIANTS.noSub).map((s) => [s.size, s.mean])).toEqual([
    [192, 37.0],
    [256, 37.0],
  ]);
  const key = seeded(0x197197)();
  for (const variant of ["noSub", "affine"]) {
    const r = await runBreak(variant, key, 0x197197);
    const html = act7(r, variant, key, plaintext);
    for (const stats of largerKeyAvalanche(plaintext, VARIANTS[variant]))
      expect(html).toContain(
        `AES-${stats.size} mean ${stats.mean.toFixed(1)} bits (${stats.min}–${stats.max})`,
      );
    if (variant === "noSub")
      expect(html).toContain('data-check="collapse" data-verdict="pass" class="ok"');
  }
});
