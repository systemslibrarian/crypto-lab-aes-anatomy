// Mutations run only on a committed, clean source baseline. Each is built, killed,
// restored byte-for-byte, rebuilt and tested green before the next begins.
import { readFileSync, writeFileSync, readdirSync, mkdirSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
process.chdir(root);
const config = process.env.PLAYWRIGHT_CONFIG;
const browser = (title) => [
  "npx",
  [
    "playwright",
    "test",
    "e2e/claims.spec.ts",
    "--project=chromium",
    "--grep",
    title,
    "--workers=1",
    "--retries=0",
    ...(config ? ["--config", config] : []),
  ],
];
const build = ["npm", ["run", "build"]];
const run = ([cmd, args]) =>
  spawnSync(cmd, args, { cwd: root, encoding: "utf8", env: { ...process.env, CI: "1" } });
const pass = (cmd, label) => {
  // Compare complete fresh artifacts; stale hashed chunks must never pollute a restore.
  if (cmd === build) rmSync("dist", { recursive: true, force: true });
  const r = run(cmd);
  if (r.status !== 0) throw Error(`${label}\n${r.stdout}\n${r.stderr}`);
  return r;
};
const hash = () => {
  const h = createHash("sha256");
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true }).sort((a, b) =>
      a.name.localeCompare(b.name),
    )) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else {
        h.update(p);
        h.update(readFileSync(p));
      }
    }
  };
  walk("dist");
  return h.digest("hex");
};
const cases = [
  {
    name: "xtime unconditional reduction",
    changes: [
      {
        file: "src/gf/gf256.ts",
        before: "(a & 0x80 ? 0x1b : 0)",
        after: "0x1b",
      },
    ],
    command: ["npx", ["vitest", "run", "-t", "FIPS GF256|FIPS all256"]],
  },
  {
    name: "ShiftRows right",
    changes: [
      {
        file: "src/aes/state.ts",
        before: "a[r + 4 * ((c + r) % 4)]",
        after: "a[r+4*((c+4-r)%4)]",
      },
    ],
    command: ["npx", ["vitest", "run", "-t", "FIPS Appendix B"]],
  },
  {
    name: "MixColumns in final round",
    changes: [
      {
        file: "src/aes/cipher.ts",
        before: "config.mixColumns && round < Nr",
        after: "config.mixColumns&&round<=Nr",
      },
    ],
    command: ["npx", ["vitest", "run", "-t", "FIPS Appendix B|FIPS 2001 Appendix C"]],
  },
  {
    name: "AES256 extra SubWord omitted",
    changes: [
      {
        file: "src/aes/keyExpansion.ts",
        before: "Nk === 8 && i % Nk === 4",
        after: "Nk===0&&i%Nk===4",
      },
    ],
    command: ["npx", ["vitest", "run", "-t", "FIPS Appendix A|FIPS 2001 Appendix C"]],
  },
  {
    name: "Inverse forward keys",
    changes: [
      {
        file: "src/aes/cipher.ts",
        before: "roundKeys.slice().reverse()",
        after: "roundKeys.slice()",
      },
    ],
    command: [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Inverse correct",
        "--workers=1",
        "--retries=0",
      ],
    ],
  },
  {
    name: "Affine second oracle query",
    changes: [
      {
        file: "src/attack/affine.ts",
        before: "offset = pack(ciphertext) ^ apply(columns, pack(plaintext))",
        after: "offset=pack(await oracle(zero))^apply(columns,0n)",
      },
    ],
    command: [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Independent browser recomputation: noSub",
        "--workers=1",
        "--retries=0",
      ],
    ],
  },
  {
    name: "Attack receives victim key",
    changes: [
      {
        file: "src/harness.ts",
        before: "drawOwnKey = () => ownSource(16)",
        after: "drawOwnKey = () => ownSource(16).map((_, i) => victimKey[i])",
      },
    ],
    command: [
      "npx",
      ["vitest", "run", "-t", "Invariant 3: attacker inputs are independent of the victim key"],
    ],
    owningTests: ["Invariant 3: attacker inputs are independent of the victim key"],
  },
  {
    name: "Heldout constructed before attack",
    changes: [
      {
        file: "src/harness.ts",
        before: "const choose = seeded(seed ^ 0x45d9f3b);",
        after:
          "const earlyHeldout = hooks.generator ? hooks.generator(heldoutSeed(seed)) : new HeldoutGenerator(heldoutSeed(seed));\n    const choose = seeded(seed ^ 0x45d9f3b);",
      },
      {
        file: "src/harness.ts",
        before:
          "const heldout = hooks.generator\n        ? hooks.generator(heldoutSeed(seed))\n        : new HeldoutGenerator(heldoutSeed(seed)),\n      rows",
        after: "const heldout = earlyHeldout, rows",
      },
    ],
    command: ["npx", ["vitest", "run", "-t", "Heldout stream"]],
    owningTests: [
      "Heldout stream is constructed only after attack promise resolves, for both runs",
    ],
  },
  {
    name: "NoShift also removes MixColumns",
    changes: [
      {
        file: "src/aes/cipher.ts",
        before: "noShift: { ...REAL, shiftRows: false }",
        after: "noShift:{...REAL,shiftRows:false,mixColumns:false}",
      },
    ],
    command: ["npx", ["vitest", "run", "-t", "Labelled ablation"]],
  },
  {
    name: "Skipped realAES control and hardcoded zero",
    changes: [
      {
        file: "src/harness.ts",
        before: "return { broken: await run(false), control: await run(true) }",
        after:
          "return {broken:await run(false),control:{...await run(false),control:true,rows:[] as HeldoutRow[],successes:0}}",
      },
    ],
    command: [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Independent browser recomputation: noSub",
        "--workers=1",
        "--retries=0",
      ],
    ],
  },
  {
    name: "WebCrypto reversed key",
    changes: [
      {
        file: "src/crosscheck.ts",
        before: 'importKey("raw", Uint8Array.from(key)',
        after: "importKey('raw',Uint8Array.from(key).reverse()",
      },
    ],
    command: [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Browser WebCrypto uses the printed key",
        "--workers=1",
        "--retries=0",
      ],
    ],
  },
  {
    name: "MDS omits 3x3 minors",
    changes: [
      {
        file: "src/aes/state.ts",
        before: "for (let size = 1; size <= 4; size++)\n    for",
        after: "for(let size=1;size<=4;size++)if(size!==3)for",
      },
    ],
    command: ["npx", ["vitest", "run", "-t", "MDS all69"]],
  },
  {
    name: "DDT includes zero difference",
    changes: [
      {
        file: "src/aes/sbox.ts",
        before: "rows.slice(1).map",
        after: "rows.slice(0).map",
      },
    ],
    command: [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Every field operation",
        "--workers=1",
        "--retries=0",
      ],
    ],
  },
  {
    name: "Affine identity only diagonal",
    changes: [
      {
        file: "src/aes/sbox.ts",
        before: "for (let y = 0; y < 256; y++) if",
        after: "for(let y=x;y===x;y++)if",
      },
      {
        file: "src/aes/sbox.ts",
        before: "total: 65536, affine: passed === 65536",
        after: "total:256,affine:passed===256",
      },
    ],
    command: ["npx", ["vitest", "run", "-t", "FIPS all256"]],
  },
  {
    name: "Linear order stops at four",
    changes: [
      {
        file: "src/aes/state.ts",
        before: "power <= 8",
        after: "power<=4",
      },
    ],
    command: ["npx", ["vitest", "run", "-t", "MDS all69"]],
  },
  {
    name: "Byte lookup uses output index",
    changes: [
      {
        file: "src/attack/bytes.ts",
        before: "const value = tables[input].get(ct[noMixPosition(input)])",
        after: "const value=tables[input].get(ct[input])",
      },
    ],
    command: [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Independent browser recomputation: noMix",
        "--workers=1",
        "--retries=0",
      ],
    ],
  },
  {
    name: "Singular ablation reported OK",
    changes: [
      {
        file: "src/harness.ts",
        before: 'kind: "implementation-error",\n        message: "Singular L',
        after: 'kind: "control-fails",\n        message: "Singular L',
      },
    ],
    command: ["npx", ["vitest", "run", "-t", "Singular affine"]],
  },
  {
    name: "Wrong mix mode uses inverse anyway",
    changes: [
      {
        file: "src/aes/cipher.ts",
        before: 'fault === "wrongMix" ? mixColumns(state) : invMixColumns(state)',
        after: "fault==='wrongMix'?invMixColumns(state):invMixColumns(state)",
      },
    ],
    command: [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Inverse correct",
        "--workers=1",
        "--retries=0",
      ],
    ],
  },
  {
    name: "Negative affine claim deleted",
    changes: [
      {
        file: "src/ui/act7.ts",
        before:
          "A good-looking avalanche is not security. This affine-only AES — where every output byte depends on every input byte and about half the output bits flip per input-bit flip on average — is still broken by one known plaintext.",
        after: "This affine-only map is broken.",
      },
    ],
    command: [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Independent browser recomputation: affine",
        "--workers=1",
        "--retries=0",
      ],
    ],
  },
  {
    name: "Avalanche counts only low seven bits",
    changes: [
      {
        file: "src/diagnostics.ts",
        before: "n + weight(x)",
        after: "n+weight(x&127)",
      },
    ],
    command: [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Independent browser recomputation: affine",
        "--workers=1",
        "--retries=0",
      ],
    ],
  },
  {
    name: "Heldout reseed replays the attacker stream",
    changes: [
      {
        file: "src/harness.ts",
        before: "hooks.generator(heldoutSeed(seed))",
        after: "hooks.generator(seed ^ 0x6c8e9cf5)",
      },
      {
        file: "src/harness.ts",
        before: "new HeldoutGenerator(heldoutSeed(seed))",
        after: "new HeldoutGenerator(seed ^ 0x6c8e9cf5)",
      },
      {
        file: "src/harness.ts",
        before: 'import { HeldoutGenerator, heldoutSeed } from "./heldout";',
        after: 'import { HeldoutGenerator } from "./heldout";',
      },
    ],
    command: ["npx", ["vitest", "run", "-t", "Invariant 4:|Invariant 4 canary:"]],
    owningTests: [
      "Invariant 4: held-out items never appeared in the attack transcript",
      "Invariant 4 canary: a memorising attack scores 0/32",
    ],
  },
  {
    name: "Control discards real candidates",
    changes: [
      {
        file: "src/harness.ts",
        before: "candidate = recovered.candidate(",
        after: "candidate = control ? null : recovered.candidate(",
      },
    ],
    command: [
      "npx",
      ["vitest", "run", "-t", "Invertible L under the control: real candidates, all fail"],
    ],
    owningTests: ["Invertible L under the control: real candidates, all fail"],
  },
  {
    name: "Control singular explanation deleted",
    changes: [
      {
        file: "src/ui/act7.ts",
        before:
          "No linear model exists; zero plaintext candidates are shown below and independently fail verification.",
        after: "",
      },
    ],
    command: ["npx", ["vitest", "run", "-t", "Singular L under the control"]],
    owningTests: ["Singular L under the control is the expected attack failure (0/32, OK)"],
  },
  {
    name: "xtime uses 0x1d modulus",
    changes: [
      {
        file: "src/gf/gf256.ts",
        before: "? 0x1b : 0",
        after: "? 0x1d : 0",
      },
    ],
    command: [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Every field operation",
        "--workers=1",
        "--retries=0",
      ],
    ],
    owningTests: ["Every field operation and 512 computed S-box entries match FIPS"],
  },
  {
    name: "Attack verdict alarm class becomes ok",
    changes: [
      {
        file: "src/ui/act7.ts",
        before: 'matrixBroken || broken.successes === 32 ? "alarm" : "info"',
        after: 'matrixBroken || broken.successes === 32 ? "ok" : "info"',
      },
    ],
    command: [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Independent browser recomputation: noSub",
        "--workers=1",
        "--retries=0",
      ],
    ],
    owningTests: [
      "Independent browser recomputation: noSub 32 heldout successes and 32 realAES failures",
    ],
  },
  {
    name: "Hidden tabpanel paints",
    changes: [
      {
        file: "src/style.css",
        before: "[hidden]{display:none!important}",
        after: "[hidden]{display:none!important}[role=tabpanel][hidden]{display:block!important}",
      },
    ],
    command: [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Hidden elements never paint",
        "--workers=1",
        "--retries=0",
      ],
    ],
    owningTests: ["Hidden elements never paint in all seven acts and after an attack"],
  },
  {
    name: "Fixture dependency check uses one round",
    changes: [
      {
        file: "src/ui/act7.ts",
        before: "affineByteDependencies(key, 2)",
        after: "affineByteDependencies(key, 1)",
      },
    ],
    command: [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Seeded affine fixture",
        "--workers=1",
        "--retries=0",
      ],
    ],
    owningTests: ["Seeded affine fixture computes every check and the full negative claim"],
  },
  {
    name: "LAT includes the zero-zero mask",
    changes: [
      {
        file: "src/aes/sbox.ts",
        before: "if (a !== 0 && b !== 0) maxBias",
        after: "if (a >= 0 && b >= 0) maxBias",
      },
    ],
    command: ["npx", ["vitest", "run", "-t", "FIPS all256"]],
    owningTests: ["FIPS all256 S-box and inverse entries, exhaustive DDT LAT affine facts"],
  },
  {
    name: "Inverse MixColumns swaps 11 and 13",
    changes: [
      {
        file: "src/aes/state.ts",
        before: "[14, 11, 13, 9],\n    [9, 14, 11, 13],\n    [13, 9, 14, 11],\n    [11, 13, 9, 14]",
        after: "[14, 13, 11, 9],\n    [9, 14, 13, 11],\n    [11, 9, 14, 13],\n    [13, 11, 9, 14]",
      },
    ],
    command: ["npx", ["vitest", "run", "-t", "MDS all69"]],
    owningTests: ["MDS all69 minors, inverse matrix, dependencies and exact order8"],
  },
  {
    name: "Collapse uses MC SR SR",
    changes: [
      {
        file: "src/ui/act7.ts",
        before: "collapsed = shiftRows(mixColumns(shiftRows(plaintext)))",
        after: "collapsed = mixColumns(shiftRows(shiftRows(plaintext)))",
      },
    ],
    command: [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Independent browser recomputation: noSub",
        "--workers=1",
        "--retries=0",
      ],
    ],
    owningTests: [
      "Independent browser recomputation: noSub 32 heldout successes and 32 realAES failures",
    ],
  },
  {
    name: "Keyed round trip omits the ablation config",
    changes: [
      {
        file: "src/diagnostics.ts",
        before: "invCipher(ct, w, undefined, config)",
        after: "invCipher(ct, w, undefined)",
      },
    ],
    command: [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Seeded affine fixture",
        "--workers=1",
        "--retries=0",
      ],
    ],
    owningTests: ["Seeded affine fixture computes every check and the full negative claim"],
  },
  {
    name: "7c splice always copies pair zero",
    changes: [
      {
        file: "src/attack/columns.ts",
        before: "out.set(pair.ciphertext.slice(c * 4, c * 4 + 4), c * 4)",
        after: "out.set(pairs[0].ciphertext.slice(c * 4, c * 4 + 4), c * 4)",
      },
    ],
    command: [
      "npx",
      [
        "playwright",
        "test",
        "e2e/claims.spec.ts",
        "--project=chromium",
        "--grep",
        "Independent browser recomputation: noShift",
        "--workers=1",
        "--retries=0",
      ],
    ],
    owningTests: [
      "Independent browser recomputation: noShift 32 heldout successes and 32 realAES failures",
    ],
  },
  {
    name: "7a larger keys display 7b statistics",
    changes: [
      {
        file: "src/ui/act7.ts",
        before: "largerKeyAvalanche(plaintext, VARIANTS[variant])",
        after: "largerKeyAvalanche(plaintext, VARIANTS.affine)",
      },
    ],
    command: ["npx", ["vitest", "run", "-t", "Larger-key avalanche"]],
    owningTests: ["Larger-key avalanche diagnostics compute each variant with the same plaintext"],
  },
];

for (const c of cases)
  if (c.command[1].includes("--grep") && config) c.command[1].push("--config", config);
const files = [...new Set(cases.flatMap((c) => c.changes.map((x) => x.file)))];
if (
  spawnSync("git", ["diff", "--exit-code", "HEAD", "--", ...files, "src", "e2e", "scripts"], {
    encoding: "utf8",
  }).status !== 0
)
  throw Error("Commit source before mutation checks.");
pass(build, "baseline build");
const baseline = hash(),
  evidence = [];
mkdirSync("mutation-logs", { recursive: true });
for (const { name, changes, command, owningTests } of cases) {
  pass(command, name + ": baseline test");
  const originals = new Map(changes.map((c) => [c.file, readFileSync(c.file, "utf8")]));
  let mutant;
  try {
    for (const { file, before, after } of changes) {
      const s = readFileSync(file, "utf8");
      if (s.split(before).length !== 2) throw Error(name + ": expected unique anchor " + before);
      writeFileSync(file, s.replace(before, after));
    }
    const diff = spawnSync("git", ["diff", "--", ...originals.keys()], { encoding: "utf8" }).stdout;
    if (!diff.trim()) throw Error("Empty mutation");
    pass(build, name + ": mutant build");
    mutant = hash();
    if (mutant === baseline) throw Error("Unchanged bundle");
    const r = run(command),
      output = r.stdout + r.stderr;
    writeFileSync("mutation-logs/" + name.replaceAll(" ", "-") + ".log", output);
    if (r.status === 0 || !/expect\(|AssertionError|Error: expect/.test(output))
      throw Error(name + ": no assertion kill\n" + output);
    if (name === "AES256 extra SubWord omitted")
      pass(
        ["npx", ["vitest", "run", "-t", "FIPS Appendix A1|FIPS 2001 Appendix C AES128"]],
        name + ": unaffected AES128 controls",
      );
    evidence.push({
      name,
      unaffectedControls:
        name === "AES256 extra SubWord omitted"
          ? ["FIPS Appendix A1", "FIPS 2001 Appendix C AES128"]
          : undefined,
      sourceDiff: diff,
      baseline,
      mutant,
      owningTest:
        command[1][
          command[1].includes("--grep")
            ? command[1].indexOf("--grep") + 1
            : command[1].indexOf("-t") + 1
        ],
      owningTests,
      failedTests: output.split("\n").filter((s) => /^\s*(?:FAIL\s|[✘×]\s)/.test(s)),
      assertionFailure: true,
      retries: 0,
    });
  } finally {
    for (const [file, s] of originals) writeFileSync(file, s);
    pass(build, name + ": restore build");
    if (hash() !== baseline) throw Error("Restored artifact differs");
    pass(command, name + ": restored test");
  }
  evidence.at(-1).restoredGreen = true;
  writeFileSync("mutation-evidence.json", JSON.stringify(evidence, null, 2) + "\n");
  console.log(name + ": killed; exact artifact restored; owning test green");
}
console.log(`${evidence.length} of ${cases.length} killed`);
