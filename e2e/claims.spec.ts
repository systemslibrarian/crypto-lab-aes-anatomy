import { createHash } from "node:crypto";
import { runBreak } from "../src/harness";
import { act7 } from "../src/ui/act7";
import { seeded } from "../src/random";
import { test, expect, type Page, type Locator } from "@playwright/test";
import fips from "../src/data/fips197.json" with { type: "json" };
import { boot, watchPageErrors } from "./gate";
import { referenceAes } from "./reference";
const sbox = fips.sbox.split(" ").map((x) => parseInt(x, 16));
async function expectVerdict(locator: Locator, verdict: string, cls: string) {
  await expect(locator).toHaveAttribute("data-verdict", verdict);
  await expect(locator).toHaveClass(cls);
}
async function expectChecks(root: Locator) {
  const checks = root.locator("[data-check]");
  expect(await checks.count()).toBeGreaterThan(0);
  for (const check of await checks.all()) await expectVerdict(check, "pass", "ok");
}
async function expectScore(
  page: Page,
  verdict: "attack" | "control",
  prefix: "broken" | "control",
) {
  const text = await page.locator(`#${verdict}-verdict`).innerText();
  const score = text.match(/(\d+)\/(\d+)/);
  expect(score, `${verdict} verdict must show N/M`).not.toBeNull();
  const rows = page.locator(`.${prefix}-rows tbody tr`);
  expect(Number(score![2])).toBe(await rows.count());
  expect(Number(score![1])).toBe(await rows.locator('[data-match="true"]').count());
}
async function expectHiddenNotPainted(page: Page) {
  const hidden = page.locator("[hidden]");
  expect(await hidden.count()).toBeGreaterThanOrEqual(7);
  expect(
    await hidden.evaluateAll((nodes) =>
      nodes
        .filter((node) => getComputedStyle(node).display !== "none")
        .map((node) => node.id || node.outerHTML),
    ),
  ).toEqual([]);
}
const negativeClaim =
  "FULL AVALANCHE (MEAN) — AND BROKEN BY ONE KNOWN PAIR. A good-looking avalanche is not security. This affine-only AES — where every output byte depends on every input byte and about half the output bits flip per input-bit flip on average — is still broken by one known plaintext.";
async function attack(page: Page, variant: string) {
  await page.locator("#tab-7").click();
  await page.locator(`input[name=variant][value=${variant}]`).check();
  await page.locator("#run-attack").click();
  await expect(page.locator("#attack-verdict")).toBeVisible();
}
test("Every field operation and 512 computed S-box entries match FIPS", async ({ page }) => {
  await boot(page);
  // Independent polynomial arithmetic: no production GF256 helper is used.
  for (const [aHex, bHex] of [
    ["57", "13"],
    ["80", "83"],
  ]) {
    await page.locator("#byte-a").fill(aHex);
    await page.locator("#byte-b").fill(bHex);
    await page.locator("#compute-1").click();
    const a = parseInt(await page.locator("#field-a").innerText(), 16);
    const b = parseInt(await page.locator("#byte-b").inputValue(), 16);
    expect(a).toBe(parseInt(aHex, 16));
    expect(b).toBe(parseInt(bHex, 16));
    const shift = a << 1;
    const xtime = shift & 0x100 ? shift ^ 0x11b : shift;
    let product = 0;
    for (let bit = 0; bit < 8; bit++) if (b & (1 << bit)) product ^= a << bit;
    for (let degree = 14; degree >= 8; degree--)
      if (product & (1 << degree)) product ^= 0x11b << (degree - 8);
    expect(parseInt(await page.locator("#field-xtime").innerText(), 16)).toBe(xtime);
    expect(parseInt(await page.locator("#field-product").innerText(), 16)).toBe(product);
    await expectChecks(page.locator("#result-1"));
  }
  await page.locator("#byte-a").fill("00");
  await page.locator("#compute-1").click();
  await expect(page.locator("#result-1")).toContainText("no inverse");
  await page.locator("#tab-2").click();
  const entries = await page.locator(".sbox-table tbody tr").evaluateAll((rows) =>
    rows.flatMap((r) =>
      Array.from(r.querySelectorAll("td"))
        .slice(1)
        .map((t) => t.textContent),
    ),
  );
  const joined = entries.join("").toLowerCase();
  expect(joined).toMatch(/^[0-9a-f]{512}$/);
  expect(joined).toBe(fips.sbox.replaceAll(" ", ""));
  expect(createHash("sha256").update(joined).digest("hex")).toBe(
    "0236816432b73ddeac16f0cd28c85e90b0f2047f9c6c8e3dc290e8dcb2ed2b24",
  );
  expect(entries[0x53]).toBe("ed");
  expect(entries[0x00]).toBe("63");
  await page.locator("#act-2 details summary").click();
  const inverse = await page
    .getByRole("region", { name: "Computed inverse S-box", exact: true })
    .locator("tbody tr")
    .evaluateAll((rows) =>
      rows.flatMap((r) =>
        Array.from(r.querySelectorAll("td"))
          .slice(1)
          .map((t) => t.textContent),
      ),
    );
  const inverseJoined = inverse.join("").toLowerCase();
  expect(inverseJoined).toMatch(/^[0-9a-f]{512}$/);
  expect(inverseJoined).toBe(fips.inverseSbox.replaceAll(" ", ""));
  expect(createHash("sha256").update(inverseJoined).digest("hex")).toBe(
    "c9addd5a7445595a20466dc976e1b89af354e44a04f28c2cc019d2582e4f1c14",
  );
  await expectChecks(page.locator("#result-2"));
  await expectVerdict(page.locator("[data-check=ddt]"), "pass", "ok");
  await expectVerdict(page.locator("[data-check=lat]"), "pass", "ok");
  await page.locator("#affine-only").check();
  await expectVerdict(page.locator("[data-check=affine-identity]"), "pass", "ok");
});
test("All key words and Appendix B states including AddRoundKey XOR are independently checked", async ({
  page,
}) => {
  await boot(page);
  for (const [idx, size] of [128, 192, 256].entries()) {
    await page.locator("#key-size").selectOption(String(size));
    await page.locator("#fips-preset").click();
    await page.locator("#tab-4").click();
    await page.locator("#compute-4").click();
    const words = await page
      .locator(".word-table tbody tr")
      .evaluateAll((rows) => rows.map((r) => r.querySelectorAll("td")[1].textContent));
    expect(words).toEqual(fips.expansions[idx].words);
    await expectChecks(page.locator("#result-4"));
  }
  await page.locator("#key-size").selectOption("128");
  await page.locator("#fips-preset").click();
  await page.locator("#tab-5").click();
  const rows = await page
    .locator(".cipher-trace tbody tr")
    .evaluateAll((rows) =>
      rows.map((r) => Array.from(r.querySelectorAll("td"), (c) => c.textContent!)),
    );
  expect(rows).toHaveLength(11);
  for (const row of rows) {
    const parse = (s: string) => s.match(/../g)!.map((x) => parseInt(x, 16));
    expect(parse(row[5]).map((x, i) => x ^ parse(row[6])[i])).toEqual(parse(row[7]));
  }
  for (let i = 1; i < 11; i++) {
    expect(rows[i].slice(1, 4)).toEqual([
      fips.appendixB.rounds[i - 1].input,
      fips.appendixB.rounds[i - 1].sub,
      fips.appendixB.rounds[i - 1].shift,
    ]);
    expect(rows[i][7]).toBe(fips.appendixB.rounds[i - 1].output);
  }
  expect(rows[10][4]).toBe("OMITTED IN LAST ROUND");
  await expectChecks(page.locator("#result-5"));
});
for (const size of [128, 256])
  test(`Browser WebCrypto uses the printed key and plaintext AES${size}`, async ({ page }) => {
    await boot(page);
    await page.locator("#key-size").selectOption(String(size));
    await page.locator("#seeded-preset").click();
    await page.locator("#tab-5").click();
    await page.locator("#webcrypto-check").click();
    await expectVerdict(page.locator("#webcrypto-verdict"), "match", "ok");
    const key = await page.locator("#web-key").innerText(),
      plaintext = await page.locator("#web-plaintext").innerText(),
      independent = await page.evaluate(referenceAes, { key, plaintext, variant: "real", sbox });
    expect(await page.locator("#web-output").innerText()).toBe(independent);
    const web = await page.evaluate(
      async ({ key, plaintext }) => {
        const parse = (s: string) => Uint8Array.from(s.match(/../g)!, (x) => parseInt(x, 16)),
          k = await crypto.subtle.importKey("raw", parse(key), "AES-CBC", false, ["encrypt"]),
          ct = new Uint8Array(
            await crypto.subtle.encrypt(
              { name: "AES-CBC", iv: new Uint8Array(16) },
              k,
              parse(plaintext),
            ),
          );
        return Array.from(ct.slice(0, 16), (x) => x.toString(16).padStart(2, "0")).join("");
      },
      { key, plaintext },
    );
    expect(web).toBe(independent);
  });
test("Inverse correct, forward-key and wrong-mix modes show computed mismatches", async ({
  page,
}) => {
  await boot(page);
  await page.locator("#tab-6").click();
  await expectVerdict(page.locator("#inverse-verdict"), "match", "ok");
  for (const mode of ["forwardKeys", "wrongMix"]) {
    await page.locator("#inverse-mode").selectOption(mode);
    await expectVerdict(page.locator("#inverse-verdict"), "mismatch", "alarm");
  }
});
for (const variant of ["noSub", "affine", "noShift", "noMix"])
  test(`Independent browser recomputation: ${variant} 32 heldout successes and 32 realAES failures`, async ({
    page,
  }) => {
    await boot(page);
    await attack(page, variant);
    await expectVerdict(page.locator("#attack-verdict"), "broken", "alarm");
    await expect(page.locator("#attack-query-count strong")).toHaveText(
      String(variant === "noShift" ? 3 : variant === "noMix" ? 256 : 1),
    );
    const key = await page.locator("#key").inputValue();
    for (const prefix of ["broken", "control"]) {
      const rows = await page.locator("." + prefix + "-rows tbody tr").evaluateAll((rows) =>
        rows.map((r) => ({
          plaintext: r.querySelector("[data-plain]")!.getAttribute("data-plain")!,
          ciphertext: r.querySelector("[data-cipher]")!.getAttribute("data-cipher")!,
          candidate: r.querySelector("[data-candidate]")!.getAttribute("data-candidate")!,
          match: r.querySelector("[data-match]")!.getAttribute("data-match"),
        })),
      );
      expect(rows).toHaveLength(32);
      for (const row of rows) {
        const cipherVariant = prefix === "control" ? "real" : variant;
        expect(
          await page.evaluate(referenceAes, {
            key,
            plaintext: row.plaintext,
            variant: cipherVariant,
            sbox,
          }),
        ).toBe(row.ciphertext);
        const candidateCt =
          variant === "noShift"
            ? row.candidate
            : await page.evaluate(referenceAes, {
                key,
                plaintext: row.candidate,
                variant: cipherVariant,
                sbox,
              });
        expect(candidateCt === row.ciphertext).toBe(prefix === "broken");
        expect(row.match).toBe(String(prefix === "broken"));
      }
    }
    await expectVerdict(page.locator("#control-verdict"), "control-fails", "ok");
    await expectScore(page, "attack", "broken");
    await expectScore(page, "control", "control");
    if (variant === "noSub" || variant === "affine") {
      await expectChecks(page.locator("#result-7"));
      await expect(page.locator("#control-verdict")).toContainText("No linear model exists");
    }
    if (variant === "affine") {
      await expect(page.locator("#affine-fixture-checks [data-verdict=pass]")).toHaveCount(3);
      await expect(page.locator("#affine-negative")).toContainText(
        "A good-looking avalanche is not security.",
      );
    }
    if (variant === "noShift") {
      await page.locator("#try-splice").click();
      await expect(page.locator("#splice-result")).toContainText("appears in no known pair");
    }
  });
test("Partial codebooks visibly retain unknown bytes and retire on genuine changes", async ({
  page,
}) => {
  await boot(page);
  await page.locator("#tab-7").click();
  await page.locator("#byte-count").fill("16");
  await attack(page, "noMix");
  await expectVerdict(page.locator("#attack-verdict"), "partial", "info");
  await expect(page.locator(".broken-rows")).toContainText("·");
  await expect(page.locator(".broken-rows")).toContainText("unknown bytes");
  await expectScore(page, "attack", "broken");
  await expectScore(page, "control", "control");
  await page.locator("input[value=noMix]").dispatchEvent("change");
  await expectVerdict(page.locator("#attack-verdict"), "partial", "info");
  await page.locator("#key").dispatchEvent("input");
  await expectVerdict(page.locator("#attack-verdict"), "partial", "info");
  await page.locator("#seed").fill("1");
  await expect(page.locator("#result-7")).toBeEmpty();
  await expect(page.locator("#state-grid")).toBeEmpty();
});
test("Invalid input lengths, unsupported192, cancellation, and mid-flight retirement", async ({
  page,
}) => {
  const errors = watchPageErrors(page);
  await boot(page);
  await page.locator("#tab-5").click();
  await page.locator("#key").fill("aa");
  await page.locator("#compute-5").click();
  await expect(page.locator("#notice-5")).toContainText("No padding or truncation");
  await expect(page.locator("#notice-5")).toContainText("found 2");
  await page.locator("#key-size").selectOption("192");
  await page.locator("#fips-preset").click();
  await page.locator("#webcrypto-check").click();
  await expectVerdict(page.locator("#webcrypto-verdict"), "unsupported", "info");
  await page.locator("#plaintext").fill("aa");
  await page.locator("#compute-5").click();
  await expect(page.locator("#notice-5")).toContainText("No padding or truncation");
  await expect(page.locator("#notice-5")).toContainText("found 2");
  await page.locator("#key-size").selectOption("128");
  await page.locator("#fips-preset").click();
  await page.locator("#tab-7").click();
  await page.locator("input[value=affine]").check();
  await page.locator("#run-attack").click();
  await page.locator("#cancel-attack").click();
  await expect(page.locator("#result-7")).toBeEmpty();
  await expect(page.locator("#notice-7")).toContainText("cancelled");
  await page.locator("#run-attack").click();
  await page.locator("#key-size").selectOption("256");
  await expect(page.locator("#result-7")).toBeEmpty();
  await expect(page.locator("#notice-7")).toContainText("retired");
  expect(errors).toEqual([]);
});
test("Invisible focus probe demonstrates the focus gate is live", async ({ page }) => {
  await boot(page);
  const { expectNoInvisibleFocusTargets } = await import("./gate");
  await page.evaluate(() => {
    const b = document.createElement("button");
    b.textContent = "probe";
    b.style.opacity = "0";
    document.body.append(b);
  });
  await expect(expectNoInvisibleFocusTargets(page, "deliberate probe")).rejects.toThrow(
    "focusable elements that paint nothing",
  );
});

test("Control with an invertible linear model", async ({ page }) => {
  await boot(page);
  await page.locator("#seed").fill("1");
  await page.locator("#seeded-preset").click();
  await attack(page, "noSub");
  await expectVerdict(page.locator("#attack-verdict"), "broken", "alarm");
  await expectVerdict(page.locator("#control-verdict"), "control-fails", "ok");
  await expect(page.locator("#control-verdict")).not.toContainText("No linear model exists");
  const key = await page.locator("#key").inputValue();
  const rows = await page.locator(".control-rows tbody tr").evaluateAll((rows) =>
    rows.map((r) => ({
      plaintext: r.querySelector("[data-plain]")!.getAttribute("data-plain")!,
      ciphertext: r.querySelector("[data-cipher]")!.getAttribute("data-cipher")!,
      candidate: r.querySelector("[data-candidate]")!.getAttribute("data-candidate")!,
      match: r.querySelector("[data-match]")!.getAttribute("data-match"),
    })),
  );
  expect(rows).toHaveLength(32);
  for (const row of rows) {
    expect(row.candidate).not.toBe("0".repeat(32));
    expect(
      await page.evaluate(referenceAes, { key, plaintext: row.plaintext, variant: "real", sbox }),
    ).toBe(row.ciphertext);
    expect(
      await page.evaluate(referenceAes, { key, plaintext: row.candidate, variant: "real", sbox }),
    ).not.toBe(row.ciphertext);
    expect(row.match).toBe("false");
  }
  await expectScore(page, "attack", "broken");
  await expectScore(page, "control", "control");
});

test("DFA display independently verifies recovered AES-128 key and candidate narrowing", async ({ page }) => {
  await boot(page);
  await page.locator("#tab-8").click();
  await page.locator("#run-dfa").click();
  const root = page.locator("#result-8");
  await expectChecks(root);

  const rows = await root.locator(".dfa-table tbody tr").evaluateAll((trs) =>
    trs.map((tr) => Array.from(tr.querySelectorAll("td"), (td) => td.textContent!.trim())),
  );
  expect(rows).toHaveLength(4);
  for (const [column, row] of rows.entries()) {
    const expectedPositions = [0, 1, 2, 3].map(
      (r) => r + 4 * ((column - r + 4) % 4),
    );
    expect(row[0]).toBe(String(column));
    expect(row[1]).toBe(expectedPositions.join(", "));
    expect(
      row[2]
        .split(",")
        .map(Number)
        .sort((a, b) => a - b),
    ).toEqual([...expectedPositions].sort((a, b) => a - b));
    expect(Number(row[3])).toBeGreaterThan(1);
    expect(Number(row[3])).toBeLessThan(1024);
    expect(Number(row[5])).toBe(1);
    expect(Number(row[6])).toBeGreaterThanOrEqual(2);
    expect(row[7]).toMatch(/^(?:[0-9a-f]{2} ){3}[0-9a-f]{2}$/);
  }

  const displayedRound10 = await page.locator("#dfa-round10").innerText();
  expect(displayedRound10).toBe(fips.appendixB.rounds[9].key);

  const displayedMaster = await page.locator("#dfa-master").innerText();
  expect(displayedMaster).toBe(await page.locator("#key").inputValue());

  const plaintext = await page.locator("#plaintext").inputValue();
  const independent = await page.evaluate(referenceAes, {
    key: displayedMaster,
    plaintext,
    variant: "real",
    sbox,
  });
  expect(independent).toBe(await page.locator("#dfa-correct").innerText());

  const heldoutPlaintext = await page.locator("#dfa-heldout-plaintext").innerText();
  const heldoutExpected = await page.evaluate(referenceAes, {
    key: displayedMaster,
    plaintext: heldoutPlaintext,
    variant: "real",
    sbox,
  });
  expect(heldoutExpected).toBe(await page.locator("#dfa-heldout-correct").innerText());

  await expect(root.locator("[data-check=dfa-heldout]")).toHaveAttribute("data-verdict", "pass");
  await expect(root.locator("[data-check=dfa-recompute]")).toHaveAttribute("data-verdict", "pass");
  await expect(root.locator("[data-check=dfa-wrong-model]")).toHaveAttribute("data-verdict", "pass");
  await expect(root).toContainText("attack is not given the victim key or the nonzero fault value");
  await expect(root).toContainText("common-mode fault");
  await expect(root).toContainText("ineffective-fault leakage is a separate next lesson");
});

test("Hidden elements never paint in all eight acts and after an attack", async ({ page }) => {
  await boot(page);
  for (let n = 1; n <= 8; n++) {
    await page.locator(`#tab-${n}`).click();
    await expectHiddenNotPainted(page);
  }
  await attack(page, "affine");
  await expectHiddenNotPainted(page);
});

test("Valid key change retires every act and all auxiliary results", async ({ page }) => {
  await boot(page);
  for (let n = 1; n <= 6; n++) {
    await page.locator(`#tab-${n}`).click();
    await page.locator(`#compute-${n}`).click();
    await expect(page.locator(`#result-${n}`)).not.toBeEmpty();
    if (n <= 5) await expectChecks(page.locator(`#result-${n}`));
    if (n === 3) await page.locator("#layer-step").click();
    if (n === 4) await page.locator("#word-next").click();
    if (n === 5) {
      await page.locator("#webcrypto-check").click();
      await expectVerdict(page.locator("#webcrypto-verdict"), "match", "ok");
    }
  }
  await attack(page, "noSub");
  await page.locator("input[value=noSub]").dispatchEvent("change");
  await expectVerdict(page.locator("#attack-verdict"), "broken", "alarm");
  await page.locator("#tab-8").click();
  await page.locator("#run-dfa").click();
  await expect(page.locator("#result-8 [data-check=dfa-master]")).toHaveAttribute("data-verdict", "pass");
  for (let n = 1; n <= 8; n++) await expect(page.locator(`#result-${n}`)).not.toBeEmpty();
  for (const id of ["webcrypto-result", "word-detail", "layer-caption"])
    await expect(page.locator(`#${id}`)).not.toBeEmpty();
  await page.locator("#key").fill("000102030405060708090a0b0c0d0e0f");
  for (let n = 1; n <= 8; n++) {
    await expect(page.locator(`#result-${n}`)).toBeEmpty();
    await expect(page.locator(`#notice-${n}`)).toContainText("retired");
  }
  for (const id of ["webcrypto-result", "word-detail", "layer-caption"])
    await expect(page.locator(`#${id}`)).toBeEmpty();
});

test("Seeded affine fixture computes every check and the full negative claim", async ({ page }) => {
  await boot(page);
  await page.locator("#tab-7").click();
  await page.locator("#attack-fixture").click();
  await expect(page.locator("#key-size")).toHaveValue("128");
  await expect(page.locator("#key")).toHaveValue("78e67caedfca8b764fbdc9a636c8f383");
  await page.locator("#run-attack").click();
  await expectVerdict(page.locator("#attack-verdict"), "broken", "alarm");
  await expectChecks(page.locator("#result-7"));
  await expect(page.locator('#result-7 [data-verdict="fail"]')).toHaveCount(0);
  await expect(page.locator("#affine-fixture-checks [data-check]")).toHaveCount(3);
  await expectVerdict(page.locator("#control-verdict"), "control-fails", "ok");
  await expect(page.locator("#affine-negative")).toBeVisible();
  await expect(page.locator("#affine-negative")).toHaveText(negativeClaim);
  await expectScore(page, "attack", "broken");
  await expectScore(page, "control", "control");
});

test("Singular affine recovery renders an implementation alarm", async ({ page }) => {
  await boot(page);
  await page.locator("#tab-7").click();
  // Inject at the test-only harness seam, then mount the actual production renderer.
  // No fault control is exposed to learners and no verdict HTML is mocked.
  const key = seeded(3)(),
    plaintext = seeded(4)();
  const result = await runBreak("affine", key, 3, 256, { injectColumns: Array(128).fill(0n) });
  await page.locator("#result-7").evaluate(
    (el, html) => {
      el.innerHTML = html;
    },
    act7(result, "affine", key, plaintext),
  );
  await expectVerdict(page.locator("#attack-verdict"), "implementation-error", "alarm");
  await expectScore(page, "attack", "broken");
  await expectScore(page, "control", "control");
  await expectVerdict(page.locator("#control-verdict"), "control-fails", "ok");
});
