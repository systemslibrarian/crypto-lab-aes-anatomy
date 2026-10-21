import { test, expect, type Page } from "@playwright/test";
import fips from "../src/data/fips197.json" with { type: "json" };
import { boot, watchPageErrors } from "./gate";
import { referenceAes } from "./reference";
const sbox = fips.sbox.split(" ").map((x) => parseInt(x, 16));
async function attack(page: Page, variant: string) {
  await page.locator("#tab-7").click();
  await page.locator(`input[name=variant][value=${variant}]`).check();
  await page.locator("#run-attack").click();
  await expect(page.locator("#attack-verdict")).toBeVisible();
}
test("Every field operation and 512 computed S-box entries match FIPS", async ({ page }) => {
  await boot(page);
  await expect(page.locator("#result-1")).toContainText("fe");
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
  expect(entries.join("")).toBe(fips.sbox.replaceAll(" ", ""));
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
  expect(inverse.join("")).toBe(fips.inverseSbox.replaceAll(" ", ""));
  await expect(page.locator("[data-check=ddt]")).toHaveAttribute("data-verdict", "pass");
  await expect(page.locator("[data-check=lat]")).toHaveAttribute("data-verdict", "pass");
  await page.locator("#affine-only").check();
  await expect(page.locator("[data-check=affine-identity]")).toHaveAttribute(
    "data-verdict",
    "pass",
  );
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
});
for (const size of [128, 256])
  test(`Browser WebCrypto uses the printed key and plaintext AES${size}`, async ({ page }) => {
    await boot(page);
    await page.locator("#key-size").selectOption(String(size));
    await page.locator("#seeded-preset").click();
    await page.locator("#tab-5").click();
    await page.locator("#webcrypto-check").click();
    await expect(page.locator("#webcrypto-verdict")).toHaveAttribute("data-verdict", "match");
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
  await expect(page.locator("#inverse-verdict")).toHaveAttribute("data-verdict", "match");
  for (const mode of ["forwardKeys", "wrongMix"]) {
    await page.locator("#inverse-mode").selectOption(mode);
    await expect(page.locator("#inverse-verdict")).toHaveAttribute("data-verdict", "mismatch");
  }
});
for (const variant of ["noSub", "affine", "noShift", "noMix"])
  test(`Independent browser recomputation: ${variant} 32 heldout successes and 32 realAES failures`, async ({
    page,
  }) => {
    await boot(page);
    await attack(page, variant);
    await expect(page.locator("#attack-verdict")).toHaveAttribute("data-verdict", "broken");
    await expect(page.locator("#attack-query-count strong")).toHaveText(
      String(variant === "noShift" ? 3 : variant === "noMix" ? 256 : 1),
    );
    const key = await page.locator("#key").inputValue();
    for (const prefix of ["broken", "control"]) {
      const rows = await page
        .locator("." + prefix + "-rows tbody tr")
        .evaluateAll((rows) =>
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
    await expect(page.locator("#control-verdict")).toHaveAttribute("data-verdict", "control-fails");
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
  await expect(page.locator("#attack-verdict")).toHaveAttribute("data-verdict", "partial");
  await expect(page.locator(".broken-rows")).toContainText("·");
  await expect(page.locator(".broken-rows")).toContainText("unknown bytes");
  await page.locator("input[value=noMix]").dispatchEvent("change");
  await expect(page.locator("#attack-verdict")).toHaveAttribute("data-verdict", "partial");
  await page.locator("#key").dispatchEvent("input");
  await expect(page.locator("#attack-verdict")).toHaveAttribute("data-verdict", "partial");
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
  await page.locator("#key-size").selectOption("192");
  await page.locator("#fips-preset").click();
  await page.locator("#webcrypto-check").click();
  await expect(page.locator("#webcrypto-verdict")).toHaveAttribute("data-verdict", "unsupported");
  await page.locator("#plaintext").fill("aa");
  await page.locator("#compute-5").click();
  await expect(page.locator("#notice-5")).toContainText("No padding or truncation");
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
