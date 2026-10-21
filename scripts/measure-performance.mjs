import { build } from "vite";
import { chromium } from "@playwright/test";
import { resolve } from "node:path";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
const out = mkdtempSync(resolve(tmpdir(), "aes-performance-"));
await build({
  configFile: false,
  build: {
    lib: {
      entry: resolve("scripts/performance-entry.ts"),
      name: "AESBench",
      formats: ["iife"],
      fileName: () => "bench.js",
    },
    outDir: out,
    minify: true,
  },
});
const browser = await chromium.launch(
    process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {},
  ),
  page = await browser.newPage();
await page.goto("about:blank");
await page.addScriptTag({ path: resolve(out, "bench.js") });
const runs = [];
for (let i = 0; i < 3; i++) runs.push(await page.evaluate(() => window.AESBench.measure()));
const cdp = await page.context().newCDPSession(page);
await cdp.send("Emulation.setCPUThrottlingRate", { rate: 4 });
const mobileBudgetRuns = [];
for (let i = 0; i < 3; i++)
  mobileBudgetRuns.push(await page.evaluate(() => window.AESBench.measure()));
const result = {
  cpuThrottling:
    "First runs unthrottled; mobileBudgetRuns use Chromium 4× CPU slowdown, a simulation rather than a physical phone",
  mobileBudgetRuns,
  date: new Date().toISOString(),
  browser: browser.version(),
  build:
    "Vite minified IIFE using the same production modules; cold then two warm runs, on the browser main thread",
  runs,
};
writeFileSync("performance-evidence.json", JSON.stringify(result, null, 2) + "\n");
console.log(result);
await browser.close();
