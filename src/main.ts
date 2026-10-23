import { splice } from "./attack/columns";
import "./style.css";
import fips from "./data/fips197.json";
import {
  parseHex,
  hex,
  shiftRows,
  mixColumns,
  invMixColumns,
  invShiftRows,
  type Block,
} from "./aes/state";
import { expand } from "./aes/keyExpansion";
import { seeded } from "./random";
import { webCryptoCheck } from "./crosscheck";
import { act1 } from "./ui/act1";
import { act2 } from "./ui/act2";
import { act3 } from "./ui/act3";
import { act4, wordStep } from "./ui/act4";
import { act5 } from "./ui/act5";
import { act6 } from "./ui/act6";
import { act8 } from "./ui/act8";
import { act9 } from "./ui/act9";
import type { SifaDefense, SifaFaultModel } from "./sifa-fixture";
import { grid } from "./ui/common";
const el = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T,
  val = (id: string) => el<HTMLInputElement>(id).value;
const specs = [
  {
    title: "Bytes are polynomials",
    intro:
      "A byte is eight coefficients, each zero or one. Addition is XOR; multiplication combines powers of x and reduces by x⁸ + x⁴ + x³ + x + 1. Extended Euclid finds the multiplier that undoes a nonzero byte.",
    predict: "Will multiplying this byte by {02} need reduction? Look at its top bit.",
    controls:
      '<div class="controls"><label>Byte a (hex)<input id="byte-a" value="57" title="Exactly two hexadecimal digits; 00 has no multiplicative inverse."></label><label>Byte b (hex)<input id="byte-b" value="13" title="The multiplier selects terms from the xtime chain."></label></div>',
  },
  {
    title: "Build the S-box",
    intro:
      "AES first inverts a byte in its finite field, then applies a fixed affine transformation. Construct all entries and compare them with the standard. Removing inversion leaves an affine map, even though its table still looks unfamiliar.",
    controls:
      '<label><input id="affine-only" type="checkbox"> Deliberately broken: show the affine-only table</label>',
  },
  {
    title: "Move and mix",
    intro:
      "A state is four columns of four bytes, indexed r + 4c. ShiftRows moves bytes between columns; MixColumns combines the four bytes in each column. Structural dependency tells us what can influence an output, while a single observed difference can disappear by chance.",
    controls:
      '<button id="layer-step">Step the linear layers on the state grid</button><p id="layer-caption" role="status" aria-live="polite"></p>',
  },
  {
    title: "Expand the key",
    intro:
      "The key schedule supplies a new round key at each stage. RotWord, the real S-box, and round constants break simple patterns between words. AES-256 has an extra SubWord step that AES-128 and AES-192 do not.",
    predict: "Flip the first key byte. Which expanded words change, and from which round onward?",
    controls:
      '<div class="actions"><button id="word-prev">Previous word</button><button id="word-next">Next word</button></div><p id="word-detail" role="status" aria-live="polite"></p>',
  },
  {
    title: "The whole cipher",
    intro:
      "The round transformations now fit together with AddRoundKey. The final round omits MixColumns, leaving a visible gap in the trace. Compare the hand-built cipher with the browser’s independent AES implementation.",
    controls:
      '<div class="actions"><button id="cipher-step">Step one cipher layer</button><button id="webcrypto-check">Run WebCrypto cross-check</button></div><p>WebCrypto checks AES-128 and AES-256 using AES-CBC with zero IV and its first output block. Chromium does not support AES-192; the hand-built 192-bit path is checked with FIPS vectors.</p><div id="webcrypto-result" role="status" aria-live="polite"></div>',
  },
  {
    title: "Reverse the cipher",
    intro:
      "Decryption undoes the transformations in reverse order. InvCipher uses the round keys backward and the inverse column matrix. Try either wrong choice to see a full-length output that still fails to recover the message.",
    controls:
      '<label>Inverse mode<select id="inverse-mode" title="The two broken choices intentionally use the wrong inverse operation."><option value="none">Correct InvCipher</option><option value="forwardKeys">Broken: forward round keys</option><option value="wrongMix">Broken: MixColumns instead of inverse</option></select></label>',
  },
  {
    title: "Remove a layer, run the break",
    intro:
      "Each removed layer creates structure an attacker can use without the key. A separate verifier chooses fresh examples only after the attack finishes. The same attack also runs against full AES, with every control row shown.",
    predict:
      "Can a cipher have a healthy-looking mean avalanche and still be broken by one known pair?",
    controls:
      '<fieldset><legend>Remove one data-path layer (AES-128)</legend><div class="variant-options">' +
      [
        ["real", "Nothing — real AES"],
        ["noSub", "SubBytes — deliberately broken"],
        ["affine", "The inversion — deliberately broken"],
        ["noShift", "ShiftRows — deliberately broken"],
        ["noMix", "MixColumns — deliberately broken"],
      ]
        .map(
          ([v, t]) =>
            `<label><input type="radio" name="variant" value="${v}"${v === "real" ? " checked" : ""}>${t}</label>`,
        )
        .join("") +
      '</div></fieldset><div class="controls"><label>Known pairs for no ShiftRows<input id="pair-count" type="number" min="3" max="20" value="3" title="At least three pairs are required; targets must splice known columns."></label><label>Chosen plaintexts for no MixColumns<input id="byte-count" type="number" min="1" max="256" value="256" title="Fewer than 256 gives a partial codebook. Unknown bytes are shown as dots, never guessed."></label></div><div class="actions"><button id="attack-fixture">Use seeded affine fixture</button><button id="run-attack">Run attack</button><button id="cancel-attack">Cancel attack</button></div><p>SubWord always uses the real S-box. Only the data path is changed. These experiments run at AES-128.</p>',
  },
  {
    title: "Inject a fault, recover the key",
    intro:
      "A transient byte fault just before round-9 MixColumns leaves a structured difference in four ciphertext bytes. Compare correct and faulty outputs, narrow last-round key candidates with the inverse S-box, then reverse the AES-128 key schedule.",
    predict:
      "If each returned ciphertext byte is still a full 8-bit value, what structure could two faulty encryptions reveal about four bytes of the last round key?",
    controls:
      '<div class="actions"><button id="run-dfa" class="primary">Run differential fault recovery</button></div><p>This bounded exercise knows the injected byte location, but the attack is not given the victim key or the nonzero fault value.</p>',
  },
  {
    title: "Keep only accepted outputs, recover a byte",
    intro:
      "A detector can suppress visibly faulty outputs and still leak if the chance of an unchanged execution depends on secret state. Execute a declared first-round AES fault, rank one key byte from observable output selection, and compare a secret-independent control plus two scoped infective cases.",
    predict:
      "If the attacker never sees a faulty ciphertext, can the pattern of which executions survive still depend on the key?",
    controls:
      '<div class="controls"><label>Target S-box output bit<select id="sifa-bit"><option value="0">bit 0</option><option value="1">bit 1</option><option value="2">bit 2</option><option value="3">bit 3</option><option value="4">bit 4</option><option value="5">bit 5</option><option value="6">bit 6</option><option value="7">bit 7</option></select></label><label>Fault selection model<select id="sifa-model"><option value="noisy-stuck-at-zero">Noisy stuck-at-zero fault</option><option value="secret-independent">Secret-independent bit-flip control</option></select></label><label>Output handling<select id="sifa-defense"><option value="reject">Reject detected faults</option><option value="infect-hidden">Infect outputs, no classifier</option><option value="infect-with-validity">Infect outputs + exact reference oracle</option></select></label></div><div class="actions"><button id="run-sifa" class="primary">Run accepted-output ranking</button></div><p>The ranker gets selected plaintext bytes and the target bit only. It does not receive the victim key, internal state, or any per-attempt fault label.</p>',
  },
];
const steps = el("steps"),
  acts = el("acts");
let selected = 0,
  version = 0,
  worker: Worker | null = null,
  wordIndex = 0,
  linearStep = 0,
  cipherStep = 0,
  signature = "",
  ablation = "real";
const initialized = new Set<number>();
const variant = () =>
  document.querySelector<HTMLInputElement>("input[name=variant]:checked")!.value;
function input() {
  const size = Number(val("key-size")),
    key = parseHex(val("key"), [size / 4]),
    plaintext = parseHex(val("plaintext"), [32]);
  if (!/^[0-9a-f]{1,8}$/i.test(val("seed")))
    throw Error("Seed must contain 1…8 hexadecimal digits.");
  return { key, plaintext, seed: parseInt(val("seed"), 16) };
}
function notice(i: number, text: string) {
  el("notice-" + i).textContent = text;
}
function setGrid(state: Block, label: string, animate = false) {
  el("state-grid").innerHTML = grid(state, "AES state, column-major order");
  el("state-label").textContent = label;
  el("state-grid").classList.toggle("state-stepped", animate);
}
function stop(reason: string) {
  version++;
  worker?.terminate();
  worker = null;
  notice(7, reason);
}
function retireAll(reason: string) {
  stop(reason);
  for (let i = 1; i <= 9; i++) {
    el("result-" + i).replaceChildren();
    notice(i, reason);
  }
  for (const id of ["webcrypto-result", "word-detail", "layer-caption"]) el(id).replaceChildren();
  el("state-grid").replaceChildren();
  el("state-label").textContent = "State retired";
  initialized.clear();
  wordIndex = linearStep = cipherStep = 0;
}
function sync() {
  const next = ["key-size", "key", "plaintext", "seed"].map(val).join("|");
  if (next === signature) return;
  signature = next;
  retireAll(
    "Inputs changed: derived trace, keys, matrices and attack results retired. Compute again.",
  );
}
function preset(random = false) {
  const size = Number(val("key-size"));
  if (random) {
    if (!/^[0-9a-f]{1,8}$/i.test(val("seed")))
      throw Error("Seed must contain 1…8 hexadecimal digits.");
    const next = seeded(parseInt(val("seed"), 16));
    el<HTMLInputElement>("key").value = hex(next(size / 8));
    el<HTMLInputElement>("plaintext").value = hex(next());
  } else {
    el<HTMLInputElement>("key").value =
      fips.expansions[size === 128 ? 0 : size === 192 ? 1 : 2].key;
    el<HTMLInputElement>("plaintext").value = fips.appendixB.plaintext;
  }
  sync();
  const v = input();
  setGrid(v.plaintext, "Input block");
  if (selected !== 6) compute(selected + 1);
}
function compute(i: number) {
  try {
    const start = performance.now();
    if (i === 1) {
      const a = parseHex(val("byte-a"), [2])[0],
        b = parseHex(val("byte-b"), [2])[0];
      el("result-1").innerHTML = act1(a, b);
    } else if (i === 2)
      el("result-2").innerHTML = act2(el<HTMLInputElement>("affine-only").checked);
    else {
      const v = input();
      if (i === 3) {
        el("result-3").innerHTML = act3(v.key, v.plaintext);
        linearStep = 0;
        setGrid(v.plaintext, "Input state");
      }
      if (i === 4) {
        el("result-4").innerHTML = act4(v.key);
        wordIndex = Math.min(wordIndex, expand(v.key).words.length - 1);
        el("word-detail").textContent = wordStep(v.key, wordIndex);
      }
      if (i === 5) {
        el("result-5").innerHTML = act5(v.key, v.plaintext).html;
        cipherStep = 0;
        setGrid(v.plaintext, "Input block");
      }
      if (i === 6)
        el("result-6").innerHTML = act6(
          v.key,
          v.plaintext,
          val("inverse-mode") as "none" | "forwardKeys" | "wrongMix",
        );
      if (i === 7) {
        notice(7, "Choose a deliberately broken layer, then run its attack.");
        return;
      }
      if (i === 8) {
        notice(8, "Run the DFA recovery to generate fresh correct/faulty ciphertext pairs for the current AES-128 inputs.");
        return;
      }
      if (i === 9) {
        notice(9, "Run the accepted-output ranking or change the fault model to compare the same-size secret-independent control.");
        return;
      }
    }
    initialized.add(i);
    notice(i, `Computed for the current inputs in ${(performance.now() - start).toFixed(1)} ms.`);
  } catch (e) {
    el("result-" + i).replaceChildren();
    notice(i, (e as Error).message);
  }
}
function activate(index: number) {
  if (selected === 6 && index !== 6 && worker)
    stop("Left attack act; computation cancelled and incomplete.");
  selected = index;
  Array.from(steps.children).forEach((b, i) => {
    b.setAttribute("aria-selected", String(i === index));
    (b as HTMLButtonElement).tabIndex = i === index ? 0 : -1;
  });
  Array.from(acts.children).forEach((a, i) => ((a as HTMLElement).hidden = i !== index));
  if (!initialized.has(index + 1)) compute(index + 1);
}
specs.forEach((spec, index) => {
  const i = index + 1,
    b = document.createElement("button");
  b.className = "step";
  b.id = "tab-" + i;
  b.setAttribute("role", "tab");
  b.setAttribute("aria-controls", "act-" + i);
  b.textContent = i + ". " + spec.title;
  b.onclick = () => activate(index);
  steps.append(b);
  const panel = document.createElement("section");
  panel.id = "act-" + i;
  panel.setAttribute("role", "tabpanel");
  panel.setAttribute("aria-labelledby", b.id);
  panel.tabIndex = 0;
  panel.hidden = i !== 1;
  panel.innerHTML = `<h2>${i}. ${spec.title}</h2><p class="intro">${spec.intro}</p>${spec.predict ? `<details class="predict-prompt"><summary>Predict before revealing</summary><p>${spec.predict}</p></details>` : ""}${spec.controls}${i === 7 || i === 8 || i === 9 ? "" : `<button id="compute-${i}" class="primary">Compute this act</button>`}<p id="notice-${i}" role="status" aria-live="polite"></p><div id="result-${i}" role="status" aria-live="polite"></div>`;
  acts.append(panel);
  if (i !== 7 && i !== 8 && i !== 9) el("compute-" + i).onclick = () => compute(i);
});
for (const id of ["key-size", "key", "plaintext", "seed"]) {
  el(id).addEventListener(id === "key-size" ? "change" : "input", sync);
}
signature = ["key-size", "key", "plaintext", "seed"].map(val).join("|");
for (const [id, random] of [
  ["fips-preset", false],
  ["seeded-preset", true],
] as const)
  el(id).onclick = () => {
    try {
      preset(random);
    } catch (e) {
      el("global-notice").textContent = (e as Error).message;
    }
  };
for (const id of ["byte-a", "byte-b"])
  el(id).addEventListener("input", () => {
    el("result-1").replaceChildren();
    notice(1, "Byte changed: prior arithmetic retired.");
  });
el("affine-only").addEventListener("change", () => compute(2));
el("inverse-mode").addEventListener("change", () => compute(6));
el("run-dfa").onclick = () => {
  try {
    const v = input();
    el("result-8").innerHTML = act8(v.key, v.plaintext);
    initialized.add(8);
    notice(8, "DFA recovery and independent recovered-key verification complete.");
  } catch (e) {
    el("result-8").replaceChildren();
    notice(8, (e as Error).message);
  }
};
function retireSifa(reason: string) {
  el("result-9").replaceChildren();
  initialized.delete(9);
  notice(9, reason);
}
for (const id of ["sifa-bit", "sifa-model", "sifa-defense"])
  el(id).addEventListener("change", () => retireSifa("Fault experiment changed: prior ranking retired."));
el("run-sifa").onclick = () => {
  try {
    const v = input();
    const bit = Number(val("sifa-bit"));
    const model = val("sifa-model") as SifaFaultModel;
    const defense = val("sifa-defense") as SifaDefense;
    el("result-9").innerHTML = act9(v.key, v.plaintext, bit, model, defense, v.seed);
    initialized.add(9);
    notice(9, "Real-AES fault witnesses and accepted-output statistics computed from the current AES-128 inputs.");
  } catch (e) {
    el("result-9").replaceChildren();
    notice(9, (e as Error).message);
  }
};
el("layer-step").onclick = () => {
  try {
    const { plaintext } = input(),
      sr = shiftRows(plaintext),
      mc = mixColumns(sr),
      states = [plaintext, sr, mc, invMixColumns(mc), invShiftRows(invMixColumns(mc))],
      labels = ["Input", "ShiftRows", "MixColumns", "InvMixColumns", "InvShiftRows: back to input"];
    linearStep = (linearStep + 1) % states.length;
    setGrid(states[linearStep], labels[linearStep], true);
    el("layer-caption").textContent = labels[linearStep];
  } catch (e) {
    notice(3, (e as Error).message);
  }
};
for (const [id, direction] of [
  ["word-prev", -1],
  ["word-next", 1],
] as const)
  el(id).onclick = () => {
    try {
      const { key } = input();
      wordIndex = Math.max(0, Math.min(expand(key).words.length - 1, wordIndex + direction));
      el("word-detail").textContent = wordStep(key, wordIndex);
    } catch (e) {
      notice(4, (e as Error).message);
    }
  };
el("cipher-step").onclick = () => {
  try {
    const v = input(),
      { trace } = act5(v.key, v.plaintext),
      layers = trace.flatMap((r) =>
        r.round
          ? [
              { state: r.sub, label: `Round ${r.round} SubBytes` },
              { state: r.shift, label: `Round ${r.round} ShiftRows` },
              ...(r.mix ? [{ state: r.mix, label: `Round ${r.round} MixColumns` }] : []),
              {
                state: r.output,
                label: `Round ${r.round} AddRoundKey${r.mix ? "" : " — final round omitted MixColumns"}`,
              },
            ]
          : [{ state: r.output, label: "Initial AddRoundKey" }],
      );
    const next = layers[cipherStep % layers.length];
    cipherStep++;
    setGrid(next.state, next.label, true);
  } catch (e) {
    notice(5, (e as Error).message);
  }
};
el("webcrypto-check").onclick = async () => {
  try {
    const v = input(),
      stamp = version,
      r = await webCryptoCheck(v.key, v.plaintext);
    if (stamp !== version) return;
    el("webcrypto-result").innerHTML =
      `<p id="webcrypto-verdict" data-verdict="${r.supported ? (r.match ? "match" : "mismatch") : "unsupported"}" class="${r.supported ? (r.match ? "ok" : "alarm") : "info"}">${r.supported ? (r.match ? "✓ Independent WebCrypto matches." : "⚠ Independent WebCrypto differs.") : "ⓘ AES-192 is unsupported by Chromium WebCrypto; FIPS vectors cover this path."}</p><p>Key <code id="web-key">${hex(v.key)}</code>; plaintext <code id="web-plaintext">${hex(v.plaintext)}</code>; hand-built <code id="web-own">${hex(r.own)}</code>${r.web ? '; WebCrypto <code id="web-output">' + hex(r.web) + "</code>" : ""}.</p>`;
  } catch (e) {
    notice(5, (e as Error).message);
  }
};
function retireAttack(reason: string) {
  stop(reason);
  el("result-7").replaceChildren();
}
for (const radio of document.querySelectorAll<HTMLInputElement>("input[name=variant]"))
  radio.addEventListener("change", () => {
    const now = variant();
    if (now === ablation) return;
    ablation = now;
    retireAttack("Ablation changed: previous attack retired.");
  });
for (const id of ["pair-count", "byte-count"])
  el(id).addEventListener("input", () =>
    retireAttack("Query budget changed: previous attack retired."),
  );
el("run-attack").onclick = () => {
  try {
    retireAttack("Preparing attack…");
    if (variant() === "real") {
      notice(
        7,
        "Real AES is selected. No layer is removed; choose a deliberately broken variant to run the paired experiment.",
      );
      return;
    }
    const v = input();
    if (v.key.length !== 16)
      throw Error("Attack acts run at AES-128 only. Select 128 and load or generate its key.");
    const count = Number(val(variant() === "noShift" ? "pair-count" : "byte-count")),
      stamp = version;
    worker = new Worker(new URL("./attack.worker.ts", import.meta.url), { type: "module" });
    notice(7, "Attack running; the held-out generator has not been supplied to the attack.");
    worker.onmessage = (e) => {
      if (stamp !== version) return;
      if (e.data.ok) {
        el("result-7").innerHTML = e.data.html;
        notice(
          7,
          `Attack and independent held-out verification complete. Worker ${e.data.elapsed.toFixed(1)} ms.`,
        );
      } else notice(7, e.data.error);
      worker?.terminate();
      worker = null;
    };
    worker.onerror = () => {
      if (stamp === version) notice(7, "Worker failed; no recovery is asserted.");
      worker?.terminate();
      worker = null;
    };
    worker.postMessage({ variant: variant(), ...v, count });
  } catch (e) {
    notice(7, (e as Error).message);
  }
};
el("cancel-attack").onclick = () =>
  retireAttack("Attack cancelled; incomplete, with no recovery asserted.");
el("attack-fixture").onclick = () => {
  try {
    el<HTMLSelectElement>("key-size").value = "128";
    preset(true);
    document.querySelector<HTMLInputElement>("input[name=variant][value=affine]")!.checked = true;
    ablation = "affine";
    retireAttack("Seeded AES-128 affine-only fixture loaded. Run the attack.");
  } catch (e) {
    notice(7, (e as Error).message);
  }
};
steps.addEventListener("keydown", (e) => {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) return;
  e.preventDefault();
  activate(
    e.key === "Home" ? 0 : e.key === "End" ? 8 : (selected + (e.key === "ArrowRight" ? 1 : 8)) % 9,
  );
  (steps.children[selected] as HTMLElement).focus();
});
setGrid(input().plaintext, "Input block");
activate(0);

el("result-7").addEventListener("click", (e) => {
  if ((e.target as HTMLElement).id !== "try-splice") return;
  try {
    const known = Array.from(
      document.querySelector(".known-pairs")!.querySelectorAll("tbody tr"),
      (r) => {
        const cells = r.querySelectorAll("td");
        return {
          plaintext: parseHex(cells[0].textContent!, [32]),
          ciphertext: parseHex(cells[1].textContent!, [32]),
        };
      },
    );
    el("splice-result").textContent =
      "Forged candidate ciphertext: " +
      hex(splice(known, parseHex(val("splice-target"), [32]))) +
      ". This is a candidate, not a claim of a break on full AES.";
  } catch (e) {
    el("splice-result").textContent = (e as Error).message;
  }
});
