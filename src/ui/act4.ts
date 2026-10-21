import fips from "../data/fips197.json";
import { expand } from "../aes/keyExpansion";
import { hex, parseHex, type Block, equal } from "../aes/state";
import { table, check } from "./common";
export function act4(key: Block) {
  const e = expand(key),
    changed = key.slice();
  changed[0] ^= 1;
  const other = expand(changed),
    kat = fips.expansions.find((x) => x.key.length === key.length * 2)!,
    computed = expand(parseHex(kat.key, [kat.key.length])).words;
  return `<p>Nk = ${e.Nk}; Nr = ${e.Nr}; <span id="word-count">${e.words.length}</span> words. SubWord always uses the real S-box, including during data-path ablations.</p>${check(
    "key-expansion",
    computed.every((w, i) => hex(w) === kat.words[i]),
    `Every word matches FIPS Appendix A.${e.Nk === 4 ? 1 : e.Nk === 6 ? 2 : 3} for its published key.`,
  )}<p>Prediction experiment: bit 0 of key byte 0 was flipped. Highlighted words differ; unmarked words are identical.</p>${table(
    "Expanded round-key words",
    ["i", "Word", "Compared with one-byte change", "Operation"],
    e.steps.map((s) => [
      String(s.index),
      `<span class="word" data-index="${s.index}">${hex(s.word)}</span>`,
      equal(s.word, other.words[s.index])
        ? "same"
        : `<strong class="changed">changed → ${hex(other.words[s.index])}</strong>`,
      s.rotated
        ? "RotWord → SubWord → Rcon → XOR prior word"
        : s.extra
          ? "Nk=8 extra SubWord → XOR prior word"
          : s.back
            ? "XOR prior word"
            : "input key",
    ]),
    "word-table",
  )}<p>Reverse direction: <a href="https://systemslibrarian.github.io/crypto-lab-glass-box/">Glass Box’s key-schedule inversion</a>.</p>`;
}
export function wordStep(key: Block, index: number) {
  const s = expand(key).steps[index];
  return `w[${index}] = ${hex(s.word)}. Previous ${hex(s.previous)}; ${s.rotated ? "RotWord " + hex(s.rotated) + "; " : ""}${s.substituted ? "SubWord " + hex(s.substituted) + "; " : ""}${s.rcon !== undefined ? "Rcon " + s.rcon.toString(16).padStart(2, "0") + "000000; " : ""}transformed ${hex(s.transformed)}; ${s.back ? "XOR w[i−Nk] " + hex(s.back) : "original key word"}.${s.extra ? " Nk = 8 extra SubWord at i mod 8 = 4." : ""}`;
}
