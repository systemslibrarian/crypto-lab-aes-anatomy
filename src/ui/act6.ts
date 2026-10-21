import { cipher, invCipher, type InverseStep } from "../aes/cipher";
import { expand } from "../aes/keyExpansion";
import { hex, equal, type Block } from "../aes/state";
import { table } from "./common";
export function act6(key: Block, plaintext: Block, fault: "none" | "forwardKeys" | "wrongMix") {
  const w = expand(key).roundKeys,
    ciphertext = cipher(plaintext, w),
    trace: InverseStep[] = [],
    recovered = invCipher(ciphertext, w, trace, undefined, fault),
    matches = equal(recovered, plaintext);
  return `<p>Ciphertext ${hex(ciphertext)}; recovered <code id="inverse-output">${hex(recovered)}</code>.</p><p id="inverse-verdict" data-verdict="${matches ? "match" : "mismatch"}" class="${matches ? "ok" : "alarm"}">${matches ? "✓" : "⚠"} ${matches ? "Inverse cipher matches the original plaintext." : "Deliberately broken inverse does not match the original plaintext."}</p>${table(
    "Inverse cipher layers",
    ["Inverse round", "Layer", "State", "Round key"],
    trace.map((r) => [String(r.round), r.layer, hex(r.state), r.key ? hex(r.key) : "—"]),
  )}<details><summary>Equivalent inverse cipher</summary><p>FIPS 197-upd1 §5.3.5 rearranges the inverse operations using transformed intermediate round keys. This page steps InvCipher from §5.3; EqInvCipher is not implemented.</p></details>`;
}
