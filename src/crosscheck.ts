import { cipher } from "./aes/cipher";
import { expand } from "./aes/keyExpansion";
import { equal, type Block } from "./aes/state";
export async function webCryptoCheck(key: Block, plaintext: Block) {
  if (key.length === 24)
    return {
      supported: false,
      match: null,
      own: cipher(plaintext, expand(key).roundKeys),
      web: null,
    };
  const k = await crypto.subtle.importKey("raw", Uint8Array.from(key), "AES-CBC", false, [
      "encrypt",
    ]),
    web = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-CBC", iv: new Uint8Array(16) },
        k,
        Uint8Array.from(plaintext),
      ),
    ).slice(0, 16),
    own = cipher(plaintext, expand(key).roundKeys);
  return { supported: true, match: equal(own, web), own, web };
}
