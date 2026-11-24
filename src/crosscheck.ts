import { cipher } from "./aes/cipher";
import { expand } from "./aes/keyExpansion";
import { equal, type Block } from "./aes/state";
export async function webCryptoCheck(key: Block, plaintext: Block) {
  const own = cipher(plaintext, expand(key).roundKeys);
  let k: CryptoKey;
  try {
    k = await crypto.subtle.importKey("raw", Uint8Array.from(key), "AES-CBC", false, ["encrypt"]);
  } catch (error) {
    if (
      key.length === 24 &&
      error instanceof DOMException &&
      (error.name === "NotSupportedError" || error.name === "OperationError")
    ) {
      return { supported: false, match: null, own, web: null };
    }
    throw error;
  }
  const web = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-CBC", iv: new Uint8Array(16) },
      k,
      Uint8Array.from(plaintext),
    ),
  ).slice(0, 16);
  return { supported: true, match: equal(own, web), own, web };
}
