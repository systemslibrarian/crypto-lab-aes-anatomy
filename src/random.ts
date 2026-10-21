/** Reproducible teaching inputs, not cryptographic randomness. Zero is a valid seed. */
export function seeded(seed: number) {
  let state = seed >>> 0;
  return (length = 16) =>
    Uint8Array.from({ length }, () => {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      return state >>> 24;
    });
}
