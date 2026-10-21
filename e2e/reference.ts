/** Browser-side independent FIPS table implementation: no production imports. */
export function referenceAes(args: {
  key: string;
  plaintext: string;
  variant: string;
  sbox: number[];
}) {
  const { sbox } = args,
    parse = (s: string) => s.match(/../g)!.map((x) => parseInt(x, 16)),
    key = parse(args.key),
    p = parse(args.plaintext),
    nk = key.length / 4,
    nr = nk + 6,
    words: number[][] = [];
  const xt = (x: number) => ((x * 2) ^ (x >= 128 ? 283 : 0)) & 255,
    mul = (a: number, b: number) => {
      let c = 0;
      while (b) {
        if (b & 1) c ^= a;
        a = xt(a);
        b >>= 1;
      }
      return c;
    };
  let rc = 1;
  for (let i = 0; i < 4 * (nr + 1); i++) {
    if (i < nk) {
      words.push(key.slice(4 * i, 4 * i + 4));
      continue;
    }
    let t = words[i - 1].slice();
    if (i % nk === 0) {
      t = [sbox[t[1]] ^ rc, sbox[t[2]], sbox[t[3]], sbox[t[0]]];
      rc = xt(rc);
    } else if (nk === 8 && i % nk === 4) t = t.map((x) => sbox[x]);
    words.push(t.map((x, j) => x ^ words[i - nk][j]));
  }
  const add = (a: number[], r: number) =>
    a.map((x, i) => x ^ words[4 * r + Math.floor(i / 4)][i % 4]);
  let state = add(p, 0);
  for (let r = 1; r <= nr; r++) {
    state = state.map((x) => {
      if (args.variant === "noSub") return x;
      if (args.variant !== "affine") return sbox[x];
      let y = x ^ 99;
      for (let i = 1; i <= 4; i++) y ^= ((x << i) | (x >>> (8 - i))) & 255;
      return y;
    });
    if (args.variant !== "noShift")
      state = state.map((_, i) => state[(i % 4) + 4 * ((Math.floor(i / 4) + (i % 4)) % 4)]);
    if (args.variant !== "noMix" && r < nr) {
      const matrix = [
        [2, 3, 1, 1],
        [1, 2, 3, 1],
        [1, 1, 2, 3],
        [3, 1, 1, 2],
      ];
      state = state.map((_, i) =>
        matrix[i % 4].reduce((v, m, k) => v ^ mul(m, state[4 * Math.floor(i / 4) + k]), 0),
      );
    }
    state = add(state, r);
  }
  return state.map((x) => x.toString(16).padStart(2, "0")).join("");
}
