/** FIPS 197-upd1 §4: coefficients in GF(2), modulus x^8+x^4+x^3+x+1. */
export const add = (a: number, b: number) => a ^ b;
export function xtime(a: number): number {
  return ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 255;
}
export function mul(a: number, b: number): number {
  let v = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) v ^= a;
    a = xtime(a);
    b >>>= 1;
  }
  return v;
}
const degree = (p: number) => 31 - Math.clz32(p);
export function polynomialMultiply(a: number, b: number): number {
  let v = 0;
  while (b) {
    if (b & 1) v ^= a;
    a <<= 1;
    b >>>= 1;
  }
  return v;
}
export function polynomialDivide(a: number, b: number): { q: number; r: number } {
  if (!b) throw Error("Polynomial division by zero.");
  let q = 0;
  while (a && degree(a) >= degree(b)) {
    const d = degree(a) - degree(b);
    q ^= 1 << d;
    a ^= b << d;
  }
  return { q, r: a };
}
export function inv(a: number): {
  value: number | null;
  rows: { q: number; r: number; s: number; t: number; check: number }[];
} {
  if (!Number.isInteger(a) || a < 0 || a > 255) throw Error("Expected one byte.");
  if (a === 0) return { value: null, rows: [] };
  let r0 = a,
    r1 = 0x11b,
    s0 = 1,
    s1 = 0,
    t0 = 0,
    t1 = 1;
  const rows = [];
  while (r1) {
    const { q, r } = polynomialDivide(r0, r1),
      s = s0 ^ polynomialMultiply(q, s1),
      t = t0 ^ polynomialMultiply(q, t1);
    rows.push({ q, r, s, t, check: polynomialMultiply(s, a) ^ polynomialMultiply(t, 0x11b) });
    [r0, r1] = [r1, r];
    [s0, s1] = [s1, s];
    [t0, t1] = [t1, t];
  }
  return { value: polynomialDivide(s0, 0x11b).r, rows };
}
/** Independent exponent route, used only by tests. */
export function pow254(a: number): number {
  let out = 1,
    b = a,
    e = 254;
  while (e) {
    if (e & 1) out = mul(out, b);
    b = mul(b, b);
    e >>>= 1;
  }
  return out;
}
