import { add, xtime, mul, inv } from "../gf/gf256";
import { table, check } from "./common";
const h = (x: number) => x.toString(16).padStart(2, "0");
export function act1(a: number, b: number) {
  let current = a;
  const chain = Array.from({ length: 8 }, (_, i) => {
      const before = current;
      current = xtime(current);
      return [
        String(i),
        h(before),
        String((b >> i) & 1),
        before & 128 ? "top bit set: reduce by 11b" : "no reduction needed",
        h(current),
      ];
    }),
    inverse = inv(a);
  return `<p>Byte <span id="field-a">${h(a)}</span> has polynomial coefficients ${a.toString(2).padStart(8, "0")}. XOR addition: ${h(a)} ⊕ ${h(b)} = ${h(add(a, b))}.</p><p>xtime(${h(a)}) = <span id="field-xtime">${h(xtime(a))}</span>. Multiply ${h(a)} · ${h(b)} = <span id="field-product">${h(mul(a, b))}</span>.</p>${table("Multiply through the xtime chain", ["Bit of b", "Current multiplicand", "Use in XOR sum?", "Reduction", "Next xtime"], chain)}<h3>Polynomial extended Euclid</h3>${
    inverse.value === null
      ? '<p class="info" data-verdict="no-inverse">ⓘ no inverse — AES maps {00} to {00} by convention before the affine step.</p>'
      : table(
          "Extended Euclid over GF(2)[x]",
          ["q", "r", "s", "t", "s·a XOR t·11b", "Check"],
          inverse.rows.map((r) => [
            h(r.q),
            h(r.r),
            h(r.s),
            h(r.t),
            h(r.check),
            check("polynomial-bezout", r.check === r.r, "polynomial identity"),
          ]),
        ) +
        check(
          "field-inverse",
          mul(a, inverse.value) === 1,
          `${h(a)} · ${h(inverse.value)} = ${h(mul(a, inverse.value))}`,
        )
  }<p>All polynomial coefficients are in GF(2): subtraction is XOR. This differs from <a href="https://systemslibrarian.github.io/crypto-lab-clock-arithmetic/">integer modular arithmetic</a>.</p>`;
}
