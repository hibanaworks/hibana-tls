//! RFC 7748 X25519 arithmetic with fixed 5x51-bit storage and fixed loop bounds.
//! No heap or entropy source. Callers must reject an all-zero shared result.
//! Target timing, temporary erasure and full Rust refinement remain unqualified.
const MASK: u64 = (1 << 51) - 1;
#[derive(Clone, Copy)]
struct Field([u64; 5]);
impl Field {
    const ZERO: Self = Self([0; 5]);
    const ONE: Self = Self([1, 0, 0, 0, 0]);
    fn carry(mut limbs: [u128; 5]) -> Self {
        // Four fixed sweeps suffice for products of bounded 51-bit limbs.
        for _ in 0..4 {
            for i in 0..4 {
                let c = limbs[i] >> 51;
                limbs[i] &= u128::from(MASK);
                limbs[i + 1] += c;
            }
            let c = limbs[4] >> 51;
            limbs[4] &= u128::from(MASK);
            limbs[0] += 19 * c;
        }
        Self(core::array::from_fn(|i| limbs[i] as u64))
    }
    fn add(self, other: Self) -> Self {
        Self::carry(core::array::from_fn(|i| {
            u128::from(self.0[i]) + u128::from(other.0[i])
        }))
    }
    fn sub(self, other: Self) -> Self {
        Self::carry(core::array::from_fn(|i| {
            u128::from(self.0[i]) + 2 * u128::from(if i == 0 { MASK - 18 } else { MASK })
                - u128::from(other.0[i])
        }))
    }
    fn mul(self, other: Self) -> Self {
        let mut out = [0u128; 5];
        for i in 0..5 {
            for j in 0..5 {
                let position = i + j;
                out[position % 5] += u128::from(self.0[i])
                    * u128::from(other.0[j])
                    * if position >= 5 { 19 } else { 1 };
            }
        }
        Self::carry(out)
    }
    fn square(self) -> Self {
        self.mul(self)
    }
    fn inverse(self) -> Self {
        let mut out = Self::ONE;
        for bit in (0..255).rev() {
            out = out.square();
            // Fixed public exponent 2^255 - 21, not a secret branch.
            if bit != 2 && bit != 4 {
                out = out.mul(self);
            }
        }
        out
    }
    fn decode(bytes: &[u8; 32]) -> Self {
        let mut out = [0u64; 5];
        for bit in 0..255 {
            out[bit / 51] |= u64::from((bytes[bit / 8] >> (bit % 8)) & 1) << (bit % 51);
        }
        Self(out)
    }
    fn encode(self) -> [u8; 32] {
        let mut h = Self::carry(self.0.map(u128::from)).0;
        // Adding 19 carries beyond bit 255 exactly for h >= 2^255-19.
        let mut q = (h[0] + 19) >> 51;
        for limb in &h[1..] {
            q = (limb + q) >> 51;
        }
        h[0] += 19 * q;
        for i in 0..4 {
            let c = h[i] >> 51;
            h[i] &= MASK;
            h[i + 1] += c;
        }
        h[4] &= MASK;
        let mut out = [0u8; 32];
        for bit in 0..255 {
            out[bit / 8] |= (((h[bit / 51] >> (bit % 51)) & 1) as u8) << (bit % 8);
        }
        out
    }
}
fn swap(a: &mut Field, b: &mut Field, bit: u8) {
    let mask = 0u64.wrapping_sub(u64::from(bit));
    for i in 0..5 {
        let delta = (a.0[i] ^ b.0[i]) & mask;
        a.0[i] ^= delta;
        b.0[i] ^= delta;
    }
}
/// Return the raw shared u-coordinate; all-zero is not a contributory exchange.
/// Scalar clamping and ignoring the peer's top bit are part of this operation.
pub fn exchange(secret: &[u8; 32], peer: &[u8; 32]) -> [u8; 32] {
    let mut scalar = crate::secret::Secret::new(*secret);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    let u = Field::decode(peer);
    let mut x = Field::ONE;
    let mut z = Field::ZERO;
    let mut next_x = u;
    let mut next_z = Field::ONE;
    let mut previous = 0u8;
    for bit in (0..255).rev() {
        let selected = (scalar[bit / 8] >> (bit % 8)) & 1;
        swap(&mut x, &mut next_x, previous ^ selected);
        swap(&mut z, &mut next_z, previous ^ selected);
        previous = selected;
        let sum = x.add(z);
        let difference = x.sub(z);
        let aa = sum.square();
        let bb = difference.square();
        let e = aa.sub(bb);
        let da = next_x.sub(next_z).mul(sum);
        let cb = next_x.add(next_z).mul(difference);
        next_x = da.add(cb).square();
        next_z = u.mul(da.sub(cb).square());
        x = aa.mul(bb);
        z = e.mul(aa.add(e.mul(Field([121665, 0, 0, 0, 0]))));
    }
    swap(&mut x, &mut next_x, previous);
    swap(&mut z, &mut next_z, previous);
    x.mul(z.inverse()).encode()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn hex(s: &str) -> [u8; 32] {
        core::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
    }
    #[test]
    fn independent_openssl_exchange() {
        for &(k, u, expected) in include!("../../tests/x25519_vectors.in") {
            assert_eq!(exchange(&hex(k), &hex(u)), hex(expected));
        }
    }
    #[test]
    fn independent_integer_field_oracle() {
        for &(a, b, sum, difference, product) in include!("../../tests/x25519_field_vectors.in") {
            let a = Field::decode(&hex(a));
            let b = Field::decode(&hex(b));
            assert_eq!(a.add(b).encode(), hex(sum));
            assert_eq!(a.sub(b).encode(), hex(difference));
            assert_eq!(a.mul(b).encode(), hex(product));
        }
    }
    #[test]
    fn rfc7748_thousand_iterations() {
        let mut k = [0u8; 32];
        k[0] = 9;
        let mut u = k;
        for _ in 0..1000 {
            let next = exchange(&k, &u);
            u = k;
            k = next;
        }
        assert_eq!(
            k,
            hex("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
        );
    }
    #[test]
    fn rfc7748_function_vectors() {
        for (k, u, out) in [
            (
                "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
                "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
                "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
            ),
            (
                "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
                "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
                "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
            ),
        ] {
            assert_eq!(exchange(&hex(k), &hex(u)), hex(out));
        }
    }
    #[test]
    fn noncanonical_field_and_low_order() {
        let mut p = [255; 32];
        p[0] = 237;
        p[31] = 127;
        assert_eq!(Field::decode(&p).encode(), [0; 32]);
        assert_eq!(exchange(&[7; 32], &p), [0; 32]);
        for v in [0, 1] {
            let mut u = [0; 32];
            u[0] = v;
            assert_eq!(exchange(&[7; 32], &u), [0; 32]);
        }
        let mut base = [0; 32];
        base[0] = 9;
        let result = exchange(&[9; 32], &base);
        base[31] |= 128;
        assert_eq!(exchange(&[9; 32], &base), result);
    }
}
