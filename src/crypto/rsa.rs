//! Fixed-storage RSA PUBLIC exponentiation for 2048/3072/4096-bit verification.
//! All inputs are public. Branches depend on public integers; this code is NOT
//! suitable for private-key operations, signing, decryption or key generation.
const MAX_LIMBS: usize = 64;
type Uint = [u64; MAX_LIMBS];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Width,
    Modulus,
    Exponent,
    Signature,
}
struct Modulus {
    n: Uint,
    limbs: usize,
    inverse: u64,
}
fn read(bytes: &[u8]) -> Uint {
    let mut out = [0; MAX_LIMBS];
    for (i, part) in bytes.rchunks_exact(8).enumerate() {
        out[i] = u64::from_be_bytes(part.try_into().unwrap());
    }
    out
}
fn subtract(a: &Uint, b: &Uint, limbs: usize) -> (Uint, u64) {
    let mut out = [0; MAX_LIMBS];
    let mut borrow = 0;
    for i in 0..limbs {
        let (x, first) = a[i].overflowing_sub(b[i]);
        let (x, second) = x.overflowing_sub(borrow);
        out[i] = x;
        borrow = u64::from(first | second);
    }
    (out, borrow)
}
impl Modulus {
    fn double(&self, a: &Uint) -> Uint {
        let mut out = [0; MAX_LIMBS];
        let mut carry = 0u128;
        for i in 0..self.limbs {
            let x = 2 * a[i] as u128 + carry;
            out[i] = x as u64;
            carry = x >> 64;
        }
        let (reduced, borrow) = subtract(&out, &self.n, self.limbs);
        if carry != 0 || borrow == 0 {
            reduced
        } else {
            out
        }
    }
    #[inline(never)]
    fn multiply(&self, a: &Uint, b: &Uint) -> Uint {
        let mut t = [0u64; 2 * MAX_LIMBS + 1];
        let limbs = self.limbs;
        for i in 0..limbs {
            let mut carry = 0u128;
            for j in 0..limbs {
                let x = a[i] as u128 * b[j] as u128 + t[i + j] as u128 + carry;
                t[i + j] = x as u64;
                carry = x >> 64;
            }
            t[i + limbs] = carry as u64;
        }
        for i in 0..limbs {
            let factor = t[i].wrapping_mul(self.inverse);
            let mut carry = 0u128;
            for j in 0..limbs {
                let x = factor as u128 * self.n[j] as u128 + t[i + j] as u128 + carry;
                t[i + j] = x as u64;
                carry = x >> 64;
            }
            for slot in &mut t[i + limbs..=2 * limbs] {
                let x = *slot as u128 + carry;
                *slot = x as u64;
                carry = x >> 64;
            }
        }
        let mut out = [0; MAX_LIMBS];
        out[..limbs].copy_from_slice(&t[limbs..2 * limbs]);
        let (reduced, borrow) = subtract(&out, &self.n, limbs);
        if t[2 * limbs] != 0 || borrow == 0 {
            reduced
        } else {
            out
        }
    }
}
/// Recover a signature representative with an odd public exponent in 3..=u32::MAX.
/// Requires exact full-bit odd moduli and representative < modulus. Failure does
/// not write output. This primitive performs neither padding nor trust checks.
pub fn recover(
    modulus: &[u8],
    exponent: u32,
    signature: &[u8],
    output: &mut [u8],
) -> Result<(), Error> {
    let width = modulus.len();
    if !matches!(width, 256 | 384 | 512) || signature.len() != width || output.len() != width {
        return Err(Error::Width);
    }
    if modulus[0] & 128 == 0 || modulus[width - 1] & 1 == 0 {
        return Err(Error::Modulus);
    }
    if exponent < 3 || exponent & 1 == 0 {
        return Err(Error::Exponent);
    }
    let n = read(modulus);
    let s = read(signature);
    let limbs = width / 8;
    if subtract(&s, &n, limbs).1 == 0 {
        return Err(Error::Signature);
    }
    let mut inverse = 1u64;
    for _ in 0..6 {
        inverse = inverse.wrapping_mul(2u64.wrapping_sub(n[0].wrapping_mul(inverse)));
    }
    let context = Modulus {
        n,
        limbs,
        inverse: inverse.wrapping_neg(),
    };
    // n >= R/2, so R-n is the canonical Montgomery encoding of one.
    let montgomery_one = subtract(&[0; MAX_LIMBS], &context.n, limbs).0;
    let mut r2 = montgomery_one;
    for _ in 0..64 * limbs {
        r2 = context.double(&r2);
    }
    let base = context.multiply(&s, &r2);
    let mut acc = montgomery_one;
    for bit in (0..32).rev() {
        acc = context.multiply(&acc, &acc);
        if (exponent >> bit) & 1 != 0 {
            acc = context.multiply(&acc, &base);
        }
    }
    let mut one = [0; MAX_LIMBS];
    one[0] = 1;
    let result = context.multiply(&acc, &one);
    for (i, chunk) in output.rchunks_exact_mut(8).enumerate() {
        chunk.copy_from_slice(&result[i].to_be_bytes());
    }
    Ok(())
}
