//! Carry-less multiplication selected only after the physical CPU feature check.
use core::arch::x86_64::*;

// Reduce a degree-at-most-254 product modulo x^128 + x^7 + x^2 + x + 1.
// Both folds are fixed-width XOR arithmetic; no secret-indexed access occurs.
fn reduce(low: u128, high: u128) -> u128 {
    let overflow = (high >> 127) ^ (high >> 126) ^ (high >> 121);
    low ^ high
        ^ (high << 1)
        ^ (high << 2)
        ^ (high << 7)
        ^ overflow
        ^ (overflow << 1)
        ^ (overflow << 2)
        ^ (overflow << 7)
}

#[target_feature(enable = "pclmulqdq")]
unsafe fn multiply(x: u128, h: u128) -> u128 {
    // GHASH enumerates polynomial coefficients from the high bit. Reflect the
    // bit order to the instruction's low-bit-first polynomial convention.
    let x = x.reverse_bits().to_le_bytes();
    let h = h.reverse_bits().to_le_bytes();
    let a = unsafe { _mm_loadu_si128(x.as_ptr().cast()) };
    let b = unsafe { _mm_loadu_si128(h.as_ptr().cast()) };
    let low = _mm_clmulepi64_si128::<0x00>(a, b);
    let high = _mm_clmulepi64_si128::<0x11>(a, b);
    let cross = _mm_xor_si128(
        _mm_clmulepi64_si128::<0x01>(a, b),
        _mm_clmulepi64_si128::<0x10>(a, b),
    );
    // SAFETY: __m128i and u128 each occupy 128 initialized bits; every bit
    // pattern is valid for u128. This is a value conversion, not an aliased view.
    let low: u128 = unsafe { core::mem::transmute(low) };
    let high: u128 = unsafe { core::mem::transmute(high) };
    let cross: u128 = unsafe { core::mem::transmute(cross) };
    reduce(low ^ (cross << 64), high ^ (cross >> 64)).reverse_bits()
}

pub(super) fn select() -> Option<fn(u128, u128) -> u128> {
    if __cpuid(1).ecx & (1 << 1) == 0 {
        return None;
    }
    // SAFETY: the returned arithmetic function is created only after verifying
    // PCLMULQDQ. Its unaligned reads are confined to initialized 16-byte arrays.
    Some(|x, h| unsafe { multiply(x, h) })
}
