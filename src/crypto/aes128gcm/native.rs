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
unsafe fn reflected_product(x: u128, b: __m128i) -> u128 {
    let a = _mm_set_epi64x((x >> 64) as i64, x as i64);
    let low = _mm_clmulepi64_si128::<0x00>(a, b);
    let high = _mm_clmulepi64_si128::<0x11>(a, b);
    let cross = _mm_xor_si128(
        _mm_clmulepi64_si128::<0x01>(a, b),
        _mm_clmulepi64_si128::<0x10>(a, b),
    );
    // SAFETY: these are initialized 128-bit values; u128 admits every pattern.
    let low: u128 = unsafe { core::mem::transmute(low) };
    let high: u128 = unsafe { core::mem::transmute(high) };
    let cross: u128 = unsafe { core::mem::transmute(cross) };
    reduce(low ^ (cross << 64), high ^ (cross >> 64))
}

#[cfg(test)]
#[target_feature(enable = "pclmulqdq")]
unsafe fn multiply(x: u128, h: u128) -> u128 {
    let h = h.reverse_bits();
    let b = _mm_set_epi64x((h >> 64) as i64, h as i64);
    unsafe { reflected_product(x.reverse_bits(), b) }.reverse_bits()
}

// Keep the accumulator in the CPU's polynomial convention throughout GHASH.
// H is reflected once and input is read directly in fixed-size borrowed blocks.
#[target_feature(enable = "pclmulqdq")]
unsafe fn hash(h: u128, aad: &[u8], body: &[u8], encoded: u128) -> u128 {
    let h = h.reverse_bits();
    let b = _mm_set_epi64x((h >> 64) as i64, h as i64);
    let mut y = 0;
    for bytes in [aad, body] {
        let mut chunks = bytes.chunks_exact(16);
        for chunk in &mut chunks {
            let block: &[u8; 16] = chunk.try_into().expect("complete GHASH block");
            // SAFETY: this function has the same PCLMULQDQ requirement.
            y = unsafe { reflected_product(y ^ u128::from_be_bytes(*block).reverse_bits(), b) };
        }
        let tail = chunks.remainder();
        if !tail.is_empty() {
            let mut block = [0; 16];
            block[..tail.len()].copy_from_slice(tail);
            y = unsafe { reflected_product(y ^ u128::from_be_bytes(block).reverse_bits(), b) };
        }
    }
    unsafe { reflected_product(y ^ encoded.reverse_bits(), b) }.reverse_bits()
}

pub(super) fn select_hash() -> Option<super::HashTransform> {
    if __cpuid(1).ecx & (1 << 1) == 0 {
        return None;
    }
    // SAFETY: the function is selected only after the physical feature check.
    Some(|h, aad, body, encoded| unsafe { hash(h, aad, body, encoded) })
}

#[cfg(test)]
pub(super) fn select() -> Option<fn(u128, u128) -> u128> {
    if __cpuid(1).ecx & (1 << 1) == 0 {
        return None;
    }
    // SAFETY: the returned arithmetic function is created only after verifying
    // PCLMULQDQ. The intrinsics operate only on initialized fixed-width values.
    Some(|x, h| unsafe { multiply(x, h) })
}
