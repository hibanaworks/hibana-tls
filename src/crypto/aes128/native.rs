//! x86-64 AES instructions; physical CPU capability is checked before entry.
//! No OS service, allocation, persistent flag, or protocol state is involved.
use core::arch::x86_64::*;
#[target_feature(enable = "aes")]
unsafe fn block(key: &[u8; 16], input: &[u8; 16]) -> [u8; 16] {
    let mut k = unsafe { _mm_loadu_si128(key.as_ptr().cast()) };
    let mut s = _mm_xor_si128(unsafe { _mm_loadu_si128(input.as_ptr().cast()) }, k);
    macro_rules! expand {
        ($rc:literal) => {{
            let assist = _mm_shuffle_epi32::<0xff>(_mm_aeskeygenassist_si128::<$rc>(k));
            k = _mm_xor_si128(k, _mm_slli_si128::<4>(k));
            k = _mm_xor_si128(k, _mm_slli_si128::<8>(k));
            k = _mm_xor_si128(k, assist);
        }};
    }
    macro_rules! round {
        ($rc:literal) => {{
            expand!($rc);
            s = _mm_aesenc_si128(s, k);
        }};
    }
    round!(1);
    round!(2);
    round!(4);
    round!(8);
    round!(16);
    round!(32);
    round!(64);
    round!(128);
    round!(27);
    expand!(54);
    s = _mm_aesenclast_si128(s, k);
    let mut out = [0; 16];
    unsafe { _mm_storeu_si128(out.as_mut_ptr().cast(), s) };
    out
}

type BlockTransform = fn(&[u8; 16], &[u8; 16]) -> [u8; 16];

pub(super) fn select() -> Option<BlockTransform> {
    // x86-64 guarantees CPUID and the SSE2 register baseline. Leaf 1 ECX bit
    // 25 identifies AES instruction support independently of operating system.
    let features = __cpuid(1);
    if features.ecx & (1 << 25) == 0 {
        return None;
    }
    // SAFETY: This function value can be obtained only after the feature check.
    // Loads/stores access exactly 16 bytes within array references. The key is
    // borrowed and no secret-key ownership or storage is duplicated here.
    Some(|key, input| unsafe { block(key, input) })
}

/// Expand once for the complete GCM counter operation. The stack-owned round
/// keys are erased on return; no mutable key cache or protocol flag is retained.
#[target_feature(enable = "aes")]
unsafe fn counter(key: &[u8; 16], nonce: &[u8; 12], body: &mut [u8]) {
    let mut rounds = crate::secret::Secret::new([0u8; 176]);
    let mut k = unsafe { _mm_loadu_si128(key.as_ptr().cast()) };
    unsafe { _mm_storeu_si128(rounds.as_mut_ptr().cast(), k) };
    macro_rules! expand {
        ($index:literal, $rc:literal) => {{
            let assist = _mm_shuffle_epi32::<0xff>(_mm_aeskeygenassist_si128::<$rc>(k));
            k = _mm_xor_si128(k, _mm_slli_si128::<4>(k));
            k = _mm_xor_si128(k, _mm_slli_si128::<8>(k));
            k = _mm_xor_si128(k, assist);
            // SAFETY: each literal index is in 1..=10, within 176 bytes.
            unsafe { _mm_storeu_si128(rounds.as_mut_ptr().add(16 * $index).cast(), k) };
        }};
    }
    expand!(1, 1);
    expand!(2, 2);
    expand!(3, 4);
    expand!(4, 8);
    expand!(5, 16);
    expand!(6, 32);
    expand!(7, 64);
    expand!(8, 128);
    expand!(9, 27);
    expand!(10, 54);
    let mut input = [0u8; 16];
    input[..12].copy_from_slice(nonce);
    for (i, chunk) in body.chunks_mut(16).enumerate() {
        let count = u32::try_from(i as u64 + 2).expect("preflighted GCM block counter");
        input[12..].copy_from_slice(&count.to_be_bytes());
        let mut state = _mm_xor_si128(unsafe { _mm_loadu_si128(input.as_ptr().cast()) }, unsafe {
            _mm_loadu_si128(rounds.as_ptr().cast())
        });
        for round in 1..10 {
            state = _mm_aesenc_si128(state, unsafe {
                _mm_loadu_si128(rounds.as_ptr().add(16 * round).cast())
            });
        }
        state = _mm_aesenclast_si128(state, unsafe {
            _mm_loadu_si128(rounds.as_ptr().add(160).cast())
        });
        if chunk.len() == 16 {
            // SAFETY: this branch has exactly one initialized writable block.
            let bytes = unsafe { _mm_loadu_si128(chunk.as_ptr().cast()) };
            unsafe { _mm_storeu_si128(chunk.as_mut_ptr().cast(), _mm_xor_si128(bytes, state)) };
        } else {
            let mut stream = crate::secret::Secret::new([0u8; 16]);
            unsafe { _mm_storeu_si128(stream.as_mut_ptr().cast(), state) };
            for (byte, mask) in chunk.iter_mut().zip(stream.iter()) {
                *byte ^= mask;
            }
        }
    }
}

pub(super) fn select_counter() -> Option<super::CounterTransform> {
    if __cpuid(1).ecx & (1 << 25) == 0 {
        return None;
    }
    // SAFETY: AES is checked above. Every vector load/store is confined to an
    // initialized full block; the final short tail uses a separate full block.
    Some(|key, nonce, body| unsafe { counter(key, nonce, body) })
}
