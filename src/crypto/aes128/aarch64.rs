//! AArch64 AES with a compile-time CPU contract, never an OS-name assumption.
//! This module exists only on little-endian targets with AES and NEON enabled.
//! Generic AArch64 builds retain the portable path. Deploying a +aes binary is
//! the caller's platform responsibility; no OS probing or mutable flag lives here.
use core::arch::aarch64::*;

/// AES-128 key expansion entirely in registers, without secret-indexed tables.
#[target_feature(enable = "aes,neon")]
unsafe fn next_key(mut key: uint8x16_t, rcon: u8) -> uint8x16_t {
    let zero = vdupq_n_u8(0);
    // Four copies of RotWord(last word): ShiftRows then has no effect, so
    // AESE with a zero key gives four copies of SubWord(RotWord(last word)).
    let last = vreinterpretq_u8_u32(vdupq_laneq_u32::<3>(vreinterpretq_u32_u8(key)));
    let rotated = vextq_u8::<1>(last, last);
    let sub = vaeseq_u8(rotated, zero);
    let assist = veorq_u8(sub, vreinterpretq_u8_u32(vdupq_n_u32(u32::from(rcon))));
    // Prefix XOR of the four original key words.
    key = veorq_u8(key, vextq_u8::<12>(zero, key));
    key = veorq_u8(key, vextq_u8::<8>(zero, key));
    veorq_u8(key, assist)
}

#[target_feature(enable = "aes,neon")]
unsafe fn block(key: &[u8; 16], input: &[u8; 16]) -> [u8; 16] {
    // SAFETY: both references contain a complete initialized 16-byte block.
    let mut key = unsafe { vld1q_u8(key.as_ptr()) };
    let mut state = unsafe { vld1q_u8(input.as_ptr()) };
    let mut rcon = 1;
    for _ in 0..9 {
        // AESE adds the key BEFORE SubBytes/ShiftRows (unlike x86 AESENC).
        state = vaesmcq_u8(vaeseq_u8(state, key));
        key = unsafe { next_key(key, rcon) };
        rcon = super::xtime(rcon);
    }
    state = vaeseq_u8(state, key);
    key = unsafe { next_key(key, rcon) };
    state = veorq_u8(state, key);
    let mut out = [0; 16];
    unsafe { vst1q_u8(out.as_mut_ptr(), state) };
    out
}

pub(super) fn select() -> Option<super::BlockTransform> {
    // SAFETY: the module's cfg requires the compiler's AES+NEON CPU contract.
    Some(|key, input| unsafe { block(key, input) })
}

/// One schedule per counter operation; addressed round-key storage is erased
/// by Secret on return/unwind. Register/spill erasure is not guaranteed.
#[target_feature(enable = "aes,neon")]
unsafe fn counter(key: &[u8; 16], nonce: &[u8; 12], body: &mut [u8]) {
    let mut rounds = crate::secret::Secret::new([0u8; 176]);
    let mut key = unsafe { vld1q_u8(key.as_ptr()) };
    unsafe { vst1q_u8(rounds.as_mut_ptr(), key) };
    let mut rcon = 1;
    for round in 1..=10 {
        key = unsafe { next_key(key, rcon) };
        rcon = super::xtime(rcon);
        // SAFETY: 16 * round + 16 <= 176 for round in 1..=10.
        unsafe { vst1q_u8(rounds.as_mut_ptr().add(16 * round), key) };
    }
    let mut input = [0u8; 16];
    input[..12].copy_from_slice(nonce);
    for (i, chunk) in body.chunks_mut(16).enumerate() {
        let count = u32::try_from(i as u64 + 2).expect("preflighted GCM block counter");
        input[12..].copy_from_slice(&count.to_be_bytes());
        let mut state = unsafe { vld1q_u8(input.as_ptr()) };
        for round in 0..9 {
            let key = unsafe { vld1q_u8(rounds.as_ptr().add(16 * round)) };
            state = vaesmcq_u8(vaeseq_u8(state, key));
        }
        state = vaeseq_u8(state, unsafe { vld1q_u8(rounds.as_ptr().add(144)) });
        state = veorq_u8(state, unsafe { vld1q_u8(rounds.as_ptr().add(160)) });
        if chunk.len() == 16 {
            // SAFETY: only full initialized writable blocks take this branch.
            let bytes = unsafe { vld1q_u8(chunk.as_ptr()) };
            unsafe { vst1q_u8(chunk.as_mut_ptr(), veorq_u8(bytes, state)) };
        } else {
            let mut stream = crate::secret::Secret::new([0u8; 16]);
            unsafe { vst1q_u8(stream.as_mut_ptr(), state) };
            for (byte, mask) in chunk.iter_mut().zip(stream.iter()) {
                *byte ^= mask;
            }
        }
    }
}

pub(super) fn select_counter() -> Option<super::CounterTransform> {
    // SAFETY: the module's cfg requires AES+NEON; tail accesses are bounded.
    Some(|key, nonce, body| unsafe { counter(key, nonce, body) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_hardware_round_key_matches_portable_expansion() {
        for seed in 0..256u16 {
            let mut expected = core::array::from_fn(|i| (seed + i as u16 * 17) as u8);
            // SAFETY: module cfg proves AES+NEON; arrays are full blocks.
            let mut actual = unsafe { vld1q_u8(expected.as_ptr()) };
            let mut rcon = 1;
            for _ in 0..10 {
                super::super::next_key(&mut expected, rcon);
                actual = unsafe { next_key(actual, rcon) };
                let mut bytes = [0; 16];
                unsafe { vst1q_u8(bytes.as_mut_ptr(), actual) };
                assert_eq!(bytes, expected);
                rcon = super::super::xtime(rcon);
            }
        }
    }
}
