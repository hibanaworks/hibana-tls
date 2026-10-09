//! The IETF ChaCha20 block primitive, RFC 8439 section 2.3.
//! This is not authenticated encryption. Nonce/counter ownership, Poly1305,
//! secret erasure and target-level timing qualification are separate obligations.
fn quarter(mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> [u32; 4] {
    a = a.wrapping_add(b);
    d = (d ^ a).rotate_left(16);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_left(12);
    a = a.wrapping_add(b);
    d = (d ^ a).rotate_left(8);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_left(7);
    [a, b, c, d]
}
fn round(state: &mut [u32; 16], indices: [usize; 4]) {
    let [a, b, c, d] = indices;
    let words = quarter(state[a], state[b], state[c], state[d]);
    for (index, word) in indices.into_iter().zip(words) {
        state[index] = word;
    }
}
/// Produce exactly one 64-byte block; no implicit counter advancement or wrap.
/// The caller must never reuse a key/nonce/counter for different plaintext.
pub fn block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&[0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
    for (word, bytes) in state[4..12].iter_mut().zip(key.chunks_exact(4)) {
        *word = u32::from_le_bytes(bytes.try_into().expect("four-byte key word"));
    }
    state[12] = counter;
    for (word, bytes) in state[13..].iter_mut().zip(nonce.chunks_exact(4)) {
        *word = u32::from_le_bytes(bytes.try_into().expect("four-byte nonce word"));
    }
    let original = state;
    for _ in 0..10 {
        for indices in [
            [0, 4, 8, 12],
            [1, 5, 9, 13],
            [2, 6, 10, 14],
            [3, 7, 11, 15],
            [0, 5, 10, 15],
            [1, 6, 11, 12],
            [2, 7, 8, 13],
            [3, 4, 9, 14],
        ] {
            round(&mut state, indices);
        }
    }
    let mut out = [0; 64];
    for (i, bytes) in out.chunks_exact_mut(4).enumerate() {
        bytes.copy_from_slice(&state[i].wrapping_add(original[i]).to_le_bytes());
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc8439_quarter_round() {
        assert_eq!(
            quarter(0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567),
            [0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb]
        );
    }
    #[test]
    fn rfc8439_block() {
        let key = core::array::from_fn(|i| i as u8);
        let actual = block(&key, 1, &[0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0]);
        let expected = "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e";
        for (i, byte) in actual.iter().enumerate() {
            assert_eq!(
                *byte,
                u8::from_str_radix(&expected[i * 2..i * 2 + 2], 16).unwrap()
            );
        }
    }
}
