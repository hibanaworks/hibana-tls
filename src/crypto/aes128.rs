//! AES-128 forward block transform, FIPS 197 (2023), for QUIC HP/GCM only.
//! Fixed-work byte arithmetic with a checked x86-64 AES instruction path.
//! Neither path uses secret-indexed lookup tables or allocation.
//! Machine-code timing, secret erasure and independent security audit are unqualified.
fn xtime(x: u8) -> u8 {
    (x << 1) ^ (0x1b & 0u8.wrapping_sub(x >> 7))
}
fn multiply(mut a: u8, mut b: u8) -> u8 {
    let mut out = 0;
    for _ in 0..8 {
        out ^= a & 0u8.wrapping_sub(b & 1);
        a = xtime(a);
        b >>= 1;
    }
    out
}
fn substitute(x: u8) -> u8 {
    // x^254 is the multiplicative inverse, with 0 mapped to 0.
    let x2 = multiply(x, x);
    let x4 = multiply(x2, x2);
    let x8 = multiply(x4, x4);
    let x16 = multiply(x8, x8);
    let x32 = multiply(x16, x16);
    let x64 = multiply(x32, x32);
    let x128 = multiply(x64, x64);
    let y = multiply(
        multiply(
            multiply(multiply(multiply(multiply(x2, x4), x8), x16), x32),
            x64,
        ),
        x128,
    );
    y ^ y.rotate_left(1) ^ y.rotate_left(2) ^ y.rotate_left(3) ^ y.rotate_left(4) ^ 0x63
}
fn next_key(key: &mut [u8; 16], round_constant: u8) {
    let t = [
        substitute(key[13]) ^ round_constant,
        substitute(key[14]),
        substitute(key[15]),
        substitute(key[12]),
    ];
    for i in 0..4 {
        key[i] ^= t[i];
    }
    for i in 4..16 {
        key[i] ^= key[i - 4];
    }
}
/// One forward block. This function provides no mode, authentication or nonce policy.
pub fn block(key: &[u8; 16], input: &[u8; 16]) -> [u8; 16] {
    blocks(key)(input)
}

/// Select physical block arithmetic once for a borrowed-key operation. This
/// immutable selection has no protocol phase, key lifetime, or cached global.
pub(crate) type BlockTransform = fn(&[u8; 16], &[u8; 16]) -> [u8; 16];

pub(crate) fn select() -> BlockTransform {
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    {
        native::select().unwrap_or(portable_block)
    }
    #[cfg(not(all(target_arch = "x86_64", not(miri))))]
    {
        portable_block
    }
}

pub(super) fn blocks(key: &[u8; 16]) -> impl Fn(&[u8; 16]) -> [u8; 16] + '_ {
    let transform = select();
    move |input| transform(key, input)
}

pub(crate) type CounterTransform = fn(&[u8; 16], &[u8; 12], &mut [u8]);

pub(crate) fn counter_transform() -> CounterTransform {
    #[cfg(all(target_arch = "x86_64", not(miri)))]
    if let Some(counter) = native::select_counter() {
        return counter;
    }
    portable_counter
}

fn portable_counter(key: &[u8; 16], nonce: &[u8; 12], body: &mut [u8]) {
    let mut input = [0; 16];
    input[..12].copy_from_slice(nonce);
    for (i, chunk) in body.chunks_mut(16).enumerate() {
        let count = u32::try_from(i as u64 + 2).expect("preflighted GCM block counter");
        input[12..].copy_from_slice(&count.to_be_bytes());
        let stream = crate::secret::Secret::new(portable_block(key, &input));
        for (byte, mask) in chunk.iter_mut().zip(stream.iter()) {
            *byte ^= mask;
        }
    }
}

#[cfg(all(target_arch = "x86_64", not(miri)))]
#[allow(unsafe_code)]
mod native;

fn portable_block(key: &[u8; 16], input: &[u8; 16]) -> [u8; 16] {
    let mut key = *key;
    let mut state = *input;
    for i in 0..16 {
        state[i] ^= key[i];
    }
    let mut rcon = 1;
    for round in 1..=10 {
        for byte in &mut state {
            *byte = substitute(*byte);
        }
        let before = state;
        // AES state is column-major: row r shifts left by r columns.
        for column in 0..4 {
            for row in 0..4 {
                state[4 * column + row] = before[4 * ((column + row) % 4) + row];
            }
        }
        if round != 10 {
            for column in state.chunks_exact_mut(4) {
                let [a, b, c, d] = <[u8; 4]>::try_from(&*column).expect("column width");
                let sum = a ^ b ^ c ^ d;
                column.copy_from_slice(&[
                    a ^ sum ^ xtime(a ^ b),
                    b ^ sum ^ xtime(b ^ c),
                    c ^ sum ^ xtime(c ^ d),
                    d ^ sum ^ xtime(d ^ a),
                ]);
            }
        }
        next_key(&mut key, rcon);
        rcon = xtime(rcon);
        for i in 0..16 {
            state[i] ^= key[i];
        }
    }
    state
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counter_operation_matches_portable_at_block_and_packet_boundaries() {
        for seed in 0..16u8 {
            let key = core::array::from_fn(|i| seed.wrapping_mul(31).wrapping_add(i as u8));
            let nonce = core::array::from_fn(|i| seed.wrapping_add(i as u8 * 7));
            for len in [0, 1, 15, 16, 17, 31, 32, 33, 127, 128, 129, 1200, 1536] {
                let mut actual = [seed; 1536];
                let mut expected = actual;
                counter_transform()(&key, &nonce, &mut actual[..len]);
                portable_counter(&key, &nonce, &mut expected[..len]);
                assert_eq!(actual, expected);
            }
        }
    }

    #[test]
    fn instruction_path_matches_portable_transform() {
        for seed in 0..4096u32 {
            let key =
                core::array::from_fn(|i| seed.wrapping_mul(37).wrapping_add(i as u32 * 71) as u8);
            let input = core::array::from_fn(|i| {
                seed.rotate_left(i as u32).wrapping_add(i as u32 * 17) as u8
            });
            assert_eq!(block(&key, &input), portable_block(&key, &input));
        }
    }

    #[test]
    fn independent_openssl_blocks() {
        for &(seed, expected) in include!("../../tests/aes_vectors.in") {
            let key = core::array::from_fn(|i| (i * 11 + seed) as u8);
            let plain = core::array::from_fn(|i| (i * 7 + seed * 3) as u8);
            let expected: [u8; 16] = core::array::from_fn(|i| {
                u8::from_str_radix(&expected[2 * i..2 * i + 2], 16).unwrap()
            });
            assert_eq!(block(&key, &plain), expected, "seed={seed}");
        }
    }
    #[test]
    fn fips197_cipher_example() {
        let key = core::array::from_fn(|i| i as u8);
        let input = core::array::from_fn(|i| (i * 17) as u8);
        assert_eq!(
            block(&key, &input),
            [
                0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
                0xc5, 0x5a
            ]
        );
    }
    #[test]
    fn zero_key_and_block() {
        assert_eq!(
            block(&[0; 16], &[0; 16]),
            [
                0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
                0x2b, 0x2e
            ]
        );
    }
    #[test]
    fn field_inverse_and_sbox_are_permutations() {
        let mut seen = [false; 256];
        for x in 0u8..=255 {
            let s = substitute(x);
            assert!(!seen[usize::from(s)]);
            seen[usize::from(s)] = true;
            if x != 0 {
                let mut inverse = 1;
                for _ in 0..254 {
                    inverse = multiply(inverse, x);
                }
                assert_eq!(multiply(x, inverse), 1);
            }
        }
        assert_eq!(substitute(0), 0x63);
        assert_eq!(substitute(0x53), 0xed);
    }
}
