//! AES-128-GCM with exactly a 96-bit nonce and a full 128-bit tag.
//! NIST SP 800-38D sections 6–7. No allocation, truncated tags or generic IV path.
//! Nonce uniqueness and aggregate key-usage limits belong to the protocol locals.
use super::aes128;
pub const MAX_BODY_BYTES: u64 = ((1u64 << 32) - 2) * 16;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Authentication,
}
fn lengths(aad: u64, body: u64) -> Result<(u64, u64), Error> {
    if aad > u64::MAX / 8 || body > MAX_BODY_BYTES {
        return Err(Error::Length);
    }
    Ok((aad * 8, body * 8))
}
fn multiply(x: u128, mut v: u128) -> u128 {
    let mut z = 0u128;
    for i in 0..128 {
        z ^= v & 0u128.wrapping_sub((x >> (127 - i)) & 1);
        let low = v & 1;
        v = (v >> 1) ^ (0xe1000000000000000000000000000000 & 0u128.wrapping_sub(low));
    }
    z
}
fn absorb(mut y: u128, h: u128, bytes: &[u8]) -> u128 {
    let mut blocks = bytes.chunks_exact(16);
    for chunk in &mut blocks {
        let block: &[u8; 16] = chunk.try_into().expect("complete GHASH block");
        y = multiply(y ^ u128::from_be_bytes(*block), h);
    }
    let tail = blocks.remainder();
    if !tail.is_empty() {
        let mut block = [0u8; 16];
        block[..tail.len()].copy_from_slice(tail);
        y = multiply(y ^ u128::from_be_bytes(block), h);
    }
    y
}
fn tag(key: &[u8; 16], nonce: &[u8; 12], aad: &[u8], body: &[u8], lens: (u64, u64)) -> [u8; 16] {
    let h = u128::from_be_bytes(aes128::block(key, &[0; 16]));
    let y = absorb(absorb(0, h, aad), h, body);
    let encoded = (u128::from(lens.0) << 64) | u128::from(lens.1);
    let hash = multiply(y ^ encoded, h);
    let mut j0 = [0; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;
    (hash ^ u128::from_be_bytes(aes128::block(key, &j0))).to_be_bytes()
}
fn xor(key: &[u8; 16], nonce: &[u8; 12], body: &mut [u8]) {
    let mut input = [0; 16];
    input[..12].copy_from_slice(nonce);
    for (i, chunk) in body.chunks_mut(16).enumerate() {
        let count = u32::try_from(i as u64 + 2).expect("preflighted GCM block counter");
        input[12..].copy_from_slice(&count.to_be_bytes());
        let stream = aes128::block(key, &input);
        for (byte, mask) in chunk.iter_mut().zip(stream) {
            *byte ^= mask;
        }
    }
}
/// Encrypt in place. Invalid lengths are rejected before mutating any byte.
pub fn seal(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    body: &mut [u8],
) -> Result<[u8; 16], Error> {
    let lens = lengths(
        u64::try_from(aad.len()).map_err(|_| Error::Length)?,
        u64::try_from(body.len()).map_err(|_| Error::Length)?,
    )?;
    xor(key, nonce, body);
    Ok(tag(key, nonce, aad, body, lens))
}
/// Verify ciphertext before decryption. Authentication failure leaves it intact.
pub fn open(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    body: &mut [u8],
    received: &[u8; 16],
) -> Result<(), Error> {
    let lens = lengths(
        u64::try_from(aad.len()).map_err(|_| Error::Length)?,
        u64::try_from(body.len()).map_err(|_| Error::Length)?,
    )?;
    let expected = tag(key, nonce, aad, body, lens);
    if !bool::from(crate::secret::FixedTimeEq::fixed_time_eq(
        &expected, received,
    )) {
        return Err(Error::Authentication);
    }
    xor(key, nonce, body);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn borrowed_full_blocks_and_padded_tails_match_ghash() {
        let bytes: [u8; 65] = core::array::from_fn(|i| (i * 17 + 3) as u8);
        let h = 0x66e94bd4ef8a2c3b884cfa59ca342b2eu128;
        for len in 0..=bytes.len() {
            let mut expected = 0x123456789abcdef0u128;
            for chunk in bytes[..len].chunks(16) {
                let mut padded = [0u8; 16];
                padded[..chunk.len()].copy_from_slice(chunk);
                expected = multiply(expected ^ u128::from_be_bytes(padded), h);
            }
            assert_eq!(absorb(0x123456789abcdef0, h, &bytes[..len]), expected);
        }
    }

    #[test]
    fn independent_openssl_aead_and_tampering() {
        for &(seed, a, n, cipher, mac) in include!("../../tests/aes_gcm_vectors.in") {
            let key = core::array::from_fn(|i| (i * 11 + seed) as u8);
            let nonce = core::array::from_fn(|i| (i * 17 + seed) as u8);
            let mut aad = [0; 33];
            for (i, b) in aad[..a].iter_mut().enumerate() {
                *b = (i * 13 + seed) as u8;
            }
            let mut body = [0; 1025];
            for (i, b) in body[..n].iter_mut().enumerate() {
                *b = (i * 7 + seed) as u8;
            }
            let plain = body;
            let expected_tag =
                core::array::from_fn(|i| u8::from_str_radix(&mac[2 * i..2 * i + 2], 16).unwrap());
            assert_eq!(
                seal(&key, &nonce, &aad[..a], &mut body[..n]),
                Ok(expected_tag)
            );
            for (i, b) in body[..n].iter().enumerate() {
                assert_eq!(
                    *b,
                    u8::from_str_radix(&cipher[2 * i..2 * i + 2], 16).unwrap()
                );
            }
            let sealed = body;
            if n > 0 {
                body[n - 1] ^= 1;
                let before = body;
                assert_eq!(
                    open(&key, &nonce, &aad[..a], &mut body[..n], &expected_tag),
                    Err(Error::Authentication)
                );
                assert_eq!(body, before);
                body = sealed;
            }
            let mut wrong_nonce = nonce;
            wrong_nonce[0] ^= 1;
            assert_eq!(
                open(&key, &wrong_nonce, &aad[..a], &mut body[..n], &expected_tag),
                Err(Error::Authentication)
            );
            assert_eq!(body, sealed);
            assert_eq!(
                open(&key, &nonce, &aad[..a], &mut body[..n], &expected_tag),
                Ok(())
            );
            assert_eq!(body, plain);
        }
    }
    #[test]
    fn nist_zero_key_vectors_and_bad_tags() {
        assert_eq!(
            seal(&[0; 16], &[0; 12], &[], &mut []).unwrap(),
            [
                0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7,
                0x45, 0x5a
            ]
        );
        let mut body = [0; 16];
        let tag = seal(&[0; 16], &[0; 12], &[], &mut body).unwrap();
        assert_eq!(
            body,
            [
                0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
                0xfe, 0x78
            ]
        );
        assert_eq!(
            tag,
            [
                0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57,
                0xbd, 0xdf
            ]
        );
        for bit in 0..128 {
            let mut bad = tag;
            bad[bit / 8] ^= 1 << (bit % 8);
            let mut copy = body;
            assert_eq!(
                open(&[0; 16], &[0; 12], &[], &mut copy, &bad),
                Err(Error::Authentication)
            );
            assert_eq!(copy, body);
        }
        assert_eq!(open(&[0; 16], &[0; 12], &[], &mut body, &tag), Ok(()));
        assert_eq!(body, [0; 16]);
    }
    #[test]
    fn length_preflight_prevents_counter_and_bit_length_overflow() {
        assert_eq!(
            lengths(u64::MAX / 8, MAX_BODY_BYTES),
            Ok((u64::MAX - 7, MAX_BODY_BYTES * 8))
        );
        assert_eq!(lengths(u64::MAX / 8 + 1, 0), Err(Error::Length));
        assert_eq!(lengths(0, MAX_BODY_BYTES + 1), Err(Error::Length));
    }
}
