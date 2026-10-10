//! In-place RFC 8439 AEAD arithmetic. Protocol locals must own nonce uniqueness.
//! This module has no session lifecycle, allocator or external crypto provider.
//! Machine-code timing and secret-erasure qualification remain outstanding.
use super::{chacha20, poly1305};

pub const MAX_PLAINTEXT_BYTES: u64 = (u32::MAX as u64) * 64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Authentication,
}

fn checked_body_length(length: u64) -> Result<(), Error> {
    if length > MAX_PLAINTEXT_BYTES {
        Err(Error::Length)
    } else {
        Ok(())
    }
}
fn lengths(aad: &[u8], data: &[u8]) -> Result<(u64, u64), Error> {
    let a = u64::try_from(aad.len()).map_err(|_| Error::Length)?;
    let d = u64::try_from(data.len()).map_err(|_| Error::Length)?;
    checked_body_length(d)?;
    Ok((a, d))
}
fn xor(key: &[u8; 32], nonce: &[u8; 12], data: &mut [u8]) {
    for (i, chunk) in data.chunks_mut(64).enumerate() {
        let counter = u32::try_from(i + 1).expect("preflighted ChaCha counter");
        let block = chacha20::block(key, counter, nonce);
        for (byte, mask) in chunk.iter_mut().zip(block) {
            *byte ^= mask;
        }
    }
}
fn tag(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], data: &[u8], lens: (u64, u64)) -> [u8; 16] {
    let block = chacha20::block(key, 0, nonce);
    let one_time: &[u8; 32] = (&block[..32]).try_into().expect("fixed key prefix");
    let zeros = [0; 16];
    let a = lens.0.to_le_bytes();
    let d = lens.1.to_le_bytes();
    poly1305::authenticate_parts(
        one_time,
        &[
            aad,
            &zeros[..(16 - aad.len() % 16) % 16],
            data,
            &zeros[..(16 - data.len() % 16) % 16],
            &a,
            &d,
        ],
    )
}
/// Encrypt in place and return the detached tag. Key/nonce reuse is forbidden.
/// Length rejection occurs before changing any caller byte.
pub fn seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
) -> Result<[u8; 16], Error> {
    let lens = lengths(aad, data)?;
    xor(key, nonce, data);
    Ok(tag(key, nonce, aad, data, lens))
}
/// Authenticate ciphertext before exposing plaintext. Failure preserves data.
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
    received: &[u8; 16],
) -> Result<(), Error> {
    let lens = lengths(aad, data)?;
    let expected = tag(key, nonce, aad, data, lens);
    if !bool::from(crate::secret::FixedTimeEq::fixed_time_eq(
        &expected, received,
    )) {
        return Err(Error::Authentication);
    }
    xor(key, nonce, data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex<const N: usize>(s: &str) -> [u8; N] {
        core::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
    }
    #[test]
    fn rfc8439_aead() {
        let key = core::array::from_fn(|i| 0x80 + i as u8);
        let nonce = hex("070000004041424344454647");
        let aad = hex::<12>("50515253c0c1c2c3c4c5c6c7");
        let original = hex::<114>(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
        );
        let cipher = hex::<114>(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
        );
        let expected = hex("1ae10b594f09e26a7e902ecbd0600691");
        let mut data = original;
        assert_eq!(seal(&key, &nonce, &aad, &mut data), Ok(expected));
        assert_eq!(data, cipher);
        assert_eq!(open(&key, &nonce, &aad, &mut data, &expected), Ok(()));
        assert_eq!(data, original);
        for bit in 0..128 {
            let mut bad = expected;
            bad[bit / 8] ^= 1 << (bit % 8);
            let mut input = cipher;
            assert_eq!(
                open(&key, &nonce, &aad, &mut input, &bad),
                Err(Error::Authentication)
            );
            assert_eq!(input, cipher);
        }
        for at in 0..cipher.len() {
            let mut input = cipher;
            input[at] ^= 1;
            let before = input;
            assert_eq!(
                open(&key, &nonce, &aad, &mut input, &expected),
                Err(Error::Authentication)
            );
            assert_eq!(input, before);
        }
        for at in 0..aad.len() {
            let mut wrong = aad;
            wrong[at] ^= 1;
            let mut input = cipher;
            assert_eq!(
                open(&key, &nonce, &wrong, &mut input, &expected),
                Err(Error::Authentication)
            );
            assert_eq!(input, cipher);
        }
        let mut wrong_nonce = nonce;
        wrong_nonce[0] ^= 1;
        let mut input = cipher;
        assert_eq!(
            open(&key, &wrong_nonce, &aad, &mut input, &expected),
            Err(Error::Authentication)
        );
        assert_eq!(input, cipher);
        let mut wrong_key = key;
        wrong_key[0] ^= 1;
        assert_eq!(
            open(&wrong_key, &nonce, &aad, &mut input, &expected),
            Err(Error::Authentication)
        );
        assert_eq!(input, cipher);
    }
    #[test]
    fn empty_and_block_boundaries() {
        let key = [5; 32];
        let nonce = [7; 12];
        let aad = [9; 33];
        for a in [0, 1, 15, 16, 17, 32, 33] {
            for n in [0, 1, 15, 16, 17, 63, 64, 65, 129] {
                let mut data = [3; 129];
                let t = seal(&key, &nonce, &aad[..a], &mut data[..n]).unwrap();
                open(&key, &nonce, &aad[..a], &mut data[..n], &t).unwrap();
                assert_eq!(data, [3; 129]);
            }
        }
    }
    #[test]
    fn independent_aead_corpus() {
        let mut aad = [0u8; 33];
        let mut data = [0u8; 1025];
        for &(seed, a, n, cipher, mac) in include!("../../tests/aead_vectors.in") {
            let key = core::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(seed as u8));
            let nonce =
                core::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(seed as u8));
            for (i, v) in aad[..a].iter_mut().enumerate() {
                *v = (i as u8).wrapping_mul(13).wrapping_add(seed as u8);
            }
            for (i, v) in data[..n].iter_mut().enumerate() {
                *v = (i as u8).wrapping_mul(7).wrapping_add(seed as u8);
            }
            let actual = seal(&key, &nonce, &aad[..a], &mut data[..n]).unwrap();
            assert_eq!(actual, hex::<16>(mac), "seed={seed} aad={a} data={n}");
            for (i, &v) in data[..n].iter().enumerate() {
                assert_eq!(
                    v,
                    u8::from_str_radix(&cipher[i * 2..i * 2 + 2], 16).unwrap()
                );
            }
            let before = data;
            let mut bad = actual;
            bad[15] ^= 128;
            assert_eq!(
                open(&key, &nonce, &aad[..a], &mut data[..n], &bad),
                Err(Error::Authentication)
            );
            assert_eq!(before, data);
            open(&key, &nonce, &aad[..a], &mut data[..n], &actual).unwrap();
            for (i, &v) in data[..n].iter().enumerate() {
                assert_eq!(v, (i as u8).wrapping_mul(7).wrapping_add(seed as u8));
            }
        }
    }
    #[test]
    fn counter_limit_is_checked_without_allocating_huge_buffers() {
        assert_eq!(checked_body_length(MAX_PLAINTEXT_BYTES), Ok(()));
        assert_eq!(
            checked_body_length(MAX_PLAINTEXT_BYTES + 1),
            Err(Error::Length)
        );
        assert_eq!(checked_body_length(u64::MAX), Err(Error::Length));
    }
}
