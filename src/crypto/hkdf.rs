//! SHA-256 HKDF and TLS 1.3 label encoding, RFC 5869 / RFC 8446 section 7.1.
//! Caller-owned output; no heap allocation or protocol-order authority.
use super::hmac::HmacSha256;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Label,
    Context,
}
pub const MAX_OUTPUT: usize = 255 * 32;
pub fn extract(salt: &[u8], input: &[u8]) -> Result<[u8; 32], Error> {
    HmacSha256::authenticate(salt, input).map_err(|_| Error::Length)
}
pub fn expand(key: &[u8; 32], info: &[u8], output: &mut [u8]) -> Result<(), Error> {
    expand_parts(key, &[info], output)
}
fn expand_parts(key: &[u8; 32], info: &[&[u8]], output: &mut [u8]) -> Result<(), Error> {
    // Validate every public length before writing any caller output.
    if output.len() > MAX_OUTPUT {
        return Err(Error::Length);
    }
    let total = info
        .iter()
        .try_fold(0u64, |n, part| {
            n.checked_add(u64::try_from(part.len()).ok()?)
        })
        .ok_or(Error::Length)?;
    if total > u64::MAX / 8 - 64 - 32 - 1 {
        return Err(Error::Length);
    }
    let mut previous = [0u8; 32];
    let mut used = 0;
    for (i, chunk) in output.chunks_mut(32).enumerate() {
        let mut h = HmacSha256::new(key).expect("fixed HKDF key length");
        h.update(&previous[..used])
            .expect("checked HKDF message length");
        for part in info {
            h.update(part).expect("checked HKDF message length");
        }
        h.update(&[(i + 1) as u8])
            .expect("checked HKDF counter length");
        previous = h.finish();
        chunk.copy_from_slice(&previous[..chunk.len()]);
        used = 32;
    }
    Ok(())
}
pub fn expand_label(
    key: &[u8; 32],
    label: &[u8],
    context: &[u8],
    output: &mut [u8],
) -> Result<(), Error> {
    if label.is_empty() || label.len() > 249 {
        return Err(Error::Label);
    }
    if context.len() > 255 {
        return Err(Error::Context);
    }
    if output.len() > MAX_OUTPUT {
        return Err(Error::Length);
    }
    let length = (output.len() as u16).to_be_bytes();
    let label_len = [(6 + label.len()) as u8];
    let context_len = [context.len() as u8];
    expand_parts(
        key,
        &[&length, &label_len, b"tls13 ", label, &context_len, context],
        output,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn hex<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), N * 2);
        core::array::from_fn(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
    }
    #[test]
    fn rfc5869_sha256_case1() {
        let key = extract(&hex::<13>("000102030405060708090a0b0c"), &[0x0b; 22]).unwrap();
        assert_eq!(
            key,
            hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        );
        let mut out = [0; 42];
        expand(&key, &hex::<10>("f0f1f2f3f4f5f6f7f8f9"), &mut out).unwrap();
        assert_eq!(
            out,
            hex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
    }
    #[test]
    fn rfc5869_sha256_case2_long_key() {
        let input: [u8; 80] = core::array::from_fn(|i| i as u8);
        let salt: [u8; 80] = core::array::from_fn(|i| 0x60 + i as u8);
        let info: [u8; 80] = core::array::from_fn(|i| 0xb0 + i as u8);
        let key = extract(&salt, &input).unwrap();
        assert_eq!(
            key,
            hex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")
        );
        let mut out = [0; 82];
        expand(&key, &info, &mut out).unwrap();
        assert_eq!(
            out,
            hex(
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
            )
        );
    }
    #[test]
    fn rfc5869_sha256_case3_empty_salt_info() {
        let key = extract(&[], &[0x0b; 22]).unwrap();
        assert_eq!(
            key,
            hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
        );
        let mut out = [0; 42];
        expand(&key, &[], &mut out).unwrap();
        assert_eq!(
            out,
            hex(
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
            )
        );
    }
    #[test]
    fn limits_reject_without_changing_output() {
        let mut out = [0xa5; MAX_OUTPUT + 1];
        assert_eq!(expand(&[1; 32], &[], &mut out), Err(Error::Length));
        assert!(out.iter().all(|b| *b == 0xa5));
        assert_eq!(
            expand_label(&[1; 32], &[], &[], &mut out[..32]),
            Err(Error::Label)
        );
        assert_eq!(
            expand_label(&[1; 32], &[b'a'; 250], &[], &mut out[..32]),
            Err(Error::Label)
        );
        assert_eq!(
            expand_label(&[1; 32], b"key", &[0; 256], &mut out[..32]),
            Err(Error::Context)
        );
        assert!(out.iter().all(|b| *b == 0xa5));
        expand(&[1; 32], &[], &mut out[..MAX_OUTPUT]).unwrap();
        expand(&[1; 32], &[], &mut []).unwrap();
        expand_label(&[1; 32], &[b'a'; 249], &[0; 255], &mut out[..32]).unwrap();
    }
    #[test]
    fn independent_label_and_counter_boundary_vectors() {
        // Independently evaluated with Python hmac/hashlib (OpenSSL).
        let key = core::array::from_fn(|i| i as u8);
        let mut out = [0; 16];
        expand_label(&key, b"key", &[], &mut out).unwrap();
        assert_eq!(out, hex("9c9783cf77ea32d44f369da41f19f3cc"));
        let mut maximum = [0; MAX_OUTPUT];
        expand(&[1; 32], &[], &mut maximum).unwrap();
        assert_eq!(
            &maximum[MAX_OUTPUT - 32..],
            &hex::<32>("958c0e5d350101f7da784ebf335623a13c73172aee061b24d8f97d00299b599d")
        );
    }
}
