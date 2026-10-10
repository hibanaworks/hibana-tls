//! Verification-only RFC 8017 encodings for the adapter's SHA-256 profiles.
//! Fixed public widths and public signatures; no signing or secret-key operations.
use super::{Error, SHA256_DIGEST_INFO};
use crate::crypto::sha256::Sha256;
use crate::secret::{FixedTimeEq, Mask};

fn width(n: usize) -> Result<(), Error> {
    if matches!(n, 256 | 384 | 512) {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

pub(super) fn pkcs1v15(digest: &[u8; 32], encoded: &[u8]) -> Result<(), Error> {
    let n = encoded.len();
    width(n)?;
    // 00 01 || FF^(n-54) || 00 || DigestInfo(19) || SHA256(32).
    let separator = n - 52;
    let mut expected = [0u8; 512];
    expected[1] = 1;
    expected[2..separator].fill(0xff);
    expected[separator + 1..n - 32].copy_from_slice(SHA256_DIGEST_INFO);
    expected[n - 32..n].copy_from_slice(digest);
    if bool::from(encoded.fixed_time_eq(&expected[..n])) {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

pub(super) fn pss(digest: &[u8; 32], encoded: &mut [u8]) -> Result<(), Error> {
    let n = encoded.len();
    width(n)?;
    // Exact full-bit moduli are checked by the public-key adapter: emBits=8*n-1.
    if encoded[n - 1] != 0xbc || encoded[0] & 0x80 != 0 {
        return Err(Error::InvalidSignature);
    }
    let db_len = n - 33;
    let mut h = [0u8; 32];
    h.copy_from_slice(&encoded[db_len..n - 1]);
    let db = &mut encoded[..db_len];
    // MGF1-SHA256: at most 15 blocks for the largest admitted modulus.
    for (counter, chunk) in db.chunks_mut(32).enumerate() {
        let mut hash = Sha256::new();
        hash.update(&h).map_err(|_| Error::InvalidSignature)?;
        hash.update(&(counter as u32).to_be_bytes())
            .map_err(|_| Error::InvalidSignature)?;
        let mask = hash.finish();
        for (value, mask) in chunk.iter_mut().zip(mask.iter()) {
            *value ^= *mask;
        }
    }
    db[0] &= 0x7f;
    let separator = db_len - 33;
    let mut valid = Mask::from(1);
    for byte in &db[..separator] {
        valid &= byte.fixed_time_eq(&0);
    }
    valid &= db[separator].fixed_time_eq(&1);
    let mut hash = Sha256::new();
    hash.update(&[0u8; 8])
        .map_err(|_| Error::InvalidSignature)?;
    hash.update(digest).map_err(|_| Error::InvalidSignature)?;
    hash.update(&db[separator + 1..])
        .map_err(|_| Error::InvalidSignature)?;
    valid &= hash.finish()[..].fixed_time_eq(&h);
    if bool::from(valid) {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_every_unsupported_encoding_width_without_indexing() {
        let digest = [0; 32];
        let mut bytes = [0; 513];
        for n in 0..=513 {
            if matches!(n, 256 | 384 | 512) {
                continue;
            }
            assert_eq!(pkcs1v15(&digest, &bytes[..n]), Err(Error::InvalidSignature));
            assert_eq!(pss(&digest, &mut bytes[..n]), Err(Error::InvalidSignature));
        }
    }
}
