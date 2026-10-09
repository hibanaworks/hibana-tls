//! Bounded RSA signature verification adapter, without allocation.
//!
//! Project-owned fixed-size arithmetic and borrowed DER parsing surround
//! project-owned RFC 8017 encoding checks. This is a review-required
//! project adapter, NOT an upstream public RSA API. See docs/tls-rsa-feasibility.md.
//! Exact 2048/3072/4096-bit moduli and odd 32-bit public exponents are supported.
//! No RSA signing, private-key operations, key generation or TLS advertisement.

use crate::crypto::sha256::Sha256;
mod encoding;
mod public_key;
use public_key::parse as public_key;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidDer,
    UnsupportedKeySize,
    InvalidModulus,
    InvalidExponent,
    InvalidSignature,
}

struct PublicKey<'a> {
    modulus: &'a [u8],
    exponent: u32,
}

// RFC8017 Appendix B.1's DER DigestInfo prefix for SHA-256, including NULL
// AlgorithmIdentifier parameters. It is public format data, not key material.
const SHA256_DIGEST_INFO: &[u8; 19] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
fn verify(public_der: &[u8], message: &[u8], signature: &[u8], pss: bool) -> Result<(), Error> {
    let key = public_key(public_der)?;
    let width = key.modulus.len();
    if signature.len() != width {
        return Err(Error::InvalidSignature);
    }
    let mut encoded = [0u8; 512];
    let encoded = &mut encoded[..width];
    crate::crypto::rsa::recover(key.modulus, key.exponent, signature, encoded)
        .map_err(|_| Error::InvalidSignature)?;
    let digest: [u8; 32] = Sha256::digest(message).map_err(|_| Error::InvalidSignature)?;
    if pss {
        // TLS rsa_pss_rsae_sha256 requires SHA256/MGF1-SHA256 and salt32.
        encoding::pss(&digest, encoded)
    } else {
        encoding::pkcs1v15(&digest, encoded)
    }
    .map_err(|_| Error::InvalidSignature)
}

/// RSASSA-PSS with SHA256, MGF1-SHA256 and exactly32 salt bytes. `public_key_der`
/// is borrowed PKCS#1 RSAPublicKey DER, as carried inside an RSA SPKI bit string.
pub fn verify_pss_sha256(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    verify(public_key_der, message, signature, true)
}
/// RSASSA-PKCS1-v1_5/SHA256 certificate-signature verification. TLS1.3 must not
/// use this scheme for CertificateVerify. Signature bytes must be modulus-width.
pub fn verify_pkcs1_sha256(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    verify(public_key_der, message, signature, false)
}
