//! Exact public AlgorithmIdentifiers, RFC5480/RFC4055; project-owned primitives.
use super::der::InvalidDer;
pub const P256: &[u8] =
    b"\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";
pub const ECDSA_SHA256: &[u8] = b"\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02";
pub const RSA: &[u8] = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
pub const PKCS1_SHA256: &[u8] = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00";
pub const PSS_SHA256: &[u8] = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a\x30\x34\xa0\x0f\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\xa1\x1c\x30\x1a\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x08\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\xa2\x03\x02\x01\x20";

pub fn verify(
    key_algorithm: &[u8],
    key: &[u8],
    algorithm: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidDer> {
    if key_algorithm == P256 && algorithm == ECDSA_SHA256 {
        crate::crypto::p256::verify(key, message, signature).map_err(|_| InvalidDer)
    } else if key_algorithm == RSA && algorithm == PSS_SHA256 {
        crate::signature::rsa::verify_pss_sha256(key, message, signature).map_err(|_| InvalidDer)
    } else if key_algorithm == RSA
        && (algorithm == PKCS1_SHA256 || algorithm == &PKCS1_SHA256[..11])
    {
        crate::signature::rsa::verify_pkcs1_sha256(key, message, signature).map_err(|_| InvalidDer)
    } else {
        Err(InvalidDer)
    }
}
