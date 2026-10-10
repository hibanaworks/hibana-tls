//! P-256 ECDH and deterministic ECDSA/SHA-256 for the QUIC TLS profile.
//! Fixed storage, no external arithmetic/crypto packages. RFC 6979 nonces.
//! This implementation is under qualification. Generated-code timing and
//! compiler-proof erasure of temporaries have NOT been established.
mod arithmetic;
mod der;
mod point;
use super::{hmac::HmacSha256, sha256::Sha256};
use crate::secret::{Erase, Secret};
use arithmetic::{Int, N};
use point::Point;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidScalar,
    InvalidPoint,
    InvalidSignature,
    Der,
    MessageTooLong,
    NonceExhausted,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "P-256 {self:?}")
    }
}
impl core::error::Error for Error {}
/// Actual non-cloneable private scalar. Construction rejects zero and >= n.
/// Drop overwrites its owned bytes; compiler-proof erasure is not claimed.
pub struct SecretKey {
    bytes: [u8; 32],
}
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.bytes.erase();
    }
}
impl SecretKey {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidScalar)?;
        let d = Int::from_be(&bytes);
        if !N.valid(d) || d.zero() == 1 {
            return Err(Error::InvalidScalar);
        }
        Ok(Self { bytes })
    }
    pub fn public_key(&self) -> [u8; 65] {
        Point::generator()
            .mul(Int::from_be(&self.bytes))
            .encode()
            .expect("nonzero scalar in prime-order group")
    }
    /// Consumes the fresh ECDH scalar after validating the complete peer point.
    pub fn agree(self, peer: &[u8]) -> Result<[u8; 32], Error> {
        Ok(Point::parse(peer)?
            .mul(Int::from_be(&self.bytes))
            .affine()?
            .0
            .to_be())
    }
    pub fn from_pkcs8_der(bytes: &[u8]) -> Result<Self, Error> {
        der::private_key(bytes, true)
    }
    pub fn from_sec1_der(bytes: &[u8]) -> Result<Self, Error> {
        der::private_key(bytes, false)
    }
    pub fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        self.sign_prehash(&Sha256::digest(message).map_err(|_| Error::MessageTooLong)?)
    }
    pub fn sign_prehash(&self, hash: &[u8; 32]) -> Result<Signature, Error> {
        let z = N.reduce(Int::from_be(hash));
        let h = z.to_be();
        let mut k = Secret::new([0; 32]);
        let mut v = Secret::new([1; 32]);
        for control in [0, 1] {
            *k = mac(&k[..], &[&v[..], &[control], &self.bytes, &h])?;
            *v = mac(&k[..], &[&v[..]])?;
        }
        for _ in 0..8 {
            *v = mac(&k[..], &[&v[..]])?;
            let nonce = Int::from_be(&v);
            if N.valid(nonce) && nonce.zero() == 0 {
                let r = N.reduce(Point::generator().mul(nonce).affine()?.0);
                let sum = N.add(
                    N.encode(z),
                    N.mul(N.encode(r), N.encode(Int::from_be(&self.bytes))),
                );
                let s = N.decode(N.mul(N.inverse(N.encode(nonce)), sum));
                if r.zero() == 0 && s.zero() == 0 {
                    return Ok(Signature {
                        r: r.to_be(),
                        s: s.to_be(),
                    });
                }
            }
            *k = mac(&k[..], &[&v[..], &[0]])?;
            *v = mac(&k[..], &[&v[..]])?;
        }
        Err(Error::NonceExhausted)
    }
}
fn mac(key: &[u8], parts: &[&[u8]]) -> Result<[u8; 32], Error> {
    let mut h = HmacSha256::new(key).map_err(|_| Error::MessageTooLong)?;
    for p in parts {
        h.update(p).map_err(|_| Error::MessageTooLong)?;
    }
    Ok(h.finish())
}
#[derive(Debug)]
pub struct Signature {
    r: [u8; 32],
    s: [u8; 32],
}
impl Signature {
    pub fn from_der(bytes: &[u8]) -> Result<Self, Error> {
        der::signature(bytes)
    }
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, Error> {
        let r = bytes[..32].try_into().unwrap();
        let s = bytes[32..].try_into().unwrap();
        for x in [r, s] {
            let x = Int::from_be(&x);
            if !N.valid(x) || x.zero() == 1 {
                return Err(Error::InvalidSignature);
            }
        }
        Ok(Self { r, s })
    }
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut b = [0; 64];
        b[..32].copy_from_slice(&self.r);
        b[32..].copy_from_slice(&self.s);
        b
    }
    pub fn to_der(&self) -> DerSignature {
        der::encode_signature(self)
    }
}
pub struct DerSignature {
    bytes: [u8; 72],
    len: usize,
}
impl DerSignature {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
    verify_prehash(
        public_key,
        &Sha256::digest(message).map_err(|_| Error::MessageTooLong)?,
        &Signature::from_der(signature)?,
    )
}
pub fn verify_prehash(
    public_key: &[u8],
    hash: &[u8; 32],
    signature: &Signature,
) -> Result<(), Error> {
    let point = Point::parse(public_key)?;
    let r = Int::from_be(&signature.r);
    let s = Int::from_be(&signature.s);
    let inv = N.inverse(N.encode(s));
    let u = N.decode(N.mul(N.encode(N.reduce(Int::from_be(hash))), inv));
    let v = N.decode(N.mul(N.encode(r), inv));
    let out = Point::generator().mul(u).add(point.mul(v));
    let (x, _) = out.affine().map_err(|_| Error::InvalidSignature)?;
    if N.reduce(x) == r {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}
#[cfg(test)]
mod tests;
