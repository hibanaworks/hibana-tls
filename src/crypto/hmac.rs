//! HMAC-SHA-256 (RFC 2104), with fixed storage and checked message lengths.
//! Secret erasure and machine-code timing qualification are still outstanding.
use super::sha256::{MessageTooLong, Sha256};
pub struct HmacSha256 {
    inner: Sha256,
    outer: Sha256,
}
impl HmacSha256 {
    pub fn new(key: &[u8]) -> Result<Self, MessageTooLong> {
        let mut block = [0u8; 64];
        if key.len() > 64 {
            block[..32].copy_from_slice(&Sha256::digest(key)?);
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        for b in &mut block {
            *b ^= 0x36;
        }
        let mut inner = Sha256::new();
        inner.update(&block)?;
        for b in &mut block {
            *b ^= 0x36 ^ 0x5c;
        }
        let mut outer = Sha256::new();
        outer.update(&block)?;
        Ok(Self { inner, outer })
    }
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), MessageTooLong> {
        self.inner.update(bytes)
    }
    pub fn finish(mut self) -> [u8; 32] {
        // The outer input is exactly 64 + 32 bytes, below SHA-256's limit.
        self.outer
            .update(&self.inner.finish())
            .expect("fixed outer HMAC length");
        self.outer.finish()
    }
    pub fn authenticate(key: &[u8], message: &[u8]) -> Result<[u8; 32], MessageTooLong> {
        let mut h = Self::new(key)?;
        h.update(message)?;
        Ok(h.finish())
    }
}
