//! Caller-owned cryptographic entropy capability.
//!
//! The no_std TLS core owns no operating-system RNG or fallback PRNG. A supplied
//! implementation must obtain fresh cryptographically secure bytes from its
//! trusted platform source. This contract does not certify an implementation's
//! quality. Protocol order and one-use secret ownership belong to Hibana locals.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Unavailable;

impl core::fmt::Display for Unavailable {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        out.write_str("cryptographic entropy unavailable")
    }
}

/// Fill the entire destination with fresh cryptographic random bytes or fail.
/// On failure the destination is unspecified and MUST NOT be used as key material.
/// Implementations must not substitute timestamps, counters, zeros or weak PRNGs.
pub trait Entropy {
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Unavailable>;
}
