#![no_std]
#![deny(unsafe_code)]
//! QUIC-specific TLS endpoint and cryptographic material; security qualification is ongoing.
//! Protocol order belongs to Hibana globals and direct locals, not a phase enum.
pub mod crypto;

pub mod x509;

pub mod entropy;

mod protocol;
pub mod schedule;
pub mod wire;
pub use protocol::{Protocol, RawProtocol};
pub mod signature;

pub mod quic;
#[cfg(test)]
extern crate std;
pub mod certificate;
pub mod early;
pub mod ticket;

#[cfg(feature = "alloc")]
extern crate alloc;
pub mod secret;

pub mod key_exchange;

pub mod endpoint;

pub mod handshake;
