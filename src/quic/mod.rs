//! QUIC-specific TLS metadata; no transport controller or socket implementation.
pub mod wire;
pub mod version;
pub mod parameters;
mod limits;
pub use limits::Limits;
pub mod packet_protection;

pub mod scope;
