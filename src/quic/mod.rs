//! QUIC-specific TLS metadata; no transport controller or socket implementation.
mod limits;
pub mod parameters;
pub mod version;
pub mod wire;
pub use limits::Limits;
pub mod packet_protection;

pub mod scope;

mod provider;
pub use provider::{
    Error, FAILURE_DIAGNOSTIC_BYTES, FailureDiagnostic, Level, Observations, Output, Provider,
};
