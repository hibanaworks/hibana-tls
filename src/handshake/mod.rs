//! Allocation-free TLS 1.3 certificate and optional PSK_DHE profile for QUIC v1.
//!
//! Fresh X25519/P-256 ECDHE, server certificate/hostname/CertificateVerify checks,
//! Finished verification, and negotiated traffic keys. Caller-owned input/output,
//! certificate, transport-parameter and optional ticket/cache storage is mandatory.
//! Resumption offers are bound to the actual client trust/verification context;
//! only authenticated OneRtt NST input can populate the provider's ticket cache.
//! Full and resumed handshakes share strict HRR and Finished state transitions.
//! Explicit early constructors additionally require replay/freshness policy,
//! remembered limits and application retry authorization. Ordinary constructors
//! keep 0-RTT disabled. Client authentication is not enabled; this is not a claim
//! of complete mandatory TLS algorithms or QUIC release conformance.

pub mod global;
mod imp;
pub mod local;

use imp::Mode;
pub use imp::{
    ALPN, BoundedTls, CipherPolicy, ClientConfig, ClientEarlyData, ClientResumption, Failure,
    ServerConfig, ServerEarlyData, ServerResumption, SigningKey, Storage,
};

#[cfg(test)]
#[path = "../../tests/support/async_tls_fixture.rs"]
pub(crate) mod async_test_fixture;

#[cfg(test)]
#[path = "../../tests/support/tls_actor_fixture.rs"]
pub(crate) mod test_fixture;
