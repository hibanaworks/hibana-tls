//! Caller-supplied TLS configuration and bounded storage contracts.
use crate::{
    certificate::{self as certificate, Limits, TrustAnchor, UnixTime},
    early::{self as early, EarlyFreshness, RememberedLimits, ServerPolicy},
    quic::packet_protection::{self as crypto},
    schedule::{self as schedule},
    ticket, wire,
};

pub use crate::crypto::p256::SecretKey as SigningKey;
pub use crate::wire::CipherPolicy;
pub const ALPN: &[u8] = b"hq-interop";
pub(super) const MAX_CHAIN: usize = certificate::MAX_INTERMEDIATES + 1;

/// The four buffers must be distinct borrows. RX holds one complete handshake
/// message; TX holds one complete outbound flight; certificate storage holds the
/// peer's encoded Certificate message (and CH1 during retry); parameters hold
/// the peer's raw extension. Server certificate scratch must also fit CH1 for HRR.
pub struct Storage<'a> {
    pub rx_message: &'a mut [u8],
    pub tx_flight: &'a mut [u8],
    pub peer_certificates: &'a mut [u8],
    pub peer_parameters: &'a mut [u8],
}

pub struct ClientConfig<'a> {
    pub protocol: crate::Protocol,
    pub version: crate::quic::version::Version,
    pub server_name: &'a str,
    pub trust_anchors: &'a [TrustAnchor<'a>],
    pub now: UnixTime,
    pub certificate_limits: Limits,
    pub transport_parameters: &'a [u8],
}
pub struct ServerConfig<'a> {
    pub protocol: crate::Protocol,
    pub version: crate::quic::version::Version,
    /// DER leaf first, then intermediate certificates. Do not include private keys.
    pub certificate_chain: &'a [&'a [u8]],
    pub signing_key: &'a SigningKey,
    pub transport_parameters: &'a [u8],
}

pub(in crate::handshake) enum Mode<'a> {
    Client(ClientConfig<'a>),
    Server(ServerConfig<'a>),
}

#[derive(Debug)]
pub enum Failure {
    InvalidStorage,
    InvalidConfig,
    Entropy,
    State,
    InvalidKeyShare,
    UnsupportedSuite,
    CertificateKeyMismatch,
    Wire(wire::Error),
    Certificate(certificate::Error),
    Schedule(schedule::Error),
    Crypto(crypto::Error),
    Ticket(ticket::Error),
    Parameters(crate::quic::parameters::Error),
    Early(early::Error),
    Capacity,
}
impl From<wire::Error> for Failure {
    fn from(e: wire::Error) -> Self {
        Self::Wire(e)
    }
}
impl From<certificate::Error> for Failure {
    fn from(e: certificate::Error) -> Self {
        Self::Certificate(e)
    }
}
impl From<schedule::Error> for Failure {
    fn from(e: schedule::Error) -> Self {
        Self::Schedule(e)
    }
}
impl From<crypto::Error> for Failure {
    fn from(e: crypto::Error) -> Self {
        Self::Crypto(e)
    }
}

impl From<ticket::Error> for Failure {
    fn from(e: ticket::Error) -> Self {
        Self::Ticket(e)
    }
}

/// Caller-owned cache and trusted millisecond clock, kept across connections.
pub struct ClientResumption<'a> {
    pub store: &'a mut dyn ticket::ClientTicketStore,
    pub clock: &'a dyn ticket::TicketClock,
}
/// Caller-owned authenticated ticket key/replay policy and entropy. The policy
/// bytes must describe stable server configuration not represented by QUIC limits.
pub struct ServerResumption<'a> {
    pub store: &'a mut dyn ticket::ServerTicketStore,
    pub entropy: &'a mut dyn crate::entropy::Entropy,
    pub clock: &'a dyn ticket::TicketClock,
    pub policy: &'a [u8],
    pub lifetime_seconds: u32,
    pub max_age_skew_ms: u32,
}
/// Explicit application opt-in. The application promises replay-tolerant
/// requests; this does not imply network exactly-once semantics. This opt-in
/// also authorizes retransmitting those queued complete requests over 1-RTT
/// after early rejection, under the newly authenticated transport limits.
/// Applications that do not authorize that retry must not enable this mode.
#[derive(Clone, Copy)]
pub struct ClientEarlyData {
    pub(in crate::handshake) generation: u64,
}
impl ClientEarlyData {
    pub const fn replay_safe_requests(generation: u64) -> Self {
        Self { generation }
    }
}
/// Checked configured receive geometry, not authority to release early data.
/// The QUIC quarantine must independently validate its actual owned buffers
/// against this policy before admitting data; this value owns no buffer.
#[derive(Clone, Copy)]
pub struct ServerEarlyData {
    pub(in crate::handshake) generation: u64,
    pub(in crate::handshake) limits: RememberedLimits,
    pub(in crate::handshake) freshness: EarlyFreshness,
}
impl ServerEarlyData {
    pub fn buffered<const BYTES: usize>(
        generation: u64,
        policy: ServerPolicy,
        parameters: &[u8],
        slots: usize,
        freshness: EarlyFreshness,
    ) -> Result<Self, Failure> {
        let limits = RememberedLimits::from_authenticated_server_parameters(parameters)
            .map_err(Failure::Early)?;
        policy
            .check_capacity::<BYTES>(limits, slots)
            .map_err(Failure::Early)?;
        Ok(Self {
            generation,
            limits,
            freshness,
        })
    }
}
