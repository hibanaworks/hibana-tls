//! Owned TLS buffers, transcript material and cryptographic operations.
use crate::crypto::p256::SecretKey;
use crate::entropy::Entropy;
use crate::secret::{Erase, Secret};
use crate::{
    certificate::{self as certificate, CertificateDer, ServerName, ServerVerifier},
    early::{self as early, EarlyStatus, RememberedLimits, ReplayClaim},
    quic::packet_protection::{self as crypto, CipherSuite, IntegrityBudget, KeyKind, PacketKey},
    quic::{self as tls, Level, Output, Provider},
    schedule::{self as schedule, KeySchedule, Side, Transcript},
    ticket, wire,
};

use super::config::*;
use super::keys;
mod provider;
mod transcript;
enum Resumption<'a> {
    Client(ClientResumption<'a>),
    Server(ServerResumption<'a>),
}

/// Hash stable parsed transport limits, never connection IDs or reset tokens.
/// This remembers a 1-RTT binding only; it does not authorize early data.
fn transport_profile(bytes: &[u8], policy: &[u8]) -> Result<[u8; 32], Failure> {
    use crate::crypto::sha256::Sha256;
    if policy.len() > ticket::MAX_BINDING_PROFILE_BYTES {
        return Err(Failure::InvalidConfig);
    }
    let params = crate::quic::parameters::Parameters::parse(
        bytes,
        crate::quic::parameters::Peer::Server,
        &mut [0; 64],
    )
    .map_err(Failure::Parameters)?;
    let mut h = Sha256::new();
    h.update(b"hibana-quic stable server limits v1")
        .map_err(|_| Failure::InvalidConfig)?;
    for (id, default) in [
        (1, 0),
        (3, 65527),
        (4, 0),
        (5, 0),
        (6, 0),
        (7, 0),
        (8, 0),
        (9, 0),
        (10, 3),
        (11, 25),
        (14, 2),
    ] {
        let value = params
            .get_integer(id, default)
            .map_err(Failure::Parameters)?;
        h.update(&id.to_be_bytes())
            .map_err(|_| Failure::InvalidConfig)?;
        h.update(&value.to_be_bytes())
            .map_err(|_| Failure::InvalidConfig)?;
    }
    h.update(&[u8::from(params.get(12).is_some())])
        .map_err(|_| Failure::InvalidConfig)?;
    h.update(&(policy.len() as u32).to_be_bytes())
        .map_err(|_| Failure::InvalidConfig)?;
    h.update(policy).map_err(|_| Failure::InvalidConfig)?;
    Ok(h.finish())
}

pub(in crate::handshake) struct DirectionalKeys {
    pub(in crate::handshake) local: PacketKey,
    pub(in crate::handshake) remote: PacketKey,
}

// Actual successful Finished verification, owned until the scoped handoff.
pub(in crate::handshake) struct VerifiedHandshake {
    pub(in crate::handshake) resumed: bool,
    pub(in crate::handshake) side: Side,
    pub(in crate::handshake) protocol: crate::Protocol,
    pub(in crate::handshake) peer_parameters_digest: [u8; 32],
    pub(in crate::handshake) early_status: EarlyStatus,
    pub(in crate::handshake) early_generation: Option<u64>,
}

/// A single-owner TLS provider. No self-references into owned receive storage;
/// peer certificates are represented by bounded offsets and reborrowed for CV.
pub struct BoundedTls<'cfg, 'buf> {
    pub(in crate::handshake) mode: Mode<'cfg>,
    pub(in crate::handshake) last_failure: Option<Failure>,
    pub(in crate::handshake) rx: Option<&'buf mut [u8]>,
    pub(in crate::handshake) rx_used: usize,
    pub(in crate::handshake) rx_target: usize,
    pub(in crate::handshake) tx: &'buf mut [u8],
    pub(in crate::handshake) tx_len: usize,
    pub(in crate::handshake) tx_sent: usize,
    pub(in crate::handshake) tx_initial_end: usize,
    pub(in crate::handshake) tx_handshake_end: usize,
    pub(in crate::handshake) certificates: &'buf mut [u8],
    pub(in crate::handshake) cert_ranges: [wire::DerRange; MAX_CHAIN],
    pub(in crate::handshake) cert_count: usize,
    pub(in crate::handshake) first_hello_len: usize,
    pub(in crate::handshake) retry_suite: Option<u16>,
    pub(in crate::handshake) retry_group: Option<u16>,
    pub(in crate::handshake) parameters: &'buf mut [u8],
    pub(in crate::handshake) parameters_len: usize,
    pub(in crate::handshake) ephemeral: Option<SecretKey>,
    pub(in crate::handshake) x25519: Option<crate::key_exchange::X25519Secret>,
    pub(in crate::handshake) x25519_share: [u8; 32],
    pub(in crate::handshake) allow_x25519: bool,
    pub(in crate::handshake) negotiated_group: Option<u16>,
    pub(in crate::handshake) share: [u8; 65],
    pub(in crate::handshake) random: [u8; 32],
    pub(in crate::handshake) transcript: Transcript,
    pub(in crate::handshake) schedule: KeySchedule,
    pub(in crate::handshake) suite: Option<CipherSuite>,
    pub(in crate::handshake) cipher_policy: CipherPolicy,
    pub(in crate::handshake) handshake: Option<DirectionalKeys>,
    pub(in crate::handshake) application: Option<DirectionalKeys>,
    pub(in crate::handshake) integrity: Option<IntegrityBudget>,
    resumption: Option<Resumption<'cfg>>,
    pub(in crate::handshake) resumption_master: Option<schedule::ResumptionMaster>,
    pub(in crate::handshake) verification_context: Option<ticket::VerificationContext>,
    pub(in crate::handshake) ticket_binding: Option<ticket::Binding>,
    pub(in crate::handshake) offer_age: Option<ticket::OfferAge>,
    pub(in crate::handshake) offer_suite: Option<u16>,
    pub(in crate::handshake) peer_wants_tickets: bool,
    pub(in crate::handshake) early_status: EarlyStatus,
    pub(in crate::handshake) early_generation: Option<u64>,
    pub(in crate::handshake) early_limits: Option<RememberedLimits>,
    pub(in crate::handshake) early_server: Option<ServerEarlyData>,
    pub(in crate::handshake) early_key: Option<PacketKey>,
    pub(in crate::handshake) early_claim: Option<ReplayClaim>,
    pub(in crate::handshake) verified_handshake: Option<VerifiedHandshake>,
}

impl<'cfg, 'buf> BoundedTls<'cfg, 'buf> {
    pub fn client<R: Entropy>(
        config: ClientConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
    ) -> Result<Self, Failure> {
        Self::client_with_policy(config, storage, rng, CipherPolicy::Default)
    }
    /// Construct with an explicit immutable suite policy, enforced before output.
    pub fn client_with_policy<R: Entropy>(
        config: ClientConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        policy: CipherPolicy,
    ) -> Result<Self, Failure> {
        let name = ServerName::try_from(config.server_name).map_err(|_| Failure::InvalidConfig)?;
        if !matches!(name, ServerName::DnsName(_)) {
            return Err(Failure::InvalidConfig);
        }
        ServerVerifier::new(config.trust_anchors, config.now, config.certificate_limits)?;
        let mut this = Self::new(Mode::Client(config), storage, rng)?;
        this.cipher_policy = policy;
        let Mode::Client(config) = &this.mode else {
            return Err(Failure::State);
        };
        let n = wire::encode_client_hello_dual_with_policy(
            this.tx,
            &this.random,
            &this.share,
            &this.x25519_share,
            config.server_name,
            config.protocol.alpn(),
            config.transport_parameters,
            policy,
        )?;
        if n > this.certificates.len() {
            return Err(Failure::Capacity);
        }
        this.certificates[..n].copy_from_slice(&this.tx[..n]);
        this.first_hello_len = n;
        this.transcript.append(&this.tx[..n])?;
        this.tx_len = n;
        this.tx_initial_end = n;
        this.tx_handshake_end = n;
        Ok(this)
    }

    pub fn client_with_tickets<R: Entropy>(
        config: ClientConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ClientResumption<'cfg>,
    ) -> Result<Self, Failure> {
        Self::client_with_tickets_and_policy(
            config,
            storage,
            rng,
            resumption,
            CipherPolicy::Default,
        )
    }
    /// Construct with an explicit immutable suite policy, enforced before output.
    pub fn client_with_tickets_and_policy<R: Entropy>(
        config: ClientConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ClientResumption<'cfg>,
        policy: CipherPolicy,
    ) -> Result<Self, Failure> {
        let context =
            ticket::VerificationContext::new(config.trust_anchors, config.certificate_limits)?;
        let mut this = Self::client_with_policy(config, storage, rng, policy)?;
        this.verification_context = Some(context);
        this.resumption = Some(Resumption::Client(resumption));
        this.encode_psk_start(None)?;
        Ok(this)
    }
    pub fn client_resuming<R: Entropy, const BYTES: usize>(
        config: ClientConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ClientResumption<'cfg>,
        offer: ticket::ClientOffer<BYTES>,
    ) -> Result<Self, Failure> {
        Self::client_resuming_with_policy(
            config,
            storage,
            rng,
            resumption,
            offer,
            CipherPolicy::Default,
        )
    }
    /// Construct with an explicit immutable suite policy, enforced before output.
    pub fn client_resuming_with_policy<R: Entropy, const BYTES: usize>(
        config: ClientConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ClientResumption<'cfg>,
        mut offer: ticket::ClientOffer<BYTES>,
        policy: CipherPolicy,
    ) -> Result<Self, Failure> {
        let context =
            ticket::VerificationContext::new(config.trust_anchors, config.certificate_limits)?;
        let origin = ticket::Binding::new(config.server_name, config.protocol.alpn(), &[])?;
        // Independently enforce trust/origin even if caller used an unfiltered lookup.
        offer.verify_context(context, &origin)?;
        if !policy.permits(offer.suite()) {
            return Err(Failure::UnsupportedSuite);
        }
        let age = offer.obfuscated_age(resumption.clock.now_ms()?)?;
        let mut this =
            Self::client_with_tickets_and_policy(config, storage, rng, resumption, policy)?;
        this.schedule = offer.schedule()?;
        this.offer_suite = Some(offer.suite());
        this.offer_age = Some(offer.age_state());
        this.encode_psk_start(Some((offer.identity(), age)))?;
        Ok(this)
    }
    pub fn client_resuming_early<R: Entropy, const BYTES: usize>(
        config: ClientConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ClientResumption<'cfg>,
        offer: ticket::ClientOffer<BYTES>,
        early: ClientEarlyData,
    ) -> Result<Self, Failure> {
        Self::client_resuming_early_with_policy(
            config,
            storage,
            rng,
            resumption,
            offer,
            early,
            CipherPolicy::Default,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn client_resuming_early_with_policy<R: Entropy, const BYTES: usize>(
        config: ClientConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ClientResumption<'cfg>,
        mut offer: ticket::ClientOffer<BYTES>,
        early: ClientEarlyData,
        policy: CipherPolicy,
    ) -> Result<Self, Failure> {
        let context =
            ticket::VerificationContext::new(config.trust_anchors, config.certificate_limits)?;
        offer.verify_context(
            context,
            &ticket::Binding::new(config.server_name, config.protocol.alpn(), &[])?,
        )?;
        let limits = offer
            .remembered_early_limits()
            .ok_or(Failure::Ticket(ticket::Error::EarlyDataUnavailable))?;
        if !policy.permits(offer.suite()) {
            return Err(Failure::UnsupportedSuite);
        }
        let age = offer.obfuscated_age(resumption.clock.now_ms()?)?;
        let mut this =
            Self::client_with_tickets_and_policy(config, storage, rng, resumption, policy)?;
        this.schedule = offer.schedule()?;
        this.offer_suite = Some(offer.suite());
        this.offer_age = Some(offer.age_state());
        this.early_generation = Some(early.generation);
        this.early_limits = Some(limits);
        this.early_status = EarlyStatus::Offered;
        this.encode_psk_start(Some((offer.identity(), age)))?;
        let secret = this.schedule.client_early_traffic(&this.transcript)?;
        this.early_key = Some(PacketKey::from_secret_for_version(
            this.version(),
            suite_from_wire(offer.suite())?,
            KeyKind::ZeroRtt,
            secret.as_bytes(),
        )?);
        Ok(this)
    }
    fn encode_psk_start(&mut self, offer: Option<(&[u8], u32)>) -> Result<(), Failure> {
        let Mode::Client(config) = &self.mode else {
            return Err(Failure::State);
        };
        let n = wire::encode_client_hello_dual_early_with_policy(
            self.tx,
            &self.random,
            &self.share,
            &self.x25519_share,
            config.server_name,
            config.protocol.alpn(),
            config.transport_parameters,
            offer,
            self.early_status == EarlyStatus::Offered,
            self.cipher_policy,
        )?;
        self.transcript = Transcript::new();
        if let Some(psk) =
            wire::parse_client_hello_early_for_protocol(&self.tx[..n], config.protocol)?.psk
        {
            let (prefix, offset) = (psk.binder_prefix, psk.binder_offset);
            let hash = self.transcript.binder_hash(&self.tx[..prefix])?;
            let binder = self.schedule.binder(schedule::PskKind::Resumption, &hash)?;
            self.tx[offset..offset + 32].copy_from_slice(&binder);
        }
        if n > self.certificates.len() {
            return Err(Failure::Capacity);
        }
        self.certificates[..n].copy_from_slice(&self.tx[..n]);
        self.first_hello_len = n;
        self.transcript.append(&self.tx[..n])?;
        self.tx_len = n;
        self.tx_sent = 0;
        self.tx_initial_end = n;
        self.tx_handshake_end = n;
        Ok(())
    }
    pub fn server_with_tickets<R: Entropy>(
        config: ServerConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ServerResumption<'cfg>,
    ) -> Result<Self, Failure> {
        Self::server_with_tickets_and_policy(
            config,
            storage,
            rng,
            resumption,
            CipherPolicy::Default,
        )
    }
    /// Construct with an explicit immutable suite policy, enforced before output.
    pub fn server_with_tickets_and_policy<R: Entropy>(
        config: ServerConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ServerResumption<'cfg>,
        policy: CipherPolicy,
    ) -> Result<Self, Failure> {
        if resumption.lifetime_seconds == 0
            || resumption.lifetime_seconds > ticket::MAX_LIFETIME_SECONDS
            || resumption.max_age_skew_ms > ticket::MAX_AGE_SKEW_MS
            || resumption.policy.len() > ticket::MAX_BINDING_PROFILE_BYTES
        {
            return Err(Failure::InvalidConfig);
        }
        transport_profile(config.transport_parameters, resumption.policy)?;
        let mut this = Self::server_with_policy(config, storage, rng, policy)?;
        this.resumption = Some(Resumption::Server(resumption));
        Ok(this)
    }
    /// Explicit P-256-only group policy with the same bounded ticket services.
    pub fn server_p256_with_tickets<R: Entropy>(
        config: ServerConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ServerResumption<'cfg>,
    ) -> Result<Self, Failure> {
        let mut this = Self::server_with_tickets(config, storage, rng, resumption)?;
        this.allow_x25519 = false;
        this.x25519 = None;
        Ok(this)
    }
    pub fn server_with_early_data<R: Entropy>(
        config: ServerConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ServerResumption<'cfg>,
        early: ServerEarlyData,
    ) -> Result<Self, Failure> {
        Self::server_with_early_data_and_policy(
            config,
            storage,
            rng,
            resumption,
            early,
            CipherPolicy::Default,
        )
    }
    pub fn server_with_early_data_and_policy<R: Entropy>(
        config: ServerConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ServerResumption<'cfg>,
        early: ServerEarlyData,
        policy: CipherPolicy,
    ) -> Result<Self, Failure> {
        if !resumption.store.supports_early()
            || RememberedLimits::from_authenticated_server_parameters(config.transport_parameters)
                .map_err(Failure::Early)?
                != early.limits
        {
            return Err(Failure::InvalidConfig);
        }
        let mut this =
            Self::server_with_tickets_and_policy(config, storage, rng, resumption, policy)?;
        this.early_generation = Some(early.generation);
        this.early_server = Some(early);
        Ok(this)
    }
    pub fn server_p256_with_early_data<R: Entropy>(
        config: ServerConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ServerResumption<'cfg>,
        early: ServerEarlyData,
    ) -> Result<Self, Failure> {
        let mut this = Self::server_with_early_data(config, storage, rng, resumption, early)?;
        this.allow_x25519 = false;
        this.x25519 = None;
        Ok(this)
    }
    fn reject_early(&mut self) {
        if self.early_status != EarlyStatus::Disabled {
            self.early_status = EarlyStatus::Rejected;
        }
        self.early_key = None;
        self.early_claim = None;
    }
    pub fn is_resumed(&self) -> bool {
        self.verified_handshake
            .as_ref()
            .is_some_and(|receipt| receipt.resumed)
    }

    pub fn server<R: Entropy>(
        config: ServerConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
    ) -> Result<Self, Failure> {
        Self::server_with_policy(config, storage, rng, CipherPolicy::Default)
    }
    /// Construct with an explicit immutable suite policy, enforced before output.
    pub fn server_with_policy<R: Entropy>(
        config: ServerConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        policy: CipherPolicy,
    ) -> Result<Self, Failure> {
        if config.certificate_chain.is_empty() || config.certificate_chain.len() > MAX_CHAIN {
            return Err(Failure::InvalidConfig);
        }
        // Prove the supplied signing key matches the supplied leaf; neither trust
        // nor peer identity is established by this local configuration check.
        certificate::verify_signing_key(config.certificate_chain[0], config.signing_key).map_err(
            |error| match error {
                certificate::SigningKeyError::InvalidConfig => Failure::InvalidConfig,
                certificate::SigningKeyError::Mismatch => Failure::CertificateKeyMismatch,
            },
        )?;
        let mut this = Self::new(Mode::Server(config), storage, rng)?;
        this.cipher_policy = policy;
        Ok(this)
    }

    /// Explicit P-256-only group policy, useful for compatibility and genuine HRR
    /// testing. Certificate verification and all other checks remain unchanged.
    pub fn server_p256<R: Entropy>(
        config: ServerConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
    ) -> Result<Self, Failure> {
        let mut this = Self::server(config, storage, rng)?;
        this.allow_x25519 = false;
        this.x25519 = None;
        Ok(this)
    }

    fn new<R: Entropy>(
        mode: Mode<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
    ) -> Result<Self, Failure> {
        if storage.rx_message.len() < 4
            || storage.tx_flight.len() < 4
            || storage.peer_parameters.is_empty()
        {
            return Err(Failure::InvalidStorage);
        }
        if matches!(mode, Mode::Client(_)) && storage.peer_certificates.is_empty() {
            return Err(Failure::InvalidStorage);
        }
        let mut scalar = crate::secret::Secret::new([0u8; 32]);
        let mut ephemeral = None;
        for _ in 0..8 {
            rng.try_fill_bytes(&mut *scalar)
                .map_err(|_| Failure::Entropy)?;
            if let Ok(key) = SecretKey::from_slice(&*scalar) {
                ephemeral = Some(key);
                break;
            }
        }
        let ephemeral = ephemeral.ok_or(Failure::Entropy)?;
        let share = ephemeral.public_key();
        let mut random = [0; 32];
        rng.try_fill_bytes(&mut random)
            .map_err(|_| Failure::Entropy)?;
        let x25519 =
            crate::key_exchange::X25519Secret::generate(rng).map_err(|_| Failure::Entropy)?;
        let x25519_share = x25519.public_key();
        Ok(Self {
            mode,
            last_failure: None,
            rx: Some(storage.rx_message),
            rx_used: 0,
            rx_target: 0,
            tx: storage.tx_flight,
            tx_len: 0,
            tx_sent: 0,
            tx_initial_end: 0,
            tx_handshake_end: 0,
            certificates: storage.peer_certificates,
            cert_ranges: core::array::from_fn(|_| wire::DerRange { offset: 0, len: 0 }),
            cert_count: 0,
            first_hello_len: 0,
            retry_suite: None,
            retry_group: None,
            parameters: storage.peer_parameters,
            parameters_len: 0,
            ephemeral: Some(ephemeral),
            x25519: Some(x25519),
            x25519_share,
            allow_x25519: true,
            negotiated_group: None,
            share,
            random,
            transcript: Transcript::new(),
            schedule: KeySchedule::new(None)?,
            suite: None,
            cipher_policy: CipherPolicy::Default,
            handshake: None,
            application: None,
            integrity: Some(IntegrityBudget::new()),
            resumption: None,
            resumption_master: None,
            verification_context: None,
            ticket_binding: None,
            offer_age: None,
            offer_suite: None,
            peer_wants_tickets: false,
            early_status: EarlyStatus::Disabled,
            early_generation: None,
            early_limits: None,
            early_server: None,
            early_key: None,
            early_claim: None,
            verified_handshake: None,
        })
    }

    pub(in crate::handshake) fn record_verified_finished(&mut self, resumed: bool) {
        self.verified_handshake = Some(VerifiedHandshake {
            resumed,
            side: self.side(),
            protocol: match &self.mode {
                Mode::Client(c) => c.protocol,
                Mode::Server(c) => c.protocol,
            },
            peer_parameters_digest: keys::peer_parameters_digest(
                &self.parameters[..self.parameters_len],
            ),
            early_status: self.early_status,
            early_generation: self.early_generation,
        });
    }

    pub(crate) fn pristine(&self) -> bool {
        self.last_failure.is_none()
            && self.suite.is_none()
            && (self.ephemeral.is_some() || self.x25519.is_some())
            && self.retry_suite.is_none()
            && self.rx_used == 0
    }
    pub(crate) fn take_message_buffer(&mut self) -> Result<&'buf mut [u8], Failure> {
        self.rx.take().ok_or(Failure::State)
    }
    pub(crate) fn restore_message_buffer(&mut self, bytes: &'buf mut [u8]) {
        self.rx = Some(bytes);
    }
    pub fn last_failure(&self) -> Option<&Failure> {
        self.last_failure.as_ref()
    }
    /// ALPN authenticated by the Finished receipt still owned by this provider.
    /// After handoff, the recipient reads the protocol from that receipt.
    pub fn negotiated_alpn(&self) -> Option<&'static [u8]> {
        Some(self.verified_handshake.as_ref()?.protocol.alpn())
    }
    pub fn negotiated_group(&self) -> Option<u16> {
        self.negotiated_group
    }
    pub fn negotiated_suite(&self) -> Option<CipherSuite> {
        self.suite
    }
    pub(in crate::handshake) fn side(&self) -> Side {
        match self.mode {
            Mode::Client(_) => Side::Client,
            Mode::Server(_) => Side::Server,
        }
    }

    pub(in crate::handshake) fn fail(&mut self, failure: Failure) -> tls::Error {
        let error = match &failure {
            Failure::Capacity | Failure::InvalidStorage => tls::Error::Capacity,
            Failure::Certificate(_)
            | Failure::CertificateKeyMismatch
            | Failure::Ticket(ticket::Error::Binder) => tls::Error::Authentication,
            Failure::Wire(wire::Error::InvalidQuicEarlyData) => tls::Error::ProtocolViolation,
            Failure::Crypto(crypto::Error::IntegrityLimit) => tls::Error::IntegrityLimit,
            Failure::Crypto(crypto::Error::KeyUpdateError) => tls::Error::KeyUpdateError,
            Failure::Crypto(crypto::Error::ConfidentialityLimit) => {
                tls::Error::ConfidentialityLimit
            }
            Failure::Crypto(crypto::Error::PacketNumberReuse) => tls::Error::PacketNumberReuse,
            _ => tls::Error::Handshake,
        };
        self.last_failure = Some(failure);
        self.ephemeral = None;
        self.x25519 = None;
        self.schedule.discard();
        self.reject_early();
        self.resumption_master = None;
        self.offer_age = None;
        self.handshake = None;
        self.application = None;
        self.verified_handshake = None;
        self.tx_len = 0;
        self.tx_sent = 0;
        error
    }

    pub const fn version(&self) -> crate::quic::version::Version {
        match &self.mode {
            Mode::Client(c) => c.version,
            Mode::Server(c) => c.version,
        }
    }
    fn save_parameters(&mut self, bytes: &[u8]) -> Result<(), Failure> {
        let peer_client = self.side() == Side::Server;
        let information = crate::quic::version::information_from_parameters(bytes, peer_client)
            .map_err(|_| Failure::InvalidConfig)?;
        match information {
            Some(info) => {
                let expected = if peer_client {
                    crate::quic::version::Version::V1
                } else {
                    self.version()
                };
                info.verify_fixed(expected)
                    .map_err(|_| Failure::InvalidConfig)?;
                if peer_client && !info.available().any(|v| v == self.version().wire()) {
                    return Err(Failure::InvalidConfig);
                }
            }
            None if self.version() != crate::quic::version::Version::V1 => {
                return Err(Failure::InvalidConfig);
            }
            None => {}
        }

        if bytes.len() > self.parameters.len() {
            return Err(Failure::Capacity);
        }
        self.parameters[..bytes.len()].copy_from_slice(bytes);
        self.parameters_len = bytes.len();
        Ok(())
    }
    fn begin_flight(&mut self) -> Result<(), Failure> {
        if self.tx_sent != self.tx_len {
            return Err(Failure::State);
        }
        self.tx_len = 0;
        self.tx_sent = 0;
        self.tx_initial_end = 0;
        self.tx_handshake_end = 0;
        Ok(())
    }
    fn commit_output(&mut self, n: usize) -> Result<(), Failure> {
        let end = self.tx_len.checked_add(n).ok_or(Failure::Capacity)?;
        let message = self.tx.get(self.tx_len..end).ok_or(Failure::Capacity)?;
        self.transcript.append(message)?;
        self.tx_len = end;
        self.tx_handshake_end = end;
        Ok(())
    }

    pub(in crate::handshake) fn install_handshake(
        &mut self,
        group: u16,
        share: &[u8],
        suite: u16,
    ) -> Result<(), Failure> {
        let suite = match suite {
            0x1301 => CipherSuite::Aes128GcmSha256,
            0x1303 => CipherSuite::ChaCha20Poly1305Sha256,
            _ => return Err(Failure::UnsupportedSuite),
        };
        match group {
            wire::GROUP_P256 => {
                if share.len() != 65 || share[0] != 4 {
                    return Err(Failure::InvalidKeyShare);
                }
                let key = self.ephemeral.take().ok_or(Failure::State)?;
                let shared = Secret::new(key.agree(share).map_err(|_| Failure::InvalidKeyShare)?);
                self.schedule.derive_handshake(&*shared, &self.transcript)?;
            }
            wire::GROUP_X25519 if self.allow_x25519 => {
                let key = self.x25519.take().ok_or(Failure::State)?;
                let shared = key.complete(share).map_err(|_| Failure::InvalidKeyShare)?;
                self.schedule.derive_handshake(&*shared, &self.transcript)?;
            }
            _ => return Err(Failure::InvalidKeyShare),
        }
        // Unselected fresh group secrets are not retained after negotiation.
        self.ephemeral = None;
        self.x25519 = None;
        self.negotiated_group = Some(group);
        self.suite = Some(suite);
        self.handshake = Some(self.packet_keys(KeyKind::Handshake)?);
        Ok(())
    }
    pub(in crate::handshake) fn packet_keys(
        &mut self,
        kind: KeyKind,
    ) -> Result<DirectionalKeys, Failure> {
        let suite = self.suite.ok_or(Failure::State)?;
        let (client, server) = match kind {
            KeyKind::Handshake => self.schedule.take_handshake_traffic()?,
            KeyKind::OneRtt => self.schedule.take_application_traffic()?,
            _ => return Err(Failure::State),
        };
        let (local, remote) = match self.side() {
            Side::Client => (client, server),
            Side::Server => (server, client),
        };
        Ok(DirectionalKeys {
            local: PacketKey::from_secret_for_version(
                self.version(),
                suite,
                kind,
                local.as_bytes(),
            )?,
            remote: PacketKey::from_secret_for_version(
                self.version(),
                suite,
                kind,
                remote.as_bytes(),
            )?,
        })
    }
    pub(in crate::handshake) fn install_application(&mut self) -> Result<(), Failure> {
        self.schedule.derive_master(&self.transcript)?;
        let keys = self.packet_keys(KeyKind::OneRtt)?;
        self.application = Some(keys);
        if self.side() == Side::Client {
            self.early_key = None;
        }
        Ok(())
    }

    fn validate_peer_certificate(&self, signature: Option<(u16, &[u8])>) -> Result<(), Failure> {
        let Mode::Client(config) = &self.mode else {
            return Err(Failure::State);
        };
        if self.cert_count == 0 {
            return Err(Failure::State);
        }
        let mut certs: [CertificateDer<'_>; MAX_CHAIN] =
            core::array::from_fn(|_| CertificateDer::from(&[][..]));
        for (slot, range) in certs.iter_mut().zip(&self.cert_ranges[..self.cert_count]) {
            let end = range
                .offset
                .checked_add(range.len)
                .ok_or(Failure::Capacity)?;
            *slot = CertificateDer::from(
                self.certificates
                    .get(range.offset..end)
                    .ok_or(Failure::Capacity)?,
            );
        }
        let verifier =
            ServerVerifier::new(config.trust_anchors, config.now, config.certificate_limits)?;
        let name = ServerName::try_from(config.server_name).map_err(|_| Failure::InvalidConfig)?;
        let verified = verifier.verify_server(&certs[0], &certs[1..self.cert_count], &name)?;
        if let Some((scheme, signature)) = signature {
            verified.verify_certificate_verify(scheme, &self.transcript.hash(), signature)?;
        }
        Ok(())
    }

    fn retain_resumption(&mut self) -> Result<(), Failure> {
        self.schedule.derive_resumption(&self.transcript)?;
        if matches!(self.resumption, Some(Resumption::Client(_)))
            || self.peer_wants_tickets && matches!(self.resumption, Some(Resumption::Server(_)))
        {
            self.resumption_master = Some(self.schedule.take_resumption_master()?);
        }
        self.schedule.discard();
        self.offer_age = None;
        Ok(())
    }
    fn issue_ticket(&mut self) -> Result<(), Failure> {
        if !self.peer_wants_tickets || !matches!(self.resumption, Some(Resumption::Server(_))) {
            return Ok(());
        }
        self.begin_flight()?;
        let Some(Resumption::Server(config)) = &mut self.resumption else {
            return Err(Failure::State);
        };
        let suite = match self.suite.ok_or(Failure::State)? {
            CipherSuite::Aes128GcmSha256 => 0x1301,
            CipherSuite::ChaCha20Poly1305Sha256 => 0x1303,
        };
        let token = if let Some(early) = self.early_server {
            config.store.prepare_early(
                config.entropy,
                config.clock.now_ms()?,
                config.lifetime_seconds,
                suite,
                self.ticket_binding.ok_or(Failure::State)?,
                early.limits,
            )?
        } else {
            config.store.prepare(
                config.entropy,
                config.clock.now_ms()?,
                config.lifetime_seconds,
                suite,
                self.ticket_binding.ok_or(Failure::State)?,
            )?
        };
        let psk = self
            .resumption_master
            .as_ref()
            .ok_or(Failure::State)?
            .derive(token.ticket_nonce())?;
        let mut identity = [0; ticket::SEALED_TICKET_BYTES];
        let issued = config.store.seal(token, psk, &mut identity)?;
        let n = wire::encode_new_session_ticket_early(
            self.tx,
            issued.lifetime_seconds,
            issued.age_add,
            &issued.nonce,
            &identity[..issued.len],
            self.early_server.is_some(),
        )?;
        self.tx_len = n;
        // Initial and Handshake spans are empty; these actual bytes are 1-RTT.
        // At most one NST per connection; the server needs no master thereafter.
        self.resumption_master = None;
        Ok(())
    }
    fn cache_ticket(&mut self, message: &[u8]) -> Result<(), Failure> {
        let received = wire::parse_new_session_ticket(message)?;
        let Some(Resumption::Client(config)) = &mut self.resumption else {
            return Ok(());
        };
        if received.lifetime_seconds == 0
            || received.lifetime_seconds > ticket::MAX_LIFETIME_SECONDS
        {
            return Ok(());
        }
        let psk = self
            .resumption_master
            .as_ref()
            .ok_or(Failure::State)?
            .derive(received.nonce)?;
        let Mode::Client(client) = &self.mode else {
            return Err(Failure::State);
        };
        let profile = transport_profile(&self.parameters[..self.parameters_len], &[])?;
        let binding = ticket::Binding::new(client.server_name, client.protocol.alpn(), &profile)?;
        let metadata = ticket::ReceivedTicket {
            ticket: received.ticket,
            lifetime_seconds: received.lifetime_seconds,
            age_add: received.age_add,
            suite: match self.suite.ok_or(Failure::State)? {
                CipherSuite::Aes128GcmSha256 => 0x1301,
                CipherSuite::ChaCha20Poly1305Sha256 => 0x1303,
            },
            binding,
        };
        let context = self.verification_context.ok_or(Failure::State)?;
        let result = if received.early_data {
            let limits = RememberedLimits::from_authenticated_server_parameters(
                &self.parameters[..self.parameters_len],
            )
            .map_err(Failure::Early)?;
            config.store.insert_verified_early(
                config.clock.now_ms()?,
                metadata,
                psk,
                context,
                limits,
            )
        } else {
            config
                .store
                .insert_verified(config.clock.now_ms()?, metadata, psk, context)
        };
        match result {
            Ok(()) | Err(ticket::Error::Capacity | ticket::Error::DuplicateTicket) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

fn suite_from_wire(suite: u16) -> Result<CipherSuite, Failure> {
    match suite {
        0x1301 => Ok(CipherSuite::Aes128GcmSha256),
        0x1303 => Ok(CipherSuite::ChaCha20Poly1305Sha256),
        _ => Err(Failure::UnsupportedSuite),
    }
}

fn map_crypto(error: crypto::Error) -> tls::Error {
    match error {
        crypto::Error::AuthenticationFailed => tls::Error::Authentication,
        crypto::Error::KeyUpdateError => tls::Error::KeyUpdateError,
        crypto::Error::KeyUpdateNotAllowed => tls::Error::KeyUpdateNotAllowed,
        crypto::Error::IntegrityLimit => tls::Error::IntegrityLimit,
        crypto::Error::ConfidentialityLimit => tls::Error::ConfidentialityLimit,
        crypto::Error::PacketNumberReuse => tls::Error::PacketNumberReuse,
        crypto::Error::KeyDiscarded => tls::Error::KeysUnavailable,
        crypto::Error::BufferTooSmall | crypto::Error::PacketTooLarge => tls::Error::Capacity,
        _ => tls::Error::InvalidInput,
    }
}
impl BoundedTls<'_, '_> {
    pub(in crate::handshake) fn receive_authenticated_ticket_bytes(
        &mut self,
        level: Level,
        mut bytes: &[u8],
    ) -> Result<(), tls::Error> {
        // Only authenticated post-handshake ticket framing remains synchronous.
        // Initial/Handshake message order belongs exclusively to async roles.
        if level != Level::OneRtt || self.last_failure.is_some() || self.side() != Side::Client {
            return Err(self.fail(Failure::State));
        }
        while !bytes.is_empty() {
            let rx = self.rx.as_deref_mut().ok_or(tls::Error::InvalidInput)?;
            let target = if self.rx_target == 0 {
                4
            } else {
                self.rx_target
            };
            if target > rx.len() {
                return Err(self.fail(Failure::Capacity));
            }
            let n = (target - self.rx_used).min(bytes.len());
            rx[self.rx_used..self.rx_used + n].copy_from_slice(&bytes[..n]);
            self.rx_used += n;
            bytes = &bytes[n..];
            if self.rx_used < target {
                continue;
            }
            if self.rx_target == 0 {
                self.rx_target =
                    4 + ((rx[1] as usize) << 16) + ((rx[2] as usize) << 8) + rx[3] as usize;
                if self.rx_target > rx.len() {
                    return Err(self.fail(Failure::Capacity));
                }
                if self.rx_used < self.rx_target {
                    continue;
                }
            }
            let rx = self.rx.take().ok_or(tls::Error::InvalidInput)?;
            let result = self.cache_ticket(&rx[..self.rx_target]);
            rx[..self.rx_target].erase();
            self.rx = Some(rx);
            self.rx_used = 0;
            self.rx_target = 0;
            if let Err(error) = result {
                return Err(self.fail(error));
            }
        }
        Ok(())
    }
}
