//! Bounded remembered transport policy and actual local replay claims.
//! This module grants no packet, Finished or application-delivery authentication.
use crate::quic::parameters::{Parameters, Peer};
const MAX: u64 = (1 << 62) - 1;
const MAX_STREAMS: u64 = 1 << 60;
pub const REMEMBERED_BYTES: usize = 73;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Parameters(crate::quic::parameters::Error),
    Packet(crate::quic::wire::Error),
    InvalidLimits,
    InvalidFreshness,
    ChangedLimits,
    Disabled,
    Capacity,
    Replay,
    Expired,
    ClockRollback,
    EpochMismatch,
    StaleGeneration,
    Exhausted,
    State,
    StreamId,
    FlowControl,
    FinalSize,
    ConflictingOverlap,
    StaleRelease,
}

/// TLS decision plus the Finished boundary. Pending acceptance never permits
/// application delivery. Rejection is terminal for this connection's early data.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EarlyStatus {
    #[default]
    Disabled,
    Offered,
    AcceptedPendingFinished,
    Accepted,
    Rejected,
}

/// Independent0RTT freshness policy. There is deliberately no Default and no
/// conversion from the ordinary resumption age tolerance. The one-minute cap
/// is this bounded profile's administrative limit, not an RFC guarantee.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EarlyFreshness {
    max_age_skew_ms: u32,
}
impl EarlyFreshness {
    pub const MAX_SKEW_MS: u32 = 60_000;
    pub fn new(max_age_skew_ms: u32) -> Result<Self, Error> {
        if max_age_skew_ms > Self::MAX_SKEW_MS {
            Err(Error::InvalidFreshness)
        } else {
            Ok(Self { max_age_skew_ms })
        }
    }
    pub fn permits(self, actual_age_ms: u64, reported_age_ms: u64) -> bool {
        actual_age_ms.abs_diff(reported_age_ms) <= u64::from(self.max_age_skew_ms)
    }
}

/// The reusable server parameters understood by this transport profile. Never
/// restore ACK-delay settings, CIDs, reset tokens, or preferred addresses.
/// Future supported transport extensions must extend this versioned encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RememberedLimits {
    idle_timeout: u64,
    max_udp_payload: u64,
    max_data: u64,
    stream_bidi_local: u64,
    stream_bidi_remote: u64,
    stream_uni: u64,
    streams_bidi: u64,
    streams_uni: u64,
    active_cids: u64,
    disable_migration: bool,
}
impl RememberedLimits {
    /// Call only on peer parameters authenticated by the completed connection.
    /// Parsing validates syntax; it does not establish their authentication.
    pub fn from_authenticated_server_parameters(bytes: &[u8]) -> Result<Self, Error> {
        let p = Parameters::parse(bytes, Peer::Server, &mut [0; 64]).map_err(Error::Parameters)?;
        let get = |id, default| p.get_integer(id, default).map_err(Error::Parameters);
        let limits = Self {
            idle_timeout: get(1, 0)?,
            max_udp_payload: get(3, 65527)?,
            max_data: get(4, 0)?,
            stream_bidi_local: get(5, 0)?,
            stream_bidi_remote: get(6, 0)?,
            stream_uni: get(7, 0)?,
            streams_bidi: get(8, 0)?,
            streams_uni: get(9, 0)?,
            active_cids: get(14, 2)?,
            disable_migration: p.get(12).is_some(),
        };
        limits.validate()?;
        Ok(limits)
    }
    fn numbers(self) -> [u64; 9] {
        [
            self.idle_timeout,
            self.max_udp_payload,
            self.max_data,
            self.stream_bidi_local,
            self.stream_bidi_remote,
            self.stream_uni,
            self.streams_bidi,
            self.streams_uni,
            self.active_cids,
        ]
    }
    fn validate(self) -> Result<(), Error> {
        if self.numbers().iter().any(|n| *n > MAX)
            || self.max_udp_payload < 1200
            || self.active_cids < 2
            || self.streams_bidi > MAX_STREAMS
            || self.streams_uni > MAX_STREAMS
        {
            return Err(Error::InvalidLimits);
        }
        Ok(())
    }
    /// Fixed 73-byte ticket payload, covered by the ticket's AEAD. This is not
    /// the TLS/QUIC wire transport-parameter encoding.
    pub fn encode(self) -> [u8; REMEMBERED_BYTES] {
        let mut out = [0; REMEMBERED_BYTES];
        for (i, n) in self.numbers().iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&n.to_be_bytes());
        }
        out[72] = u8::from(self.disable_migration);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != REMEMBERED_BYTES || bytes[72] > 1 {
            return Err(Error::InvalidLimits);
        }
        let mut n = [0; 9];
        for (i, value) in n.iter_mut().enumerate() {
            *value = u64::from_be_bytes(
                bytes[i * 8..i * 8 + 8]
                    .try_into()
                    .map_err(|_| Error::InvalidLimits)?,
            );
        }
        let limits = Self {
            idle_timeout: n[0],
            max_udp_payload: n[1],
            max_data: n[2],
            stream_bidi_local: n[3],
            stream_bidi_remote: n[4],
            stream_uni: n[5],
            streams_bidi: n[6],
            streams_uni: n[7],
            active_cids: n[8],
            disable_migration: bytes[72] != 0,
        };
        limits.validate()?;
        Ok(limits)
    }
    /// Conservative acceptance: credit/UDP/CID limits may grow; idle/migration
    /// policy must remain identical. Clients continue using remembered limits
    /// for 0-RTT even if new handshake values are larger.
    pub fn permits_early_from(self, remembered: Self) -> Result<(), Error> {
        if self.idle_timeout != remembered.idle_timeout
            || self.disable_migration != remembered.disable_migration
            || self.numbers()[1..]
                .iter()
                .zip(&remembered.numbers()[1..])
                .any(|(new, old)| new < old)
        {
            return Err(Error::ChangedLimits);
        }
        Ok(())
    }
    pub fn stream_limits(self) -> crate::quic::Limits {
        crate::quic::Limits {
            max_data: self.max_data,
            max_streams_bidi: self.streams_bidi,
            max_streams_uni: self.streams_uni,
            stream_data_bidi_local: self.stream_bidi_local,
            stream_data_bidi_remote: self.stream_bidi_remote,
            stream_data_uni: self.stream_uni,
        }
    }
    pub fn active_connection_id_limit(self) -> u64 {
        self.active_cids
    }
    pub fn max_data(self) -> u64 {
        self.max_data
    }
    pub fn max_streams(self) -> u64 {
        self.streams_bidi + self.streams_uni
    }
    pub fn max_udp_payload(self) -> u64 {
        self.max_udp_payload
    }
}

/// Explicit opt-in for replay-tolerant requests. This only authorizes buffering;
/// the application must still restrict operations (initially HTTP/0.9 GET).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerPolicy {
    Disabled,
    BufferedReplaySafeRequests {
        max_bytes: usize,
        max_streams: usize,
    },
}
impl ServerPolicy {
    pub fn check_capacity<const BYTES: usize>(
        self,
        limits: RememberedLimits,
        slots: usize,
    ) -> Result<(), Error> {
        let Self::BufferedReplaySafeRequests {
            max_bytes,
            max_streams,
        } = self
        else {
            return Err(Error::Disabled);
        };
        let capacity = slots.checked_mul(BYTES).ok_or(Error::Capacity)?;
        if max_bytes == 0
            || max_streams == 0
            || max_bytes > capacity
            || max_streams > slots
            || limits.max_data > max_bytes as u64
            || limits.max_streams() > max_streams as u64
            || limits.stream_bidi_remote > BYTES as u64
            || limits.stream_uni > BYTES as u64
        {
            return Err(Error::Capacity);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct ReplayEntry {
    issuer: [u8; 16],
    nonce: [u8; 12],
    expires: u64,
    occupied: bool,
}
impl ReplayEntry {
    const EMPTY: Self = Self {
        issuer: [0; 16],
        nonce: [0; 12],
        expires: 0,
        occupied: false,
    };
}
/// Caller-owned persistent storage. Reborrowing does not reset live claims.
/// Production integration must borrow it for the ticket-key lifetime and create
/// a fresh random ticket issuer/key after process restart; there is no clear API.
pub struct ReplayStorage<const N: usize> {
    epoch: Option<[u8; 16]>,
    entries: [ReplayEntry; N],
    last_time: Option<u64>,
    last_generation: Option<u64>,
    next_claim: u64,
}
impl<const N: usize> ReplayStorage<N> {
    pub const fn new() -> Self {
        Self {
            epoch: None,
            entries: [ReplayEntry::EMPTY; N],
            last_time: None,
            last_generation: None,
            next_claim: 1,
        }
    }
}
impl<const N: usize> Default for ReplayStorage<N> {
    fn default() -> Self {
        Self::new()
    }
}
/// Used only while exclusively borrowed by one freshly generated ticket key.
/// The key constructor starts its random issuer epoch; no live owner exposes a
/// reset operation. Dropping a key destroys its secret before storage is reused.
pub trait ReplayProtection {
    fn start_fresh_key_epoch(&mut self, issuer: [u8; 16]) -> Result<(), Error>;
    fn claim_authenticated(
        &mut self,
        issuer: [u8; 16],
        nonce: [u8; 12],
        expires: u64,
        now: u64,
        generation: u64,
    ) -> Result<ReplayClaim, Error>;
}
impl<const N: usize> ReplayProtection for ReplayStorage<N> {
    fn start_fresh_key_epoch(&mut self, issuer: [u8; 16]) -> Result<(), Error> {
        if N == 0 {
            return Err(Error::Capacity);
        }
        if self.epoch != Some(issuer) {
            *self = Self::new();
            self.epoch = Some(issuer);
        }
        Ok(())
    }
    fn claim_authenticated(
        &mut self,
        issuer: [u8; 16],
        nonce: [u8; 12],
        expires: u64,
        now: u64,
        generation: u64,
    ) -> Result<ReplayClaim, Error> {
        ReplayLedger::bind(issuer, self)?
            .claim_after_authentication(issuer, nonce, expires, now, generation)
    }
}

pub struct ReplayLedger<'a, const N: usize> {
    storage: &'a mut ReplayStorage<N>,
}
/// Only proves a committed local replay claim. It is not evidence of ticket,
/// binder, packet, or peer authentication, all of which precede claim issuance.
pub struct ReplayClaim {
    issuer: [u8; 16],
    generation: u64,
    serial: u64,
}
impl ReplayClaim {
    /// Consume the local replay claim into its actual identifiers; identifiers alone do not authenticate packets or Finished.
    pub fn into_parts(self) -> ([u8; 16], u64, u64) { (self.issuer, self.generation, self.serial) }
    pub fn generation(&self) -> u64 {
        self.generation
    }
}
impl<'a, const N: usize> ReplayLedger<'a, N> {
    pub fn bind(epoch: [u8; 16], storage: &'a mut ReplayStorage<N>) -> Result<Self, Error> {
        if N == 0 {
            return Err(Error::Capacity);
        }
        match storage.epoch {
            Some(previous) if previous != epoch => return Err(Error::EpochMismatch),
            None => storage.epoch = Some(epoch),
            _ => {}
        }
        Ok(Self { storage })
    }
    /// Caller has already verified ticket AEAD, binder, expiry, origin/trust,
    /// remembered limits and resource admission. Commit before accepting 0-RTT.
    /// Dropping the returned claim never refunds it, even if Finished fails.
    pub fn claim_after_authentication(
        &mut self,
        issuer: [u8; 16],
        nonce: [u8; 12],
        expires_ms: u64,
        now_ms: u64,
        connection_generation: u64,
    ) -> Result<ReplayClaim, Error> {
        let s = &mut self.storage;
        if s.epoch != Some(issuer) {
            return Err(Error::EpochMismatch);
        }
        if s.last_time.is_some_and(|old| now_ms < old) {
            return Err(Error::ClockRollback);
        }
        s.last_time = Some(now_ms);
        if now_ms >= expires_ms {
            return Err(Error::Expired);
        }
        if s.last_generation
            .is_some_and(|old| connection_generation <= old)
        {
            return Err(Error::StaleGeneration);
        }
        for entry in &mut s.entries {
            if entry.occupied && now_ms >= entry.expires {
                *entry = ReplayEntry::EMPTY;
            }
        }
        if s.entries
            .iter()
            .any(|e| e.occupied && e.issuer == issuer && e.nonce == nonce)
        {
            return Err(Error::Replay);
        }
        let next = s.next_claim.checked_add(1).ok_or(Error::Exhausted)?;
        let entry = s
            .entries
            .iter_mut()
            .find(|e| !e.occupied)
            .ok_or(Error::Capacity)?;
        *entry = ReplayEntry {
            issuer,
            nonce,
            expires: expires_ms,
            occupied: true,
        };
        let serial = s.next_claim;
        s.next_claim = next;
        s.last_generation = Some(connection_generation);
        Ok(ReplayClaim {
            issuer,
            generation: connection_generation,
            serial,
        })
    }
}


#[cfg(test)]
mod tests {
 use super::*;
    // Syntactically valid server parameters, including required connection IDs.
    const PARAMS: &[u8] = &[
        0, 0, 15, 0, 4, 1, 16, 5, 1, 8, 6, 1, 8, 7, 1, 8, 8, 1, 1, 9, 1, 1,
    ];
    const POLICY: ServerPolicy = ServerPolicy::BufferedReplaySafeRequests {
        max_bytes: 16,
        max_streams: 2,
    };
    fn limits() -> RememberedLimits {
        RememberedLimits::from_authenticated_server_parameters(PARAMS).unwrap()
    }
    #[test]
    fn remembered_parameters_roundtrip_and_forbidden_fields_are_not_restored() {
        let expected = limits();
        assert_eq!(RememberedLimits::decode(&expected.encode()), Ok(expected));
        // Changed CIDs and ACK-delay settings do not become remembered values.
        let mut changed = [0; 64];
        let extra = [10, 1, 4, 11, 1, 40, 16, 1, 99];
        changed[..PARAMS.len()].copy_from_slice(PARAMS);
        changed[PARAMS.len()..PARAMS.len() + extra.len()].copy_from_slice(&extra);
        assert_eq!(
            RememberedLimits::from_authenticated_server_parameters(
                &changed[..PARAMS.len() + extra.len()]
            ),
            Ok(expected)
        );
        let mut reordered = [0; PARAMS.len()];
        let rest = PARAMS.len() - 4;
        reordered[..rest].copy_from_slice(&PARAMS[4..]);
        reordered[rest..].copy_from_slice(&PARAMS[..4]);
        assert_eq!(
            RememberedLimits::from_authenticated_server_parameters(&reordered),
            Ok(expected)
        );
        for n in 0..REMEMBERED_BYTES {
            assert_eq!(
                RememberedLimits::decode(&expected.encode()[..n]),
                Err(Error::InvalidLimits)
            );
        }
        let mut bad = expected.encode();
        bad[72] = 2;
        assert_eq!(RememberedLimits::decode(&bad), Err(Error::InvalidLimits));
    }
    #[test]
    fn all_relevant_limit_reductions_and_changed_policies_reject() {
        let old = RememberedLimits {
            idle_timeout: 50,
            max_udp_payload: 1400,
            max_data: 16,
            stream_bidi_local: 8,
            stream_bidi_remote: 8,
            stream_uni: 8,
            streams_bidi: 1,
            streams_uni: 1,
            active_cids: 4,
            disable_migration: true,
        };
        for index in 1..9 {
            let mut bytes = old.encode();
            let n = u64::from_be_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap());
            bytes[index * 8..index * 8 + 8].copy_from_slice(&(n - 1).to_be_bytes());
            let reduced = RememberedLimits::decode(&bytes).unwrap();
            assert_eq!(reduced.permits_early_from(old), Err(Error::ChangedLimits));
        }
        assert_eq!(
            RememberedLimits {
                idle_timeout: 51,
                ..old
            }
            .permits_early_from(old),
            Err(Error::ChangedLimits)
        );
        assert_eq!(
            RememberedLimits {
                disable_migration: false,
                ..old
            }
            .permits_early_from(old),
            Err(Error::ChangedLimits)
        );
        assert_eq!(
            RememberedLimits {
                max_data: 32,
                streams_bidi: 2,
                ..old
            }
            .permits_early_from(old),
            Ok(())
        );
    }
    #[test]
    fn policy_requires_explicit_opt_in_and_backed_credit() {
        assert_eq!(
            ServerPolicy::Disabled.check_capacity::<8>(limits(), 2),
            Err(Error::Disabled)
        );
        assert_eq!(POLICY.check_capacity::<8>(limits(), 2), Ok(()));
        assert_eq!(
            POLICY.check_capacity::<8>(limits(), 1),
            Err(Error::Capacity)
        );
        assert_eq!(
            POLICY.check_capacity::<4>(limits(), 2),
            Err(Error::Capacity)
        );
        assert_eq!(
            POLICY.check_capacity::<8>(
                RememberedLimits {
                    max_data: 17,
                    ..limits()
                },
                2
            ),
            Err(Error::Capacity)
        );
    }
    #[test]
    fn replay_claims_survive_reborrow_drop_and_capacity_pressure() {
        let mut storage = ReplayStorage::<1>::new();
        {
            let mut ledger = ReplayLedger::bind([1; 16], &mut storage).unwrap();
            let _burned = ledger
                .claim_after_authentication([1; 16], [2; 12], 100, 10, 1)
                .unwrap();
        }
        let mut ledger = ReplayLedger::bind([1; 16], &mut storage).unwrap();
        assert!(matches!(
            ledger.claim_after_authentication([1; 16], [2; 12], 100, 11, 2),
            Err(Error::Replay)
        ));
        assert!(matches!(
            ledger.claim_after_authentication([1; 16], [3; 12], 101, 12, 2),
            Err(Error::Capacity)
        ));
        assert!(
            ledger
                .claim_after_authentication([1; 16], [3; 12], 101, 100, 2)
                .is_ok()
        );
        assert!(matches!(
            ledger.claim_after_authentication([1; 16], [4; 12], 200, 100, 2),
            Err(Error::StaleGeneration)
        ));
        assert!(matches!(
            ReplayLedger::bind([9; 16], &mut storage),
            Err(Error::EpochMismatch)
        ));
    }
    #[test]
    fn replay_expiry_clock_and_identifier_exhaustion_fail_closed() {
        let mut storage = ReplayStorage::<2>::new();
        let mut ledger = ReplayLedger::bind([1; 16], &mut storage).unwrap();
        assert!(matches!(
            ledger.claim_after_authentication([1; 16], [2; 12], 10, 10, 1),
            Err(Error::Expired)
        ));
        assert!(matches!(
            ledger.claim_after_authentication([1; 16], [2; 12], 100, 9, 1),
            Err(Error::ClockRollback)
        ));
        assert!(matches!(
            ledger.claim_after_authentication([2; 16], [2; 12], 100, 11, 1),
            Err(Error::EpochMismatch)
        ));
        ledger.storage.next_claim = u64::MAX;
        assert!(matches!(
            ledger.claim_after_authentication([1; 16], [2; 12], 100, 11, 1),
            Err(Error::Exhausted)
        ));
        assert!(!ledger.storage.entries.iter().any(|e| e.occupied));
    }

}
