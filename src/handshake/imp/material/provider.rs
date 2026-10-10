//! Provider operations on the actual owned material.
use super::*;
impl Provider for BoundedTls<'_, '_> {
    fn observations(&self) -> tls::Observations {
        tls::Observations {
            resumed: self
                .verified_handshake
                .as_ref()
                .map(|receipt| receipt.resumed),
            negotiated_suite: self.negotiated_suite().map(|suite| match suite {
                CipherSuite::Aes128GcmSha256 => 0x1301,
                CipherSuite::ChaCha20Poly1305Sha256 => 0x1303,
            }),
            failed_authentications: self.integrity.as_ref().map(IntegrityBudget::failed_packets),
        }
    }
    fn write_failure_diagnostic(&self, out: &mut dyn core::fmt::Write) -> core::fmt::Result {
        if let Some(failure) = self.last_failure() {
            write!(out, "{failure:?}")?;
        }
        Ok(())
    }

    fn early_status(&self) -> EarlyStatus {
        self.early_status
    }
    fn early_generation(&self) -> Option<u64> {
        self.early_generation
    }
    fn remembered_early_limits(&self) -> Option<RememberedLimits> {
        self.early_limits
    }
    fn take_early_replay_claim(&mut self) -> Option<ReplayClaim> {
        self.early_claim.take()
    }
    fn has_early_keys(&self) -> bool {
        self.integrity.is_some() && self.last_failure.is_none() && self.early_key.is_some()
    }
    fn seal_early(
        &mut self,
        pn: u64,
        header: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, tls::Error> {
        if self.integrity.is_none() {
            return Err(tls::Error::KeysUnavailable);
        }
        if self.side() != Side::Client {
            return Err(tls::Error::InvalidInput);
        }
        if self.last_failure.is_some()
            || self.application.is_some()
            || !matches!(
                self.early_status,
                EarlyStatus::Offered | EarlyStatus::AcceptedPendingFinished
            )
        {
            return Err(tls::Error::KeysUnavailable);
        }
        self.early_key
            .as_mut()
            .ok_or(tls::Error::KeysUnavailable)?
            .seal(pn, header, buffer, plaintext_len)
            .map_err(map_crypto)
    }
    fn open_early(
        &mut self,
        pn: u64,
        header: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize, tls::Error> {
        if self.integrity.is_none() {
            return Err(tls::Error::KeysUnavailable);
        }
        if self.side() != Side::Server {
            return Err(tls::Error::InvalidInput);
        }
        if self.last_failure.is_some()
            || !matches!(
                self.early_status,
                EarlyStatus::AcceptedPendingFinished | EarlyStatus::Accepted
            )
        {
            return Err(tls::Error::KeysUnavailable);
        }
        let result = self
            .early_key
            .as_ref()
            .ok_or(tls::Error::KeysUnavailable)?
            .open(
                pn,
                header,
                buffer,
                self.integrity.as_mut().ok_or(tls::Error::KeysUnavailable)?,
            );
        match result {
            Err(crypto::Error::IntegrityLimit) => {
                Err(self.fail(Failure::Crypto(crypto::Error::IntegrityLimit)))
            }
            other => other.map_err(map_crypto),
        }
    }
    fn early_header_mask(&self, local: bool, sample: &[u8; 16]) -> Result<[u8; 5], tls::Error> {
        if self.integrity.is_none() {
            return Err(tls::Error::KeysUnavailable);
        }
        if local != (self.side() == Side::Client) {
            return Err(tls::Error::InvalidInput);
        }
        if self.last_failure.is_some() {
            return Err(tls::Error::KeysUnavailable);
        }
        self.early_key
            .as_ref()
            .ok_or(tls::Error::KeysUnavailable)?
            .header_mask(sample)
            .map_err(map_crypto)
    }
    fn discard_early_keys(&mut self) {
        self.early_key = None;
    }
    fn negotiated_group(&self) -> Option<u16> {
        self.negotiated_group
    }
    fn integrity_budget(&mut self) -> Option<&mut crate::quic::packet_protection::IntegrityBudget> {
        self.integrity.as_mut()
    }
    fn receive(&mut self, level: Level, bytes: &[u8]) -> Result<(), tls::Error> {
        if self.verified_handshake.is_none() || self.last_failure.is_some() {
            return Err(self.fail(Failure::State));
        }
        self.receive_authenticated_ticket_bytes(level, bytes)
    }

    fn transmit(&mut self, out: &mut [u8]) -> Result<Option<Output>, tls::Error> {
        if self.last_failure.is_some() {
            return Err(tls::Error::Handshake);
        }
        if self.tx_sent == self.tx_len {
            return Ok(None);
        }
        if out.is_empty() {
            return Err(tls::Error::Capacity);
        }
        // These are byte boundaries in the actual generated flight, not a
        // parallel handshake-phase or post-handshake completion flag.
        if self.tx_initial_end > self.tx_handshake_end || self.tx_handshake_end > self.tx_len {
            return Err(self.fail(Failure::State));
        }
        let (level, end) = if self.tx_sent < self.tx_initial_end {
            (Level::Initial, self.tx_initial_end)
        } else if self.tx_sent < self.tx_handshake_end {
            (Level::Handshake, self.tx_handshake_end)
        } else {
            (Level::OneRtt, self.tx_len)
        };
        let n = out.len().min(end - self.tx_sent);
        out[..n].copy_from_slice(&self.tx[self.tx_sent..self.tx_sent + n]);
        self.tx_sent += n;
        Ok(Some(Output { level, len: n }))
    }
    fn has_keys(&self, level: Level) -> bool {
        if self.integrity.is_none() || self.last_failure.is_some() {
            return false;
        }
        match level {
            Level::Initial => false,
            Level::Handshake => self.handshake.is_some(),
            Level::OneRtt => self.application.is_some(),
        }
    }
    fn discard_keys(&mut self, level: Level) {
        match level {
            Level::Initial => {}
            Level::Handshake => {
                self.handshake = None;
                // Before installation, retire the actual fresh agreement secrets.
                // After installation they have already moved and cannot regenerate.
                self.ephemeral = None;
                self.x25519 = None;
            }
            Level::OneRtt => {
                self.application = None;
                self.early_key = None;
                self.early_claim = None;
                self.resumption_master = None;
                // Destroy derivation material rather than retain a discarded flag.
                // Existing separately owned Handshake PacketKeys are unaffected.
                self.schedule.discard();
                self.ephemeral = None;
                self.x25519 = None;
            }
        }
    }
    fn is_handshaking(&self) -> bool {
        self.verified_handshake.is_none()
    }
    fn peer_transport_parameters(&self) -> Option<&[u8]> {
        if self.verified_handshake.is_some() {
            Some(&self.parameters[..self.parameters_len])
        } else {
            None
        }
    }
    fn seal(
        &mut self,
        level: Level,
        pn: u64,
        header: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, tls::Error> {
        if self.integrity.is_none() {
            return Err(tls::Error::KeysUnavailable);
        }
        if self.last_failure.is_some() {
            return Err(tls::Error::Handshake);
        }
        if level == Level::OneRtt && self.verified_handshake.is_none() {
            return Err(tls::Error::KeysUnavailable);
        }
        if level == Level::OneRtt && header.first().is_none_or(|byte| byte & 4 != 0) {
            return Err(tls::Error::InvalidInput);
        }
        match level {
            Level::Initial => Err(tls::Error::KeysUnavailable),
            Level::Handshake => self
                .handshake
                .as_mut()
                .ok_or(tls::Error::KeysUnavailable)?
                .local
                .seal(pn, header, buffer, plaintext_len)
                .map_err(map_crypto),
            Level::OneRtt => self
                .application
                .as_mut()
                .ok_or(tls::Error::KeysUnavailable)?
                .local
                .seal(pn, header, buffer, plaintext_len)
                .map_err(map_crypto),
        }
    }
    fn open(
        &mut self,
        level: Level,
        pn: u64,
        header: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize, tls::Error> {
        if self.integrity.is_none() {
            return Err(tls::Error::KeysUnavailable);
        }
        if self.last_failure.is_some() {
            return Err(tls::Error::Handshake);
        }
        if level == Level::OneRtt && self.verified_handshake.is_none() {
            return Err(tls::Error::KeysUnavailable);
        }
        let result = match level {
            Level::Initial => return Err(tls::Error::KeysUnavailable),
            Level::Handshake => self
                .handshake
                .as_ref()
                .ok_or(tls::Error::KeysUnavailable)?
                .remote
                .open(
                    pn,
                    header,
                    buffer,
                    self.integrity.as_mut().ok_or(tls::Error::KeysUnavailable)?,
                ),
            Level::OneRtt => {
                let keys = self
                    .application
                    .as_mut()
                    .ok_or(tls::Error::KeysUnavailable)?;
                if header.first().is_none_or(|byte| byte & 4 != 0) {
                    return Err(tls::Error::InvalidInput);
                }
                keys.remote.open(
                    pn,
                    header,
                    buffer,
                    self.integrity.as_mut().ok_or(tls::Error::KeysUnavailable)?,
                )
            }
        };
        match result {
            Err(crypto::Error::IntegrityLimit) => {
                Err(self.fail(Failure::Crypto(crypto::Error::IntegrityLimit)))
            }
            other => other.map_err(map_crypto),
        }
    }
    fn header_mask(
        &self,
        level: Level,
        local: bool,
        sample: &[u8; 16],
    ) -> Result<[u8; 5], tls::Error> {
        if self.integrity.is_none() {
            return Err(tls::Error::KeysUnavailable);
        }
        if self.last_failure.is_some() {
            return Err(tls::Error::Handshake);
        }
        match level {
            Level::Initial => Err(tls::Error::KeysUnavailable),
            Level::Handshake => {
                let keys = self.handshake.as_ref().ok_or(tls::Error::KeysUnavailable)?;
                if local {
                    keys.local.header_mask(sample)
                } else {
                    keys.remote.header_mask(sample)
                }
                .map_err(map_crypto)
            }
            Level::OneRtt => {
                let keys = self
                    .application
                    .as_ref()
                    .ok_or(tls::Error::KeysUnavailable)?;
                if local {
                    keys.local.header_mask(sample)
                } else {
                    keys.remote.header_mask(sample)
                }
                .map_err(map_crypto)
            }
        }
    }
}
