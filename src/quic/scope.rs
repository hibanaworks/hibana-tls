//! Shared affine installation identities for QUIC and its TLS locals.
use super::packet_protection::Error;

/// Caller-owned connection identity and one-time installation bindings.
pub struct ApplicationKeyScope {
    connection_generation: u64,
    claimed: bool,
    material: hibana::runtime::transport::EndpointBinding,
    write: hibana::runtime::transport::EndpointBinding,
    production: hibana::runtime::transport::EndpointBinding,
}
impl ApplicationKeyScope {
    // Constructing the resource binding is this connection's integration boundary.
    #[allow(unsafe_code)]
    pub const fn new(connection_generation: u64) -> Self {
        Self {
            connection_generation,
            claimed: false,
            // SAFETY: this scope identifies one fresh connection's keys. Its
            // unique installation is consumed by KeySource. All key-source
            // transports obtain the same binding through that source.
            material: unsafe { hibana::runtime::transport::EndpointBinding::new() },
            // SAFETY: this scope is the unique issuer for its packet-write
            // keys, which KeySource moves out at most once.
            write: unsafe { hibana::runtime::transport::EndpointBinding::new() },
            // SAFETY: the same fresh connection owns its stream production.
            // All transports use this single issuer through KeySource.
            production: unsafe { hibana::runtime::transport::EndpointBinding::new() },
        }
    }
    pub const fn connection_generation(&self) -> u64 {
        self.connection_generation
    }
    /// Initial bindings for key installation, packet writing and stream production.
    ///
    /// Every session and transport for this connection must use these bindings.
    pub const fn endpoint_bindings(
        &self,
    ) -> [(u8, &hibana::runtime::transport::EndpointBinding); 3] {
        use crate::handshake::global::owned::{MATERIAL, PRODUCTION, WRITE_KEYS};
        [
            (MATERIAL, &self.material),
            (WRITE_KEYS, &self.write),
            (PRODUCTION, &self.production),
        ]
    }
    /// Claim before application keys exist, then share immutable identity with
    /// the actual authority producers. Dropping the claim cannot reissue it.
    pub fn claim(&mut self) -> Result<ApplicationKeyInstallation<'_>, Error> {
        if self.claimed {
            return Err(Error::KeyUpdateNotAllowed);
        }
        self.claimed = true;
        Ok(ApplicationKeyInstallation {
            scope: self,
            recovery: Some(RecoveryInstallation { scope: self }),
            publication: Some(PublicationGateInstallation { scope: self }),
        })
    }
}

impl core::fmt::Debug for ApplicationKeyScope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ApplicationKeyScope")
            .field("connection_generation", &self.connection_generation)
            .field("claimed", &self.claimed)
            .finish_non_exhaustive()
    }
}

/// One-shot installation capability. Fresh provider-owned 1-RTT keys are the
/// intended source; installation does not import old raw authorization state.
/// ```compile_fail
/// use hibana_tls::quic::scope::ApplicationKeyInstallation;
/// fn duplicate(grant: ApplicationKeyInstallation<'_>) { let first = grant; let second = grant; }
/// ```
#[must_use = "dropping installation permanently closes this scope to new keys"]
#[derive(Debug)]
pub struct ApplicationKeyInstallation<'a> {
    scope: &'a ApplicationKeyScope,
    recovery: Option<RecoveryInstallation<'a>>,
    publication: Option<PublicationGateInstallation<'a>>,
}
impl<'a> ApplicationKeyInstallation<'a> {
    pub fn take_recovery(&mut self) -> Result<RecoveryInstallation<'a>, Error> {
        self.recovery.take().ok_or(Error::KeyUpdateNotAllowed)
    }
    pub fn take_publication_gate(&mut self) -> Result<PublicationGateInstallation<'a>, Error> {
        self.publication.take().ok_or(Error::KeyUpdateNotAllowed)
    }
    pub const fn scope(&self) -> &'a ApplicationKeyScope {
        self.scope
    }
    /// Consume this unique packet-key installation permission.
    pub fn into_scope(self) -> &'a ApplicationKeyScope {
        self.scope
    }
}

/// One affine recovery-installation capability for an actual key scope.
/// ```compile_fail
/// use hibana_tls::quic::scope::RecoveryInstallation;
/// fn duplicate(token: RecoveryInstallation<'_>) {
///     let first = token; let second = token;
/// }
/// ```
#[must_use = "dropping installation permanently closes this scope to recovery"]
#[derive(Debug)]
pub struct RecoveryInstallation<'a> {
    scope: &'a ApplicationKeyScope,
}

impl<'a> RecoveryInstallation<'a> {
    pub fn into_scope(self) -> &'a ApplicationKeyScope {
        self.scope
    }
}

/// One affine publication-gate capability for an actual key scope.
/// ```compile_fail
/// use hibana_tls::quic::scope::PublicationGateInstallation;
/// fn duplicate(token: PublicationGateInstallation<'_>) {
///     let first = token; let second = token;
/// }
/// ```
#[must_use = "dropping installation permanently closes this scope to a publication gate"]
#[derive(Debug)]
pub struct PublicationGateInstallation<'a> {
    scope: &'a ApplicationKeyScope,
}

impl<'a> PublicationGateInstallation<'a> {
    pub fn into_scope(self) -> &'a ApplicationKeyScope {
        self.scope
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_installation_permissions_move_once_and_retain_identity() {
        let mut scope = ApplicationKeyScope::new(4);
        let mut installation = scope.claim().unwrap();
        let identity = installation.scope();
        let recovery = installation.take_recovery().unwrap();
        let publication = installation.take_publication_gate().unwrap();
        assert!(matches!(
            installation.take_recovery(),
            Err(Error::KeyUpdateNotAllowed)
        ));
        assert!(matches!(
            installation.take_publication_gate(),
            Err(Error::KeyUpdateNotAllowed)
        ));
        assert!(core::ptr::eq(identity, recovery.into_scope()));
        assert!(core::ptr::eq(identity, publication.into_scope()));
        assert!(core::ptr::eq(identity, installation.into_scope()));
        assert!(matches!(scope.claim(), Err(Error::KeyUpdateNotAllowed)));
    }
}
