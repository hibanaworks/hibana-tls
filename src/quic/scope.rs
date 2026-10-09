//! Shared affine installation identities for QUIC and its TLS locals.
use super::packet_protection::Error;

/// Caller-owned identity claimed once. It has no keys or shared running state.
#[derive(Debug)]
pub struct ApplicationKeyScope {
    connection_generation: u64,
    claimed: bool,
}
impl ApplicationKeyScope {
    pub const fn new(connection_generation: u64) -> Self {
        Self {
            connection_generation,
            claimed: false,
        }
    }
    pub const fn connection_generation(&self) -> u64 {
        self.connection_generation
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
