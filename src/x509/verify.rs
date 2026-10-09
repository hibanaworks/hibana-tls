//! Project-owned bounded certificate path validation candidate.
//! Pure verification of supplied public bytes; no handshake-progress controller.
//! Used by the direct TLS endpoint. Caller supplies trust and time.
use super::types::{Der, TrustAnchor};
use super::{
    constraints,
    der::InvalidDer,
    name::{self, Identity},
    parsed::{self, Certificate},
    policy, signature,
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Der,
    Limits,
    Time,
    Usage,
    Name,
    Untrusted,
    WorkLimit,
    Signature,
}
impl From<InvalidDer> for Error {
    fn from(_: InvalidDer) -> Self {
        Self::Der
    }
}

/// Receipt of successful chain/name validation, not TLS Finished authority.
/// Private material prevents callers constructing a successful result themselves.
pub struct VerifiedServer<'a> {
    certificate: Certificate<'a>,
}
impl VerifiedServer<'_> {
    pub fn certificate_verify(
        &self,
        scheme: u16,
        hash: &[u8; 32],
        signature_bytes: &[u8],
    ) -> Result<(), Error> {
        let algorithm = match scheme {
            0x0403 => signature::ECDSA_SHA256,
            0x0804 => signature::PSS_SHA256,
            _ => return Err(Error::Signature),
        };
        let mut message = [0x20; 130];
        message[64..97].copy_from_slice(b"TLS 1.3, server CertificateVerify");
        message[97] = 0;
        message[98..].copy_from_slice(hash);
        signature::verify(
            self.certificate.public_key_algorithm,
            self.certificate.public_key,
            algorithm,
            &message,
            signature_bytes,
        )
        .map_err(|_| Error::Signature)
    }
}

pub fn server<'a>(
    leaf: &'a [u8],
    intermediates: &[&[u8]],
    roots: &[&[u8]],
    identity: Identity<'_>,
    unix_seconds: u64,
) -> Result<VerifiedServer<'a>, Error> {
    if roots.is_empty() || roots.len() > 32 {
        return Err(Error::Limits);
    }
    let mut anchors = [TrustAnchor {
        subject: Der::from(&[][..]),
        subject_public_key_info: Der::from(&[][..]),
        name_constraints: None,
    }; 32];
    for (slot, root) in anchors.iter_mut().zip(roots) {
        *slot = anchor(root)?;
    }
    server_anchored(
        leaf,
        intermediates,
        &anchors[..roots.len()],
        identity,
        unix_seconds,
    )
}
pub fn anchor(root: &[u8]) -> Result<TrustAnchor<'_>, Error> {
    if root.len() > 65535 {
        return Err(Error::Limits);
    }
    let cert = parsed::parse(root)?;
    let ext = policy::read(&cert)?;
    if ext.key_usage.is_some_and(|u| u & 32 == 0) {
        return Err(Error::Usage);
    }
    Ok(TrustAnchor {
        subject: Der::from(cert.subject),
        subject_public_key_info: Der::from(cert.spki),
        name_constraints: ext.constraints.map(Der::from),
    })
}
pub fn server_anchored<'a>(
    leaf: &'a [u8],
    intermediates: &[&[u8]],
    roots: &[TrustAnchor<'_>],
    identity: Identity<'_>,
    unix_seconds: u64,
) -> Result<VerifiedServer<'a>, Error> {
    if roots.is_empty() || roots.len() > 32 || intermediates.len() > 8 {
        return Err(Error::Limits);
    }
    let mut bytes = 0usize;
    for cert in core::iter::once(&leaf).chain(intermediates) {
        if cert.len() > 65535 {
            return Err(Error::Limits);
        }
        bytes = bytes.checked_add(cert.len()).ok_or(Error::Limits)?;
    }
    if bytes > 589815 {
        return Err(Error::Limits);
    }
    let now = i64::try_from(unix_seconds).map_err(|_| Error::Time)?;
    let certificate = parsed::parse(leaf)?;
    usable(&certificate, now, false, 0)?;
    let ext = policy::read(&certificate)?;
    let san = ext.san.ok_or(Error::Name)?;
    if !name::matches_san(san, identity)? {
        return Err(Error::Name);
    }
    let mut path: [Option<&Certificate<'_>>; 9] = [None; 9];
    path[0] = Some(&certificate);
    let mut remaining_work = 100usize;
    chain(
        &certificate,
        intermediates,
        roots,
        now,
        &mut path,
        1,
        &mut remaining_work,
    )?;
    Ok(VerifiedServer { certificate })
}
fn usable(cert: &Certificate<'_>, now: i64, ca: bool, ca_below: usize) -> Result<(), Error> {
    if now < cert.not_before || now > cert.not_after {
        return Err(Error::Time);
    }
    let ext = policy::read(cert)?;
    if ext.ca != ca || !ext.server_auth {
        return Err(Error::Usage);
    }
    if ext
        .key_usage
        .is_some_and(|usage| usage & if ca { 32 } else { 1 } == 0)
    {
        return Err(Error::Usage);
    }
    if ca && ext.path_length.is_some_and(|limit| ca_below > limit) {
        return Err(Error::Usage);
    }
    if !ca && ext.constraints.is_some() {
        return Err(Error::Usage);
    }
    Ok(())
}
fn issuer_accepts(
    issuer: &Certificate<'_>,
    child: &Certificate<'_>,
    path: &[Option<&Certificate<'_>>],
    work: &mut usize,
) -> Result<(), Error> {
    if issuer.subject != child.issuer {
        return Err(Error::Untrusted);
    }
    let ext = policy::read(issuer)?;
    if ext.key_usage.is_some_and(|u| u & 32 == 0) {
        return Err(Error::Usage);
    }
    if let Some(value) = ext.constraints {
        for descendant in path.iter().flatten() {
            constraints::check(value, descendant)?;
        }
    }
    *work = work.checked_sub(1).ok_or(Error::WorkLimit)?;
    signature::verify(
        issuer.public_key_algorithm,
        issuer.public_key,
        child.signature_algorithm,
        child.signed,
        child.signature,
    )
    .map_err(|_| Error::Signature)
}
fn chain<'c>(
    child: &Certificate<'_>,
    intermediates: &'c [&'c [u8]],
    roots: &[TrustAnchor<'_>],
    now: i64,
    path: &mut [Option<&Certificate<'_>>; 9],
    depth: usize,
    work: &mut usize,
) -> Result<(), Error> {
    for root in roots {
        if anchor_accepts(root, child, &path[..depth], work).is_ok() {
            return Ok(());
        }
        if *work == 0 {
            return Err(Error::WorkLimit);
        }
    }
    if depth == path.len() {
        return Err(Error::Untrusted);
    }
    for candidate in intermediates {
        let issuer = parsed::parse(candidate)?;
        if path[..depth]
            .iter()
            .flatten()
            .any(|p| p.signed == issuer.signed)
        {
            continue;
        }
        let ca_below = path[1..depth]
            .iter()
            .flatten()
            .filter(|c| c.issuer != c.subject)
            .count();
        if usable(&issuer, now, true, ca_below).is_err()
            || issuer_accepts(&issuer, child, &path[..depth], work).is_err()
        {
            if *work == 0 {
                return Err(Error::WorkLimit);
            }
            continue;
        }
        // The path borrows this stack frame's certificate only for the recursive
        // proof attempt; no numeric phase or externally retained progress exists.
        let mut next = [None; 9];
        next[..depth].copy_from_slice(&path[..depth]);
        next[depth] = Some(&issuer);
        if chain(
            &issuer,
            intermediates,
            roots,
            now,
            &mut next,
            depth + 1,
            work,
        )
        .is_ok()
        {
            return Ok(());
        }
        if *work == 0 {
            return Err(Error::WorkLimit);
        }
    }
    Err(Error::Untrusted)
}

fn anchor_accepts(
    anchor: &TrustAnchor<'_>,
    child: &Certificate<'_>,
    path: &[Option<&Certificate<'_>>],
    work: &mut usize,
) -> Result<(), Error> {
    if anchor.subject.as_ref() != child.issuer {
        return Err(Error::Untrusted);
    }
    if let Some(value) = anchor.name_constraints {
        for descendant in path.iter().flatten() {
            constraints::check(value.as_ref(), descendant)?;
        }
    }
    let mut spki = anchor.subject_public_key_info.as_ref();
    let algorithm = super::der::take(&mut spki, 0x30)?.1;
    let bits = super::der::take(&mut spki, 3)?.1;
    let key = bits.strip_prefix(&[0]).ok_or(Error::Der)?;
    if !spki.is_empty() {
        return Err(Error::Der);
    }
    *work = work.checked_sub(1).ok_or(Error::WorkLimit)?;
    signature::verify(
        algorithm,
        key,
        child.signature_algorithm,
        child.signed,
        child.signature,
    )
    .map_err(|_| Error::Signature)
}
