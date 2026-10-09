//! Borrowed certificate inputs owned by this project; no external PKI ABI.
use super::{der::InvalidDer, name::Identity};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Der<'a>(&'a [u8]);
impl<'a> From<&'a [u8]> for Der<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self(value)
    }
}
impl AsRef<[u8]> for Der<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateDer<'a>(&'a [u8]);
impl<'a> From<&'a [u8]> for CertificateDer<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self(value)
    }
}
impl AsRef<[u8]> for CertificateDer<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}
impl<'a> CertificateDer<'a> {
    pub const fn bytes(&self) -> &'a [u8] {
        self.0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustAnchor<'a> {
    pub subject: Der<'a>,
    pub subject_public_key_info: Der<'a>,
    pub name_constraints: Option<Der<'a>>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnixTime(u64);
impl UnixTime {
    pub const fn since_unix_epoch(duration: core::time::Duration) -> Self {
        Self(duration.as_secs())
    }
    pub const fn as_secs(self) -> u64 {
        self.0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerName<'a> {
    DnsName(&'a str),
    IpAddress(core::net::IpAddr),
}
impl<'a> TryFrom<&'a str> for ServerName<'a> {
    type Error = InvalidDer;
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Ok(match Identity::try_from(value)? {
            Identity::Dns(name) => Self::DnsName(name),
            Identity::Ip(ip) => Self::IpAddress(ip),
        })
    }
}
impl<'a> From<ServerName<'a>> for Identity<'a> {
    fn from(name: ServerName<'a>) -> Self {
        match name {
            ServerName::DnsName(name) => Self::Dns(name),
            ServerName::IpAddress(ip) => Self::Ip(ip),
        }
    }
}
