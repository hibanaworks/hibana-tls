//! Immutable application protocol negotiated by the QUIC-specific TLS profile.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Protocol {
    #[default]
    Http09,
    Http3,
    /// Application-defined bytes on QUIC streams, without HTTP framing.
    Raw(RawProtocol),
}
impl Protocol {
    pub const fn success_code(self) -> u64 {
        match self {
            Self::Http09 | Self::Raw(_) => 0,
            Self::Http3 => 0x100,
        }
    }
    pub const fn failure_code(self) -> u64 {
        match self {
            Self::Http09 => 0x100,
            Self::Raw(_) => 1,
            Self::Http3 => 0x102,
        }
    }
    /// RFC 9114 section 8 requires unknown application close codes to be
    /// treated as H3_NO_ERROR. Preserve the actual peer code in the outcome;
    /// this classification never supplies missing response FINs or ACKs.
    pub const fn peer_application_close_is_clean(self, code: u64) -> bool {
        match self {
            Self::Http09 | Self::Raw(_) => code == 0,
            Self::Http3 => !matches!(code, 0x101..=0x110 | 0x200..=0x202),
        }
    }
    pub const fn alpn(self) -> &'static [u8] {
        match self {
            Self::Http09 => b"hq-interop",
            Self::Http3 => b"h3",
            Self::Raw(protocol) => protocol.0,
        }
    }
}

/// Validated ALPN for an application-owned raw stream protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawProtocol(&'static [u8]);
impl RawProtocol {
    /// ALPN names contain 1..=255 bytes. HTTP ALPNs select their dedicated mode.
    pub fn new(alpn: &'static [u8]) -> Option<Self> {
        if alpn.is_empty() || alpn.len() > 255 || matches!(alpn, b"h3" | b"hq-interop") {
            None
        } else {
            Some(Self(alpn))
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_alpn_is_bounded_and_cannot_impersonate_http() {
        for name in [&b""[..], b"h3", b"hq-interop", &[b'x'; 256]] {
            assert!(RawProtocol::new(name).is_none());
        }
        let protocol = Protocol::Raw(RawProtocol::new(b"hello-quic/1").unwrap());
        assert_eq!(protocol.alpn(), b"hello-quic/1");
        assert!(protocol.peer_application_close_is_clean(0));
        assert!(!protocol.peer_application_close_is_clean(1));
        assert!(!protocol.peer_application_close_is_clean(0x100));
        assert_ne!(protocol.success_code(), protocol.failure_code());
    }
}
