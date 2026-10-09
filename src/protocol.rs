//! Immutable application protocol negotiated by the QUIC-specific TLS profile.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Protocol {
    #[default]
    Http09,
    Http3,
}
impl Protocol {
    pub const fn success_code(self) -> u64 {
        match self {
            Self::Http09 => 0,
            Self::Http3 => 0x100,
        }
    }
    pub const fn failure_code(self) -> u64 {
        match self {
            Self::Http09 => 0x100,
            Self::Http3 => 0x102,
        }
    }
    /// RFC 9114 section 8 requires unknown application close codes to be
    /// treated as H3_NO_ERROR. Preserve the actual peer code in the outcome;
    /// this classification never supplies missing response FINs or ACKs.
    pub const fn peer_application_close_is_clean(self, code: u64) -> bool {
        match self {
            Self::Http09 => code == 0,
            Self::Http3 => !matches!(code, 0x101..=0x110 | 0x200..=0x202),
        }
    }
    pub const fn alpn(self) -> &'static [u8] {
        match self {
            Self::Http09 => b"hq-interop",
            Self::Http3 => b"h3",
        }
    }
}
