//! Borrowed DNS/IP identities and SAN comparison (RFC9525).
//! These public names confer no trust and contain no protocol progress state.
use super::der::{self, InvalidDer};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Identity<'a> {
    Dns(&'a str),
    Ip(core::net::IpAddr),
}
impl<'a> TryFrom<&'a str> for Identity<'a> {
    type Error = InvalidDer;
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        if let Ok(ip) = value.parse() {
            return Ok(Self::Ip(ip));
        }
        dns(value.as_bytes(), false)?;
        Ok(Self::Dns(value))
    }
}
pub(super) fn dns(value: &[u8], wildcard: bool) -> Result<(), InvalidDer> {
    if value.is_empty() || value.len() > 253 {
        return Err(InvalidDer);
    }
    let mut labels = value.split(|&b| b == b'.');
    let first = labels.next().ok_or(InvalidDer)?;
    if wildcard && first == b"*" {
        let suffix = value.get(2..).ok_or(InvalidDer)?;
        // Require at least two ordinary suffix labels; no bare TLD wildcard.
        if !suffix.contains(&b'.') {
            return Err(InvalidDer);
        }
        return dns(suffix, false);
    }
    for label in core::iter::once(first).chain(labels) {
        if label.is_empty()
            || label.len() > 63
            || !label[0].is_ascii_alphanumeric()
            || !label[label.len() - 1].is_ascii_alphanumeric()
            || !label
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return Err(InvalidDer);
        }
    }
    Ok(())
}
pub fn matches_dns(pattern: &[u8], reference: &[u8]) -> Result<bool, InvalidDer> {
    dns(pattern, true)?;
    dns(reference, false)?;
    if let Some(suffix) = pattern.strip_prefix(b"*.") {
        let Some(dot) = reference.iter().position(|&b| b == b'.') else {
            return Ok(false);
        };
        Ok(reference[dot + 1..].eq_ignore_ascii_case(suffix))
    } else {
        Ok(pattern.eq_ignore_ascii_case(reference))
    }
}
/// Consume the entire DER SAN, while comparing each usable presented identity.
/// RFC 9525 section 6.2 accepts any matching presented identifier. A malformed
/// DNS identifier cannot authenticate a service; unrelated identifiers do not
/// invalidate a valid match. Structural DER errors still reject after a match.
/// NameConstraints applies its own strict validation to every constrained name.
pub fn matches_san(value: &[u8], identity: Identity<'_>) -> Result<bool, InvalidDer> {
    let mut names = der::exact(value, 0x30)?;
    if names.is_empty() {
        return Err(InvalidDer);
    }
    let mut matched = false;
    while !names.is_empty() {
        let tag = names[0];
        let (_, value) = der::take(&mut names, tag)?;
        match tag {
            0x82 => {
                if !value.is_ascii() {
                    return Err(InvalidDer);
                }
                if dns(value, true).is_ok()
                    && let Identity::Dns(reference) = identity
                {
                    matched |= matches_dns(value, reference.as_bytes())?;
                }
            }
            0x87 => {
                if !matches!(value.len(), 4 | 16) {
                    return Err(InvalidDer);
                }
                matched |= match identity {
                    Identity::Ip(core::net::IpAddr::V4(ip)) => value == ip.octets(),
                    Identity::Ip(core::net::IpAddr::V6(ip)) => value == ip.octets(),
                    _ => false,
                };
            }
            // Other GeneralName forms don't establish a DNS/IP server identity.
            0xa0 | 0x81 | 0xa3 | 0xa4 | 0xa5 | 0x86 | 0x88 => {}
            _ => return Err(InvalidDer),
        }
    }
    Ok(matched)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_is_case_insensitive_and_wildcards_cover_exactly_one_label() {
        assert_eq!(matches_dns(b"Example.com", b"example.COM"), Ok(true));
        assert_eq!(matches_dns(b"*.example.com", b"a.example.com"), Ok(true));
        assert_eq!(matches_dns(b"*.example.com", b"a.b.example.com"), Ok(false));
        assert_eq!(matches_dns(b"*.example.com", b"example.com"), Ok(false));
        for invalid in [
            b"f*.example.com".as_slice(),
            b"*.*.com",
            b"*.com",
            b"a..com",
            b"-x.com",
            b"x-.com",
            b"x.com\0",
            b"x.com.",
        ] {
            assert!(matches_dns(invalid, b"x.example.com").is_err());
        }
    }
    #[test]
    fn numeric_identity_requires_ip_san_not_dns_text() {
        let dns = b"\x30\x0b\x82\x09127.0.0.1";
        let ip = b"\x30\x06\x87\x04\x7f\0\0\x01";
        let identity = Identity::try_from("127.0.0.1").unwrap();
        assert_eq!(matches_san(dns, identity), Ok(false));
        assert_eq!(matches_san(ip, identity), Ok(true));
        assert!(matches_san(b"\x30\x05\x87\x03\x7f\0\0", identity).is_err());
    }
    #[test]
    fn invalid_presented_dns_cannot_authenticate_or_invalidate_another_identity() {
        let bytes = b"\x30\x12\x82\x09localhost\x82\x05a..co";
        assert_eq!(matches_san(bytes, Identity::Dns("localhost")), Ok(true));
        assert_eq!(
            matches_san(bytes, Identity::Dns("other.example")),
            Ok(false)
        );
        let invalid_only = b"\x30\x07\x82\x05a..co";
        assert_eq!(
            matches_san(invalid_only, Identity::Dns("localhost")),
            Ok(false)
        );
    }
    #[test]
    fn truncated_der_after_a_matching_name_still_rejects() {
        let bytes = b"\x30\x12\x82\x09localhost\x82\x06a..co";
        assert!(matches_san(bytes, Identity::Dns("localhost")).is_err());
    }
    #[test]
    fn overlong_single_label_in_other_san_does_not_become_an_identity() {
        let mut bytes = [b'a'; 267];
        bytes[..4].copy_from_slice(&[0x30, 0x82, 1, 7]);
        bytes[4..14].copy_from_slice(b"\x82\x08server42");
        bytes[14..17].copy_from_slice(&[0x82, 0x81, 250]);
        assert_eq!(matches_san(&bytes, Identity::Dns("server42")), Ok(true));
        assert_eq!(
            matches_san(&bytes, Identity::Dns("other.example")),
            Ok(false)
        );
    }
}
