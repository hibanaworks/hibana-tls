//! DNS/IP NameConstraints for the bounded verifier.
//! Unsupported constraint forms, non-default distances and constrained wildcards
//! reject rather than silently widening trust. Directory-name canonicalization
//! is deliberately not advertised as implemented.
use super::{
    der::{self, InvalidDer},
    parsed::Certificate,
    policy,
};

pub fn check(value: &[u8], descendant: &Certificate<'_>) -> Result<(), InvalidDer> {
    let mut sequence = der::exact(value, 0x30)?;
    if sequence.is_empty() {
        return Err(InvalidDer);
    }
    let permitted = if sequence.first() == Some(&0xa0) {
        Some(der::take(&mut sequence, 0xa0)?.1)
    } else {
        None
    };
    let excluded = if sequence.first() == Some(&0xa1) {
        Some(der::take(&mut sequence, 0xa1)?.1)
    } else {
        None
    };
    if !sequence.is_empty() {
        return Err(InvalidDer);
    }
    for subtrees in [permitted, excluded].into_iter().flatten() {
        validate(subtrees)?;
    }
    let ext = policy::read(descendant)?;
    if let Some(san) = ext.san {
        super::name::matches_san(san,super::name::Identity::Dns("invalid"))?;
        let mut names = der::exact(san, 0x30)?;
        while !names.is_empty() {
            let tag = names[0];
            let name = der::take(&mut names, tag)?.1;
            // Identity matching may ignore unrelated unusable presented DNS
            // names, but they must never bypass a constrained issuer's scope.
            if tag == 0x82 {
                super::name::dns(name, true)?;
            }
            for (subtrees, deny) in [(permitted, false), (excluded, true)] {
                if let Some(mut input) = subtrees {
                    let mut applicable = false;
                    let mut matched = false;
                    while !input.is_empty() {
                        let (kind, base) = subtree(&mut input)?;
                        if kind == tag {
                            applicable = true;
                            matched |= contains(kind, base, name)?;
                        }
                    }
                    if (deny && matched) || (!deny && applicable && !matched) {
                        return Err(InvalidDer);
                    }
                }
            }
        }
    }
    Ok(())
}
fn subtree<'a>(input: &mut &'a [u8]) -> Result<(u8, &'a [u8]), InvalidDer> {
    let mut tree = der::take(input, 0x30)?.1;
    let tag = *tree.first().ok_or(InvalidDer)?;
    let value = der::take(&mut tree, tag)?.1;
    // minimum DEFAULT 0 must be omitted; maximum is unsupported by the profile.
    if !tree.is_empty() {
        return Err(InvalidDer);
    }
    match tag {
        0x82 => {
            let name = value.strip_prefix(b".").unwrap_or(value);
            let name = core::str::from_utf8(name).map_err(|_| InvalidDer)?;
            if !matches!(
                super::name::Identity::try_from(name)?,
                super::name::Identity::Dns(_)
            ) {
                return Err(InvalidDer);
            }
        }
        0x87 if matches!(value.len(), 8 | 32) => {
            let (_, mask) = value.split_at(value.len() / 2);
            let mut zero_seen = false;
            for byte in mask {
                for bit in (0..8).rev() {
                    if byte & (1 << bit) == 0 {
                        zero_seen = true;
                    } else if zero_seen {
                        return Err(InvalidDer);
                    }
                }
            }
        }
        _ => return Err(InvalidDer),
    }
    Ok((tag, value))
}
fn validate(mut input: &[u8]) -> Result<(), InvalidDer> {
    if input.is_empty() {
        return Err(InvalidDer);
    }
    let mut count = 0;
    while !input.is_empty() {
        if count == 64 {
            return Err(InvalidDer);
        }
        subtree(&mut input)?;
        count += 1;
    }
    Ok(())
}
fn contains(tag: u8, base: &[u8], name: &[u8]) -> Result<bool, InvalidDer> {
    if tag == 0x82 {
        if name.contains(&b'*') {
            return Err(InvalidDer);
        }
        let suffix = base.strip_prefix(b".").unwrap_or(base);
        if name.eq_ignore_ascii_case(suffix) {
            return Ok(base.first() != Some(&b'.'));
        }
        Ok(name.len() > suffix.len()
            && name[name.len() - suffix.len() - 1] == b'.'
            && name[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix))
    } else {
        let (address, mask) = base.split_at(base.len() / 2);
        if name.len() != address.len() {
            return Ok(false);
        }
        Ok(name
            .iter()
            .zip(address)
            .zip(mask)
            .all(|((&n, &a), &m)| n & m == a & m))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_subtree_boundaries() {
        assert_eq!(contains(0x82, b"example.com", b"a.example.com"), Ok(true));
        assert_eq!(contains(0x82, b"example.com", b"badexample.com"), Ok(false));
        assert_eq!(contains(0x82, b".example.com", b"example.com"), Ok(false));
        assert_eq!(contains(0x82, b"example.com", b"EXAMPLE.COM"), Ok(true));
        assert!(contains(0x82, b"example.com", b"*.example.com").is_err());
    }
    #[test]
    fn invalid_presented_dns_never_bypasses_name_constraints() {
        let mut certificate=super::super::parsed::parse(include_bytes!("../../tests/vectors/x509-owned/direct-valid.der")).unwrap();
        // This is a syntax-only policy unit test, not a forged trust receipt.
        certificate.extensions=b"\x30\x14\x06\x03\x55\x1d\x11\x04\x0d\x30\x0b\x82\x09a..domain";
        let permitted=b"\x30\x0e\xa0\x0c\x30\x0a\x82\x08a.domain";
        assert!(check(permitted,&certificate).is_err());
    }
    #[test]
    fn ip_subtree_masks() {
        assert_eq!(
            contains(0x87, &[10, 0, 0, 0, 255, 0, 0, 0], &[10, 2, 3, 4]),
            Ok(true)
        );
        assert_eq!(
            contains(0x87, &[10, 0, 0, 0, 255, 0, 0, 0], &[11, 2, 3, 4]),
            Ok(false)
        );
        assert!(validate(&[0x30, 10, 0x87, 8, 10, 0, 0, 0, 255, 0, 255, 0]).is_err());
    }
}
