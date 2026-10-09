//! Borrowed certificate syntax. Parsed bytes are never an authentication proof.
//! Profile: X.509 v3, canonical positive serial, octet-aligned keys/signatures.
use super::{
    der::{self, InvalidDer},
    time,
};

#[derive(Debug)]
pub struct Certificate<'a> {
    pub signed: &'a [u8],
    pub signature_algorithm: &'a [u8],
    pub signature: &'a [u8],
    pub issuer: &'a [u8],
    pub subject: &'a [u8],
    pub spki: &'a [u8],
    pub public_key_algorithm: &'a [u8],
    pub public_key: &'a [u8],
    pub not_before: i64,
    pub not_after: i64,
    /// Raw sequence contents, after duplicate OID and DER validation.
    pub extensions: &'a [u8],
}

pub fn parse(bytes: &[u8]) -> Result<Certificate<'_>, InvalidDer> {
    let mut outer = der::exact(bytes, 0x30)?;
    let (signed, mut tbs) = der::take(&mut outer, 0x30)?;
    let (_, signature_algorithm) = der::take(&mut outer, 0x30)?;
    algorithm(signature_algorithm)?;
    let signature = octets(der::take(&mut outer, 3)?.1)?;
    if !outer.is_empty() || signature.is_empty() {
        return Err(InvalidDer);
    }
    if der::exact(der::take(&mut tbs, 0xa0)?.1, 2)? != [2] {
        return Err(InvalidDer);
    }
    let serial = der::take(&mut tbs, 2)?.1;
    let serial_number = der::unsigned(serial)?;
    if serial.len() > 20 || serial_number.iter().all(|&b| b == 0) {
        return Err(InvalidDer);
    }
    let inner_algorithm = der::take(&mut tbs, 0x30)?.1;
    if inner_algorithm != signature_algorithm {
        return Err(InvalidDer);
    }
    let (_, issuer) = der::take(&mut tbs, 0x30)?;
    name(issuer)?;
    if issuer.is_empty() {
        return Err(InvalidDer);
    }
    let (_, mut validity) = der::take(&mut tbs, 0x30)?;
    let before_tag = *validity.first().ok_or(InvalidDer)?;
    let not_before = time::parse(before_tag, der::take(&mut validity, before_tag)?.1)?;
    let after_tag = *validity.first().ok_or(InvalidDer)?;
    let not_after = time::parse(after_tag, der::take(&mut validity, after_tag)?.1)?;
    if !validity.is_empty() || not_before > not_after {
        return Err(InvalidDer);
    }
    let (_, subject) = der::take(&mut tbs, 0x30)?;
    name(subject)?;
    let (_, spki_bytes) = der::take(&mut tbs, 0x30)?;
    let mut spki = spki_bytes;
    let (_, public_key_algorithm) = der::take(&mut spki, 0x30)?;
    algorithm(public_key_algorithm)?;
    let public_key = octets(der::take(&mut spki, 3)?.1)?;
    if !spki.is_empty() || public_key.is_empty() {
        return Err(InvalidDer);
    }
    // Unique IDs have no supported role in this bounded v3 profile; reject.
    let extensions = if tbs.is_empty() {
        &[][..]
    } else {
        der::exact(der::take(&mut tbs, 0xa3)?.1, 0x30)?
    };
    if !tbs.is_empty() {
        return Err(InvalidDer);
    }
    validate_extensions(extensions)?;
    Ok(Certificate {
        signed,
        signature_algorithm,
        signature,
        issuer,
        subject,
        spki: spki_bytes,
        public_key_algorithm,
        public_key,
        not_before,
        not_after,
        extensions,
    })
}

fn algorithm(mut value: &[u8]) -> Result<(), InvalidDer> {
    der::oid(der::take(&mut value, 6)?.1)?;
    if !value.is_empty() {
        let tag = value[0];
        let (_, parameters) = der::take(&mut value, tag)?;
        if tag == 5 && !parameters.is_empty() {
            return Err(InvalidDer);
        }
    }
    if !value.is_empty() {
        return Err(InvalidDer);
    }
    Ok(())
}
fn octets(value: &[u8]) -> Result<&[u8], InvalidDer> {
    match value.split_first() {
        Some((&0, bytes)) => Ok(bytes),
        _ => Err(InvalidDer),
    }
}
fn name(mut value: &[u8]) -> Result<(), InvalidDer> {
    while !value.is_empty() {
        let (_, mut set) = der::take(&mut value, 0x31)?;
        if set.is_empty() {
            return Err(InvalidDer);
        }
        let mut previous: Option<&[u8]> = None;
        while !set.is_empty() {
            let (encoded, mut attribute) = der::take(&mut set, 0x30)?;
            if previous.is_some_and(|p| p > encoded) {
                return Err(InvalidDer);
            }
            previous = Some(encoded);
            der::oid(der::take(&mut attribute, 6)?.1)?;
            let tag = *attribute.first().ok_or(InvalidDer)?;
            der::take(&mut attribute, tag)?;
            if !attribute.is_empty() {
                return Err(InvalidDer);
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct Extension<'a> {
    pub oid: &'a [u8],
    pub critical: bool,
    pub value: &'a [u8],
}
pub fn extension<'a>(input: &mut &'a [u8]) -> Result<Extension<'a>, InvalidDer> {
    let (_, mut value) = der::take(input, 0x30)?;
    let oid = der::take(&mut value, 6)?.1;
    der::oid(oid)?;
    let critical = if value.first() == Some(&1) {
        // FALSE is the DEFAULT and must be omitted in DER.
        if der::take(&mut value, 1)?.1 != [255] {
            return Err(InvalidDer);
        }
        true
    } else {
        false
    };
    let contents = der::take(&mut value, 4)?.1;
    if !value.is_empty() {
        return Err(InvalidDer);
    }
    Ok(Extension {
        oid,
        critical,
        value: contents,
    })
}
fn validate_extensions(mut input: &[u8]) -> Result<(), InvalidDer> {
    let mut seen: [Option<&[u8]>; 64] = [None; 64];
    let mut count = 0;
    while !input.is_empty() {
        if count == seen.len() {
            return Err(InvalidDer);
        }
        let next = extension(&mut input)?;
        if seen[..count].contains(&Some(next.oid)) {
            return Err(InvalidDer);
        }
        seen[count] = Some(next.oid);
        count += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extensions_reject_duplicates_and_explicit_default() {
        let valid = [0x30, 8, 6, 3, 0x55, 0x1d, 0x13, 4, 1, 0];
        assert!(validate_extensions(&valid).is_ok());
        let mut duplicate = std::vec::Vec::from(valid);
        duplicate.extend_from_slice(&valid);
        assert!(validate_extensions(&duplicate).is_err());
        assert!(
            validate_extensions(&[0x30, 11, 6, 3, 0x55, 0x1d, 0x13, 1, 1, 0, 4, 1, 0]).is_err()
        );
        assert!(
            validate_extensions(&[0x30, 11, 6, 3, 0x55, 0x1d, 0x13, 1, 1, 255, 4, 1, 0]).is_ok()
        );
    }
}
