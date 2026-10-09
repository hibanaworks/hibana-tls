//! Strict borrowed DER for the two INTEGERs of an RSA public key.
//! This grammar has no optional fields, nesting recursion, allocation or I/O.
use super::{Error, PublicKey};

fn value<'a>(input: &mut &'a [u8], tag: u8) -> Result<&'a [u8], Error> {
    let (&actual, tail) = input.split_first().ok_or(Error::InvalidDer)?;
    if actual != tag {
        return Err(Error::InvalidDer);
    }
    let (&first, mut tail) = tail.split_first().ok_or(Error::InvalidDer)?;
    let length = if first < 128 {
        usize::from(first)
    } else {
        let count = usize::from(first & 127);
        // Zero denotes an indefinite length, forbidden by DER. A length wider
        // than usize cannot address any supplied borrowed slice.
        if count == 0 || count > core::mem::size_of::<usize>() || tail.len() < count {
            return Err(Error::InvalidDer);
        }
        let (bytes, rest) = tail.split_at(count);
        if bytes[0] == 0 {
            return Err(Error::InvalidDer);
        }
        let mut length = 0usize;
        for &byte in bytes {
            length = length
                .checked_mul(256)
                .and_then(|n| n.checked_add(usize::from(byte)))
                .ok_or(Error::InvalidDer)?;
        }
        if length < 128 {
            return Err(Error::InvalidDer);
        }
        tail = rest;
        length
    };
    if length > tail.len() {
        return Err(Error::InvalidDer);
    }
    let (value, rest) = tail.split_at(length);
    *input = rest;
    Ok(value)
}

fn integer<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], Error> {
    let bytes = value(input, 2)?;
    let (&first, rest) = bytes.split_first().ok_or(Error::InvalidDer)?;
    if first & 128 != 0 {
        return Err(Error::InvalidDer);
    }
    if first == 0 && !rest.is_empty() {
        if rest[0] & 128 == 0 {
            return Err(Error::InvalidDer);
        }
        Ok(rest)
    } else {
        Ok(bytes)
    }
}

pub(super) fn parse(mut input: &[u8]) -> Result<PublicKey<'_>, Error> {
    let mut sequence = value(&mut input, 0x30)?;
    if !input.is_empty() {
        return Err(Error::InvalidDer);
    }
    let modulus = integer(&mut sequence)?;
    let exponent = integer(&mut sequence)?;
    if !sequence.is_empty() {
        return Err(Error::InvalidDer);
    }
    if !matches!(modulus.len(), 256 | 384 | 512) || modulus[0] & 128 == 0 {
        return Err(Error::UnsupportedKeySize);
    }
    if modulus[modulus.len() - 1] & 1 == 0 {
        return Err(Error::InvalidModulus);
    }
    if exponent.len() > 4 {
        return Err(Error::InvalidExponent);
    }
    let mut e = 0u32;
    for &byte in exponent {
        e = (e << 8) | u32::from(byte);
    }
    if e < 3 || e & 1 == 0 {
        return Err(Error::InvalidExponent);
    }
    Ok(PublicKey {
        modulus,
        exponent: e,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn supported_widths_borrow_and_reject_every_truncation() {
        for width in [256usize, 384, 512] {
            let mut der = [0u8; 532];
            let body = width + 8;
            der[..4].copy_from_slice(&[0x30, 0x82, (body >> 8) as u8, body as u8]);
            let integer_len = width + 1;
            der[4..8].copy_from_slice(&[2, 0x82, (integer_len >> 8) as u8, integer_len as u8]);
            der[9] = 0x80;
            der[8 + width] = 1;
            der[9 + width..12 + width].copy_from_slice(&[2, 1, 3]);
            let end = 12 + width;
            let key = parse(&der[..end]).unwrap();
            assert_eq!(key.modulus.as_ptr(), der[9..].as_ptr());
            assert_eq!(key.modulus.len(), width);
            assert_eq!(key.exponent, 3);
            for n in 0..end {
                assert!(parse(&der[..n]).is_err());
            }
            assert!(matches!(parse(&der[..end + 1]), Err(Error::InvalidDer)));
            der[end - 1] = 2;
            assert!(matches!(parse(&der[..end]), Err(Error::InvalidExponent)));
            der[end - 1] = 3;
            der[8 + width] = 2;
            assert!(matches!(parse(&der[..end]), Err(Error::InvalidModulus)));
        }
    }
    #[test]
    fn lengths_are_canonical_and_bounded() {
        for bad in [
            &[2, 0x80][..],
            &[2, 0x81, 0x7f][..],
            &[2, 0x82, 0, 0x80][..],
            &[2, 0xff][..],
            &[2, 0x82, 1][..],
            &[2, 3, 1, 2][..],
        ] {
            assert_eq!(value(&mut &bad[..], 2), Err(Error::InvalidDer));
        }
        let mut data = [0u8; 132];
        data[..3].copy_from_slice(&[2, 0x81, 128]);
        let mut input = &data[..];
        assert_eq!(value(&mut input, 2).unwrap().len(), 128);
        assert_eq!(input.len(), 1);
    }
    #[test]
    fn integer_sign_and_minimality() {
        for bad in [
            &[2, 0][..],
            &[2, 1, 128][..],
            &[2, 2, 0, 1][..],
            &[2, 2, 0, 0][..],
        ] {
            assert_eq!(integer(&mut &bad[..]), Err(Error::InvalidDer));
        }
        assert_eq!(integer(&mut &[2, 1, 0][..]).unwrap(), &[0]);
        assert_eq!(integer(&mut &[2, 2, 0, 128][..]).unwrap(), &[128]);
    }
    #[test]
    fn exact_sequence_grammar() {
        for bad in [
            &[0x30, 6, 2, 1, 1, 2, 1, 3, 0][..],
            &[0x30, 9, 2, 1, 1, 2, 1, 3, 2, 1, 3][..],
            &[0x31, 6, 2, 1, 1, 2, 1, 3][..],
            &[0x30, 6, 3, 1, 1, 2, 1, 3][..],
        ] {
            assert!(matches!(parse(bad), Err(Error::InvalidDer)));
        }
    }
}
