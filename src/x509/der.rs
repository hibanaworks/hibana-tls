//! Project-owned, borrowed DER primitives for public certificate bytes.
//! No trust decision, allocation, retained parser state or external reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidDer;

/// Consume one low-tag-number DER value, retaining its exact signed encoding.
pub fn take<'a>(input: &mut &'a [u8], tag: u8) -> Result<(&'a [u8], &'a [u8]), InvalidDer> {
    let original = *input;
    if tag & 31 == 31 || original.first() != Some(&tag) {
        return Err(InvalidDer);
    }
    let first = *original.get(1).ok_or(InvalidDer)?;
    let (header, length) = if first < 128 {
        (2, usize::from(first))
    } else {
        let count = usize::from(first & 127);
        if count == 0 || count > core::mem::size_of::<usize>() {
            return Err(InvalidDer);
        }
        let octets = original.get(2..2 + count).ok_or(InvalidDer)?;
        if octets[0] == 0 {
            return Err(InvalidDer);
        }
        let mut length = 0usize;
        for &byte in octets {
            length = length
                .checked_mul(256)
                .and_then(|v| v.checked_add(usize::from(byte)))
                .ok_or(InvalidDer)?;
        }
        if length < 128 {
            return Err(InvalidDer);
        }
        (2 + count, length)
    };
    let end = header.checked_add(length).ok_or(InvalidDer)?;
    let encoded = original.get(..end).ok_or(InvalidDer)?;
    *input = &original[end..];
    Ok((encoded, &encoded[header..]))
}

pub fn exact(input: &[u8], tag: u8) -> Result<&[u8], InvalidDer> {
    let mut remaining = input;
    let (_, value) = take(&mut remaining, tag)?;
    if !remaining.is_empty() {
        return Err(InvalidDer);
    }
    Ok(value)
}

/// DER nonnegative INTEGER, including the canonical sign octet when needed.
pub fn unsigned(bytes: &[u8]) -> Result<&[u8], InvalidDer> {
    let (&first, rest) = bytes.split_first().ok_or(InvalidDer)?;
    if first & 128 != 0 || (bytes.len() > 1 && first == 0 && rest[0] & 128 == 0) {
        return Err(InvalidDer);
    }
    Ok(if bytes.len() > 1 && first == 0 {
        rest
    } else {
        bytes
    })
}

pub fn oid(bytes: &[u8]) -> Result<(), InvalidDer> {
    if bytes.is_empty() {
        return Err(InvalidDer);
    }
    // Every base-128 subidentifier must terminate and have no leading zero group.
    let mut rest = bytes;
    while !rest.is_empty() {
        if rest[0] == 128 {
            return Err(InvalidDer);
        }
        let end = rest.iter().position(|b| b & 128 == 0).ok_or(InvalidDer)?;
        rest = &rest[end + 1..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_encoding_and_remainder() {
        let bytes = [4, 2, 7, 8, 5, 0];
        let mut rest = bytes.as_slice();
        assert_eq!(take(&mut rest, 4), Ok((&bytes[..4], &bytes[2..4])));
        assert_eq!(rest, [5, 0]);
        assert!(exact(&bytes, 4).is_err());
    }
    #[test]
    fn malformed_lengths_do_not_consume_input() {
        for bytes in [
            &[4, 128, 0, 0][..],
            &[4, 129, 1, 0],
            &[4, 130, 0, 128],
            &[4, 255],
            &[4, 2, 0],
            &[31, 0],
        ] {
            let mut rest = bytes;
            assert!(take(&mut rest, 4).is_err());
            assert_eq!(rest, bytes);
        }
    }
    #[test]
    fn canonical_positive_integer_and_oid() {
        for value in [&[][..], &[128], &[0, 1], &[0, 0]] {
            assert!(unsigned(value).is_err());
        }
        assert_eq!(unsigned(&[0, 128]), Ok(&[128][..]));
        assert_eq!(unsigned(&[0]), Ok(&[0][..]));
        assert!(oid(&[42, 134, 72, 206, 61, 4, 3, 2]).is_ok());
        for value in [&[][..], &[128, 0], &[42, 129], &[42, 128, 0]] {
            assert!(oid(value).is_err());
        }
    }
}
