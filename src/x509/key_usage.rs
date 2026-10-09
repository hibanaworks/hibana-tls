//! Borrowed DER traversal for the bounded X.509 KeyUsage profile.
//! No allocation, parser FSM, progress flags or certificate trust decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Der,
    Usage,
}
fn take<'a>(input: &mut &'a [u8], tag: u8) -> Result<&'a [u8], Error> {
    if input.first() != Some(&tag) {
        return Err(Error::Der);
    }
    let first = *input.get(1).ok_or(Error::Der)?;
    let mut header = 2;
    let len = if first < 128 {
        usize::from(first)
    } else {
        let count = usize::from(first & 127);
        if count == 0 || count > core::mem::size_of::<usize>() {
            return Err(Error::Der);
        }
        let mut len = 0usize;
        for i in 0..count {
            let byte = *input.get(header + i).ok_or(Error::Der)?;
            if i == 0 && byte == 0 {
                return Err(Error::Der);
            }
            len = len
                .checked_mul(256)
                .and_then(|n| n.checked_add(usize::from(byte)))
                .ok_or(Error::Der)?;
        }
        header += count;
        if len < 128 {
            return Err(Error::Der);
        }
        len
    };
    let end = header.checked_add(len).ok_or(Error::Der)?;
    let result = input.get(header..end).ok_or(Error::Der)?;
    *input = &input[end..];
    Ok(result)
}
fn exact(input: &[u8], tag: u8) -> Result<&[u8], Error> {
    let mut rest = input;
    let value = take(&mut rest, tag)?;
    if !rest.is_empty() {
        return Err(Error::Der);
    }
    Ok(value)
}
fn bit_string(value: &[u8]) -> Result<(&[u8], u8), Error> {
    let (&unused, bytes) = value.split_first().ok_or(Error::Der)?;
    if unused > 7 || (bytes.is_empty() && unused != 0) {
        return Err(Error::Der);
    }
    Ok((bytes, unused))
}
fn usage(value: &[u8]) -> Result<u16, Error> {
    let (bytes, unused) = bit_string(exact(value, 3)?)?;
    let bits = bytes
        .len()
        .checked_mul(8)
        .and_then(|n| n.checked_sub(usize::from(unused)))
        .ok_or(Error::Der)?;
    if bits == 0 || bits > 9 {
        return Err(Error::Usage);
    }
    if unused != 0 && bytes[bytes.len() - 1] & ((1u8 << unused) - 1) != 0 {
        return Err(Error::Usage);
    }
    let mut out = 0u16;
    for bit in 0..bits {
        if bytes[bit / 8] & (0x80 >> (bit % 8)) != 0 {
            out |= 1 << bit;
        }
    }
    if out == 0 {
        return Err(Error::Usage);
    }
    Ok(out)
}
/// Read KeyUsage as bit positions (digitalSignature=0, keyCertSign=5), if present.
/// Bounds and exact consumption are enforced at each admitted DER nesting.
/// Certificate signatures, names, validity and chain trust MUST be checked by
/// the owning verifier; this function supplies no authentication capability.
pub fn read(certificate: &[u8], max_extensions: usize) -> Result<Option<u16>, Error> {
    let mut certificate = exact(certificate, 0x30)?;
    let mut tbs = take(&mut certificate, 0x30)?;
    let _algorithm = take(&mut certificate, 0x30)?;
    let _signature = bit_string(take(&mut certificate, 3)?)?;
    if !certificate.is_empty() {
        return Err(Error::Der);
    }
    if tbs.first() == Some(&0xa0) {
        let _version = take(&mut tbs, 0xa0)?;
    }
    for tag in [2, 0x30, 0x30, 0x30, 0x30, 0x30] {
        let _field = take(&mut tbs, tag)?;
    }
    if tbs.is_empty() {
        return Ok(None);
    }
    let mut extensions = exact(take(&mut tbs, 0xa3)?, 0x30)?;
    if !tbs.is_empty() {
        return Err(Error::Der);
    }
    let mut result = None;
    let mut count = 0usize;
    while !extensions.is_empty() {
        count = count.checked_add(1).ok_or(Error::Der)?;
        if count > max_extensions {
            return Err(Error::Der);
        }
        let mut extension = take(&mut extensions, 0x30)?;
        let oid = take(&mut extension, 6)?;
        if extension.first() == Some(&1) {
            let critical = take(&mut extension, 1)?;
            if critical != [0] && critical != [255] {
                return Err(Error::Der);
            }
        }
        let value = take(&mut extension, 4)?;
        if !extension.is_empty() {
            return Err(Error::Der);
        }
        if oid == [0x55, 0x1d, 0x0f] {
            if result.is_some() {
                return Err(Error::Der);
            }
            result = Some(usage(value)?);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    // Structural fixture only; its dummy signature establishes no trust.
    const CERT: &[u8] = &[
        0x30, 0x2b, 0x30, 0x23, 0xa0, 0x3, 0x2, 0x1, 0x2, 0x2, 0x1, 0x1, 0x30, 0x0, 0x30, 0x0,
        0x30, 0x0, 0x30, 0x0, 0x30, 0x0, 0xa3, 0xf, 0x30, 0xd, 0x30, 0xb, 0x6, 0x3, 0x55, 0x1d,
        0xf, 0x4, 0x4, 0x3, 0x2, 0x7, 0x80, 0x30, 0x0, 0x3, 0x2, 0x0, 0x1,
    ];
    #[test]
    fn extracts_the_actual_usage_and_enforces_capacity() {
        assert_eq!(read(CERT, 1), Ok(Some(1)));
        assert_eq!(read(CERT, 0), Err(Error::Der));
    }
    #[test]
    fn rejects_every_truncated_prefix_and_nonminimal_lengths() {
        for n in 0..CERT.len() {
            assert!(read(&CERT[..n], 64).is_err());
        }
        assert!(read(&[0x30, 0x80, 0, 0], 64).is_err());
        assert!(read(&[0x30, 0x81, 0], 64).is_err());
        assert!(read(&[0x30, 0x82, 0, 128], 64).is_err());
    }
}
