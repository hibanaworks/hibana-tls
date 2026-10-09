//! Strict borrowed DER parsing. Canonical lengths, integer signs and full consumption.
use super::{DerSignature, Error, SecretKey, Signature};
const EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1];
const CURVE: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7];
fn value<'a>(input: &mut &'a [u8], tag: u8) -> Result<&'a [u8], Error> {
    if input.first() != Some(&tag) {
        return Err(Error::Der);
    }
    let first = *input.get(1).ok_or(Error::Der)?;
    let mut offset = 2;
    let length = if first < 128 {
        usize::from(first)
    } else {
        let count = usize::from(first & 127);
        if count == 0 || count > core::mem::size_of::<usize>() {
            return Err(Error::Der);
        }
        let mut len = 0usize;
        for i in 0..count {
            let byte = *input.get(offset + i).ok_or(Error::Der)?;
            if i == 0 && byte == 0 {
                return Err(Error::Der);
            }
            len = len
                .checked_mul(256)
                .and_then(|n| n.checked_add(usize::from(byte)))
                .ok_or(Error::Der)?;
        }
        offset += count;
        if len < 128 {
            return Err(Error::Der);
        }
        len
    };
    let end = offset.checked_add(length).ok_or(Error::Der)?;
    let result = input.get(offset..end).ok_or(Error::Der)?;
    *input = &input[end..];
    Ok(result)
}
fn exact(bytes: &[u8], tag: u8) -> Result<&[u8], Error> {
    let mut input = bytes;
    let out = value(&mut input, tag)?;
    if !input.is_empty() {
        return Err(Error::Der);
    }
    Ok(out)
}
fn scalar_integer(input: &mut &[u8]) -> Result<[u8; 32], Error> {
    let mut n = value(input, 2)?;
    if n.is_empty() || n[0] & 128 != 0 {
        return Err(Error::Der);
    }
    if n[0] == 0 {
        if n.len() == 1 || n[1] & 128 == 0 {
            return Err(Error::Der);
        }
        n = &n[1..];
    }
    if n.len() > 32 {
        return Err(Error::Der);
    }
    let mut out = [0; 32];
    out[32 - n.len()..].copy_from_slice(n);
    Ok(out)
}
pub(super) fn signature(bytes: &[u8]) -> Result<Signature, Error> {
    let mut seq = exact(bytes, 0x30)?;
    let r = scalar_integer(&mut seq)?;
    let s = scalar_integer(&mut seq)?;
    if !seq.is_empty() {
        return Err(Error::Der);
    }
    let mut raw = [0; 64];
    raw[..32].copy_from_slice(&r);
    raw[32..].copy_from_slice(&s);
    Signature::from_bytes(&raw)
}
pub(super) fn encode_signature(sig: &Signature) -> DerSignature {
    let mut out = DerSignature {
        bytes: [0; 72],
        len: 2,
    };
    out.bytes[0] = 0x30;
    for part in [&sig.r, &sig.s] {
        let offset = part.iter().position(|b| *b != 0).unwrap_or(31);
        let body = &part[offset..];
        let pad = usize::from(body[0] & 128 != 0);
        out.bytes[out.len] = 2;
        out.bytes[out.len + 1] = (body.len() + pad) as u8;
        out.len += 2 + pad;
        out.bytes[out.len..out.len + body.len()].copy_from_slice(body);
        out.len += body.len();
    }
    out.bytes[1] = (out.len - 2) as u8;
    out
}
pub(super) fn private_key(bytes: &[u8], pkcs8: bool) -> Result<SecretKey, Error> {
    let inner = if pkcs8 {
        let mut outer = exact(bytes, 0x30)?;
        if value(&mut outer, 2)? != [0] {
            return Err(Error::Der);
        }
        let mut algorithm = value(&mut outer, 0x30)?;
        if value(&mut algorithm, 6)? != EC
            || value(&mut algorithm, 6)? != CURVE
            || !algorithm.is_empty()
        {
            return Err(Error::Der);
        }
        let secret = value(&mut outer, 4)?;
        if !outer.is_empty() {
            return Err(Error::Der);
        }
        secret
    } else {
        bytes
    };
    let mut seq = exact(inner, 0x30)?;
    if value(&mut seq, 2)? != [1] {
        return Err(Error::Der);
    }
    let key = SecretKey::from_slice(value(&mut seq, 4)?)?;
    if seq.first() == Some(&0xa0) && exact(value(&mut seq, 0xa0)?, 6)? != CURVE {
        return Err(Error::Der);
    }
    if seq.first() == Some(&0xa1) {
        let bits = exact(value(&mut seq, 0xa1)?, 3)?;
        if bits.first() != Some(&0) {
            return Err(Error::Der);
        }
        let public = super::point::Point::parse(&bits[1..])?.encode()?;
        if public != key.public_key() {
            return Err(Error::InvalidPoint);
        }
    }
    if !seq.is_empty() {
        return Err(Error::Der);
    }
    Ok(key)
}
