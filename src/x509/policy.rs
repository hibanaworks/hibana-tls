//! Bounded X.509 extension semantics; unknown critical extensions fail closed.
use super::{
    der::{self, InvalidDer},
    parsed::{self, Certificate},
};
#[derive(Debug)]
pub struct Extensions<'a> {
    pub ca: bool,
    pub path_length: Option<usize>,
    pub key_usage: Option<u16>,
    pub server_auth: bool,
    pub san: Option<&'a [u8]>,
    pub constraints: Option<&'a [u8]>,
}
pub fn read<'a>(cert: &Certificate<'a>) -> Result<Extensions<'a>, InvalidDer> {
    let mut input = cert.extensions;
    let mut result = Extensions {
        ca: false,
        path_length: None,
        key_usage: None,
        server_auth: true,
        san: None,
        constraints: None,
    };
    while !input.is_empty() {
        let extension = parsed::extension(&mut input)?;
        match extension.oid {
            [0x55, 0x1d, 0x13] => {
                let mut contents = der::exact(extension.value, 0x30)?;
                if contents.first() == Some(&1) {
                    if der::take(&mut contents, 1)?.1 != [255] {
                        return Err(InvalidDer);
                    }
                    result.ca = true;
                }
                if !contents.is_empty() {
                    if !result.ca {
                        return Err(InvalidDer);
                    }
                    let bytes = der::unsigned(der::take(&mut contents, 2)?.1)?;
                    let mut length = 0usize;
                    for &byte in bytes {
                        length = length
                            .checked_mul(256)
                            .and_then(|v| v.checked_add(usize::from(byte)))
                            .ok_or(InvalidDer)?;
                    }
                    result.path_length = Some(length);
                }
                if !contents.is_empty() {
                    return Err(InvalidDer);
                }
            }
            [0x55, 0x1d, 0x0f] => {
                let value = der::exact(extension.value, 3)?;
                let (&unused, bytes) = value.split_first().ok_or(InvalidDer)?;
                if unused > 7 || bytes.is_empty() || bytes.len() > 2 {
                    return Err(InvalidDer);
                }
                let bits = bytes.len() * 8 - usize::from(unused);
                if bits == 0 || bits > 9 || bytes[bytes.len() - 1] & ((1u8 << unused) - 1) != 0 {
                    return Err(InvalidDer);
                }
                let mut usage = 0u16;
                for bit in 0..bits {
                    if bytes[bit / 8] & (128 >> (bit % 8)) != 0 {
                        usage |= 1 << bit;
                    }
                }
                if usage == 0 {
                    return Err(InvalidDer);
                }
                result.key_usage = Some(usage);
            }
            [0x55, 0x1d, 0x25] => {
                let mut contents = der::exact(extension.value, 0x30)?;
                if contents.is_empty() {
                    return Err(InvalidDer);
                }
                result.server_auth = false;
                while !contents.is_empty() {
                    let oid = der::take(&mut contents, 6)?.1;
                    der::oid(oid)?;
                    if oid == [0x2b, 6, 1, 5, 5, 7, 3, 1] {
                        result.server_auth = true;
                    }
                }
            }
            [0x55, 0x1d, 0x11] => {
                if cert.subject.is_empty() && !extension.critical {
                    return Err(InvalidDer);
                }
                result.san = Some(extension.value);
            }
            [0x55, 0x1d, 0x1e] => {
                if !extension.critical {
                    return Err(InvalidDer);
                }
                result.constraints = Some(extension.value);
            }
            _ if extension.critical => return Err(InvalidDer),
            _ => {}
        }
    }
    if cert.subject.is_empty() && result.san.is_none() {
        return Err(InvalidDer);
    }
    Ok(result)
}
