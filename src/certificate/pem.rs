//! RFC 7468 decoding into caller-owned storage, without heap allocation.
//! DER, certificate trust and protocol decisions remain with their consumers.
use crate::secret::{Erase, Secret};
type Result<T> = core::result::Result<T, &'static str>;
#[derive(Debug)]
enum PrivateKeyFormat {
    Pkcs8,
    Sec1,
}
#[derive(Debug)]
pub enum PrivateKeyDer<'a> {
    Pkcs8(Secret<&'a mut [u8]>),
    Sec1(Secret<&'a mut [u8]>),
}
/// Validate the entire file and borrow decoded certificates from `output`.
/// Only the returned prefix of `certificates` is populated. A failure must not
/// be treated as a successfully decoded partial certificate chain.
pub fn decode_certificates<'a>(
    bytes: &[u8],
    mut output: &'a mut [u8],
    certificates: &mut [&'a [u8]],
) -> Result<usize> {
    certificates.fill(&[]);
    let mut rest = bytes;
    let mut count = 0;
    loop {
        let next = block(&mut rest, output)
            .map_err(|_| "invalid certificate PEM: malformed block or insufficient output")?;
        let Some((label, len)) = next else {
            break;
        };
        if label == b"CERTIFICATE" {
            if count == certificates.len() {
                output[..len].erase();
                return Err("certificate slots exhausted");
            }
            let (value, remaining) = output.split_at_mut(len);
            certificates[count] = value;
            count += 1;
            output = remaining;
        } else {
            output[..len].erase();
        }
    }
    if count == 0 {
        return Err("certificate PEM contains no certificates");
    }
    Ok(count)
}
/// Select the first supported key and erase its decoded caller-owned storage on
/// drop. Every preceding PEM block is validated; failures erase output storage.
pub fn decode_private_key<'a>(bytes: &[u8], output: &'a mut [u8]) -> Result<PrivateKeyDer<'a>> {
    let result = (|| {
        let mut rest = bytes;
        while let Some((label, len)) = block(&mut rest, output)
            .map_err(|_| "invalid private-key PEM: malformed block or insufficient output")?
        {
            match label {
                b"RSA PRIVATE KEY" => {
                    return Err("unsupported RSA signing key; ECDSA P-256 required");
                }
                b"PRIVATE KEY" => return Ok((PrivateKeyFormat::Pkcs8, len)),
                b"EC PRIVATE KEY" => return Ok((PrivateKeyFormat::Sec1, len)),
                _ => output[..len].erase(),
            }
        }
        Err("key PEM contains no supported private key")
    })();
    match result {
        Ok((kind, len)) => {
            let (key, rest) = output.split_at_mut(len);
            rest.erase();
            let key = Secret::new(key);
            Ok(match kind {
                PrivateKeyFormat::Pkcs8 => PrivateKeyDer::Pkcs8(key),
                PrivateKeyFormat::Sec1 => PrivateKeyDer::Sec1(key),
            })
        }
        Err(error) => {
            output.erase();
            Err(error)
        }
    }
}
fn line<'a>(input: &mut &'a [u8]) -> &'a [u8] {
    let end = input
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(input.len());
    let value = &input[..end];
    *input = &input[(end + 1).min(input.len())..];
    value.strip_suffix(b"\r").unwrap_or(value)
}
fn block<'a>(input: &mut &'a [u8], output: &mut [u8]) -> Result<Option<(&'a [u8], usize)>> {
    while !input.is_empty() {
        let header = line(input);
        if !header.starts_with(b"-----BEGIN ") {
            continue;
        }
        let label = header
            .strip_prefix(b"-----BEGIN ")
            .and_then(|s| s.strip_suffix(b"-----"))
            .ok_or("bad header")?;
        if label.is_empty()
            || !label
                .iter()
                .all(|b| b.is_ascii_uppercase() || *b == b' ' || b.is_ascii_digit())
        {
            return Err("bad label");
        }
        let body = *input;
        while !input.is_empty() {
            let before = *input;
            let next = line(input);
            if next.starts_with(b"-----END ") {
                if next
                    .strip_prefix(b"-----END ")
                    .and_then(|s| s.strip_suffix(b"-----"))
                    != Some(label)
                {
                    return Err("mismatched footer");
                }
                let encoded = &body[..body.len() - before.len()];
                let result = decode(encoded, output);
                if result.is_err() {
                    output.erase();
                }
                return result.map(|len| Some((label, len)));
            }
        }
        return Err("missing footer");
    }
    Ok(None)
}
fn decode(input: &[u8], output: &mut [u8]) -> Result<usize> {
    let count = input.iter().filter(|b| !b.is_ascii_whitespace()).count();
    if count == 0 || !count.is_multiple_of(4) {
        return Err("invalid base64 length");
    }
    let digit = |b| match b {
        b'A'..=b'Z' => Ok(b - b'A'),
        b'a'..=b'z' => Ok(b - b'a' + 26),
        b'0'..=b'9' => Ok(b - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err("invalid base64 digit"),
    };
    let mut chars = input.iter().copied().filter(|b| !b.is_ascii_whitespace());
    let mut used = 0;
    for group in 0..count / 4 {
        let a = digit(chars.next().ok_or("missing digit")?)?;
        let b = digit(chars.next().ok_or("missing digit")?)?;
        let c = chars.next().ok_or("missing digit")?;
        let d = chars.next().ok_or("missing digit")?;
        let last = (group + 1) * 4 == count;
        *output.get_mut(used).ok_or("output exhausted")? = (a << 2) | (b >> 4);
        used += 1;
        if c == b'=' {
            if !last || d != b'=' || b & 15 != 0 {
                return Err("invalid base64 padding");
            }
        } else {
            let c = digit(c)?;
            *output.get_mut(used).ok_or("output exhausted")? = (b << 4) | (c >> 2);
            used += 1;
            if d == b'=' {
                if !last || c & 3 != 0 {
                    return Err("invalid base64 padding");
                }
            } else {
                *output.get_mut(used).ok_or("output exhausted")? = (c << 6) | digit(d)?;
                used += 1;
            }
        }
    }
    Ok(used)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{format, vec::Vec};
    fn decode_certificates(input: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut bytes = [0; 1024];
        let mut slots: [&[u8]; 16] = [&[]; 16];
        let count = super::decode_certificates(input, &mut bytes, &mut slots)?;
        Ok(slots[..count].iter().map(|der| der.to_vec()).collect())
    }

    // Tiny alleged DER values isolate PEM decoding from TLS's DER validation.
    const CERT: &str = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
    const KEY: &str = "-----BEGIN PRIVATE KEY-----\nBAUG\n-----END PRIVATE KEY-----\n";
    const BAD_CERT: &str = "-----BEGIN CERTIFICATE-----\n!invalid!\n-----END CERTIFICATE-----\n";
    const BAD_KEY: &str = "-----BEGIN PRIVATE KEY-----\n!invalid!\n-----END PRIVATE KEY-----\n";

    #[test]
    fn certificates_collect_all_and_skip_other_well_formed_sections() {
        let pem = format!("comment\n{KEY}{CERT}{CERT}");
        let certs = decode_certificates(pem.as_bytes()).unwrap();
        assert_eq!(certs.len(), 2);
        assert!(certs.iter().all(|cert| cert.as_ref() == [1, 2, 3]));
        assert_eq!(
            decode_certificates(CERT.replace('\n', "\r\n").as_bytes())
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            decode_certificates(CERT.trim_end().as_bytes())
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn certificates_reject_malformed_blocks_even_after_a_valid_certificate() {
        for bad in [
            BAD_CERT,
            BAD_KEY,
            "-----BEGIN CERTIFICATE----\nAQID\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nAQID\n",
            "-----BEGIN CERTIFICATE-----\nAQID\n-----END PRIVATE KEY-----\n",
        ] {
            assert!(
                decode_certificates(bad.as_bytes())
                    .unwrap_err()
                    .starts_with("invalid certificate PEM:")
            );
            assert!(decode_certificates(format!("{CERT}{bad}").as_bytes()).is_err());
        }
    }

    #[test]
    fn absence_of_certificate_or_supported_key_fails_closed() {
        for bytes in [b"".as_slice(), b"plain text", KEY.as_bytes()] {
            assert_eq!(
                decode_certificates(bytes).unwrap_err(),
                "certificate PEM contains no certificates"
            );
        }
        for bytes in [
            b"".as_slice(),
            b"plain text",
            CERT.as_bytes(),
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAQID\n-----END ENCRYPTED PRIVATE KEY-----\n",
        ] {
            assert_eq!(
                decode_private_key(bytes, &mut [0; 1024]).unwrap_err(),
                "key PEM contains no supported private key"
            );
        }
    }

    #[test]
    fn first_supported_key_selection_and_formats_are_preserved() {
        for (label, expected) in [("PRIVATE KEY", 8), ("EC PRIVATE KEY", 2)] {
            let pem = format!(
                "{CERT}-----BEGIN {label}-----\nBAUG\n-----END {label}-----\n{KEY}{BAD_KEY}"
            );
            let mut storage = [0; 1024];
            let key = decode_private_key(pem.as_bytes(), &mut storage).unwrap();
            let actual = match key {
                PrivateKeyDer::Pkcs8(key) => {
                    assert_eq!(&**key, [4, 5, 6]);
                    8
                }
                PrivateKeyDer::Sec1(key) => {
                    assert_eq!(&**key, [4, 5, 6]);
                    2
                }
            };
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn unsupported_rsa_signing_material_is_rejected_without_selecting_a_later_key() {
        let bytes =
            format!("-----BEGIN RSA PRIVATE KEY-----\nBAUG\n-----END RSA PRIVATE KEY-----\n{KEY}");
        assert_eq!(
            decode_private_key(bytes.as_bytes(), &mut [0; 1024]).unwrap_err(),
            "unsupported RSA signing key; ECDSA P-256 required"
        );
    }

    #[test]
    fn malformed_data_before_a_key_is_not_silently_skipped() {
        for bad in [
            BAD_KEY,
            BAD_CERT,
            "-----BEGIN PRIVATE KEY----\nBAUG\n-----END PRIVATE KEY-----\n",
        ] {
            assert!(
                decode_private_key(format!("{bad}{KEY}").as_bytes(), &mut [0; 1024])
                    .unwrap_err()
                    .starts_with("invalid private-key PEM:")
            );
        }
        assert!(
            decode_private_key(b"-----BEGIN PRIVATE KEY-----\nBAUG\n", &mut [0; 1024]).is_err()
        );
    }
}

#[cfg(test)]
mod storage_tests {
    use super::*;
    const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n";
    #[test]
    fn private_key_borrows_and_erases_storage() {
        let mut storage = [0xa5; 16];
        let pointer = storage.as_ptr();
        {
            let PrivateKeyDer::Pkcs8(key) = decode_private_key(KEY, &mut storage).unwrap() else {
                panic!()
            };
            assert_eq!(key.as_ptr(), pointer);
            assert_eq!(&**key, &[1, 2, 3]);
        }
        assert_eq!(storage, [0; 16]);
    }
    #[test]
    fn capacity_and_padding_fail_closed_and_erase() {
        for encoded in [b"AQID".as_slice(), b"AR==", b"AQJ=", b"AQ==AQ==", b"AQ?="] {
            let mut output = [0xa5; 2];
            let mut pem = std::vec::Vec::from(b"-----BEGIN PRIVATE KEY-----\n".as_slice());
            pem.extend_from_slice(encoded);
            pem.extend_from_slice(b"\n-----END PRIVATE KEY-----\n");
            assert!(decode_private_key(&pem, &mut output).is_err());
            assert_eq!(output, [0; 2]);
        }
    }
    #[test]
    fn certificate_storage_is_borrowed_and_bounded() {
        let input = b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
        let mut output = [0xa5; 8];
        let ptr = output.as_ptr();
        let mut slots: [&[u8]; 1] = [&[]];
        assert_eq!(decode_certificates(input, &mut output, &mut slots), Ok(1));
        assert_eq!(slots[0].as_ptr(), ptr);
        assert_eq!(slots[0], &[1, 2, 3]);
        assert_eq!(output[3..], [0xa5; 5]);
        assert!(decode_certificates(input, &mut output, &mut []).is_err());
        assert_eq!(output[..3], [0; 3]);
    }
}

#[cfg(test)]
mod allocation_tests {
    use super::*;
    #[test]
    fn credentials_decode_and_erase_without_allocating() {
        let mut certificates = [0; 64];
        let mut slots: [&[u8]; 2] = [&[]; 2];
        let mut secret = [0; 64];
        let guard = actor_test_allocator::NoAlloc::start();
        assert_eq!(
            decode_certificates(
                b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
                &mut certificates,
                &mut slots
            ),
            Ok(1)
        );
        drop(
            decode_private_key(
                b"-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n",
                &mut secret,
            )
            .unwrap(),
        );
        assert_eq!(secret, [0; 64]);
        guard.finish();
    }
}
