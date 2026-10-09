use super::arithmetic::ZERO;
use super::*;
fn hex<const N: usize>(s: &str) -> [u8; N] {
    let mut out = [0; N];
    assert_eq!(s.len(), 2 * N);
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}
#[test]
fn rfc6979_p256_sha256_sample() {
    let key = SecretKey::from_slice(&hex::<32>(
        "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
    ))
    .unwrap();
    assert_eq!(
        &key.public_key()[1..33],
        &hex::<32>("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6")
    );
    assert_eq!(
        &key.public_key()[33..],
        &hex::<32>("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")
    );
    let sig = key.sign(b"sample").unwrap();
    assert_eq!(
        sig.r,
        hex::<32>("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716")
    );
    assert_eq!(
        sig.s,
        hex::<32>("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8")
    );
    verify(&key.public_key(), b"sample", sig.to_der().as_bytes()).unwrap();
    assert!(verify(&key.public_key(), b"samples", sig.to_der().as_bytes()).is_err());
}
#[test]
fn field_and_group_boundaries() {
    use arithmetic::{ONE, P};
    for m in [&P, &N] {
        for i in 1..128 {
            let n = Int([i, 0, 0, 0]);
            let a = m.encode(n);
            assert_eq!(m.decode(a), n);
            assert_eq!(m.mul(a, m.inverse(a)), m.one());
            assert_eq!(m.add(m.sub(ZERO, a), a), ZERO);
        }
        assert_eq!(
            m.decode(m.mul(
                m.encode(m.value.sub_raw(ONE).0),
                m.encode(m.value.sub_raw(ONE).0)
            )),
            ONE
        );
    }
    let g = Point::generator();
    assert!(g.mul(N.value).affine().is_err());
    assert_eq!(g.add(g).encode().unwrap(), g.double().encode().unwrap());
    assert_eq!(
        g.add(Point::infinity()).encode().unwrap(),
        g.encode().unwrap()
    );
    assert_eq!(
        Point::infinity().add(g).encode().unwrap(),
        g.encode().unwrap()
    );
}
#[test]
fn reject_invalid_scalars_points_and_der() {
    assert!(SecretKey::from_slice(&[0; 32]).is_err());
    assert!(SecretKey::from_slice(&N.value.to_be()).is_err());
    assert!(SecretKey::from_slice(&[255; 32]).is_err());
    let key = SecretKey::from_slice(&[1; 32]).unwrap();
    let point = key.public_key();
    let mut bad = point;
    bad[5] ^= 1;
    assert!(Point::parse(&bad).is_err());
    assert!(Point::parse(&[0]).is_err());
    let mut compressed = [0; 33];
    compressed[0] = 2 | (point[64] & 1);
    compressed[1..].copy_from_slice(&point[1..33]);
    assert_eq!(Point::parse(&compressed).unwrap().encode().unwrap(), point);
    let sig = key.sign(b"test").unwrap().to_der();
    for len in 0..sig.as_bytes().len() {
        assert!(Signature::from_der(&sig.as_bytes()[..len]).is_err());
    }
    let mut trailing = [0; 73];
    trailing[..sig.len].copy_from_slice(sig.as_bytes());
    assert!(Signature::from_der(&trailing[..sig.len + 1]).is_err());
    assert!(Signature::from_bytes(&[0; 64]).is_err());
}
#[test]
fn independent_python_modular_corpus() {
    let bytes = include_bytes!("../../../tests/vectors/p256-modular.bin");
    let half = bytes.len() / 2;
    for (m, records) in [(&arithmetic::P, &bytes[..half]), (&N, &bytes[half..])] {
        for row in records.chunks_exact(192) {
            let a = Int::from_be(row[..32].try_into().unwrap());
            let b = Int::from_be(row[32..64].try_into().unwrap());
            let x = m.encode(a);
            let y = m.encode(b);
            for (index, result) in [m.add(x, y), m.sub(x, y), m.mul(x, y), m.inverse(x)]
                .into_iter()
                .enumerate()
            {
                assert_eq!(
                    m.decode(result).to_be(),
                    row[64 + index * 32..96 + index * 32]
                );
            }
        }
    }
}
#[test]
fn independent_openssl_ecdh_ecdsa_corpus() {
    let bytes = include_bytes!("../../../tests/vectors/p256-openssl.bin");
    assert_eq!(bytes.len(), 128 * 354);
    for row in bytes.chunks_exact(354) {
        let key = SecretKey::from_slice(&row[..32]).unwrap();
        assert_eq!(key.public_key(), row[32..97]);
        let peer = &row[97..162];
        assert_eq!(
            SecretKey::from_slice(&row[..32])
                .unwrap()
                .agree(peer)
                .unwrap(),
            row[162..194]
        );
        let hash = row[194..226].try_into().unwrap();
        let sig = key.sign_prehash(hash).unwrap();
        assert_eq!(sig.to_bytes(), row[226..290]);
        for bytes in [&row[226..290], &row[290..354]] {
            let sig = Signature::from_bytes(bytes.try_into().unwrap()).unwrap();
            verify_prehash(&row[32..97], hash, &sig).unwrap();
            let mut wrong = *hash;
            wrong[0] ^= 1;
            assert!(verify_prehash(&row[32..97], &wrong, &sig).is_err());
            let der = sig.to_der();
            assert_eq!(
                Signature::from_der(der.as_bytes()).unwrap().to_bytes(),
                sig.to_bytes()
            );
        }
        let mut compressed = [0; 33];
        compressed[0] = 2 | (row[96] & 1);
        compressed[1..].copy_from_slice(&row[33..65]);
        assert_eq!(
            Point::parse(&compressed).unwrap().encode().unwrap(),
            row[32..97]
        );
    }
}
#[test]
fn independent_openssl_private_key_der() {
    let mut bytes = include_bytes!("../../../tests/vectors/p256-key-der.bin").as_slice();
    for i in 0..16 {
        let len = u16::from_be_bytes(bytes[..2].try_into().unwrap()) as usize;
        let key = if i % 2 == 0 {
            SecretKey::from_pkcs8_der(&bytes[2..2 + len])
        } else {
            SecretKey::from_sec1_der(&bytes[2..2 + len])
        }
        .unwrap();
        assert_eq!(key.public_key(), bytes[2 + len..2 + len + 65]);
        for short in 0..len {
            let result = if i % 2 == 0 {
                SecretKey::from_pkcs8_der(&bytes[2..2 + short])
            } else {
                SecretKey::from_sec1_der(&bytes[2..2 + short])
            };
            assert!(result.is_err());
        }
        bytes = &bytes[2 + len + 65..];
    }
    assert!(bytes.is_empty());
}
