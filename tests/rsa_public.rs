use hibana_tls::crypto::rsa::{Error, recover};
#[test]
fn independent_python_public_exponentiation() {
    let mut bytes = include_bytes!("vectors/rsa-public-python.bin").as_slice();
    let mut count = 0;
    while !bytes.is_empty() {
        let width = u16::from_be_bytes(bytes[..2].try_into().unwrap()) as usize;
        let exponent = u32::from_be_bytes(bytes[2..6].try_into().unwrap());
        let modulus = &bytes[6..6 + width];
        let signature = &bytes[6 + width..6 + 2 * width];
        let expected = &bytes[6 + 2 * width..6 + 3 * width];
        let mut output = [0; 512];
        recover(modulus, exponent, signature, &mut output[..width]).unwrap();
        assert_eq!(&output[..width], expected);
        bytes = &bytes[6 + 3 * width..];
        count += 1;
    }
    assert_eq!(count, 144);
}
#[test]
fn malformed_inputs_preserve_output() {
    let mut modulus = [255u8; 512];
    let signature = [0; 512];
    let mut output = [0xa5; 512];
    for n in 0..=512 {
        if !matches!(n, 256 | 384 | 512) {
            assert_eq!(
                recover(&modulus[..n], 65537, &signature[..n], &mut output[..n]),
                Err(Error::Width)
            );
        }
    }
    for exponent in [0, 1, 2, 4, u32::MAX - 1] {
        assert_eq!(
            recover(&modulus, exponent, &signature, &mut output),
            Err(Error::Exponent)
        );
    }
    assert_eq!(
        recover(&modulus, 65537, &modulus, &mut output),
        Err(Error::Signature)
    );
    modulus[0] = 0x7f;
    assert_eq!(
        recover(&modulus, 65537, &signature, &mut output),
        Err(Error::Modulus)
    );
    modulus[0] = 255;
    modulus[511] = 254;
    assert_eq!(
        recover(&modulus, 65537, &signature, &mut output),
        Err(Error::Modulus)
    );
    assert_eq!(output, [0xa5; 512]);
}
