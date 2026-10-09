//! Independent C2SP Wycheproof corpus, compiled to data without JSON/test crates.
//! See vectors/wycheproof/PROVENANCE.json for exact selected and excluded IDs.
use hibana_tls::{
    crypto::{aes128gcm, chacha20poly1305, p256},
    entropy::{Entropy, Unavailable},
    key_exchange::{Error, X25519Secret},
};
struct Data<'a>(&'a [u8]);
impl<'a> Data<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let (v, rest) = self.0.split_at(n);
        self.0 = rest;
        v
    }
    fn number(&mut self) -> usize {
        u32::from_be_bytes(self.take(4).try_into().unwrap()) as usize
    }
    fn bytes(&mut self) -> &'a [u8] {
        let n = self.number();
        self.take(n)
    }
    fn begin(&mut self) -> usize {
        assert_eq!(self.take(8), b"WYCP0001");
        self.number()
    }
}
fn aead(bytes: &[u8], aes: bool) {
    let mut data = Data(bytes);
    let count = data.begin();
    assert!(count > 0);
    for _ in 0..count {
        let id = data.number();
        let valid = data.take(1)[0] == 1;
        let key = data.bytes();
        let nonce = data.bytes().try_into().unwrap();
        let aad = data.bytes();
        let message = data.bytes();
        let ciphertext = data.bytes();
        let tag = data.bytes().try_into().unwrap();
        let mut body = ciphertext.to_vec();
        let accepted = if aes {
            aes128gcm::open(key.try_into().unwrap(), nonce, aad, &mut body, tag).is_ok()
        } else {
            chacha20poly1305::open(key.try_into().unwrap(), nonce, aad, &mut body, tag).is_ok()
        };
        assert_eq!(accepted, valid, "AEAD tcId={id}");
        if valid {
            assert_eq!(body, message, "plaintext tcId={id}");
            let generated = if aes {
                aes128gcm::seal(key.try_into().unwrap(), nonce, aad, &mut body).unwrap()
            } else {
                chacha20poly1305::seal(key.try_into().unwrap(), nonce, aad, &mut body).unwrap()
            };
            assert_eq!(body, ciphertext, "ciphertext tcId={id}");
            assert_eq!(&generated, tag, "tag tcId={id}");
        } else {
            assert_eq!(body, ciphertext, "failure modified ciphertext tcId={id}");
        }
    }
    assert!(data.0.is_empty());
}
#[test]
fn aes128_gcm_profile() {
    aead(include_bytes!("vectors/wycheproof/aes_gcm_test.bin"), true)
}
#[test]
fn chacha20_poly1305_profile() {
    aead(
        include_bytes!("vectors/wycheproof/chacha20_poly1305_test.bin"),
        false,
    )
}
struct PublicTestScalar<'a>(&'a [u8]);
impl Entropy for PublicTestScalar<'_> {
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Unavailable> {
        assert_eq!(out.len(), self.0.len());
        out.copy_from_slice(self.0);
        Ok(())
    }
}
#[test]
fn x25519_owned_agreement() {
    let mut data = Data(include_bytes!("vectors/wycheproof/x25519_test.bin"));
    let count = data.begin();
    assert_eq!(count, 518);
    for _ in 0..count {
        let id = data.number();
        let classification = data.take(1)[0];
        assert!(classification == 1 || classification == 2);
        let private = data.bytes();
        let public = data.bytes();
        let shared = data.bytes();
        let secret = X25519Secret::generate(&mut PublicTestScalar(private)).unwrap();
        let result = secret.complete(public);
        if shared.iter().all(|b| *b == 0) {
            assert_eq!(
                result.unwrap_err(),
                Error::NonContributory,
                "low-order tcId={id}"
            );
        } else {
            assert_eq!(result.unwrap().as_slice(), shared, "agreement tcId={id}");
        }
    }
    assert!(data.0.is_empty());
}
#[test]
fn p256_ecdsa_sha256() {
    let mut data = Data(include_bytes!(
        "vectors/wycheproof/ecdsa_secp256r1_sha256_test.bin"
    ));
    let count = data.begin();
    assert_eq!(count, 484);
    for _ in 0..count {
        let id = data.number();
        let valid = data.take(1)[0] == 1;
        let public = data.bytes();
        let message = data.bytes();
        let signature = data.bytes();
        assert_eq!(
            p256::verify(public, message, signature).is_ok(),
            valid,
            "ECDSA tcId={id}"
        );
    }
    assert!(data.0.is_empty());
}
