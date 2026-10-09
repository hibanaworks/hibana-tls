//! Borrowed, no-allocation SHA-256 certificate authentication building block.
//!
//! Project-owned bounded parsing and verification cover chain, time, DNS/IP names,
//! DNS/IP constraints, EKU and key usage; unsupported critical forms reject.
//! Project-owned P-256 and bounded RSA primitives verify signatures.
//! The project-owned bounded extension reader additionally enforces
//! X.509 KeyUsage (digitalSignature for the leaf, keyCertSign for actual CAs).
//! RSA verification permits exact 2048/3072/4096-bit rsaEncryption keys. PSS
//! uses SHA-256/MGF1-SHA256/salt32; PKCS1-v1_5 is certificate-only. This does not
//! implement RSA signing, PSS-restricted SPKI keys, or a full TLS backend.
//! The RSA adapter has significant target stack cost; see tls-rsa-feasibility.md.
//! No certificate failure has a permissive fallback. No heap, clock, entropy,
//! network trust-root lookup, or ring dependency is used by this module.

use crate::x509::key_usage::{self, read as read_key_usage};
use crate::x509::{verify, parsed, signature};
pub use crate::x509::types::{CertificateDer, Der, ServerName, TrustAnchor, UnixTime};

pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
/// Certificate-signature scheme only; forbidden for TLS1.3 CertificateVerify.
pub const RSA_PKCS1_SHA256_SCHEME: u16 = 0x0401;
pub const MAX_INTERMEDIATES: usize = 8;
pub const MAX_TRUST_ANCHORS: usize = 32;
pub const MAX_CERTIFICATE_BYTES: usize = 65_535;
const MAX_EXTENSIONS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidLimits,
    NoTrustAnchors,
    TooManyTrustAnchors,
    TooManyIntermediates,
    CertificateTooLarge,
    ChainTooLarge,
    InvalidDer,
    InvalidKeyUsage,
    MissingDigitalSignature,
    MissingKeyCertSign,
    UnsupportedSignatureScheme(u16),
    Certificate(verify::Error),
    CertificateVerify,
}

/// Fixed hard caps supplement the project-owned bounded path search.
/// Byte/count limits are policy limits, not a measurement of peak target stack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_certificate_bytes: usize,
    pub max_chain_bytes: usize,
    pub max_intermediates: usize,
    pub max_trust_anchors: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_certificate_bytes: 8192,
            max_chain_bytes: 32768,
            max_intermediates: MAX_INTERMEDIATES,
            max_trust_anchors: 16,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), Error> {
        if self.max_certificate_bytes == 0
            || self.max_certificate_bytes > MAX_CERTIFICATE_BYTES
            || self.max_chain_bytes < self.max_certificate_bytes
            || self.max_intermediates > MAX_INTERMEDIATES
            || self.max_trust_anchors == 0
            || self.max_trust_anchors > MAX_TRUST_ANCHORS
        {
            return Err(Error::InvalidLimits);
        }
        Ok(())
    }
}

/// Convert an already-trusted caller-provisioned root to a borrowed trust anchor.
/// This does not establish trust or download/install a root. Self-signature and
/// root validity dates are not a substitute for the caller's trust decision.
pub fn trust_anchor_from_der<'a>(
    certificate: &CertificateDer<'a>,
) -> Result<TrustAnchor<'a>, Error> {
    if certificate.as_ref().len() > MAX_CERTIFICATE_BYTES {
        return Err(Error::CertificateTooLarge);
    }
    check_key_usage(certificate.as_ref(), RequiredUsage::Ca)?;
    verify::anchor(certificate.bytes()).map_err(Error::Certificate)
}

/// Trust roots/time are supplied by the caller. The caller must provide a trusted
/// time source; omitting time verification or substituting a made-up time is not
/// a supported certificate-verification mode.
pub struct ServerVerifier<'a> {
    anchors: &'a [TrustAnchor<'a>],
    time: UnixTime,
    limits: Limits,
}
impl<'a> ServerVerifier<'a> {
    pub fn new(
        anchors: &'a [TrustAnchor<'a>],
        time: UnixTime,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if anchors.is_empty() {
            return Err(Error::NoTrustAnchors);
        }
        if anchors.len() > limits.max_trust_anchors {
            return Err(Error::TooManyTrustAnchors);
        }
        Ok(Self {
            anchors,
            time,
            limits,
        })
    }

    /// Validate the server certificate chain, requested hostname/IP, validity,
    /// basic/name constraints, EKU and KeyUsage. Returned certificate remains
    /// borrowed from the caller. TLS CertificateVerify and Finished are separate,
    /// mandatory subsequent checks before application data may be authorized.
    pub fn verify_server<'c>(
        &self,
        leaf: &'c CertificateDer<'c>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
    ) -> Result<ValidatedServerCertificate<'c>, Error> {
        if intermediates.len() > self.limits.max_intermediates {
            return Err(Error::TooManyIntermediates);
        }
        let mut total = 0usize;
        for cert in core::iter::once(leaf).chain(intermediates.iter()) {
            if cert.as_ref().len() > self.limits.max_certificate_bytes {
                return Err(Error::CertificateTooLarge);
            }
            total = total
                .checked_add(cert.as_ref().len())
                .ok_or(Error::ChainTooLarge)?;
            if total > self.limits.max_chain_bytes {
                return Err(Error::ChainTooLarge);
            }
        }
        check_key_usage(leaf.as_ref(), RequiredUsage::Leaf)?;
        let mut chain = [&[][..]; MAX_INTERMEDIATES];
        for (slot, intermediate) in chain.iter_mut().zip(intermediates) {
            *slot = intermediate.as_ref();
            check_key_usage(intermediate.as_ref(), RequiredUsage::Ca)?;
        }
        let cert = verify::server_anchored(leaf.bytes(), &chain[..intermediates.len()], self.anchors, (*name).into(), self.time.as_secs()).map_err(Error::Certificate)?;
        Ok(ValidatedServerCertificate { cert })
    }
}

/// Chain/name/usage-validated certificate, NOT an authenticated TLS connection.
/// This type intentionally cannot be cloned and exposes no unverified leaf key.
pub struct ValidatedServerCertificate<'a> {
    cert: verify::VerifiedServer<'a>,
}
impl ValidatedServerCertificate<'_> {
    /// RFC8446 section4.4.3 server CertificateVerify with the transcript hash
    /// BEFORE CertificateVerify. Permits ECDSA-P256 (0x0403) and RSA-PSS-rsae
    /// (0x0804), both SHA256. PKCS1 (0x0401) and PSS-restricted keys (0x0809)
    /// reject. The signature bytes are exactly those carried in the TLS message.
    pub fn verify_certificate_verify(
        &self,
        scheme: u16,
        transcript_hash: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), Error> {
        if !matches!(scheme, ECDSA_SECP256R1_SHA256 | RSA_PSS_RSAE_SHA256) { return Err(Error::UnsupportedSignatureScheme(scheme)); }
        self.cert.certificate_verify(scheme,transcript_hash,signature).map_err(|_|Error::CertificateVerify)
    }
}

#[derive(Clone, Copy)]
enum RequiredUsage {
    Leaf,
    Ca,
}

fn check_key_usage(certificate: &[u8], required: RequiredUsage) -> Result<(), Error> {
    let usage = read_key_usage(certificate, MAX_EXTENSIONS).map_err(|error| match error {
        key_usage::Error::Der => Error::InvalidDer,
        key_usage::Error::Usage => Error::InvalidKeyUsage,
    })?;
    let Some(usage) = usage else {
        // RFC8446 requires digitalSignature when KeyUsage is present.
        return Ok(());
    };
    let bit = match required { RequiredUsage::Leaf => 0, RequiredUsage::Ca => 5 };
    if usage & (1 << bit) == 0 {
        return Err(match required {
            RequiredUsage::Leaf => Error::MissingDigitalSignature,
            RequiredUsage::Ca => Error::MissingKeyCertSign,
        });
    }
    Ok(())
}


/// Owned RFC 7468 credential decoding; no filesystem access.
#[cfg(feature = "alloc")]
pub mod pem;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owned_chain_checks_real_signatures_and_tls_certificate_verify() {
        use crate::x509::{name::Identity, verify};
        let root=root(); let intermediate=intermediate(); let leaf=leaf();
        let receipt=verify::server(&leaf,&[&intermediate],&[&root],Identity::Dns("localhost"),1800000000).unwrap();
        receipt.certificate_verify(0x0403,&[0x42;32],&certificate_verify()).unwrap();
        assert!(receipt.certificate_verify(0x0403,&[0x43;32],&certificate_verify()).is_err());
        assert!(receipt.certificate_verify(0x0401,&[0x42;32],&certificate_verify()).is_err());
        assert!(verify::server(&leaf,&[&intermediate],&[&root],Identity::Dns("elsewhere"),1800000000).is_err());
        assert!(verify::server(&leaf,&[],&[&root],Identity::Dns("localhost"),1800000000).is_err());
        assert!(verify::server(&leaf,&[&intermediate],&[&wrong_root()],Identity::Dns("localhost"),1800000000).is_err());
        for time in [1700000000,2100000000] { assert!(verify::server(&leaf,&[&intermediate],&[&root],Identity::Dns("localhost"),time).is_err()); }
        assert!(verify::server(&bad_key_usage(),&[&intermediate],&[&root],Identity::Dns("localhost"),1800000000).is_err());
        assert!(verify::server(&bad_eku(),&[&intermediate],&[&root],Identity::Dns("localhost"),1800000000).is_err());
        assert!(verify::server(&leaf,&[&bad_ca_usage()],&[&root],Identity::Dns("localhost"),1800000000).is_err());
        let mut corrupt=leaf; let last=corrupt.len()-1; corrupt[last]^=1;
        assert!(verify::server(&corrupt,&[&intermediate],&[&root],Identity::Dns("localhost"),1800000000).is_err());
    }

    #[test]
    fn owned_parser_preserves_signed_bytes_and_rejects_all_truncations() {
        for fixture in [&root()[..], &intermediate()[..], &leaf()[..]] {
            let parsed = crate::x509::parsed::parse(fixture).expect("real P256 certificate syntax");
            assert_eq!(parsed.not_before, 1735689600);
            assert_eq!(parsed.not_after, 2051222400);
            assert_eq!(parsed.public_key.len(), 65);
            assert_eq!(parsed.signed[0], 0x30);
            for end in 0..fixture.len() {
                assert!(crate::x509::parsed::parse(&fixture[..end]).is_err(), "prefix {end}");
            }
            let mut trailing = std::vec::Vec::from(fixture);
            trailing.push(0);
            assert!(crate::x509::parsed::parse(&trailing).is_err());
        }
    }

    use core::time::Duration;

    fn hex<const N: usize>(text: &str) -> [u8; N] {
        let mut out = [0; N];
        let mut n = 0;
        for ch in text.bytes().filter(|ch| !ch.is_ascii_whitespace()) {
            let x = match ch {
                b'0'..=b'9' => ch - b'0',
                b'a'..=b'f' => ch - b'a' + 10,
                _ => panic!("bad hex"),
            };
            assert!(n / 2 < N);
            out[n / 2] = (out[n / 2] << 4) | x;
            n += 1;
        }
        assert_eq!(n, N * 2);
        out
    }

    // Real ephemeral P-256 CA/intermediate/leaf generated with rcgen 0.13.2
    // and ring 0.17.14. CertificateVerify was signed by ring over the standard
    // server context and transcript hash [0x42;32]. No private key is retained.
    // Fixtures' validity is 2025-01-01 through 2035-01-01; tests inject time.
    fn root() -> [u8; 392] {
        hex(
            "3082018430820129a0030201020214634e303a6f1f18a40bd9673aec18016eb2
            7e16dc300a06082a8648ce3d04030230143112301006035504030c0974657374
            20726f6f74301e170d3235303130313030303030305a170d3335303130313030
            303030305a30143112301006035504030c097465737420726f6f743059301306
            072a8648ce3d020106082a8648ce3d030107034200045d0a7848239e3b29fde0
            60cfc744c76d88a9e8a241e3e5329251c513c618c50be5d257b37cfd40d22bc8
            959636c9eb1c0cbface8a49f538f71d23e43bbb85c94a359305730140603551d
            11040d300b82097465737420726f6f74300f0603551d0f0101ff040503030706
            00301d0603551d0e041604148eb92b8aa47af202e8e6f9d68d14798f8672d14f
            300f0603551d130101ff040530030101ff300a06082a8648ce3d040302034900
            3046022100f53b961b495597acc028a8c6c00fc1bbb8405e8da3d43265eb06e5
            9d38c9e8ed022100e295ac20bea89ff508eb074afc1b9c211f78ffb1daf8bb7c
            7b4a62ce2765b65c",
        )
    }
    fn wrong_root() -> [u8; 395] {
        hex(
            "308201873082012ca00302010202141c975ffd0948062bec56984411230fef4c
            80ea5d300a06082a8648ce3d04030230153113301106035504030c0a77726f6e
            6720726f6f74301e170d3235303130313030303030305a170d33353031303130
            30303030305a30153113301106035504030c0a77726f6e6720726f6f74305930
            1306072a8648ce3d020106082a8648ce3d0301070342000490f6e43e33df559f
            238cd2e3e33ad2cd845e986e8dda74f8f7bf444930b9cb7eb69bc18386c1dd38
            c2b0cd432701ad8a7abe3fd268c0b56807ccb26184362920a35a305830150603
            551d11040e300c820a77726f6e6720726f6f74300f0603551d0f0101ff040503
            03070600301d0603551d0e0416041423cd5a653d762fa689fc59c7e3b4fbd544
            6e4927300f0603551d130101ff040530030101ff300a06082a8648ce3d040302
            0349003046022100dfe35572169f7b9b9f08bfaad65dec300d506bf599b8c1a8
            cde06056977a002a022100f29a90952c109234aecacaac239f41bc5beec1b556
            10ffa995d771828021032e",
        )
    }
    fn intermediate() -> [u8; 410] {
        hex(
            "308201963082013ca0030201020214645fc7c2dce0329f5d39bbad8407a1132b
            60208c300a06082a8648ce3d04030230143112301006035504030c0974657374
            20726f6f74301e170d3235303130313030303030305a170d3335303130313030
            303030305a301c311a301806035504030c117465737420696e7465726d656469
            6174653059301306072a8648ce3d020106082a8648ce3d03010703420004c715
            e83c99564d432de616bd7d2caed1554cfc4e4175c5e28f358346dd0cb0624bed
            c54348310cf9445bb0539f33b918eb5ea7ac97ecba5013f4dd2a3ae1417ea364
            3062301c0603551d110415301382117465737420696e7465726d656469617465
            300f0603551d0f0101ff04050303070600301d0603551d0e041604142169d229
            fb9689229f540a8a75697293a6bf588230120603551d130101ff040830060101
            ff020100300a06082a8648ce3d0403020348003045022100c60faddf6bedd880
            20ddefeefdf58a5b7ebab06866f5b4a10ea68080d1f0cb5002206c2996aaa6d3
            40e1fb91a0b337f9b92ac8cd8a56aa0beda668e296631f259af2",
        )
    }
    fn bad_ca_usage() -> [u8; 410] {
        hex(
            "308201963082013ca0030201020214645fc7c2dce0329f5d39bbad8407a1132b
            60208c300a06082a8648ce3d04030230143112301006035504030c0974657374
            20726f6f74301e170d3235303130313030303030305a170d3335303130313030
            303030305a301c311a301806035504030c117465737420696e7465726d656469
            6174653059301306072a8648ce3d020106082a8648ce3d03010703420004c715
            e83c99564d432de616bd7d2caed1554cfc4e4175c5e28f358346dd0cb0624bed
            c54348310cf9445bb0539f33b918eb5ea7ac97ecba5013f4dd2a3ae1417ea364
            3062301c0603551d110415301382117465737420696e7465726d656469617465
            300f0603551d0f0101ff04050303078000301d0603551d0e041604142169d229
            fb9689229f540a8a75697293a6bf588230120603551d130101ff040830060101
            ff020100300a06082a8648ce3d0403020348003045022100abd76f2c9ed8a2d0
            99bad13a12d9f67d8179b184bb3fad457389676d7edfb5120220172831c19c37
            fdfa01313b0caf79257da8e7b6a1cdec61c2b3ef157935a1eaf7",
        )
    }
    fn leaf() -> [u8; 372] {
        hex(
            "3082017030820116a0030201020214503708698b167fb4dabe5fc37713f9292a
            fa2342300a06082a8648ce3d040302301c311a301806035504030c1174657374
            20696e7465726d656469617465301e170d3235303130313030303030305a170d
            3335303130313030303030305a30143112301006035504030c096c6f63616c68
            6f73743059301306072a8648ce3d020106082a8648ce3d03010703420004bd6e
            187a4448091d5e5d15b2b1766efa92dc7857ad34cf9f806caabe153f05bc121c
            b9ca9e3d77f8f7837e08389bd24223c010a877a6254755debd5edf8cb151a33e
            303c30140603551d11040d300b82096c6f63616c686f7374300f0603551d0f01
            01ff0405030307800030130603551d25040c300a06082b06010505070301300a
            06082a8648ce3d0403020348003045022100cd3e0b6e5162265c8a3035ab648e
            ad936369e7d7533dc4c47873e70b3fccc846022061c3460f474bf555abe08828
            5736c82c441a39790a8ef3f51d88ce93ce125701",
        )
    }
    fn bad_key_usage() -> [u8; 372] {
        hex(
            "3082017030820116a0030201020214503708698b167fb4dabe5fc37713f9292a
            fa2342300a06082a8648ce3d040302301c311a301806035504030c1174657374
            20696e7465726d656469617465301e170d3235303130313030303030305a170d
            3335303130313030303030305a30143112301006035504030c096c6f63616c68
            6f73743059301306072a8648ce3d020106082a8648ce3d03010703420004bd6e
            187a4448091d5e5d15b2b1766efa92dc7857ad34cf9f806caabe153f05bc121c
            b9ca9e3d77f8f7837e08389bd24223c010a877a6254755debd5edf8cb151a33e
            303c30140603551d11040d300b82096c6f63616c686f7374300f0603551d0f01
            01ff0405030307200030130603551d25040c300a06082b06010505070301300a
            06082a8648ce3d04030203480030450220590b98ffd2338e4bec26decb61ea7d
            c1ba61b6105e18bc9a2055d843bd8452d60221008971afa5c8061f27206fade7
            9c2fb347b9b43e4d57744ff9eb0d8d86fac5ae8e",
        )
    }
    fn bad_eku() -> [u8; 371] {
        hex(
            "3082016f30820116a0030201020214503708698b167fb4dabe5fc37713f9292a
            fa2342300a06082a8648ce3d040302301c311a301806035504030c1174657374
            20696e7465726d656469617465301e170d3235303130313030303030305a170d
            3335303130313030303030305a30143112301006035504030c096c6f63616c68
            6f73743059301306072a8648ce3d020106082a8648ce3d03010703420004bd6e
            187a4448091d5e5d15b2b1766efa92dc7857ad34cf9f806caabe153f05bc121c
            b9ca9e3d77f8f7837e08389bd24223c010a877a6254755debd5edf8cb151a33e
            303c30140603551d11040d300b82096c6f63616c686f7374300f0603551d0f01
            01ff0405030307800030130603551d25040c300a06082b06010505070302300a
            06082a8648ce3d040302034700304402203d417153f2dfa05132363df10f4bd8
            bca91d6a1579feef82c633b2b019f6012602204bf3ed8f60a3c5a335cd5e1e7d
            4d739e3c98157352bbb2cd442478eeb2a8e06f",
        )
    }
    fn no_key_usage() -> [u8; 354] {
        hex(
            "3082015e30820105a0030201020214503708698b167fb4dabe5fc37713f9292a
            fa2342300a06082a8648ce3d040302301c311a301806035504030c1174657374
            20696e7465726d656469617465301e170d3235303130313030303030305a170d
            3335303130313030303030305a30143112301006035504030c096c6f63616c68
            6f73743059301306072a8648ce3d020106082a8648ce3d03010703420004bd6e
            187a4448091d5e5d15b2b1766efa92dc7857ad34cf9f806caabe153f05bc121c
            b9ca9e3d77f8f7837e08389bd24223c010a877a6254755debd5edf8cb151a32d
            302b30140603551d11040d300b82096c6f63616c686f737430130603551d2504
            0c300a06082b06010505070301300a06082a8648ce3d04030203470030440220
            7649970d8146164c6bf792532aa3166f91957e5e111552bdabdcccd8ff5074fe
            022031efdb1736124eb2c9147822febc0ddf0f285da36b2595ed969c606ee854
            bef2",
        )
    }
    fn certificate_verify() -> [u8; 71] {
        hex(
            "3045022049e13b465faaa5456711957c334064c0e52e386e852547599a3d9417
            23c822c80221008906687d637e341498c8b92d416fe9a525561bbf281abd6c90
            7b14635061b0a6",
        )
    }

    const VALID_TIME: u64 = 1_800_000_000;
    fn validate(
        leaf: &[u8],
        intermediate: &[u8],
        root: &[u8],
        name: &str,
        now: u64,
        signature: Option<&[u8]>,
    ) -> Result<(), Error> {
        let root = CertificateDer::from(root);
        let anchors = [trust_anchor_from_der(&root)?];
        let verifier = ServerVerifier::new(
            &anchors,
            UnixTime::since_unix_epoch(Duration::from_secs(now)),
            Limits::default(),
        )?;
        let leaf = CertificateDer::from(leaf);
        let intermediate_array = [CertificateDer::from(intermediate)];
        let chain = if intermediate.is_empty() {
            &[][..]
        } else {
            &intermediate_array[..]
        };
        let verified =
            verifier.verify_server(&leaf, chain, &ServerName::try_from(name).unwrap())?;
        if let Some(signature) = signature {
            verified.verify_certificate_verify(ECDSA_SECP256R1_SHA256, &[0x42; 32], signature)?;
        }
        Ok(())
    }

    #[test]
    fn actual_ca_intermediate_hostname_and_tls_certificate_verify_succeed() {
        assert_eq!(
            validate(
                &leaf(),
                &intermediate(),
                &root(),
                "localhost",
                VALID_TIME,
                Some(&certificate_verify())
            ),
            Ok(())
        );
        assert_eq!(
            validate(
                &no_key_usage(),
                &intermediate(),
                &root(),
                "localhost",
                VALID_TIME,
                Some(&certificate_verify())
            ),
            Ok(())
        );
    }

    #[test]
    fn wrong_trust_root_hostname_missing_intermediate_and_corrupted_certificate_fail() {
        assert!(matches!(
            validate(
                &leaf(),
                &intermediate(),
                &wrong_root(),
                "localhost",
                VALID_TIME,
                None
            ),
            Err(Error::Certificate(verify::Error::Untrusted))
        ));
        assert!(matches!(
            validate(
                &leaf(),
                &intermediate(),
                &root(),
                "wrong.example",
                VALID_TIME,
                None
            ),
            Err(Error::Certificate(verify::Error::Name))
        ));
        assert!(matches!(
            validate(&leaf(), &[], &root(), "localhost", VALID_TIME, None),
            Err(Error::Certificate(verify::Error::Untrusted))
        ));
        let mut tampered = leaf();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(matches!(
            validate(
                &tampered,
                &intermediate(),
                &root(),
                "localhost",
                VALID_TIME,
                None
            ),
            Err(Error::Certificate(_))
        ));
    }

    #[test]
    fn actual_chain_validity_and_both_key_usages_are_enforced() {
        assert!(matches!(
            validate(
                &leaf(),
                &intermediate(),
                &root(),
                "localhost",
                1_500_000_000,
                None
            ),
            Err(Error::Certificate(verify::Error::Time))
        ));
        assert!(matches!(
            validate(
                &leaf(),
                &intermediate(),
                &root(),
                "localhost",
                2_200_000_000,
                None
            ),
            Err(Error::Certificate(verify::Error::Time))
        ));
        assert_eq!(
            validate(
                &bad_key_usage(),
                &intermediate(),
                &root(),
                "localhost",
                VALID_TIME,
                None
            ),
            Err(Error::MissingDigitalSignature)
        );
        assert_eq!(
            validate(
                &leaf(),
                &bad_ca_usage(),
                &root(),
                "localhost",
                VALID_TIME,
                None
            ),
            Err(Error::MissingKeyCertSign)
        );
        assert!(matches!(
            validate(
                &bad_eku(),
                &intermediate(),
                &root(),
                "localhost",
                VALID_TIME,
                None
            ),
            Err(Error::Certificate(
                verify::Error::Usage
            ))
        ));
        assert_eq!(
            trust_anchor_from_der(&CertificateDer::from(bad_ca_usage().as_slice())).err(),
            Some(Error::MissingKeyCertSign)
        );
    }

    #[test]
    fn certificate_verify_rejects_signature_context_hash_and_unsupported_scheme() {
        let root_bytes = root();
        let root = CertificateDer::from(root_bytes.as_slice());
        let anchors = [trust_anchor_from_der(&root).unwrap()];
        let verifier = ServerVerifier::new(
            &anchors,
            UnixTime::since_unix_epoch(Duration::from_secs(VALID_TIME)),
            Limits::default(),
        )
        .unwrap();
        let leaf_bytes = leaf();
        let leaf = CertificateDer::from(leaf_bytes.as_slice());
        let intermediate_bytes = intermediate();
        let chain = [CertificateDer::from(intermediate_bytes.as_slice())];
        let cert = verifier
            .verify_server(&leaf, &chain, &ServerName::try_from("localhost").unwrap())
            .unwrap();
        let signature = certificate_verify();
        cert.verify_certificate_verify(0x0403, &[0x42; 32], &signature)
            .unwrap();
        assert_eq!(
            cert.verify_certificate_verify(0x0403, &[0x43; 32], &signature),
            Err(Error::CertificateVerify)
        );
        assert_eq!(
            cert.verify_certificate_verify(0x0804, &[0x42; 32], &signature),
            Err(Error::CertificateVerify)
        );
        for scheme in [RSA_PKCS1_SHA256_SCHEME, 0x0809] {
            assert_eq!(
                cert.verify_certificate_verify(scheme, &[0x42; 32], &signature),
                Err(Error::UnsupportedSignatureScheme(scheme))
            );
        }
        for i in 0..signature.len() {
            let mut bad = signature;
            bad[i] ^= 1;
            assert_eq!(
                cert.verify_certificate_verify(0x0403, &[0x42; 32], &bad),
                Err(Error::CertificateVerify)
            );
        }
        for len in 0..signature.len() {
            assert_eq!(
                cert.verify_certificate_verify(0x0403, &[0x42; 32], &signature[..len]),
                Err(Error::CertificateVerify)
            );
        }
    }

    #[test]
    fn malformed_der_limits_and_missing_roots_fail_without_authentication() {
        let root_bytes = root();
        let root = CertificateDer::from(root_bytes.as_slice());
        let anchors = [trust_anchor_from_der(&root).unwrap()];
        let now = UnixTime::since_unix_epoch(Duration::from_secs(VALID_TIME));
        assert!(matches!(
            ServerVerifier::new(&[], now, Limits::default()),
            Err(Error::NoTrustAnchors)
        ));
        let limits = Limits {
            max_intermediates: MAX_INTERMEDIATES + 1,
            ..Limits::default()
        };
        assert!(matches!(
            ServerVerifier::new(&anchors, now, limits),
            Err(Error::InvalidLimits)
        ));
        let limits = Limits {
            max_certificate_bytes: 64,
            ..Limits::default()
        };
        let verifier = ServerVerifier::new(&anchors, now, limits).unwrap();
        let leaf_bytes = leaf();
        let leaf_cert = CertificateDer::from(leaf_bytes.as_slice());
        let name = ServerName::try_from("localhost").unwrap();
        assert!(matches!(
            verifier.verify_server(&leaf_cert, &[], &name),
            Err(Error::CertificateTooLarge)
        ));
        let verifier = ServerVerifier::new(&anchors, now, Limits::default()).unwrap();
        let too_many: [CertificateDer<'_>; MAX_INTERMEDIATES + 1] =
            core::array::from_fn(|_| CertificateDer::from(&[][..]));
        assert!(matches!(
            verifier.verify_server(&leaf_cert, &too_many, &name),
            Err(Error::TooManyIntermediates)
        ));
        for len in 0..leaf_bytes.len() {
            let truncated = CertificateDer::from(&leaf_bytes[..len]);
            assert!(verifier.verify_server(&truncated, &[], &name).is_err());
        }
        assert!(read_key_usage(&[0x30, 0x80, 0, 0], MAX_EXTENSIONS).is_err());
        assert!(read_key_usage(&[0x30, 0xff], MAX_EXTENSIONS).is_err());
    }
}

/// Local key/certificate consistency only; not chain or peer authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningKeyError { InvalidConfig, Mismatch }
pub fn verify_signing_key(leaf_der: &[u8], key: &crate::crypto::p256::SecretKey) -> Result<(), SigningKeyError> {
    let cert = parsed::parse(leaf_der).map_err(|_| SigningKeyError::InvalidConfig)?;
    let signed = key.sign(b"hibana-quic TLS signing key consistency").map_err(|_| SigningKeyError::InvalidConfig)?;
    signature::verify(cert.public_key_algorithm,cert.public_key,signature::ECDSA_SHA256,b"hibana-quic TLS signing key consistency",signed.to_der().as_bytes()).map_err(|_| SigningKeyError::Mismatch)
}
