// Owned-key authority checks driven by actual asynchronous transcript roles.
use super::*;
use crate::handshake::test_fixture as fixture;
use crate::{
    certificate::{CertificateDer, Limits, trust_anchor_from_der},
    handshake::{CipherPolicy, ClientConfig, ServerConfig},
};
use actor_test_allocator::NoAlloc;
use fixture::{Buffers, CLIENT_PARAMS, SERVER_PARAMS, TestRandom};

use crate::handshake::async_test_fixture as async_fixture;
fn handshake(source: &mut KeySource<'_, '_, '_>, target: &mut KeySource<'_, '_, '_>) {
    async_fixture::handshake(&mut source.provider, &mut target.provider);
    assert!(source.peer_transport_parameters().is_some());
    assert!(target.peer_transport_parameters().is_some());
}
fn transferred_keys_are_unavailable(provider: &mut BoundedTls<'_, '_>) {
    let mut buffer = [0; 32];
    for level in [Level::Handshake, Level::OneRtt] {
        assert!(!provider.has_keys(level));
        assert_eq!(
            provider.seal(level, 1, b"h", &mut buffer, 4),
            Err(tls::Error::KeysUnavailable)
        );
        assert_eq!(
            provider.open(level, 1, b"h", &mut buffer),
            Err(tls::Error::KeysUnavailable)
        );
        assert_eq!(
            provider.header_mask(level, true, &[0; 16]),
            Err(tls::Error::KeysUnavailable)
        );
    }
    assert!(provider.integrity_budget().is_none());
    assert!(!provider.has_early_keys());
    assert_eq!(
        provider.seal_early(1, b"h", &mut buffer, 4),
        Err(tls::Error::KeysUnavailable)
    );
    assert_eq!(
        provider.open_early(1, b"h", &mut buffer),
        Err(tls::Error::KeysUnavailable)
    );
}

#[test]
fn actual_owned_tls_keys_and_finished_are_affine_scoped_and_allocation_free() {
    for policy in [CipherPolicy::Aes128Only, CipherPolicy::ChaCha20Only] {
        for p256 in [false, true] {
            let root = CertificateDer::from(fixture::ROOT_DER);
            let anchors = [trust_anchor_from_der(&root).unwrap()];
            let chain = [fixture::LEAF_DER];
            let signer = fixture::signing_key();
            let mut cb = Buffers::new();
            let mut sb = Buffers::new();
            let mut client_scope = ApplicationKeyScope::new(17);
            let mut server_scope = ApplicationKeyScope::new(17);
            let allocation = NoAlloc::start();
            let client_installation = client_scope.claim().unwrap();
            let server_installation = server_scope.claim().unwrap();
            let mut client = BoundedTls::client_with_policy(
                ClientConfig {
                    protocol: Default::default(),
                    version: crate::quic::version::Version::V1,
                    server_name: "localhost",
                    trust_anchors: &anchors,
                    now: fixture::now(),
                    certificate_limits: Limits::default(),
                    transport_parameters: CLIENT_PARAMS,
                },
                cb.storage(),
                &mut TestRandom(121),
                policy,
            )
            .unwrap();
            // Existing Initial failures must transfer with their budget, never reset.
            assert!(
                client
                    .integrity_budget()
                    .unwrap()
                    .authenticate(100, || Err::<(), _>(()))
                    .is_err()
            );
            let mut server = BoundedTls::server_with_policy(
                ServerConfig {
                    protocol: Default::default(),
                    version: crate::quic::version::Version::V1,
                    certificate_chain: &chain,
                    signing_key: &signer,
                    transport_parameters: SERVER_PARAMS,
                },
                sb.storage(),
                &mut TestRandom(143),
                policy,
            )
            .unwrap();
            if p256 {
                server.allow_x25519 = false;
                server.x25519 = None;
            }
            let mut client = client.into_key_source(client_installation).unwrap();
            let mut server = server.into_key_source(server_installation).unwrap();
            let mut cbudget = client.take_integrity_budget().unwrap();
            let mut sbudget = server.take_integrity_budget().unwrap();
            assert_eq!(cbudget.failed_packets(), 1);
            assert!(client.take_integrity_budget().is_err());
            assert_eq!(client.observations().failed_authentications, None);
            // There is no second budget, even a depleted numeric stand-in.
            assert!(client.provider.integrity.is_none());
            assert_eq!(client.provider.observations().failed_authentications, None);
            assert!(client.take_handshake_keys().is_err());
            assert!(client.take_application_keys().is_err());
            assert!(client.take_finished().is_err());
            assert!(client.peer_transport_parameters().is_none());
            transferred_keys_are_unavailable(&mut client.provider);
            handshake(&mut client, &mut server);
            assert_eq!(server.peer_transport_parameters(), Some(CLIENT_PARAMS));
            let (shs_rx, mut shs_tx) = server.take_handshake_keys().unwrap().install();
            let smaterial = server.take_application_keys().unwrap();
            assert!(core::ptr::eq(smaterial.scope(), server.scope()));
            let (server_installation, mut stx, mut srx) = smaterial.into_parts();
            let server_key_scope = server_installation.into_scope();
            assert!(server.provider.application.is_none());
            assert!(server.take_handshake_keys().is_err());
            assert!(server.take_application_keys().is_err());
            assert!(server.provider.install_application().is_err());
            assert!(server.provider.packet_keys(KeyKind::Handshake).is_err());
            assert!(server.provider.packet_keys(KeyKind::OneRtt).is_err());
            transferred_keys_are_unavailable(&mut server.provider);
            // QUIC confirmation/ACK/update-policy checks stay with the actual
            // QUIC directional owner tests, using real TLS handoff material.

            assert_eq!(client.peer_transport_parameters(), Some(SERVER_PARAMS));
            let (chs_rx, mut chs_tx) = client.take_handshake_keys().unwrap().install();
            let (client_installation, mut ctx, mut crx) =
                client.take_application_keys().unwrap().into_parts();
            let client_key_scope = client_installation.into_scope();
            assert_eq!(client.peer_transport_parameters(), Some(SERVER_PARAMS));
            let cfinished = client.take_finished().unwrap();
            assert!(client.peer_transport_parameters().is_none());
            assert_eq!(cfinished.side(), Side::Client);
            assert_eq!(cfinished.protocol(), crate::Protocol::Http09);
            assert_eq!(client.provider.negotiated_alpn(), None);
            assert!(core::ptr::eq(cfinished.scope(), client_key_scope));
            assert!(cfinished.authenticates_peer_parameters(SERVER_PARAMS));
            assert!(!cfinished.authenticates_peer_parameters(CLIENT_PARAMS));
            assert!(client.take_finished().is_err());
            // Actual independently owned handshake keys interoperate in both directions.
            let mut cipher = [0; 20];
            cipher[..4].copy_from_slice(b"hand");
            chs_tx.seal(3, b"header", &mut cipher, 4).unwrap();
            assert_eq!(shs_rx.open(3, b"header", &mut cipher, &mut sbudget), Ok(4));
            assert_eq!(&cipher[..4], b"hand");
            assert_eq!(
                chs_tx.seal(3, b"header", &mut cipher, 4),
                Err(crypto::Error::PacketNumberReuse)
            );
            shs_tx.seal(9, b"header", &mut cipher, 4).unwrap();
            assert_eq!(chs_rx.open(9, b"header", &mut cipher, &mut cbudget), Ok(4));
            assert_eq!(chs_tx.header_mask(&[1; 16]), shs_rx.header_mask(&[1; 16]));
            assert_eq!(shs_tx.header_mask(&[2; 16]), chs_rx.header_mask(&[2; 16]));

            assert_eq!(client.negotiated_suite(), server.negotiated_suite());
            let mut server_transcript = server;
            // Output capacity failure must not consume the authenticated
            // receipt; a later adequate buffer receives that exact ownership.
            assert!(matches!(
                server_transcript.take_finished_with_parameters::<0>(),
                Err(crate::quic::Error::Capacity)
            ));
            let finished = server_transcript
                .take_finished_with_parameters::<512>()
                .unwrap();
            let sfinished = finished.into_receipt();
            assert_eq!(sfinished.side(), Side::Server);
            assert_eq!(sfinished.protocol(), crate::Protocol::Http09);
            assert!(sfinished.authenticates_peer_parameters(CLIENT_PARAMS));
            assert!(core::ptr::eq(sfinished.scope(), server_key_scope));
            assert!(!core::ptr::eq(sfinished.scope(), cfinished.scope()));
            assert_eq!(
                client.receive(&sfinished, Level::OneRtt, &[]),
                Err(tls::Error::InvalidInput)
            );
            assert!(client.last_failure().is_none());
            assert_eq!(client.receive(&cfinished, Level::OneRtt, &[]), Ok(()));
            assert!(!cfinished.resumed());

            assert!(matches!(
                server_transcript.take_finished_with_parameters::<512>(),
                Err(crate::quic::Error::KeysUnavailable)
            ));
            assert_eq!(
                client.negotiated_group(),
                Some(if p256 {
                    crate::wire::GROUP_P256
                } else {
                    crate::wire::GROUP_X25519
                })
            );
            for (tx, rx, budget) in [
                (&mut ctx, &mut srx, &mut sbudget),
                (&mut stx, &mut crx, &mut cbudget),
            ] {
                cipher[..4].copy_from_slice(b"apps");
                tx.seal(0, b"header", &mut cipher, 4).unwrap();
                assert_eq!(rx.open(0, b"header", &mut cipher, budget), Ok(4));
                assert_eq!(&cipher[..4], b"apps");
                // The separate QUIC test retains both pre/post-send refusal
                // assertions with the real directional authority types.
            }
            transferred_keys_are_unavailable(&mut client.provider);
            assert!(client.provider.install_application().is_err());
            // The source cannot use a historical Connected bit after lending
            // the actual Finished authority to RX.
            assert!(client.provider.receive(Level::OneRtt, &[]).is_err());
            allocation.finish();
        }
    }
}

#[test]
fn http3_finished_authenticates_application_protocol_without_allocation() {
    let root = CertificateDer::from(fixture::ROOT_DER);
    let anchors = [trust_anchor_from_der(&root).unwrap()];
    let chain = [fixture::LEAF_DER];
    let signer = fixture::signing_key();
    let mut cb = Buffers::new();
    let mut sb = Buffers::new();
    let allocation = NoAlloc::start();
    let client = BoundedTls::client(
        ClientConfig {
            protocol: crate::Protocol::Http3,
            version: crate::quic::version::Version::V1,
            server_name: "localhost",
            trust_anchors: &anchors,
            now: fixture::now(),
            certificate_limits: Limits::default(),
            transport_parameters: CLIENT_PARAMS,
        },
        cb.storage(),
        &mut TestRandom(731),
    )
    .unwrap();
    let server = BoundedTls::server(
        ServerConfig {
            protocol: crate::Protocol::Http3,
            version: crate::quic::version::Version::V1,
            certificate_chain: &chain,
            signing_key: &signer,
            transport_parameters: SERVER_PARAMS,
        },
        sb.storage(),
        &mut TestRandom(739),
    )
    .unwrap();
    assert_eq!(client.negotiated_alpn(), None);
    assert_eq!(server.negotiated_alpn(), None);
    let mut client_scope = crate::quic::scope::ApplicationKeyScope::new(731);
    let mut server_scope = crate::quic::scope::ApplicationKeyScope::new(739);
    let mut client = client
        .into_key_source(client_scope.claim().unwrap())
        .unwrap();
    let mut server = server
        .into_key_source(server_scope.claim().unwrap())
        .unwrap();
    handshake(&mut client, &mut server);
    assert_eq!(client.provider.negotiated_alpn(), Some(b"h3".as_slice()));
    assert_eq!(server.provider.negotiated_alpn(), Some(b"h3".as_slice()));
    let client_finished = client.take_finished().unwrap();
    let server_finished = server.take_finished().unwrap();
    assert_eq!(client_finished.protocol(), crate::Protocol::Http3);
    assert_eq!(server_finished.protocol(), crate::Protocol::Http3);
    assert_eq!(client.provider.negotiated_alpn(), None);
    assert_eq!(server.provider.negotiated_alpn(), None);
    assert!(client.take_finished().is_err());
    assert!(server.take_finished().is_err());
    allocation.finish();
}

#[test]
fn early_retirement_destroys_generation_material_and_blocks_owned_migration() {
    for level in [Level::Handshake, Level::OneRtt] {
        let root = CertificateDer::from(fixture::ROOT_DER);
        let anchors = [trust_anchor_from_der(&root).unwrap()];
        let mut buffers = Buffers::new();
        let mut scope = ApplicationKeyScope::new(71);
        let mut client = BoundedTls::client(
            ClientConfig {
                protocol: Default::default(),
                version: crate::quic::version::Version::V1,
                server_name: "localhost",
                trust_anchors: &anchors,
                now: fixture::now(),
                certificate_limits: Limits::default(),
                transport_parameters: CLIENT_PARAMS,
            },
            buffers.storage(),
            &mut TestRandom(44),
        )
        .unwrap();
        assert!(client.pristine());
        client.discard_keys(level);
        assert!(!client.pristine());
        assert!(client.ephemeral.is_none());
        assert!(client.x25519.is_none());
        assert!(
            client
                .install_handshake(crate::wire::GROUP_X25519, &[9; 32], 0x1301)
                .is_err()
        );
        assert!(client.install_application().is_err());
        assert!(client.into_key_source(scope.claim().unwrap()).is_err());
    }
}
