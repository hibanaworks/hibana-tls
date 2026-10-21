//! TLS verification and delegated permission to install its packet keys.
pub use crate::handshake::global::Applied;
pub use crate::handshake::global::Certificate;
pub use crate::handshake::global::CertificateVerify;
pub use crate::handshake::global::ClientStart;
pub use crate::handshake::global::Complete;
pub use crate::handshake::global::Extensions;
pub use crate::handshake::global::Finished;
pub use crate::handshake::global::Full;
pub use crate::handshake::global::Hello;
pub use crate::handshake::global::HelloReady;
pub use crate::handshake::global::INPUT;
pub use crate::handshake::global::NeedCertificate;
pub use crate::handshake::global::NeedCertificateVerify;
pub use crate::handshake::global::NeedExtensions;
pub use crate::handshake::global::NeedFinished;
pub use crate::handshake::global::NeedHello;
pub use crate::handshake::global::NeedRetryHello;
pub use crate::handshake::global::Resumed;
pub use crate::handshake::global::Retry;
pub use crate::handshake::global::RetryHello;
pub use crate::handshake::global::ServerStart;
pub use crate::handshake::global::VERIFY;
use hibana::runtime::program::Projectable;
use hibana::{Endpoint, g};
pub const HANDOFF: u8 = 33;
/// Permission to request installation from the transcript owner, VERIFY.
pub const MATERIAL: u8 = 36;
pub type Keys<'r> = g::Msg<240, Endpoint<'r, MATERIAL>>;
pub type Install = g::Msg<241, ()>;
pub type Installed = g::Msg<249, ()>;
fn receive<N: g::Message<Payload = ()>, D: g::Message<Payload = ()>>() -> impl Projectable {
    g::seq(
        g::send::<VERIFY, INPUT, N>(),
        g::seq(
            g::send::<INPUT, VERIFY, D>(),
            g::send::<VERIFY, INPUT, Applied>(),
        ),
    )
}
fn install() -> impl Projectable {
    g::seq(
        g::send::<VERIFY, HANDOFF, Keys<'_>>(),
        g::seq(
            g::send::<MATERIAL, VERIFY, Install>(),
            g::seq(
                g::send::<VERIFY, MATERIAL, Installed>(),
                g::send::<HANDOFF, VERIFY, Keys<'_>>(),
            ),
        ),
    )
}
fn hello() -> impl Projectable {
    g::seq(
        receive::<NeedHello, Hello>(),
        g::route(
            g::seq(
                g::send::<VERIFY, INPUT, Retry>(),
                receive::<NeedRetryHello, RetryHello>(),
            ),
            g::send::<VERIFY, INPUT, HelloReady>(),
        ),
    )
}
fn finish() -> impl Projectable {
    g::seq(
        g::send::<VERIFY, INPUT, NeedFinished>(),
        g::seq(
            g::send::<INPUT, VERIFY, Finished>(),
            g::seq(
                install(),
                g::seq(
                    g::send::<VERIFY, INPUT, Applied>(),
                    g::send::<VERIFY, INPUT, Complete>(),
                ),
            ),
        ),
    )
}
pub fn client() -> impl Projectable {
    g::seq(
        hello(),
        g::seq(
            install(),
            g::seq(
                receive::<NeedExtensions, Extensions>(),
                g::seq(
                    g::route(
                        g::send::<VERIFY, INPUT, Resumed>(),
                        g::seq(
                            g::send::<VERIFY, INPUT, Full>(),
                            g::seq(
                                receive::<NeedCertificate, Certificate>(),
                                receive::<NeedCertificateVerify, CertificateVerify>(),
                            ),
                        ),
                    ),
                    finish(),
                ),
            ),
        ),
    )
}
pub fn server() -> impl Projectable {
    g::seq(hello(), g::seq(install(), finish()))
}
pub fn choreography() -> impl Projectable {
    g::route(
        g::seq(g::send::<VERIFY, INPUT, ClientStart>(), client()),
        g::seq(g::send::<VERIFY, INPUT, ServerStart>(), server()),
    )
}
