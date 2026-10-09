//! TLS transcript order with an explicit affine-material handoff participant.
//! This graph is for the direct QUIC/TLS composition, not a runtime controller.
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
use hibana::{
    g,
    runtime::program::{RoleProgram, project},
};
// The existing QUIC composition uses roles 0..32. This is its independent
// material consumer; no existing endpoint is aliased or driven twice.
pub const HANDOFF: u8 = 33;
pub type KeysReady = g::Msg<240, ()>;
pub type KeysTaken = g::Msg<241, ()>;
pub type RetryKeys = g::Msg<242, ()>;
pub type HelloKeys = g::Msg<243, ()>;
pub type ResumedKeys = g::Msg<244, ()>;
pub type FullKeys = g::Msg<245, ()>;
pub type CompleteKeys = g::Msg<246, ()>;
pub type ClientKeys = g::Msg<247, ()>;
pub type ServerKeys = g::Msg<248, ()>;
pub type KeyTransfer =
    g::Seq<g::Send<VERIFY, HANDOFF, KeysReady>, g::Send<HANDOFF, VERIFY, KeysTaken>>;
pub type Receive<N, D> = g::Seq<
    g::Send<VERIFY, INPUT, N>,
    g::Seq<g::Send<INPUT, VERIFY, D>, g::Seq<KeyTransfer, g::Send<VERIFY, INPUT, Applied>>>,
>;
pub type HelloFlow = g::Seq<
    Receive<NeedHello, Hello>,
    g::Route<
        g::Seq<
            g::Send<VERIFY, INPUT, Retry>,
            g::Seq<g::Send<VERIFY, HANDOFF, RetryKeys>, Receive<NeedRetryHello, RetryHello>>,
        >,
        g::Seq<g::Send<VERIFY, INPUT, HelloReady>, g::Send<VERIFY, HANDOFF, HelloKeys>>,
    >,
>;
pub type CertificateFlow = g::Seq<
    Receive<NeedCertificate, Certificate>,
    Receive<NeedCertificateVerify, CertificateVerify>,
>;
pub type FinishFlow = g::Seq<
    Receive<NeedFinished, Finished>,
    g::Seq<g::Send<VERIFY, INPUT, Complete>, g::Send<VERIFY, HANDOFF, CompleteKeys>>,
>;
pub type ClientFlow = g::Seq<
    HelloFlow,
    g::Seq<
        Receive<NeedExtensions, Extensions>,
        g::Seq<
            g::Route<
                g::Seq<g::Send<VERIFY, INPUT, Resumed>, g::Send<VERIFY, HANDOFF, ResumedKeys>>,
                g::Seq<
                    g::Send<VERIFY, INPUT, Full>,
                    g::Seq<g::Send<VERIFY, HANDOFF, FullKeys>, CertificateFlow>,
                >,
            >,
            FinishFlow,
        >,
    >,
>;
pub type ServerFlow = g::Seq<HelloFlow, FinishFlow>;
pub type Flow = g::Route<
    g::Seq<
        g::Send<VERIFY, INPUT, ClientStart>,
        g::Seq<g::Send<VERIFY, HANDOFF, ClientKeys>, ClientFlow>,
    >,
    g::Seq<
        g::Send<VERIFY, INPUT, ServerStart>,
        g::Seq<g::Send<VERIFY, HANDOFF, ServerKeys>, ServerFlow>,
    >,
>;
fn receive<N: g::Message<Payload = ()>, D: g::Message<Payload = ()>>() -> g::Program<Receive<N, D>>
{
    g::seq(
        g::send::<VERIFY, INPUT, N>(),
        g::seq(
            g::send::<INPUT, VERIFY, D>(),
            g::seq(
                g::seq(
                    g::send::<VERIFY, HANDOFF, KeysReady>(),
                    g::send::<HANDOFF, VERIFY, KeysTaken>(),
                ),
                g::send::<VERIFY, INPUT, Applied>(),
            ),
        ),
    )
}
fn hello() -> g::Program<HelloFlow> {
    g::seq(
        receive::<NeedHello, Hello>(),
        g::route(
            g::seq(
                g::send::<VERIFY, INPUT, Retry>(),
                g::seq(
                    g::send::<VERIFY, HANDOFF, RetryKeys>(),
                    receive::<NeedRetryHello, RetryHello>(),
                ),
            ),
            g::seq(
                g::send::<VERIFY, INPUT, HelloReady>(),
                g::send::<VERIFY, HANDOFF, HelloKeys>(),
            ),
        ),
    )
}
fn finish() -> g::Program<FinishFlow> {
    g::seq(
        receive::<NeedFinished, Finished>(),
        g::seq(
            g::send::<VERIFY, INPUT, Complete>(),
            g::send::<VERIFY, HANDOFF, CompleteKeys>(),
        ),
    )
}
pub fn client() -> g::Program<ClientFlow> {
    g::seq(
        hello(),
        g::seq(
            receive::<NeedExtensions, Extensions>(),
            g::seq(
                g::route(
                    g::seq(
                        g::send::<VERIFY, INPUT, Resumed>(),
                        g::send::<VERIFY, HANDOFF, ResumedKeys>(),
                    ),
                    g::seq(
                        g::send::<VERIFY, INPUT, Full>(),
                        g::seq(
                            g::send::<VERIFY, HANDOFF, FullKeys>(),
                            g::seq(
                                receive::<NeedCertificate, Certificate>(),
                                receive::<NeedCertificateVerify, CertificateVerify>(),
                            ),
                        ),
                    ),
                ),
                finish(),
            ),
        ),
    )
}
pub fn server() -> g::Program<ServerFlow> {
    g::seq(hello(), finish())
}
pub fn choreography() -> g::Program<Flow> {
    g::route(
        g::seq(
            g::send::<VERIFY, INPUT, ClientStart>(),
            g::seq(g::send::<VERIFY, HANDOFF, ClientKeys>(), client()),
        ),
        g::seq(
            g::send::<VERIFY, INPUT, ServerStart>(),
            g::seq(g::send::<VERIFY, HANDOFF, ServerKeys>(), server()),
        ),
    )
}
pub struct Programs {
    pub input: RoleProgram<INPUT>,
    pub verify: RoleProgram<VERIFY>,
    pub handoff: RoleProgram<HANDOFF>,
}
pub fn programs() -> Programs {
    let graph = choreography();
    Programs {
        input: project(&graph),
        verify: project(&graph),
        handoff: project(&graph),
    }
}
