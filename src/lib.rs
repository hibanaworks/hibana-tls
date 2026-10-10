#![no_std]
#![deny(unsafe_code)]
//! QUIC-specific TLS endpoint and cryptographic material; security qualification is ongoing.
//! Protocol order belongs to Hibana globals and direct locals, not a phase enum.
pub mod crypto;

pub mod x509;

pub mod entropy;

mod protocol;
pub mod schedule;
pub mod wire;
pub use protocol::{Protocol, RawProtocol};
pub mod signature;

#[cfg(test)]
extern crate std;
pub mod certificate;
pub mod early;
pub mod ticket;

pub mod secret;

pub mod key_exchange;

pub mod quic;

pub mod handshake;

#[cfg(test)]
#[global_allocator]
static TEST_ALLOCATOR: actor_test_allocator::Counting = actor_test_allocator::Counting;

#[cfg(test)]
mod allocator_instrumentation {
    #[test]
    #[should_panic(expected = "allocated")]
    fn counter_rejects_a_real_allocation() {
        let guard = actor_test_allocator::NoAlloc::start();
        let bytes = std::vec![core::hint::black_box(7_u8); 64];
        core::hint::black_box(&bytes);
        guard.finish();
    }
}
