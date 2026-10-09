# hibana-tls

TLS 1.3 handshake and authentication for
[hibana-quic](https://github.com/hibanaworks/hibana-quic), expressed using Hibana
protocols and direct role execution. This is a QUIC-specific TLS implementation;
it does not provide TCP TLS records or a TLS socket API.

The default build is `no_std` without an allocator. Its sole production dependency
is Hibana. The optional `alloc` feature supports Host-owned secret byte vectors.
This is experimental security-sensitive software, not a claim of a complete
cryptographic security proof.

## Start here

- [handshake/global.rs](src/handshake/global.rs): legal transcript order.
- [handshake/local/](src/handshake/local/mod.rs): the actual projected TLS roles.
- [handshake/key_source.rs](src/handshake/key_source.rs): owned keys and
  authenticated Finished receipts passed to QUIC.
- [handshake/imp/](src/handshake/imp/mod.rs): transcript and cryptographic operations
  used by those roles.

`client_owned` and `server_owned` are the roles used by QUIC. The key handoff must
finish before the projected transcript may accept its next input. Consumers
should use the QUIC connection entry to compose TLS and packet ownership.

## Build

```sh
cargo check --locked --lib
cargo check --locked --lib --target thumbv6m-none-eabi
```

To run the integration tests, place the matching `hibana-quic` repository beside
this repository, then run `cargo test --locked`.

See [supported certificate profile](X509-PROFILE.md) and
[secret-memory boundary](MEMORY-BOUNDARY.md) before integrating. Unsafe Rust is
limited to the explicit volatile secret-memory boundary.

Licensed under MIT OR Apache-2.0; see LICENSE-MIT and LICENSE-APACHE.
