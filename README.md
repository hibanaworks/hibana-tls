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
- [handshake/local/keys.rs](src/handshake/local/keys.rs): owned keys and
  authenticated Finished receipts passed to QUIC.
- [handshake/imp/](src/handshake/imp/mod.rs): transcript and cryptographic operations
  used by those roles.

`client_owned` and `server_owned` are the roles used by QUIC. The key handoff must
finish before the projected transcript may accept its next input. Consumers
should use the QUIC connection entry to compose TLS and packet ownership.

## How Hibana owns TLS progression

Read [global.rs](src/handshake/global.rs), then its
[owned-key composition](src/handshake/global/owned.rs), then
[`client_owned` / `server_owned`](src/handshake/local/mod.rs).
The globals describe Hello, certificate verification, Finished and key-handoff
order. Each choreography function returns `impl Projectable`; Rust infers its
step-list from the `g::send`, `g::seq`, `g::route`, and `g::par` expressions.
QUIC composes the owned-key TLS global directly into its connection global,
then projects the combined choreography for each role. The localsides execute
that order directly through projected endpoints.

A typical handoff publishes actual key material into
[`Handoff`](src/handshake/local/keys.rs), sends `KeysReady`, receives `KeysTaken`,
and checks that the handoff is empty before sending `Applied`. The next
transcript step cannot use that branch's completion signal while the previous
key material remains unconsumed. QUIC checks the associated connection scope
when it installs the resulting keys and Finished receipts.

[imp/transcript.rs](src/handshake/imp/transcript.rs) performs transcript and
cryptographic operations. It does not choose the next projected endpoint step.
Pure primitives live in [crypto/](src/crypto), certificate-chain/name checks in
[x509/](src/x509), and the explicit erasure boundary in [secret/](src/secret).

## Guarantees and verification

Hibana enforces the permitted per-endpoint transitions, route participation and
single-owner publication of progress. Rust moves and borrowing constrain the
ownership and lifetime of key material. The integration also checks that
Finished and key receipts belong to the same connection scope.

Those mechanisms do not establish that an AES implementation, certificate parser
or key schedule is cryptographically correct. Known-answer, malformed-input,
independent-oracle and QUIC interoperability tests cover those separate concerns.
[Secret-memory tests](src/secret.rs) run under Miri for the exercised volatile
memory and aliasing boundaries; Miri is not a timing or whole-program security
proof.

The sibling QUIC repository also contains Lean proofs and Z3 counterexample
checks for abstract ownership, cancellation and reclamation models. Their
assumptions and Rust correspondence matter: they are not an automatic proof of
this complete TLS implementation. For the runtime's precise premises, see
[Hibana's guarantees](https://github.com/hibanaworks/hibana/blob/2eaba16d204a3f33f25ab00087d504380fe7e27f/README.md#guarantees).

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
