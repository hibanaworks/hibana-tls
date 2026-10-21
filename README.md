# hibana-tls

TLS 1.3 handshake and authentication for
[hibana-quic](https://github.com/hibanaworks/hibana-quic), expressed using Hibana
protocols and direct role execution. This is a QUIC-specific TLS implementation;
it does not provide TCP TLS records or a TLS socket API.

The library is `no_std` and does not link the `alloc` crate. Its sole production
dependency is [Hibana 0.10.0](https://github.com/hibanaworks/hibana), pinned in
[Cargo.toml](Cargo.toml). [PEM decoding](src/certificate/pem.rs) writes into caller-owned
byte storage and returns borrowed DER. Secret key storage is erased when its owner
is dropped. There is no filesystem or operating-system access.
This is experimental security-sensitive software, not a claim of a complete
cryptographic security proof.

## Start here

- [handshake/global.rs](src/handshake/global.rs): legal transcript order.
- [handshake/localside/](src/handshake/localside/mod.rs): the actual projected TLS roles.
- [handshake/imp/keys.rs](src/handshake/imp/keys.rs): owned keys and
  authenticated Finished receipts passed to QUIC.
- [handshake/imp/](src/handshake/imp/mod.rs): transcript and cryptographic operations
  used by those roles.

`client_owned` and `server_owned` are the roles used by QUIC. The key handoff must
finish before the projected transcript may accept its next input. Consumers
should use the QUIC connection entry to compose TLS and packet ownership.

## How Hibana owns TLS progression

Read [global.rs](src/handshake/global.rs), then its
[owned-key composition](src/handshake/global/owned.rs), then
[`client_owned` / `server_owned`](src/handshake/localside/verify.rs).
The globals describe Hello, certificate verification, Finished and key-handoff
order. Each choreography function returns `impl Projectable`; Rust infers its
step-list from the `g::send`, `g::seq`, `g::route`, and `g::par` expressions.
QUIC composes the owned-key TLS global directly into its connection global,
then projects the combined choreography for each role. The localsides execute
that order directly through projected endpoints.

After Hello and again after Finished, VERIFY sends the `MATERIAL` endpoint to
HANDOFF as `Keys`. HANDOFF uses that endpoint to send `Install` to VERIFY and
wait for `Installed`, then passes the endpoint to OUTPUT. OUTPUT returns it to
VERIFY. VERIFY supplies the actual
keys and Finished receipt to the install function before sending `Installed`.
The install function writes the values into QUIC's key storage. Endpoint
delegation and the request/reply order replace the separate handoff slots.
`hello`, `installation`, `client_messages`, `server_messages`, and `complete`
are protocol fragments for composing this order with packet transmission.

The initial endpoint uses the binding returned by `KeySource::endpoint_binding`.
Attach VERIFY before MATERIAL, and pass that same binding to every transport
exposing the connection's key source. A new session does not restore its one-time
issuance. QUIC checks the connection scope when it installs keys and Finished
receipts.

[imp/](src/handshake/imp/mod.rs) owns the bounded TLS material, and
[imp/material/transcript.rs](src/handshake/imp/material/transcript.rs) performs transcript and
cryptographic operations. It does not choose the next projected endpoint step.
Pure primitives live in [crypto/](src/crypto), certificate-chain/name checks in
[x509/](src/x509), and the explicit erasure boundary in [secret/](src/secret).

## Find the actual endpoint owners

The handshake entry module declares `global`, `localside` and the private calculation
parts. It exports configuration, caller-owned storage and TLS material without
adding a dispatch object. The material's methods calculate or validate bytes;
`localside` chooses their order by executing projected endpoint operations.

- INPUT is `client_input` or `server_input` in [localside/input.rs](src/handshake/localside/input.rs).
  It owns reassembly input and lends one complete message through `MessageSlot`.
- VERIFY is `client_owned` or `server_owned` in [localside/verify.rs](src/handshake/localside/verify.rs). Its exclusive
  endpoint and TLS material govern transcript checks and Finished authentication.
- HANDOFF receives the MATERIAL endpoint, requests installation and passes it to OUTPUT.
  [global/owned](src/handshake/global/owned.rs) defines the transfer and the
  installation request/reply. [KeySource](src/handshake/imp/keys.rs) retains
  the actual key material until VERIFY performs the installation.
- OUTPUT receives the endpoint after installation and returns it to VERIFY.
- QUIC composes and projects this graph with packet receive/transmit and timers.
  Its [handshake endpoint set](https://github.com/hibanaworks/hibana-quic/blob/main/src/quic/localside/mod.rs)
  projects each role and attaches its Endpoint; its [handshake execution](https://github.com/hibanaworks/hibana-quic/blob/main/src/quic/localside/run.rs)
  owns the actual concurrent futures. TLS does not spawn a hidden executor.

Pure crypto, certificate and wire modules have no message choreography to invent.
Their correctness requires separate algorithm, parser and memory checks.

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
[Hibana's guarantees](https://github.com/hibanaworks/hibana/blob/main/README.md#guarantees-and-verification).

## AES instruction paths

AES-128 block encryption and GCM counter encryption use checked AES-NI on x86-64.
On little-endian AArch64, they use AESE/AESMC only when the compiler target enables
both `aes` and `neon`. Rust 1.95's `aarch64-apple-darwin` baseline enables these;
generic AArch64 targets retain the table-free portable path. For a deployment
that guarantees the extensions, `-C target-feature=+aes` selects the AArch64 path.
Do not use that flag for hardware without the extensions: this is a build-time
CPU contract, not runtime feature detection. Miri uses the portable path.

GCM authentication (GHASH) remains portable on AArch64. Round keys are expanded
once per counter operation into stack storage erased by `Secret`; this does not
guarantee erasure of historical register/spill copies or constant-time machine
code. No allocator, OS query, dependency, or persistent key cache is added.

## Build

```sh
cargo check --locked --lib
cargo check --locked --lib --target thumbv6m-none-eabi
```

To run the integration tests, place the matching `hibana-quic` repository beside
this repository, then run `cargo test --locked`.

See [supported certificate profile](X509-PROFILE.md) and
[secret-memory boundary](MEMORY-BOUNDARY.md) before integrating. Unsafe Rust
implements secret erasure, CPU intrinsics and the connection's initial resource
binding. The binding is created once in the caller-owned key scope.

Licensed under MIT OR Apache-2.0; see LICENSE-MIT and LICENSE-APACHE.

## Application protocols

`Protocol::Raw` and `Protocol::Http3` are available by default. The default
protocol is raw QUIC with ALPN `hibana/1`. To negotiate the HTTP/0.9
interoperability profile, enable the default-off `hq` Cargo feature and select
`Protocol::Http09` explicitly. Enabling this feature keeps the library `no_std`
and does not introduce an `alloc` dependency. QUIC exposes the corresponding
feature through `hibana-quic/hq`.
