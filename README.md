# hibana-tls

## Read the Hibana program first

- [Handshake global](src/handshake/global.rs) defines transcript order.
- [Handshake locals](src/handshake/local.rs) execute the projected exchanges.
- [Owned key handoff](src/handshake/key_source.rs) transfers actual key material.
- [Handshake implementation parts](src/handshake/imp/mod.rs) contain the
  individual transcript computations selected by those locals.

Each choreographed unit exposes its global and local roles first. Numerical
implementation parts live under `imp/`; they must not select the next protocol
phase or duplicate the key owner's authority. Pure arithmetic modules do not
need artificial global/local files. This layout migration is in progress.


A separate, work-in-progress TLS 1.3 crate for hibana-quic, built around Hibana choreography.
The core is `no_std` with no default allocator. Optional `alloc` only supports
Host-owned secret byte vectors. Unsafe Rust is denied except the explicit volatile
memory boundary in `src/secret/memory.rs`; see MEMORY-BOUNDARY.md.
Its sole default production dependency is the pinned Hibana core.

This is a working QUIC-specific endpoint integration under regression validation,
**not a production-security qualification**. This crate now owns `BoundedTls`,
`KeySource`, private cryptographic operations, the shared transcript global and
the direct input/verification locals. `owned_global` adds the projected material
handoff participant used by QUIC. Actual keys and authenticated Finished receipts
move through owned slots before that participant sends Taken; the next TLS input
cannot advance before the projected exchange completes.

The production QUIC connection uses `client_owned` / `server_owned`. Reference
fixtures may also exercise raw two-participant locals; those use direct RefCell
borrows. CryptoAccess/SourceAccess forwarding adapters have been removed.
See `DIRECT-LOCAL-MIGRATION.md` for the exact ownership boundary.

Scope is TLS 1.3 handshake and authentication for QUIC. Generic TCP TLS, TLS record
framing and a general-purpose TLS socket API are out of scope. QUIC-specific
handshake needs may shape this API; there is no requirement to serve other consumers.

TLS owns transcript order, cryptographic verification, key derivation and secret
lifetimes. QUIC retains CRYPTO-stream reassembly/retransmission, scoped directional packet-key
owners and QUIC-specific key retirement; numerical packet material and parameter
parsing are now shared from this crate. The TLS crate
has no production dependency on hibana-quic, HTTP/3, an OS, an executor or an allocator.
Its test-only dependency on QUIC supplies the existing deterministic test runtime.

Validation must distinguish executable code, Lean models and actual refinement
claims. Passing abstract models alone is not proof of cryptographic security or
constant-time machine code. Reference implementations belong only in tests.

## Initial primitive checks

SHA-256 and HMAC/HKDF-SHA-256 use fixed storage and no non-Hibana runtime
library. Tests include public SHA-256 known answers, all three RFC 5869 SHA-256
cases, TLS label encoding and the final allowed HKDF block. Lean files prove
selected arithmetic/bit-vector facts only. Secret erasure and target-level
constant-time qualification remain separate obligations; primitive tests alone do not
qualify deployment of the integrated endpoint.

The initial ChaCha20 block primitive is also present, with RFC known-answer
tests and a Lean quarter-round inverse theorem. A fixed-storage Poly1305
primitive now passes its RFC known answer and 235 independently generated
Python-integer cases (including all-ones carry stress). Seven Lean arithmetic
lemmas cover product/carry bounds and modular subtraction, not full Rust
refinement or cryptographic security. In-place ChaCha20-Poly1305 AEAD composition now also passes the RFC known
answer, authentication-failure buffer preservation tests and 231 independent
cryptography/OpenSSL vectors. Four further Lean lemmas check padding and counter
bounds. The integrated QUIC endpoint uses these primitives; neither their
known-answer tests nor the ownership migration establish complete security
qualification.

Poly1305 follows [RFC 8439 section 2.5](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.5).
The standalone authenticator does not enforce one-time key ownership; the calling
protocol locals must provide that authority. Machine-code constant-time behavior
and guaranteed secret erasure remain unqualified.

## Integration contract

The QUIC connection must embed this crate's canonical global and execute its
direct locals. The boundary transfers actual affine directional traffic secrets
and verified Finished evidence. It must not synchronize two State machines or
introduce ready/created/discarded flags or communication-proxy wrappers. QUIC
keeps reassembly, recovery, packet protection and its own confirmation rules.
This is the central acceptance criterion for the integration work, not an
optional ergonomic layer. The production direct TLS locals and owned handoff are implemented; full-suite
results and remaining qualification limits are recorded with each checkpoint.


## Source layout

- `src/handshake/global.rs`: transcript message definitions and raw two-party reference graph.
- `src/handshake/global/owned.rs`: the shared three-party TLS/input/material-handoff graph embedded by QUIC.
- `src/handshake/`: direct locals, private operations and actual affine key/Finished material.
- `src/endpoint.rs`: the common QUIC TLS interface, reexported by QUIC.
- `src/crypto/`: fixed-storage arithmetic, including detached-tag in-place AEAD;
  it contains no protocol controller or communication proxy.
- `proofs/`: explicitly scoped Lean arithmetic/bit-vector obligations.
- `tests/*.in`: reproducible independent expected values used by Rust tests.
- `tools/*_vectors.py`: test-only fixture generators; their Python packages are
  not Cargo or production dependencies.

AEAD `open` authenticates before changing caller bytes. Invalid tags preserve
ciphertext; length limits are checked before encryption. The calling global and
locals must still guarantee key/nonce uniqueness. That ownership integration,
guaranteed erasure and target-level timing audits are not completed by these
primitive tests. See [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8).

AES-128 forward blocks and 96-bit-nonce/full-tag AES-128-GCM are also implemented
in `crypto/aes128.rs` and `crypto/aes128gcm.rs`. They have fixed-loop arithmetic,
independent oracle fixtures and bounded counter checks; see `proofs/aes/README.md`
for the precise validation limits. This is not a claim of audited security or
constant-time/erasure qualification on any target.

`crypto/x25519.rs` implements the raw RFC 7748 arithmetic with fixed 5x51-bit
storage. See `proofs/x25519/README.md` for independent vector coverage and limited
arithmetic proofs. A raw shared result is not a verified TLS peer; callers must
reject zero and preserve actual one-use secret ownership. Integration qualification
and timing/erasure assessment remain separate obligations.

## P-256 extraction candidate

Own fixed-storage P-256 field/scalar arithmetic, ECDH, RFC6979 ECDSA and strict
SEC1/PKCS8 decoding are present. The accompanying QUIC candidate removes p256
and hmac together from resolved root, host and reference dependency graphs.
See proofs/p256/README.md for independent comparison coverage and explicit
limits. These tests do not establish production side-channel safety or complete
compiler-proof erasure; the cryptographic qualification remains separate from the direct-local integration.

The SHA-256 integration corpus additionally compares 810 Python hashlib known
answers across padding/block boundaries, each through ten incremental chunk
sizes. It complements the existing million-byte known answer and state-preserving
overflow rejection tests; it is not a security or compiler refinement proof.

Own RSA public modular exponentiation supports the bounded 2048/3072/4096-bit
verification profile. Public operands permit variable-time arithmetic branches;
this primitive must never be used for private-key operations. Its 144 independent
Python pow cases and failure-output checks are documented in proofs/rsa/README.md.
Protocol ordering and authority remain the responsibility of Hibana locals;
there is no separate RSA protocol state machine or progress flag.

The bounded X.509 KeyUsage reader in `src/x509/key_usage.rs` consumes borrowed
DER slices without allocation or a protocol-progress controller. It checks
canonical TLV lengths, exact admitted nesting, extension count and KeyUsage
bits. It is not a general DER validator or certificate authenticator: signature,
name, validity, chain and critical-extension verification remain mandatory in
the owning verifier. The integration reference suite retains an independent
RustCrypto DER parser for 10,240 grammar comparisons, truncation/bit-mutation
rejection and duplicate/critical/capacity cases. Arithmetic and parser cursors
represent actual data consumption, not a second TLS state machine.

`entropy::Entropy` is the caller's direct cryptographic input capability, with
one fallible whole-buffer operation. It does not own an RNG implementation,
external package adapter or protocol progression. Production callers must supply
a trusted cryptographic platform source; deterministic implementations are for
tests only. Failure never authorizes use of partially filled key material.


## Canonical numerical implementation

The QUIC crate now directly reexports this crate's schedule, wire and RSA types;
there is no second implementation or runtime forwarding adapter. The existing
independent protocol/certificate reference tests still consume the same API.
Traffic secrets move once while distinct Finished keys remain with the numeric
owner. The resumed/full choice is held by the projected local continuation in
this crate's direct local continuation, not stored as a second control flag. Finished authority
is retained by the actual RX continuation and lent for subsequent ticket input.
The private Finished-minting operations must not be exposed as arbitrary public
callbacks merely to cross a crate boundary. The direct-local implementation now lives here; QUIC consumes the same types
and global. Numerical moves alone are not evidence of cryptographic qualification.


## Owned certificate validation candidate

See [X509-PROFILE.md](X509-PROFILE.md) for exact accepted/rejected forms and
qualification limits. The product path no longer imports rustls-webpki,
rustls-pki-types or untrusted, and no copied webpki source is retained. Borrowed
certificate inputs and trust anchors are project-owned. Host/reference fixtures
remain separately qualified; a package count is not a security proof.
