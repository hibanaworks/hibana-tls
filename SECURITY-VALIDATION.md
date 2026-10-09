# Security validation scope and remaining qualification

This is an experimental QUIC-specific TLS implementation. A finite test suite,
source review or local interop run cannot establish comprehensive cryptographic
security. Do not treat the following engineering checks as production-security
certification or a mathematical refinement proof.

## Changes from the preceding checkpoint

- TicketKey retirement now consumes/drops the actual Secret owner. It cannot
  retain an erased placeholder key plus a separate retired flag.
- ReplaySlot owns an optional nonce/expiry entry; clearing it drops that entry.
  Replay checks, capacity failure and expiry behavior remain mandatory.
- QUIC recovery stores the actual authenticated peer timing configuration in one
  Option, removing the separate parameters_bound flag and detached default fields.
- AEAD tag checks use the common volatile-barrier fixed-work comparison instead
  of two duplicated comparison loops. Failed authentication preserves ciphertext.
- The clamped X25519 scalar copy is now an actual Secret owner and its addressed
  storage is erased on drop. This does not erase every field-arithmetic copy.
- Host test rcgen/DER dependencies are removed. Ticket tests use independently
  generated public deterministic credentials; the changed-trust test still uses
  a genuinely different root. Two independent DER tests moved to the reference
  workspace unchanged, rather than deleting comparison coverage.
- Obsolete webpki patch/inventory/checker files are removed. The development gate
  now checks the current owned implementation, not a deleted vendor directory.

## Independent adversarial crypto data

The dependency-free Wycheproof integration executes 1,385 selected cases:
AES-128-GCM 67, ChaCha20-Poly1305 316, X25519 518, P-256 ECDSA/SHA-256 484.
The exact downloaded data hashes and excluded AEAD-profile IDs are in
`tests/vectors/wycheproof/PROVENANCE.json`. 258 AEAD cases outside supported
key/nonce/tag sizes are excluded, not passed. The low-order X25519 cases must
reject all-zero secrets through the actual one-use secret API.

Existing SHA/HMAC/HKDF, modular arithmetic, ECDH, signature, certificate, ticket,
replay, cancellation, allocation and compile-fail ownership tests remain gates.
Independent Rustls/ring/DER comparison is intentionally retained only in the
reference workspace: replacing that oracle with this implementation would lose
independent verification. Those packages are not product or Host test dependencies.

## Memory and generated code

The addressed-erasure/equality boundary passed a fresh five-test Miri run on
2026-10-09 (nightly 1.101.0, compiler commit 1d81eb4ad). The initial sysroot
registry failure was resolved through the same normal registry route after
native peer build dependencies were installed. The final run used a writable
XDG_CACHE_HOME and completed all five selected secret:: tests. This is scoped
memory-boundary evidence, not interpretation of every cryptographic primitive.

Rust 1.95 opt-level 3 generated-code inspection on x86_64 and thumbv6m shows no
conditional jumps in the 16-byte equality harness; the 64-byte harness branches
only on its public count. Both addressed 64-byte erasure/drop harnesses retain
64 byte stores and the LLVM IR retains volatile writes/fence. This is a limited
boundary inspection, not all-primitive/all-optimizer constant-time qualification.

## Remaining limits requiring explicit decisions/evidence

- P-256 RFC6979 rejection/retry and all compiled elliptic-curve paths have not
  received complete target-specific timing/leakage qualification.
- Copies in arithmetic temporaries/registers, swap and crash dumps are not
  comprehensively erased by addressed volatile writes.
- Existing Lean lemmas are scoped arithmetic/model facts, not full Rust refinement
  of AES/GHASH/Poly1305/ECC/X.509 or a cryptographic security proof.
- Real system entropy is injected by the Host; platform entropy failure tests do
  not prove the OS entropy source's health under every deployment condition.
- Native same-implementation loopback and fault tests are not independent QUIC
  interoperability, official quic-interop-runner results, or remote CI success.
- Mac execution and Pico hardware-in-the-loop remain separate, unexecuted gates.

## Retained boolean data and functions

Parsed wire bits (FIN, early_data, ACK/ECN properties), application configuration,
public numerical results, and one-shot identity accounting are not removed just
to achieve a textual zero-bool count. Raw arithmetic/parser functions also remain.
A field that mirrors protocol order must instead be owned by the projected local
or the actual resource. The named removed-controller ratchet detects regressions
but is not proof that all possible hidden controllers are absent.

## Presented DNS identifiers in the amplification fixture

The unchanged pinned runner creates a nine-certificate chain whose leaf includes
valid server names plus unrelated 250-byte DNS labels used to inflate its size.
Identity comparison ignores those unusable names, never matches them, and still
requires a valid requested identity. The entire DER SAN is consumed; non-ASCII
IA5 data and malformed/truncated DER reject. Constrained issuers validate every
presented DNS name strictly, so invalid names cannot bypass NameConstraints.
This implements the identifier-by-identifier matching policy of RFC 9525 sections
6.2 and 6.3; it does not waive trust, signature, validity, purpose or chain checks.
Public certificates from the unchanged runner and positive/wrong-host/wrong-root/
expired/corrupted-signature regressions are included. No private keys are shipped.
