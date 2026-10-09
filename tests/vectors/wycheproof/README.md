# Independent Wycheproof data

These are public cryptographic test vectors from C2SP/Wycheproof, under the
included Apache License 2.0. They are data, not a vendored implementation.
PROVENANCE.json records each source URL, downloaded content SHA-256, exact
selected counts, output hash, and excluded test IDs. The importer uses only
Python's standard library; the Rust tests add no package dependency.

AEAD selection matches this QUIC profile: AES-128 or ChaCha20, 96-bit nonce,
128-bit tag. Tests outside those key/nonce/tag widths are explicitly excluded,
not reported as passes. Every admitted valid case checks decrypt, plaintext,
re-encrypt, ciphertext and tag. Every invalid case must reject while preserving
ciphertext. X25519 uses the real affine secret API: all-zero results must reject,
including Wycheproof's acceptable low-order cases; other RFC7748 inputs must
produce the independent expected secret. All 484 ECDSA/P-256/SHA-256 cases test
the production DER signature and SEC1 public-point verification path.

Passing these finite vectors is not a proof of cryptographic security, constant
time, protocol conformance for every input, or complete erasure of temporaries.
