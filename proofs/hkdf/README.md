# HKDF arithmetic bounds

Run with Lean 4.30: `lean Bounds.lean`.

These lemmas cover the one-byte expansion counter, TLS label length, encoded
metadata length and output-length field. They do not prove HMAC/HKDF security,
Rust refinement, secret erasure or constant-time target execution. Rust tests
use RFC 5869 SHA-256 vectors and independent Python/OpenSSL boundary values.
