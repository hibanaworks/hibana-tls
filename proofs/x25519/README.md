# X25519 arithmetic validation

The fixed 5x51-bit implementation follows [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html).
It clamps scalars, ignores the peer encoding's top bit, accepts noncanonical
field encodings and returns a canonical raw shared result. The caller must reject
an all-zero result and own entropy, lifetime and the one-use exchange permission.
No TLS completion/authentication authority is represented by this primitive.

Tests cover the RFC function vectors and 1,000-iteration vector, 256 independent
OpenSSL exchange results and 2,601 Python-integer field input pairs (sum,
difference, product), plus low-order/noncanonical/high-bit cases. The seven Lean
lemmas cover limb products, convolution width, reduction congruence, subtraction
and carry-sweep bounds. They are not full ladder correctness, Rust refinement,
cryptographic security, target timing or temporary secret-erasure proofs.
