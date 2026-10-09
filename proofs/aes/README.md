# AES/GCM validation scope

The six Lean lemmas in Bounds.lean cover AES row indexing, byte-mask bounds,
64-bit encoded lengths, and GCM's reserved/non-wrapping block counters. They do
not prove the Rust implementation refines AES/GHASH, cryptographic security,
constant-time compiled instructions or erasure of stack temporaries.

The Rust implementation uses fixed-loop field arithmetic, without secret-indexed
S-box tables. Tests include the FIPS 197 cipher example, standard zero-key GCM
vectors, exhaustive byte inversion/permutation checks, 256 independently generated
AES block cases, and 231 independent AES-GCM cases including partial blocks and
AAD. Authentication failure is checked before modifying caller ciphertext.

References: [FIPS 197](https://doi.org/10.6028/NIST.FIPS.197-upd1),
[SP 800-38D](https://doi.org/10.6028/NIST.SP.800-38D).
This implementation is unqualified for production security use. Performance and
machine-code timing require separate target measurements.
