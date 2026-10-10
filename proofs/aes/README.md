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

On x86-64, checked CPU capabilities select AES-NI and PCLMULQDQ arithmetic.
Other targets and Miri use the portable arithmetic. QUIC packet material retains
only immutable arithmetic function pointers alongside its owned key storage;
CPU detection is outside the per-packet path. Neither backend allocates or
requires an operating-system service.

`Native.lean` and `check_native.py` verify the XOR prefix identity used by the
AES-NI key expansion. `NativeGhash.lean` bounds the polynomial reduction folds;
`check_native_ghash.py` checks their equivalence to GF(2) long division for every
256-bit product. These are arithmetic lemmas, not a proof of CPU instruction
semantics or of the complete Rust-to-machine-code implementation. Differential
Rust tests compare the selected AES implementation against the portable one,
and GHASH multiplication across all polynomial basis pairs and mixed inputs.
Miri exercises the portable memory paths; it does not execute the native
instruction backend.

The native GCM counter pass expands the round keys once per operation into a
176-byte Secret-owned buffer. Full blocks use bounded vector XOR; short tails
use a separate 16-byte buffer. Both temporary buffers follow the secret erasure
contract. Native counter tests compare whole and partial packet lengths against
the portable transform. The expanded-round access lemma bounds all eleven
16-byte key slots; it does not establish compiler register erasure.
