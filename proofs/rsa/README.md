# RSA public arithmetic

The primitive computes only the public RSAVP1 representative for exact
2048/3072/4096-bit odd moduli and odd public exponents fitting u32. Output is
unchanged on invalid input. It neither parses keys nor verifies padding/trust.
Public-dependent branches are allowed here. Never use this implementation for
RSA signing, private-key operations, key generation or decryption.

144 Python integer pow comparisons cover all widths, public exponent extremes,
zero/one/near-modulus representatives and carry-heavy moduli. The existing QUIC
reference corpus independently checks actual RSA-PSS and PKCS1 signatures.
Six Lean lemmas cover limb accumulator/carry bounds, buffer indexing and the
Montgomery encoding of one. They are not a proof of the complete reduction or
exponentiation algorithm, Rust refinement, padding security or certificate trust.
Reference: RFC 8017, https://www.rfc-editor.org/rfc/rfc8017.html .
