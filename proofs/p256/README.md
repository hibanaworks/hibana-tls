# P-256 qualification scope

Own four-limb Montgomery arithmetic supplies both the field and scalar order.
Jacobian addition/doubling and fixed 256-bit scalar multiplication supply ECDH
and ECDSA. Deterministic SHA-256 ECDSA uses RFC 6979, including bits2octets
reduction and retry of invalid candidates. The private-key owner is non-Clone;
ECDH consumes it. Strict DER rejects nonminimal lengths/integers, wrong curve
identifiers, trailing fields, truncation and inconsistent included public keys.

References: [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979.html),
[FIPS 186-5](https://doi.org/10.6028/NIST.FIPS.186-5), and
[SEC 1 v2](https://www.secg.org/sec1-v2.pdf).

Tests: RFC6979 P-256/SHA-256 known answer; 1,040 independent Python modular
records; 128 OpenSSL public keys/ECDH exchanges and deterministic/reference
signature pairs, compressed points, hash mutations; 16 OpenSSL SEC1/PKCS8 keys
and all truncated prefixes. The nine Lean facts cover multiply/carry/index
bounds, single-subtraction canonicalization and constant identities only.
They do not prove complete Montgomery reduction, elliptic-curve formulas,
ECDSA security, Rust refinement, secret erasure or constant-time machine code.
Safe-Rust Drop overwrites the owned scalar but does not guarantee that the
compiler preserves erasure or that arithmetic temporaries are erased.
No production side-channel/secret-erasure qualification is claimed.
