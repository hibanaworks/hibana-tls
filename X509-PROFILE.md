# Project-owned X.509 candidate

The certificate module now uses project-owned parsing, types, signature dispatch
and path verification. rustls-webpki, rustls-pki-types and untrusted are absent
from the production TLS dependency graph; no copied webpki source is retained.
The independently allocating Rustls/rcgen reference tests are still external.

The public certificate input types are borrowed; neither parsing nor successful
chain validation mints TLS Finished authority. CertificateVerify and Finished
must still succeed in the Hibana handshake. The path search is a bounded pure
calculation over supplied public certificate bytes, not a second handshake
progress machine. No clock, root download, allocation or network access occurs.

Supported bounded profile:
- Canonical definite-length DER and X509v3; positive serial <=20 octets
- Exact inner/outer signature identifiers and exact signed TBS bytes
- Injected time; canonical UTC/GeneralizedTime, calendar/ordering validation
- P256/SHA256, RSA2048/3072/4096 with SHA256 PKCS1 (certificate-only) and PSS
  with SHA256/MGF1-SHA256/salt32; no algorithm downgrade or invalid fallback
- DNS/IP SAN only, no common-name fallback; case-insensitive DNS and one-label
  whole-label wildcard, at least two suffix labels
- BasicConstraints, path length, leaf digitalSignature and issuer keyCertSign
  where KU exists, serverAuth EKU, duplicate extensions and unknown critical
  extension rejection
- DNS/IP permitted/excluded subtrees checked against every descendant SAN
- <=8 intermediates, <=32 provisioned trust anchors, <=100 signature attempts
- Trust anchor names/SPKI/constraints are supplied by an explicit caller trust
  decision; a root self-signature/date does not establish trust

Conservative compatibility differences (not silently ignored):
- v1/v2 certificates/roots and issuer/subject unique IDs reject
- Directory-name and other unsupported NameConstraints reject, as do non-default
  subtree distances, noncontiguous IP masks and DNS wildcards under constraints
- Exact DER issuer/subject matching; no general directory-name normalization
- DNS trailing dot/underscore names and bare-TLD wildcards reject
- Unknown critical extensions and unsupported policy extensions reject;
  noncritical policy data does not add authorization
- No revocation fetch/check or general purpose browser-PKI qualification

Tests: public P256 chain and CertificateVerify fixtures; full truncated-prefix
rejection; strict length/integer/OID/time/name tests; independent OpenSSL signed
permitted/excluded/pathlen/EKU/critical/DNS/IP fixtures. Broader Host/reference
and target qualification is tracked in the checkpoint evidence, not inferred
from the existence of these tests. This is not a cryptographic security audit.
