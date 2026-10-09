# Direct TLS ownership integration

## Implemented product path

- TLS owns BoundedTls, KeySource, the numerical operations and projected locals.
  QUIC's old handshake module is a type reexport; its private implementation
  directory has been removed.
- QUIC embeds `owned_global` in its existing composed global and registers the
  material HANDOFF role. VERIFY sends KeysReady and waits for KeysTaken; only
  then may INPUT overwrite its message or proceed to the next request.
- The transit slots contain actual HandshakeKeyMaterial,
  ApplicationKeyMaterial and Finished<P> values. Taking a slot moves its value.
  Application installation consumes the shared scope's affine permission.
- Finished<P> carries the TLS-minted FinishedAuthenticated receipt and the
  authenticated peer parameters. No public success constructor or mutable
  KeySource material escape was added to cross the crate boundary.
- QUIC directional owners retain packet number, replay, confirmation and
  retirement responsibilities. TLS Finished is not QUIC key-update permission.
- TLS's old State, key-created/key-discarded flags, schedule Stage/with_psk
  and packet/RX active flags are gone. Outbound encryption level is selected
  from actual ordered byte spans, not a tx_post_handshake flag.
- Cancelled/erroring verification locals fail their material closed; slots
  own secret-bearing values until consumed or dropped. Projected Taken is not
  considered successful until the transit slots are empty.

## Deliberate limits and remaining work

The raw two-participant reference locals now borrow ordinary RefCells directly
using Rust's BorrowMut contract. CryptoAccess, SourceAccess, with_crypto,
client_source_owner/server_source_owner, client_transcript_role and the private
material escape method have been removed. Test transport wakes and allocation
measurement live in the test polling code, not a TLS forwarding callback.

Scoped reference fixtures, recovery tests, early-data owner tests and the
connection-loss inspector now run the three-party owned locals and retain the
actual transferred key/Finished values. They cannot retrieve duplicate material
from KeySource after its HANDOFF local consumed it.

Configuration choices, branch-local values, buffer lengths and one-shot resource
identity checks remain where they represent data or ownership rather than a
second TLS progression controller. Raw arithmetic/parser helpers also remain.

The reference/dev workspace retains independent rustls/ring and test generators.
Production normal/build dependency closures contain only owned Hibana crates.
A zero external production-package count is not a security proof. Full official
interop-runner execution, independent security review and comprehensive target
side-channel/erasure qualification have not been established by this migration.
Mac execution is deferred by the user. Core portability and native Host execution
are separate checks.

## Regression evidence to retain

The paired checkpoint records full QUIC, TLS, Host, reference, strict TLS Clippy,
thumbv6m and dependency/controller-ratchet results separately. Never treat an
in-progress log, an earlier passing source revision or an abstract graph model
as a final cryptographic end-to-end pass.

The two ACK-loss fixtures now require a real dropped ACK-only packet after
application receipt before releasing their response, and assert zero delivered
application ACKs. The old fixture allowed a real ACK coalesced with STREAM data;
that correctly acknowledged the request. Loss masks and completion assertions
were not relaxed to make the migrated implementation pass.
