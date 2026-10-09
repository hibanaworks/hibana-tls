# Quarter-round invertibility

Run with Lean 4.30: `lean QuarterRound.lean`.

The theorem proves that the explicit inverse recovers all four 32-bit words of
the specified add/XOR/rotate quarter round. It does not prove the full 20-round
block's security, Rust refinement, secret erasure or constant-time execution.
Rust known-answer tests use RFC 8439 sections 2.1.1 and 2.3.2.
