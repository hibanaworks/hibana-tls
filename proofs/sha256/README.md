# SHA-256 proof boundary

`Bounds.lean` proves six buffer/length and 32-bit boolean identities used by the
byte-oriented implementation. Run with Lean 4.30.0. These are mathematical
obligations, not a source-to-machine refinement proof, collision-resistance
proof, constant-time guarantee, certification or completed crypto audit.

The executable source follows FIPS 180-4 sections 5 and 6.2. Its four tests cover
published known answers, a million-byte message, all splits through 193 bytes,
and transactional overflow rejection. Complete CAVP/differential coverage,
full compression correspondence and target-machine review remain required.
