import Std.Tactic
namespace AesNative
-- Arithmetic correspondence for the two fixed lane shifts in native.rs.
-- AES instruction semantics, CPU feature reporting, timing, and Rust memory
-- refinement are not established by this bit-vector identity.
theorem prefix_xor (key assist : BitVec 128) :
    let first := key ^^^ (key <<< 32)
    (first ^^^ (first <<< 64)) ^^^ assist =
    key ^^^ (key <<< 32) ^^^ (key <<< 64) ^^^ (key <<< 96) ^^^ assist := by
  bv_decide

theorem exact_vector_access (index : Nat) (h : index < 16) : index + 1 ≤ 16 := by
  omega
-- Every byte of the eleven expanded round keys is within the owned buffer.
theorem expanded_round_access (round byte : Nat) (hr : round ≤ 10) (hb : byte < 16) :
    16 * round + byte < 176 := by
  omega
end AesNative
