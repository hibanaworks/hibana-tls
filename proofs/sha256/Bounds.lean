import Std.Tactic
import Std.Tactic.BVDecide

namespace Sha256Bounds
-- The fixed block buffer has 64 bytes; the length occupies the final eight.
theorem buffered_index (used : Nat) (h : used < 64) : used + 1 ≤ 64 := by omega
theorem short_padding_fits (used : Nat) (h : used < 56) : used + 1 ≤ 56 := by omega
theorem long_padding_two_blocks (used : Nat) (lo : 56 ≤ used) (hi : used < 64) :
    used + 1 ≤ 64 ∧ 56 + 8 = 64 := by omega
theorem message_bits_fit (bytes : Nat) (h : bytes ≤ 2305843009213693951) :
    bytes * 8 < 18446744073709551616 := by omega

-- Algebraic identities for the exact 32-bit boolean round operations.
theorem choose_identity (x y z : BitVec 32) :
    (x &&& y) ^^^ ((~~~x) &&& z) = z ^^^ (x &&& (y ^^^ z)) := by bv_decide
theorem majority_identity (x y z : BitVec 32) :
    (x &&& y) ^^^ (x &&& z) ^^^ (y &&& z) = (x &&& y) ||| (z &&& (x ||| y)) := by bv_decide
end Sha256Bounds
