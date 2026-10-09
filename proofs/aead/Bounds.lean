import Std.Tactic
namespace AeadBounds
-- Side conditions only: not a proof of Rust refinement or AEAD security.
theorem data_counter_fits (length index : Nat)
    (h : length ≤ (2^32-1)*64) (i : index < (length+63)/64) :
    1 ≤ index+1 ∧ index+1 ≤ 2^32-1 := by omega

theorem padding_bound (n : Nat) : (16-n%16)%16 < 16 := by omega

theorem padding_aligns (n : Nat) : (n+(16-n%16)%16)%16 = 0 := by omega

theorem reserved_zero_is_not_data (index : Nat) : index+1 ≠ 0 := by omega
end AeadBounds
