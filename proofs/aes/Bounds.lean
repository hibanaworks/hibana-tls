import Std.Tactic
namespace AesGcmBounds
-- Length/index obligations only. Not a Rust refinement or security proof.
theorem shift_rows_index (column row : Nat) (hr : row < 4) :
    4 * ((column + row) % 4) + row < 16 := by omega

theorem byte_mask_bounds (x : Nat) (hx : x < 256) : x / 128 ≤ 1 := by omega

theorem bit_length_fits (n : Nat) (hn : n ≤ (2^64-1)/8) : n*8 < 2^64 := by omega

theorem counter_fits (bytes index : Nat)
    (hb : bytes ≤ (2^32-2)*16) (hi : index < (bytes+15)/16) :
    2 ≤ index+2 ∧ index+2 < 2^32 := by omega

theorem payload_counter_not_j0 (index : Nat) : index+2 ≠ 1 := by omega

theorem padding_is_short (n : Nat) : (16-n%16)%16 < 16 := by omega
end AesGcmBounds
