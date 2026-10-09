import Std.Tactic
namespace HkdfBounds
-- Arithmetic side conditions used by the fixed-storage Rust mechanism.
theorem counter_fits (length index : Nat) (h : length ≤ 8160)
    (i : index < (length + 31) / 32) : 1 ≤ index + 1 ∧ index + 1 ≤ 255 := by omega
theorem label_length_fits (n : Nat) (lo : 1 ≤ n) (hi : n ≤ 249) :
    7 ≤ 6 + n ∧ 6 + n ≤ 255 := by omega
theorem encoded_info_bound (label context : Nat) (hl : label ≤ 249)
    (hc : context ≤ 255) : 2 + 1 + 6 + label + 1 + context ≤ 514 := by omega
theorem output_length_fits (n : Nat) (h : n ≤ 8160) : n < 65536 := by omega
end HkdfBounds
