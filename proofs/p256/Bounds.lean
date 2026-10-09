import Std.Tactic
namespace P256Bounds
-- Local arithmetic obligations only. No claim of full REDC/curve/Rust refinement.
theorem limb_multiply_accumulate_fits (a b t c : Nat)
    (ha : a < 2^64) (hb : b < 2^64) (ht : t < 2^64) (hc : c < 2^64) :
    a*b+t+c < 2^128 := by
  have h := Nat.mul_le_mul (show a ≤ 2^64-1 by omega) (show b ≤ 2^64-1 by omega)
  omega

theorem carry_fits (x : Nat) (h : x < 2^128) : x / 2^64 < 2^64 := by omega

theorem propagation_fits (t c : Nat) (ht : t < 2^64) (hc : c < 2^64) :
    t+c < 2^65 := by omega

theorem product_index (i j : Nat) (hi : i < 4) (hj : j < 4) : i+j < 8 := by omega

theorem carry_index (i : Nat) (hi : i < 4) : i+4 < 9 := by omega

theorem one_subtraction_canonical (m x : Nat) (hx : x < 2*m) :
    (if x < m then x else x-m) < m := by split <;> omega

theorem p_low_inverse : ((2^64-1)*1+1) % 2^64 = 0 := by decide

theorem n_low_inverse :
    (0xf3b9cac2fc632551*0xccd1c8aaee00bc4f+1) % 2^64 = 0 := by decide

theorem square_root_exponent :
    4*0x3fffffffc0000000400000000000000000000000400000000000000000000000 =
    2^256-2^224+2^192+2^96 := by decide
end P256Bounds
