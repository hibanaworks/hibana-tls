import Std.Tactic
namespace RsaPublicBounds
-- Public arithmetic bounds, not a complete Montgomery/Rust/signature proof.
theorem multiply_accumulate_fits (a b t c : Nat)
    (ha : a < 2^64) (hb : b < 2^64) (ht : t < 2^64) (hc : c < 2^64) :
    a*b+t+c < 2^128 := by
  have h := Nat.mul_le_mul (show a ≤ 2^64-1 by omega) (show b ≤ 2^64-1 by omega)
  omega

theorem carry_fits (x : Nat) (h : x < 2^128) : x / 2^64 < 2^64 := by omega

theorem doubling_fits (a c : Nat) (ha : a < 2^64) (hc : c ≤ 1) :
    2*a+c < 2^65 := by omega

theorem multiplication_index (i j limbs : Nat)
    (hi : i < limbs) (hj : j < limbs) (hl : limbs ≤ 64) : i+j < 129 := by omega

theorem reduction_carry_index (limbs : Nat) (hl : limbs ≤ 64) :
    2*limbs < 129 := by omega

theorem montgomery_one_canonical (r n : Nat) (hn : n < r) (h : r < 2*n) :
    0 < r-n ∧ r-n < n := by omega
end RsaPublicBounds
