import Std.Tactic
namespace X25519Bounds
-- Arithmetic obligations, not a ladder/Rust/security/timing refinement proof.
theorem product_fits (a b : Nat) (ha : a < 2^52) (hb : b < 2^52) :
    a*b*19 < 19*2^104 := by
  have h := Nat.mul_le_mul (show a ≤ 2^52-1 by omega) (show b ≤ 2^52-1 by omega)
  have h' := Nat.mul_le_mul_right 19 h
  omega

theorem convolution_fits (a b c d e : Nat)
    (ha : a < 19*2^104) (hb : b < 19*2^104) (hc : c < 19*2^104)
    (hd : d < 19*2^104) (he : e < 19*2^104) : a+b+c+d+e < 2^111 := by omega

theorem wrapped_carry_congruent (lo hi : Nat) :
    (lo + hi*2^255) % (2^255-19) = (lo+hi*19) % (2^255-19) := by omega

theorem subtraction_nonnegative (a b : Nat) (hb : b < 2^51) :
    b ≤ a+2*(2^51-19) := by omega

theorem first_sweep_low_fits (a b c d e : Nat)
    (ha : a < 2^111) (hb : b < 2^111) (hc : c < 2^111)
    (hd : d < 2^111) (he : e < 2^111) :
    a%2^51 + 19*((e+(d+(c+(b+a/2^51)/2^51)/2^51)/2^51)/2^51) < 2^51+19*2^61 := by omega

theorem second_sweep_low_fits (a b c d e : Nat)
    (ha : a < 2^51+19*2^61) (hb : b < 2^51) (hc : c < 2^51)
    (hd : d < 2^51) (he : e < 2^51) :
    a%2^51 + 19*((e+(d+(c+(b+a/2^51)/2^51)/2^51)/2^51)/2^51) < 2^51+19 := by omega

theorem third_sweep_low_fits (a b c d e : Nat)
    (ha : a < 2^51+19) (hb : b < 2^51) (hc : c < 2^51)
    (hd : d < 2^51) (he : e < 2^51) :
    a%2^51 + 19*((e+(d+(c+(b+a/2^51)/2^51)/2^51)/2^51)/2^51) < 2^51 := by omega
end X25519Bounds
