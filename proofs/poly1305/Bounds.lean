import Std.Tactic
namespace Poly1305Bounds
-- Arithmetic side conditions only, not a Rust refinement/security/timing proof.
theorem product_bound (h r : Nat) (hh : h < 2^27) (hr : r < 2^26) :
    h*r*5 < 5*2^53 := by
  have hp : h*r ≤ (2^27-1)*(2^26-1) := Nat.mul_le_mul (by omega) (by omega)
  have hs := Nat.mul_le_mul_right 5 hp
  omega

theorem convolution_fits (a b c d e : Nat)
    (ha : a < 5*2^53) (hb : b < 5*2^53) (hc : c < 5*2^53)
    (hd : d < 5*2^53) (he : e < 5*2^53) : a+b+c+d+e < 2^58 := by omega

theorem wrapped_carry_congruent (lo hi : Nat) :
    (lo + hi * 2^130) % (2^130-5) = (lo + hi*5) % (2^130-5) := by omega

theorem canonical_subtraction (h : Nat) (hh : h < 2^130) :
    (if h+5 ≥ 2^130 then h+5-2^130 else h) = h % (2^130-5) := by
  split <;> omega

-- Final sweep precondition: preceding sweeps have bounded the low carry to 5.
-- The last wrap cannot overflow the normalized low limb.
theorem last_sweep_low_fits (a b c d e : Nat)
    (ha : a < 2^26+5) (hb : b < 2^26) (hc : c < 2^26)
    (hd : d < 2^26) (he : e < 2^26) :
    a % 2^26 + 5 * ((e + (d + (c + (b + a / 2^26) / 2^26) / 2^26) / 2^26) / 2^26) < 2^26 := by
  omega
theorem first_sweep_low_fits (a b c d e : Nat)
    (ha : a < 2^58) (hb : b < 2^58) (hc : c < 2^58)
    (hd : d < 2^58) (he : e < 2^58) :
    a % 2^26 + 5 * ((e + (d + (c + (b + a / 2^26) / 2^26) / 2^26) / 2^26) / 2^26) < 2^26 + 5*2^33 := by
  omega

theorem second_sweep_low_fits (a b c d e : Nat)
    (ha : a < 2^26+5*2^33) (hb : b < 2^26) (hc : c < 2^26)
    (hd : d < 2^26) (he : e < 2^26) :
    a % 2^26 + 5 * ((e + (d + (c + (b + a / 2^26) / 2^26) / 2^26) / 2^26) / 2^26) < 2^26+5 := by
  omega
end Poly1305Bounds
