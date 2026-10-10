import Std.Tactic
namespace NativeGhash
-- Bound the only overflow in the first fixed polynomial reduction fold.
-- CPU instruction semantics and Rust memory refinement remain separate.
def overflow (high : BitVec 128) : BitVec 128 :=
  (high >>> 127) ^^^ (high >>> 126) ^^^ (high >>> 121)
theorem overflow_has_seven_bits (high : BitVec 128) :
    overflow high >>> 7 = 0 := by
  unfold overflow
  bv_decide
theorem second_fold_has_no_high_half (high : BitVec 128) :
    let carry := overflow high
    (carry ^^^ (carry <<< 1) ^^^ (carry <<< 2) ^^^ (carry <<< 7)) >>> 14 = 0 := by
  unfold overflow
  bv_decide
end NativeGhash
