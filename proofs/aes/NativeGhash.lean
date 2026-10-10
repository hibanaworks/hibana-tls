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
-- The streaming implementation keeps the accumulator reflected between blocks.
-- This establishes equivalence for every finite sequence, assuming the same
-- native polynomial multiplication operation used by the block implementation.
theorem reverse_xor (x y : BitVec 128) :
    (x ^^^ y).reverse = x.reverse ^^^ y.reverse := by
  bv_decide

def blockStep (mul : BitVec 128 → BitVec 128 → BitVec 128)
    (h y block : BitVec 128) : BitVec 128 :=
  (mul (y ^^^ block).reverse h.reverse).reverse

def reflectedStep (mul : BitVec 128 → BitVec 128 → BitVec 128)
    (h y block : BitVec 128) : BitVec 128 :=
  mul (y ^^^ block.reverse) h.reverse

theorem reflected_fold (mul : BitVec 128 → BitVec 128 → BitVec 128)
    (h y : BitVec 128) (blocks : List (BitVec 128)) :
    (blocks.foldl (blockStep mul h) y).reverse =
      blocks.foldl (reflectedStep mul h) y.reverse := by
  induction blocks generalizing y with
  | nil => rfl
  | cons block rest ih =>
    simp only [List.foldl_cons]
    rw [ih]
    simp only [blockStep, reflectedStep, BitVec.reverse_reverse_eq, reverse_xor]
end NativeGhash
