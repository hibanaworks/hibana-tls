import Std.Tactic.BVDecide
namespace ChaCha20
abbrev Word := BitVec 32
def quarter (a b c d : Word) : Word × Word × Word × Word :=
  let a := a + b
  let d := (d ^^^ a).rotateLeft 16
  let c := c + d
  let b := (b ^^^ c).rotateLeft 12
  let a := a + b
  let d := (d ^^^ a).rotateLeft 8
  let c := c + d
  let b := (b ^^^ c).rotateLeft 7
  (a,b,c,d)
def inverse (words : Word × Word × Word × Word) : Word × Word × Word × Word :=
  let (a,b,c,d) := words
  let b := b.rotateRight 7 ^^^ c
  let c := c - d
  let d := d.rotateRight 8 ^^^ a
  let a := a - b
  let b := b.rotateRight 12 ^^^ c
  let c := c - d
  let d := d.rotateRight 16 ^^^ a
  let a := a - b
  (a,b,c,d)
theorem quarter_inverse (a b c d : Word) : inverse (quarter a b c d) = (a,b,c,d) := by
  unfold quarter inverse
  simp only [Word, BitVec.rotateLeft, BitVec.rotateLeftAux, BitVec.rotateRight, BitVec.rotateRightAux]
  apply Prod.ext
  · bv_decide
  · apply Prod.ext
    · bv_decide
    · apply Prod.ext <;> bv_decide
end ChaCha20
