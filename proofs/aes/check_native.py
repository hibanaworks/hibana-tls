"""Fixed-width key-expansion arithmetic, not a hardware or timing proof."""
from z3 import BitVec, Solver, unsat
key, assist = BitVec('key', 128), BitVec('assist', 128)
first = key ^ (key << 32)
actual = first ^ (first << 64) ^ assist
expected = key ^ (key << 32) ^ (key << 64) ^ (key << 96) ^ assist
solver = Solver()
solver.add(actual != expected)
assert solver.check() == unsat
print('AES native key-prefix XOR identity: UNSAT counterexample')
