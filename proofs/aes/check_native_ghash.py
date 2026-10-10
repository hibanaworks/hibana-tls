"""Universal GHASH reduction correspondence; CPU instructions remain trusted."""
from z3 import BitVec, BoolVal, Extract, LShR, Or, Solver, Xor, unsat
low, high = BitVec('low', 128), BitVec('high', 128)
overflow = LShR(high, 127) ^ LShR(high, 126) ^ LShR(high, 121)
actual = low ^ high ^ (high << 1) ^ (high << 2) ^ (high << 7)
actual ^= overflow ^ (overflow << 1) ^ (overflow << 2) ^ (overflow << 7)
# Polynomial long division expressed as coefficient XOR, avoiding conditional
# copies of entire 256-bit words. The symbolic input still ranges over all bits.
reference = [Extract(i, i, low) == 1 for i in range(128)]
reference += [Extract(i, i, high) == 1 for i in range(128)]
for bit in range(255, 127, -1):
    coefficient = reference[bit]
    reference[bit] = BoolVal(False)
    for offset in (0, 1, 2, 7):
        index = bit - 128 + offset
        reference[index] = Xor(reference[index], coefficient)
solver = Solver()
solver.set(timeout=120000)
solver.add(Or(*[(Extract(i, i, actual) == 1) != reference[i] for i in range(128)]))
result = solver.check()
assert result == unsat, result
print('GHASH two-fold reduction equals polynomial long division: UNSAT counterexample')
