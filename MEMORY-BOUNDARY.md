# Owned memory boundary (under integration qualification)

The owner explicitly authorized a minimal unsafe boundary for removing subtle
and zeroize. Unsafe is denied by default and permitted only in secret/memory.rs.
QUIC's own unsafe prohibition is unchanged. No code from either dependency is
copied. The default TLS/QUIC normal/build graph contains only the project crates
and pinned Hibana; Host networking and independent test dependencies remain.

Production unsafe sites:
1. read_volatile of the initialized stack u8 passed to opaque; its reference is
   aligned/live for the synchronous read and never escapes.
2. write_volatile through each uniquely borrowed mutable slice element.
3. Optional Host Vec<u8> allocation erasure: every index < capacity lies in the
   uniquely borrowed allocation. Writes initialize spare capacity without reading
   it; u8 has no invalid representations/destructors. Zero capacity never uses
   its dangling pointer. Length is cleared only after writes and a compiler fence.

A Miri-only assertion reads spare capacity after every byte has been initialized
by the erasure; the allocation remains live and owned. This is not a dangling
read after free. Secret<T> drop calls T's Erase implementation and does not expose
contents in Debug. There is no Clone/Copy implementation on Secret.

Comparison visits every byte for equal public lengths. Per-byte differences and
final masks cross volatile-read optimization barriers. Masks use arithmetic and
bitwise composition; length mismatch and loop counts depend on public lengths.
Miri tests enumerate all 65,536 byte pairs, every differing position of a 64-byte
array, public lengths, mask algebra, drop and allocated capacity erasure.

Generated-code review: Rust1.95.0 (59807616e), opt-level3, x86_64-unknown-linux-gnu
and thumbv6m-none-eabi. Exact source copies are used by the audit harness. Both
fixed-length comparison loops branch only on the public 64-byte count; slice
comparison branches additionally on public lengths. Final byte equality uses
arithmetic/set instructions rather than content-dependent jumps. 64-byte addressed
erasure retains all 64 stores; LLVM IR retains volatile stores and compiler fence.
This is a scoped inspection, NOT an all-target/all-optimizer or timing proof.

Limits: volatile writes protect the addressed writes from dead-store elimination.
They do not erase earlier copies, registers, swap, crash dumps or every arithmetic
temporary. Constant-time behavior requires target/compiler requalification. An
opaque barrier has overhead. No claim of complete cryptographic side-channel
qualification is made. P256's actual owned scalar and RFC6979 K/V now use this
same addressed erasure; other historical arithmetic copies remain unqualified.
