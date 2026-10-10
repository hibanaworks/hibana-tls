//! The only permitted unsafe boundary: volatile accesses to valid owned bytes.
//! No pointer escapes, allocation, foreign call or protocol state lives here.
use core::sync::atomic::{Ordering, compiler_fence};

#[inline(never)]
pub(super) fn opaque(value: u8) -> u8 {
    // SAFETY: value is initialized, aligned and alive for this synchronous read.
    // Volatile prevents replacing this read by compile-time knowledge of value.
    unsafe { core::ptr::read_volatile(&value) }
}
pub(super) fn erase(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: the unique slice borrow guarantees one writable live u8.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn erases_the_complete_owned_storage() {
        let mut bytes = [0xa5; 64];
        erase(&mut bytes);
        assert_eq!(bytes, [0; 64]);
        erase(&mut []);
    }
}
