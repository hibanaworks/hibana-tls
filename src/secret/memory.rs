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
#[cfg(feature = "alloc")]
pub(super) fn erase_allocation(bytes: &mut alloc::vec::Vec<u8>) {
    let pointer = bytes.as_mut_ptr();
    for index in 0..bytes.capacity() {
        // SAFETY: index is within this Vec's uniquely borrowed allocation.
        // Writing a u8 is valid even in spare capacity; no uninitialized value
        // is read, and u8 has no invalid bit patterns or destructor. For zero
        // capacity this loop is empty and the dangling pointer is never used.
        unsafe { core::ptr::write_volatile(pointer.add(index), 0) };
    }
    compiler_fence(Ordering::SeqCst);
    bytes.clear();
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    #[test]
    fn erases_live_and_previously_initialized_spare_capacity() {
        let mut bytes = alloc::vec![0xa5;64];
        bytes.truncate(3);
        let capacity = bytes.capacity();
        erase_allocation(&mut bytes);
        assert_eq!(bytes.len(), 0);
        assert_eq!(bytes.capacity(), capacity);
        for byte in bytes.spare_capacity_mut() {
            // SAFETY: erase_allocation initialized every capacity byte above;
            // the allocation remains live and uniquely borrowed throughout.
            assert_eq!(unsafe { byte.assume_init() }, 0);
        }
        erase_allocation(&mut alloc::vec::Vec::new());
    }
}
