//! Owned secret lifetime and fixed-work byte comparison.
//! Volatile operations are confined to memory.rs. This prevents dead-store
//! removal of the addressed erasure and provides an optimization barrier for
//! comparisons; it does not erase historical copies/registers or establish
//! target-independent constant-time execution. Audit emitted code per target.
use core::{
    fmt,
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Deref, DerefMut},
};
#[allow(unsafe_code)]
mod memory;

pub trait Erase {
    fn erase(&mut self);
}
impl Erase for [u8] {
    fn erase(&mut self) {
        memory::erase(self)
    }
}
impl Erase for &mut [u8] {
    fn erase(&mut self) {
        memory::erase(self)
    }
}
impl<const N: usize> Erase for [u8; N] {
    fn erase(&mut self) {
        self.as_mut_slice().erase()
    }
}

/// Owns the actual value and erases its addressed storage when dropped.
/// Deliberately not Clone, Copy or a formatter exposing secret contents.
pub struct Secret<T: Erase>(T);
impl<T: Erase> Secret<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }
}
impl<T: Erase> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.erase()
    }
}
impl<T: Erase> Erase for Secret<T> {
    fn erase(&mut self) {
        self.0.erase()
    }
}
impl<T: Erase> Deref for Secret<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}
impl<T: Erase> DerefMut for Secret<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}
impl<T: Erase + AsRef<U>, U: ?Sized> AsRef<U> for Secret<T> {
    fn as_ref(&self) -> &U {
        self.0.as_ref()
    }
}
impl<T: Erase + AsMut<U>, U: ?Sized> AsMut<U> for Secret<T> {
    fn as_mut(&mut self) -> &mut U {
        self.0.as_mut()
    }
}
impl<T: Erase> fmt::Debug for Secret<T> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("Secret([REDACTED])")
    }
}

#[derive(Clone, Copy)]
pub struct Mask(u8);
impl From<u8> for Mask {
    fn from(value: u8) -> Self {
        let nonzero = 1 ^ ((u16::from(value).wrapping_sub(1) >> 8) as u8 & 1);
        Self(memory::opaque(nonzero))
    }
}
impl From<Mask> for bool {
    fn from(value: Mask) -> Self {
        value.0 != 0
    }
}
impl BitAnd for Mask {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}
impl BitOr for Mask {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}
impl BitAndAssign for Mask {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}
impl BitOrAssign for Mask {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}
pub trait FixedTimeEq {
    fn fixed_time_eq(&self, other: &Self) -> Mask;
}
impl FixedTimeEq for u8 {
    fn fixed_time_eq(&self, other: &Self) -> Mask {
        let difference = memory::opaque(*self ^ *other);
        Mask(memory::opaque(
            (u16::from(difference).wrapping_sub(1) >> 8) as u8 & 1,
        ))
    }
}
impl FixedTimeEq for [u8] {
    fn fixed_time_eq(&self, other: &Self) -> Mask {
        // Lengths and loop bounds are public. No content-dependent early return.
        if self.len() != other.len() {
            return Mask::from(0);
        }
        let mut difference = 0u8;
        for (&a, &b) in self.iter().zip(other) {
            difference |= memory::opaque(a ^ b);
        }
        difference.fixed_time_eq(&0)
    }
}
impl<const N: usize> FixedTimeEq for [u8; N] {
    fn fixed_time_eq(&self, other: &Self) -> Mask {
        self.as_slice().fixed_time_eq(other.as_slice())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_byte_pair_and_mask_matches_boolean_algebra() {
        for a in 0u8..=255 {
            for b in 0u8..=255 {
                assert_eq!(bool::from(a.fixed_time_eq(&b)), a == b);
            }
        }
        for a in 0u8..=255 {
            assert_eq!(bool::from(Mask::from(a)), a != 0);
        }
        for a in [0, 1] {
            for b in [0, 1] {
                assert_eq!(bool::from(Mask::from(a) & Mask::from(b)), a & b != 0);
                assert_eq!(bool::from(Mask::from(a) | Mask::from(b)), a | b != 0);
            }
        }
    }
    #[test]
    fn comparisons_cover_every_position_and_public_length() {
        let original = [0xa5; 64];
        assert!(bool::from(original.fixed_time_eq(&original)));
        for i in 0..64 {
            let mut other = original;
            other[i] ^= 1;
            assert!(!bool::from(original.fixed_time_eq(&other)));
        }
        assert!(bool::from([].as_slice().fixed_time_eq(&[])));
        assert!(!bool::from(
            original.as_slice().fixed_time_eq(&original[..63])
        ));
    }
    #[test]
    fn explicit_erasure_clears_storage_and_debug_is_redacted() {
        let mut value = Secret::new([0xa5; 32]);
        value.erase();
        assert_eq!(*value, [0; 32]);
        assert_eq!(
            std::format!("{:?}", Secret::new([42; 4])),
            "Secret([REDACTED])"
        );
    }
    #[test]
    fn drop_calls_the_owned_values_erasure() {
        struct Probe<'a>(&'a core::cell::Cell<bool>);
        impl Erase for Probe<'_> {
            fn erase(&mut self) {
                self.0.set(true);
            }
        }
        let observed = core::cell::Cell::new(false);
        {
            let _secret = Secret::new(Probe(&observed));
        }
        assert!(observed.get());
    }
}
