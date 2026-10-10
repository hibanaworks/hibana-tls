//! Borrowed TLS message storage and erasure.
use crate::handshake::{Error, Failure};
use core::cell::{Cell, RefCell};
/// Caller-owned space for one complete TLS handshake message. No allocation,
/// clone of secret-bearing buffers, or arbitrary message queue is introduced.
pub struct MessageSlot<'a> {
    pub(in crate::handshake) bytes: RefCell<Option<&'a mut [u8]>>,
    pub(in crate::handshake) len: Cell<usize>,
}
impl<'a> MessageSlot<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self {
            bytes: RefCell::new(Some(bytes)),
            len: Cell::new(0),
        }
    }
    pub(in crate::handshake) fn apply<T>(
        &self,
        f: impl FnOnce(&[u8]) -> Result<T, Failure>,
    ) -> Result<T, Error> {
        let n = self.len.get();
        if n == 0 {
            return Err(Error::Binding);
        }
        let bytes = self.bytes.borrow();
        let bytes = bytes.as_deref().ok_or(Error::Binding)?;
        f(&bytes[..n]).map_err(Error::Crypto)
    }
    pub fn into_buffer(self) -> Result<&'a mut [u8], Error> {
        self.bytes.into_inner().ok_or(Error::Binding)
    }
    pub(in crate::handshake) fn clear(&self) {
        use crate::secret::Erase;
        let n = self.len.replace(0);
        if let Some(bytes) = self.bytes.borrow_mut().as_deref_mut() {
            bytes[..n].erase();
        }
    }
}
