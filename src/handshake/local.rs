//! Direct TLS transcript roles for `protocol`.
//!
//! The numerical operations never dispatch on a handwritten TLS phase. The
//! owner's async continuation and the projected endpoints determine order.
//! The QUIC connection and its transcript tests embed these roles directly.
use super::{BoundedTls, Failure, Mode, global as p};
use crate::endpoint::Level;
use core::{
    cell::{Cell, RefCell},
    future::Future,
};
use hibana::{Endpoint, EndpointError};

#[derive(Debug)]
pub enum Error {
    Endpoint(EndpointError),
    Crypto(Failure),
    Binding,
    Capacity,
    Input(crate::endpoint::Error),
}
impl From<EndpointError> for Error {
    fn from(e: EndpointError) -> Self {
        Self::Endpoint(e)
    }
}
impl From<Failure> for Error {
    fn from(e: Failure) -> Self {
        Self::Crypto(e)
    }
}
/// Caller-owned space for one complete TLS handshake message. No allocation,
/// clone of secret-bearing buffers, or arbitrary message queue is introduced.
pub struct MessageSlot<'a> {
    bytes: RefCell<Option<&'a mut [u8]>>,
    len: Cell<usize>,
}
impl<'a> MessageSlot<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self {
            bytes: RefCell::new(Some(bytes)),
            len: Cell::new(0),
        }
    }
    fn apply<T>(&self, f: impl FnOnce(&[u8]) -> Result<T, Failure>) -> Result<T, Error> {
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
    fn clear(&self) {
        use crate::secret::Erase;
        let n = self.len.replace(0);
        if let Some(bytes) = self.bytes.borrow_mut().as_deref_mut() {
            bytes[..n].erase();
        }
    }
}
/// A CRYPTO-stream adapter must return exactly one complete TLS message at the
/// requested level, including its four-byte handshake header. It must retain
/// following messages for later calls and reject wrong-level input.
pub trait MessageInput {
    fn read_message(
        &mut self,
        level: Level,
        bytes: &mut [u8],
    ) -> impl Future<Output = Result<usize, Error>>;
}
/// Exclusive ownership of the input buffer while I/O is pending. No RefCell
/// guard crosses an await. Partial bytes are erased even before len is committed.
struct InputLease<'s, 'buf> {
    slot: &'s MessageSlot<'buf>,
    bytes: Option<&'buf mut [u8]>,
}
impl Drop for InputLease<'_, '_> {
    fn drop(&mut self) {
        use crate::secret::Erase;
        if let Some(bytes) = self.bytes.take() {
            bytes.erase();
            *self.slot.bytes.borrow_mut() = Some(bytes);
        }
    }
}
async fn fill(
    slot: &MessageSlot<'_>,
    io: &mut impl MessageInput,
    level: Level,
) -> Result<(), Error> {
    if slot.len.get() != 0 {
        return Err(Error::Binding);
    }
    let bytes = slot.bytes.borrow_mut().take().ok_or(Error::Binding)?;
    let mut lease = InputLease {
        slot,
        bytes: Some(bytes),
    };
    let bytes = lease.bytes.as_deref_mut().ok_or(Error::Binding)?;
    let n = io.read_message(level, bytes).await?;
    if n < 4 || n > bytes.len() {
        return Err(Error::Capacity);
    }
    let encoded = ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | bytes[3] as usize;
    if encoded.checked_add(4) != Some(n) {
        return Err(Error::Binding);
    }
    *slot.bytes.borrow_mut() = lease.bytes.take();
    slot.len.set(n);
    Ok(())
}

/// Cancellation erases the pending message and the actually borrowed material.
struct Owner<'a, 'slot, 'cfg, 'buf, T: core::borrow::BorrowMut<BoundedTls<'cfg, 'buf>>> {
    tls: &'a RefCell<T>,
    slot: &'a MessageSlot<'slot>,
    material: core::marker::PhantomData<BoundedTls<'cfg, 'buf>>,
}
impl<'cfg, 'buf, T: core::borrow::BorrowMut<BoundedTls<'cfg, 'buf>>> Drop
    for Owner<'_, '_, 'cfg, 'buf, T>
{
    fn drop(&mut self) {
        self.slot.clear();
        self.tls.borrow_mut().borrow_mut().fail(Failure::State);
    }
}

pub async fn client_owner<'cfg, 'buf, T: core::borrow::BorrowMut<BoundedTls<'cfg, 'buf>>>(
    endpoint: &mut Endpoint<'_, { p::VERIFY }>,
    tls: &RefCell<T>,
    slot: &MessageSlot<'_>,
) -> Result<(), Error> {
    if !{
        let mut value = tls.borrow_mut();
        let t = value.borrow_mut();
        matches!(t.mode, Mode::Client(_)) && t.pristine()
    } {
        return Err(Error::Binding);
    }
    let owner = Owner {
        tls,
        slot,
        material: core::marker::PhantomData,
    };
    endpoint.send::<p::NeedHello>(&()).await?;
    endpoint.recv::<p::Hello>().await?;
    let hello = slot.apply(|m| owner.tls.borrow_mut().borrow_mut().client_hello(m, false))?;
    slot.clear();
    endpoint.send::<p::Applied>(&()).await?;

    // Negotiation is retained by this projected local continuation only.
    // The numeric material contains no resumption-selection control flag.
    let resumed = if let Some(resumed) = hello {
        endpoint.send::<p::HelloReady>(&()).await?;
        resumed
    } else {
        endpoint.send::<p::Retry>(&()).await?;
        endpoint.send::<p::NeedRetryHello>(&()).await?;
        endpoint.recv::<p::RetryHello>().await?;
        let resumed = slot
            .apply(|m| owner.tls.borrow_mut().borrow_mut().client_hello(m, true))?
            .ok_or(Error::Binding)?;
        slot.clear();
        endpoint.send::<p::Applied>(&()).await?;
        resumed
    };
    endpoint.send::<p::NeedExtensions>(&()).await?;
    endpoint.recv::<p::Extensions>().await?;
    slot.apply(|m| {
        owner
            .tls
            .borrow_mut()
            .borrow_mut()
            .client_extensions(m, resumed)
    })?;
    slot.clear();
    endpoint.send::<p::Applied>(&()).await?;

    if resumed {
        endpoint.send::<p::Resumed>(&()).await?;
    } else {
        endpoint.send::<p::Full>(&()).await?;
        endpoint.send::<p::NeedCertificate>(&()).await?;
        endpoint.recv::<p::Certificate>().await?;
        slot.apply(|m| owner.tls.borrow_mut().borrow_mut().client_certificate(m))?;
        slot.clear();
        endpoint.send::<p::Applied>(&()).await?;

        endpoint.send::<p::NeedCertificateVerify>(&()).await?;
        endpoint.recv::<p::CertificateVerify>().await?;
        slot.apply(|m| {
            owner
                .tls
                .borrow_mut()
                .borrow_mut()
                .client_certificate_verify(m)
        })?;
        slot.clear();
        endpoint.send::<p::Applied>(&()).await?;
    }
    endpoint.send::<p::NeedFinished>(&()).await?;
    endpoint.recv::<p::Finished>().await?;
    slot.apply(|m| owner.tls.borrow_mut().borrow_mut().client_finished(m))?;
    owner
        .tls
        .borrow_mut()
        .borrow_mut()
        .record_verified_finished(resumed);
    slot.clear();
    endpoint.send::<p::Applied>(&()).await?;

    endpoint.send::<p::Complete>(&()).await?;
    // Only this successful Hibana continuation discharges cancellation.
    // The guard contains borrowed references only; no owned buffer/key is leaked.
    core::mem::forget(owner);
    Ok(())
}

pub async fn server_owner<'cfg, 'buf, T: core::borrow::BorrowMut<BoundedTls<'cfg, 'buf>>>(
    endpoint: &mut Endpoint<'_, { p::VERIFY }>,
    tls: &RefCell<T>,
    slot: &MessageSlot<'_>,
) -> Result<(), Error> {
    if !{
        let mut value = tls.borrow_mut();
        let t = value.borrow_mut();
        matches!(t.mode, Mode::Server(_)) && t.pristine()
    } {
        return Err(Error::Binding);
    }
    let owner = Owner {
        tls,
        slot,
        material: core::marker::PhantomData,
    };
    endpoint.send::<p::NeedHello>(&()).await?;
    endpoint.recv::<p::Hello>().await?;
    let hello = slot.apply(|m| owner.tls.borrow_mut().borrow_mut().server_hello(m, false))?;
    slot.clear();
    endpoint.send::<p::Applied>(&()).await?;

    // Negotiation is retained by this projected local continuation only.
    // The numeric material contains no resumption-selection control flag.
    let resumed = if let Some(resumed) = hello {
        endpoint.send::<p::HelloReady>(&()).await?;
        resumed
    } else {
        endpoint.send::<p::Retry>(&()).await?;
        endpoint.send::<p::NeedRetryHello>(&()).await?;
        endpoint.recv::<p::RetryHello>().await?;
        let resumed = slot
            .apply(|m| owner.tls.borrow_mut().borrow_mut().server_hello(m, true))?
            .ok_or(Error::Binding)?;
        slot.clear();
        endpoint.send::<p::Applied>(&()).await?;
        resumed
    };
    endpoint.send::<p::NeedFinished>(&()).await?;
    endpoint.recv::<p::Finished>().await?;
    slot.apply(|m| owner.tls.borrow_mut().borrow_mut().server_finished(m))?;
    owner
        .tls
        .borrow_mut()
        .borrow_mut()
        .record_verified_finished(resumed);
    slot.clear();
    endpoint.send::<p::Applied>(&()).await?;

    endpoint.send::<p::Complete>(&()).await?;
    // Only this successful Hibana continuation discharges cancellation.
    // The guard contains borrowed references only; no owned buffer/key is leaked.
    core::mem::forget(owner);
    Ok(())
}

pub async fn client_input(
    endpoint: &mut Endpoint<'_, { p::INPUT }>,
    slot: &MessageSlot<'_>,
    io: &mut impl MessageInput,
) -> Result<(), Error> {
    endpoint.recv::<p::NeedHello>().await?;
    fill(slot, io, Level::Initial).await?;
    endpoint.send::<p::Hello>(&()).await?;
    endpoint.recv::<p::Applied>().await?;

    let route = endpoint.offer().await?;
    match route.label() {
        183 => {
            route.recv::<p::Retry>().await?;
            endpoint.recv::<p::NeedRetryHello>().await?;
            fill(slot, io, Level::Initial).await?;
            endpoint.send::<p::RetryHello>(&()).await?;
            endpoint.recv::<p::Applied>().await?;
        }
        184 => route.recv::<p::HelloReady>().await?,
        _ => return Err(Error::Binding),
    }

    endpoint.recv::<p::NeedExtensions>().await?;
    fill(slot, io, Level::Handshake).await?;
    endpoint.send::<p::Extensions>(&()).await?;
    endpoint.recv::<p::Applied>().await?;

    let route = endpoint.offer().await?;
    match route.label() {
        189 => route.recv::<p::Resumed>().await?,
        190 => {
            route.recv::<p::Full>().await?;
            endpoint.recv::<p::NeedCertificate>().await?;
            fill(slot, io, Level::Handshake).await?;
            endpoint.send::<p::Certificate>(&()).await?;
            endpoint.recv::<p::Applied>().await?;

            endpoint.recv::<p::NeedCertificateVerify>().await?;
            fill(slot, io, Level::Handshake).await?;
            endpoint.send::<p::CertificateVerify>(&()).await?;
            endpoint.recv::<p::Applied>().await?;
        }
        _ => return Err(Error::Binding),
    }
    endpoint.recv::<p::NeedFinished>().await?;
    fill(slot, io, Level::Handshake).await?;
    endpoint.send::<p::Finished>(&()).await?;
    endpoint.recv::<p::Applied>().await?;

    endpoint.recv::<p::Complete>().await?;
    Ok(())
}
pub async fn server_input(
    endpoint: &mut Endpoint<'_, { p::INPUT }>,
    slot: &MessageSlot<'_>,
    io: &mut impl MessageInput,
) -> Result<(), Error> {
    endpoint.recv::<p::NeedHello>().await?;
    fill(slot, io, Level::Initial).await?;
    endpoint.send::<p::Hello>(&()).await?;
    endpoint.recv::<p::Applied>().await?;

    let route = endpoint.offer().await?;
    match route.label() {
        183 => {
            route.recv::<p::Retry>().await?;
            endpoint.recv::<p::NeedRetryHello>().await?;
            fill(slot, io, Level::Initial).await?;
            endpoint.send::<p::RetryHello>(&()).await?;
            endpoint.recv::<p::Applied>().await?;
        }
        184 => route.recv::<p::HelloReady>().await?,
        _ => return Err(Error::Binding),
    }

    endpoint.recv::<p::NeedFinished>().await?;
    fill(slot, io, Level::Handshake).await?;
    endpoint.send::<p::Finished>(&()).await?;
    endpoint.recv::<p::Applied>().await?;

    endpoint.recv::<p::Complete>().await?;
    Ok(())
}

struct OwnedGuard<'a, 'source, 'scope, 'cfg, 'buf, 'slot> {
    source: &'a RefCell<&'source mut super::key_source::KeySource<'scope, 'cfg, 'buf>>,
    slot: &'a MessageSlot<'slot>,
}
impl Drop for OwnedGuard<'_, '_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        self.slot.clear();
        self.source.borrow_mut().provider.fail(Failure::State);
    }
}

pub async fn client_owned<'scope, const P: usize>(
    endpoint: &mut Endpoint<'_, { p::VERIFY }>,
    source: &RefCell<&mut super::key_source::KeySource<'scope, '_, '_>>,
    slot: &MessageSlot<'_>,
    handoff: &super::key_source::Handoff<'scope, P>,
) -> Result<(), Error> {
    use crate::owned_global as p;
    {
        let source = source.borrow();
        if !matches!(source.provider.mode, Mode::Client(_)) || !source.provider.pristine() {
            return Err(Error::Binding);
        }
    }
    let owner = OwnedGuard { source, slot };
    endpoint.send::<p::ClientKeys>(&()).await?;
    endpoint.send::<p::NeedHello>(&()).await?;
    endpoint.recv::<p::Hello>().await?;
    let hello = slot.apply(|m| owner.source.borrow_mut().provider.client_hello(m, false))?;
    handoff
        .publish(&mut owner.source.borrow_mut())
        .map_err(Error::Input)?;
    endpoint.send::<p::KeysReady>(&()).await?;
    endpoint.recv::<p::KeysTaken>().await?;
    if !handoff.is_empty() {
        return Err(Error::Binding);
    }
    slot.clear();
    endpoint.send::<p::Applied>(&()).await?;

    // Negotiation is retained by this projected local continuation only.
    // The numeric material contains no resumption-selection control flag.
    let resumed = if let Some(resumed) = hello {
        endpoint.send::<p::HelloReady>(&()).await?;
        endpoint.send::<p::HelloKeys>(&()).await?;
        resumed
    } else {
        endpoint.send::<p::Retry>(&()).await?;
        endpoint.send::<p::RetryKeys>(&()).await?;
        endpoint.send::<p::NeedRetryHello>(&()).await?;
        endpoint.recv::<p::RetryHello>().await?;
        let resumed = slot
            .apply(|m| owner.source.borrow_mut().provider.client_hello(m, true))?
            .ok_or(Error::Binding)?;
        handoff
            .publish(&mut owner.source.borrow_mut())
            .map_err(Error::Input)?;
        endpoint.send::<p::KeysReady>(&()).await?;
        endpoint.recv::<p::KeysTaken>().await?;
        if !handoff.is_empty() {
            return Err(Error::Binding);
        }
        slot.clear();
        endpoint.send::<p::Applied>(&()).await?;
        resumed
    };
    endpoint.send::<p::NeedExtensions>(&()).await?;
    endpoint.recv::<p::Extensions>().await?;
    slot.apply(|m| {
        owner
            .source
            .borrow_mut()
            .provider
            .client_extensions(m, resumed)
    })?;
    handoff
        .publish(&mut owner.source.borrow_mut())
        .map_err(Error::Input)?;
    endpoint.send::<p::KeysReady>(&()).await?;
    endpoint.recv::<p::KeysTaken>().await?;
    if !handoff.is_empty() {
        return Err(Error::Binding);
    }
    slot.clear();
    endpoint.send::<p::Applied>(&()).await?;

    if resumed {
        endpoint.send::<p::Resumed>(&()).await?;
        endpoint.send::<p::ResumedKeys>(&()).await?;
    } else {
        endpoint.send::<p::Full>(&()).await?;
        endpoint.send::<p::FullKeys>(&()).await?;
        endpoint.send::<p::NeedCertificate>(&()).await?;
        endpoint.recv::<p::Certificate>().await?;
        slot.apply(|m| owner.source.borrow_mut().provider.client_certificate(m))?;
        handoff
            .publish(&mut owner.source.borrow_mut())
            .map_err(Error::Input)?;
        endpoint.send::<p::KeysReady>(&()).await?;
        endpoint.recv::<p::KeysTaken>().await?;
        if !handoff.is_empty() {
            return Err(Error::Binding);
        }
        slot.clear();
        endpoint.send::<p::Applied>(&()).await?;

        endpoint.send::<p::NeedCertificateVerify>(&()).await?;
        endpoint.recv::<p::CertificateVerify>().await?;
        slot.apply(|m| {
            owner
                .source
                .borrow_mut()
                .provider
                .client_certificate_verify(m)
        })?;
        handoff
            .publish(&mut owner.source.borrow_mut())
            .map_err(Error::Input)?;
        endpoint.send::<p::KeysReady>(&()).await?;
        endpoint.recv::<p::KeysTaken>().await?;
        if !handoff.is_empty() {
            return Err(Error::Binding);
        }
        slot.clear();
        endpoint.send::<p::Applied>(&()).await?;
    }
    endpoint.send::<p::NeedFinished>(&()).await?;
    endpoint.recv::<p::Finished>().await?;
    slot.apply(|m| owner.source.borrow_mut().provider.client_finished(m))?;
    owner
        .source
        .borrow_mut()
        .provider
        .record_verified_finished(resumed);
    handoff
        .publish(&mut owner.source.borrow_mut())
        .map_err(Error::Input)?;
    endpoint.send::<p::KeysReady>(&()).await?;
    endpoint.recv::<p::KeysTaken>().await?;
    if !handoff.is_empty() {
        return Err(Error::Binding);
    }
    slot.clear();
    endpoint.send::<p::Applied>(&()).await?;

    endpoint.send::<p::Complete>(&()).await?;
    endpoint.send::<p::CompleteKeys>(&()).await?;
    // Only this successful Hibana continuation discharges cancellation.
    // The guard contains borrowed references only; no owned buffer/key is leaked.
    core::mem::forget(owner);
    Ok(())
}

pub async fn server_owned<'scope, const P: usize>(
    endpoint: &mut Endpoint<'_, { p::VERIFY }>,
    source: &RefCell<&mut super::key_source::KeySource<'scope, '_, '_>>,
    slot: &MessageSlot<'_>,
    handoff: &super::key_source::Handoff<'scope, P>,
) -> Result<(), Error> {
    use crate::owned_global as p;
    {
        let source = source.borrow();
        if !matches!(source.provider.mode, Mode::Server(_)) || !source.provider.pristine() {
            return Err(Error::Binding);
        }
    }
    let owner = OwnedGuard { source, slot };
    endpoint.send::<p::ServerKeys>(&()).await?;
    endpoint.send::<p::NeedHello>(&()).await?;
    endpoint.recv::<p::Hello>().await?;
    let hello = slot.apply(|m| owner.source.borrow_mut().provider.server_hello(m, false))?;
    handoff
        .publish(&mut owner.source.borrow_mut())
        .map_err(Error::Input)?;
    endpoint.send::<p::KeysReady>(&()).await?;
    endpoint.recv::<p::KeysTaken>().await?;
    if !handoff.is_empty() {
        return Err(Error::Binding);
    }
    slot.clear();
    endpoint.send::<p::Applied>(&()).await?;

    // Negotiation is retained by this projected local continuation only.
    // The numeric material contains no resumption-selection control flag.
    let resumed = if let Some(resumed) = hello {
        endpoint.send::<p::HelloReady>(&()).await?;
        endpoint.send::<p::HelloKeys>(&()).await?;
        resumed
    } else {
        endpoint.send::<p::Retry>(&()).await?;
        endpoint.send::<p::RetryKeys>(&()).await?;
        endpoint.send::<p::NeedRetryHello>(&()).await?;
        endpoint.recv::<p::RetryHello>().await?;
        let resumed = slot
            .apply(|m| owner.source.borrow_mut().provider.server_hello(m, true))?
            .ok_or(Error::Binding)?;
        handoff
            .publish(&mut owner.source.borrow_mut())
            .map_err(Error::Input)?;
        endpoint.send::<p::KeysReady>(&()).await?;
        endpoint.recv::<p::KeysTaken>().await?;
        if !handoff.is_empty() {
            return Err(Error::Binding);
        }
        slot.clear();
        endpoint.send::<p::Applied>(&()).await?;
        resumed
    };
    endpoint.send::<p::NeedFinished>(&()).await?;
    endpoint.recv::<p::Finished>().await?;
    slot.apply(|m| owner.source.borrow_mut().provider.server_finished(m))?;
    owner
        .source
        .borrow_mut()
        .provider
        .record_verified_finished(resumed);
    handoff
        .publish(&mut owner.source.borrow_mut())
        .map_err(Error::Input)?;
    endpoint.send::<p::KeysReady>(&()).await?;
    endpoint.recv::<p::KeysTaken>().await?;
    if !handoff.is_empty() {
        return Err(Error::Binding);
    }
    slot.clear();
    endpoint.send::<p::Applied>(&()).await?;

    endpoint.send::<p::Complete>(&()).await?;
    endpoint.send::<p::CompleteKeys>(&()).await?;
    // Only this successful Hibana continuation discharges cancellation.
    // The guard contains borrowed references only; no owned buffer/key is leaked.
    core::mem::forget(owner);
    Ok(())
}
