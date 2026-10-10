//! Execute VERIFY: validate messages and transfer actual keys/Finished.
use super::Error;
use crate::handshake::{BoundedTls, Failure, MessageSlot, Mode, global as p};
use core::cell::RefCell;
use hibana::Endpoint;
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

struct OwnedGuard<'a, 'source, 'scope, 'cfg, 'buf, 'slot> {
    source: &'a RefCell<&'source mut crate::handshake::keys::KeySource<'scope, 'cfg, 'buf>>,
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
    source: &RefCell<&mut crate::handshake::keys::KeySource<'scope, '_, '_>>,
    slot: &MessageSlot<'_>,
    handoff: &crate::handshake::keys::Handoff<'scope, P>,
) -> Result<(), Error> {
    use crate::handshake::global::owned as p;
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
    source: &RefCell<&mut crate::handshake::keys::KeySource<'scope, '_, '_>>,
    slot: &MessageSlot<'_>,
    handoff: &crate::handshake::keys::Handoff<'scope, P>,
) -> Result<(), Error> {
    use crate::handshake::global::owned as p;
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
