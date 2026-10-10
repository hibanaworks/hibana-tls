//! Execute INPUT: acquire the requested message and settle its borrow.
use super::Error;
use crate::handshake::{MessageInput, MessageSlot, global as p};
use crate::quic::Level;
use hibana::Endpoint;
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
