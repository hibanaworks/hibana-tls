//! Shared QUIC/TLS profile wire values and variable-length integers.
//! No packet authentication or protocol progression occurs here.
pub const MAX_VARINT: u64 = (1u64 << 62) - 1;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceLimit {
    Bytes,
    Packets,
    Frames,
    AckRanges,
}

/// Wire syntax errors only; the caller selects discard versus transport error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Truncated,
    BufferTooShort,
    VarIntTooLarge,
    InvalidVarIntWidth,
    InvalidPacketNumber,
    InvalidConnectionIdLength,
    InvalidFixedBit,
    InvalidLength,
    InvalidVersionNegotiation,
    EmptyToken,
    ReservedBits,
    UnknownFrameType(u64),
    NonMinimalFrameType,
    InvalidAckRange,
    InvalidOffset,
    InvalidStreamCount,
    InvalidRetirePriorTo,
    FrameNotAllowed {
        frame_type: u64,
        level: EncryptionLevel,
    },
    EmptyPayload,
    LimitExceeded(ResourceLimit),
}

/// Returns the integer and number of input bytes consumed. Non-minimal encodings
/// are deliberately accepted (RFC 9000 §16).
pub fn decode_varint(input: &[u8]) -> Result<(u64, usize), Error> {
    let first = *input.first().ok_or(Error::Truncated)?;
    let width = 1usize << (first >> 6);
    let bytes = input.get(..width).ok_or(Error::Truncated)?;
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((value, width))
}

pub fn varint_len(value: u64) -> Result<usize, Error> {
    match value {
        0..=63 => Ok(1),
        64..=16383 => Ok(2),
        16384..=1073741823 => Ok(4),
        1073741824..=MAX_VARINT => Ok(8),
        _ => Err(Error::VarIntTooLarge),
    }
}

/// Encodes using the shortest legal width. Output is unchanged on error.
pub fn encode_varint(value: u64, output: &mut [u8]) -> Result<usize, Error> {
    encode_varint_with_len(value, varint_len(value)?, output)
}

/// Explicit-width encoding is useful for length fields reserved before sealing.
/// Non-minimal widths are legal except when encoding a frame type.
pub fn encode_varint_with_len(value: u64, width: usize, output: &mut [u8]) -> Result<usize, Error> {
    let tag = match width {
        1 => 0,
        2 => 0x40,
        4 => 0x80,
        8 => 0xc0,
        _ => return Err(Error::InvalidVarIntWidth),
    };
    if varint_len(value)? > width {
        return Err(Error::InvalidVarIntWidth);
    }
    let out = output.get_mut(..width).ok_or(Error::BufferTooShort)?;
    let bytes = value.to_be_bytes();
    out.copy_from_slice(&bytes[8 - width..]);
    out[0] |= tag;
    Ok(width)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptionLevel {
    Initial,
    Handshake,
    ZeroRtt,
    OneRtt,
}

