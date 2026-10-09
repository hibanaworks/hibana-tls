//! Bounded immutable stream-credit metadata shared by TLS and QUIC.
const MAX_OFFSET: u64 = (1 << 62) - 1;
const MAX_STREAMS: u64 = 1 << 60;
/// Transport-parameter values relative to the endpoint advertising them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_data: u64,
    pub max_streams_bidi: u64,
    pub max_streams_uni: u64,
    pub stream_data_bidi_local: u64,
    pub stream_data_bidi_remote: u64,
    pub stream_data_uni: u64,
}
impl Limits {
    pub const ZERO: Self = Self {
        max_data: 0,
        max_streams_bidi: 0,
        max_streams_uni: 0,
        stream_data_bidi_local: 0,
        stream_data_bidi_remote: 0,
        stream_data_uni: 0,
    };
    pub fn valid(self) -> bool {
        self.max_data <= MAX_OFFSET
            && self.max_streams_bidi <= MAX_STREAMS
            && self.max_streams_uni <= MAX_STREAMS
            && self.stream_data_bidi_local <= MAX_OFFSET
            && self.stream_data_bidi_remote <= MAX_OFFSET
            && self.stream_data_uni <= MAX_OFFSET
    }
}

