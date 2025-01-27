#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutboundRequestId(u64);

static LAST_OUTBOUND_REQUEST_ID: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

impl OutboundRequestId {
    pub fn new() -> Self {
        Self(LAST_OUTBOUND_REQUEST_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }

    pub fn serialize(&self) -> u64 {
        self.0
    }

    pub fn from_serialized(serialized: u64) -> Self {
        Self(serialized)
    }
}
