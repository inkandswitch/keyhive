use std::cmp::Ordering;

use crate::{sync::SessionId, UnixTimestampMillis};

pub(super) struct ExpiryKey {
    pub(super) expires_at: UnixTimestampMillis,
    pub(super) session_id: SessionId,
}

impl Ord for ExpiryKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // Invert the order because we want the oldest item to be first in the heap
        other.expires_at.cmp(&self.expires_at)
    }
}

impl PartialOrd for ExpiryKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for ExpiryKey {}

impl PartialEq for ExpiryKey {
    fn eq(&self, other: &Self) -> bool {
        self.expires_at == other.expires_at
    }
}
