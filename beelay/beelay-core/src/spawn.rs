use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct SpawnId(u64);

static LAST_SPAWN_ID: AtomicU64 = AtomicU64::new(0);

impl SpawnId {
    pub(crate) fn new() -> SpawnId {
        SpawnId(LAST_SPAWN_ID.fetch_add(1, Ordering::Relaxed))
    }
}
