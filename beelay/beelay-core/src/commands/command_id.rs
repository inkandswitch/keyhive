use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommandId(u64);

static LAST_COMMAND_ID: AtomicU64 = AtomicU64::new(0);

impl CommandId {
    pub(crate) fn new() -> Self {
        Self(LAST_COMMAND_ID.fetch_add(1, Ordering::Relaxed))
    }

    pub fn serialize(&self) -> u64 {
        self.0
    }

    pub fn from_serialized(serialized: u64) -> Self {
        Self(serialized)
    }
}

impl std::str::FromStr for CommandId {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}
