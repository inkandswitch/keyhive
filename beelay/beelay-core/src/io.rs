use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::StorageKey;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IoTaskId(u64);

static LAST_IO_TASK_ID: AtomicU64 = AtomicU64::new(0);

impl IoTaskId {
    pub(crate) fn new() -> IoTaskId {
        IoTaskId(LAST_IO_TASK_ID.fetch_add(1, Ordering::Relaxed))
    }

    pub fn serialize(&self) -> String {
        self.0.to_string()
    }
}

impl std::str::FromStr for IoTaskId {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}

#[derive(Debug)]
pub struct IoTask {
    id: IoTaskId,
    action: IoAction,
}

impl IoTask {
    pub(crate) fn load(id: IoTaskId, key: StorageKey) -> IoTask {
        IoTask {
            id,
            action: IoAction::Load { key },
        }
    }

    pub(crate) fn load_range(id: IoTaskId, prefix: StorageKey) -> IoTask {
        IoTask {
            id,
            action: IoAction::LoadRange { prefix },
        }
    }

    pub(crate) fn put(id: IoTaskId, key: StorageKey, data: Vec<u8>) -> IoTask {
        IoTask {
            id,
            action: IoAction::Put { key, data },
        }
    }

    pub(crate) fn delete(id: IoTaskId, key: StorageKey) -> IoTask {
        IoTask {
            id,
            action: IoAction::Delete { key },
        }
    }

    pub fn action(&self) -> &IoAction {
        &self.action
    }

    pub fn take_action(self) -> IoAction {
        self.action
    }

    pub fn id(&self) -> IoTaskId {
        self.id
    }
}

#[derive(Debug)]
pub enum IoAction {
    Load { key: StorageKey },
    LoadRange { prefix: StorageKey },
    Put { key: StorageKey, data: Vec<u8> },
    Delete { key: StorageKey },
}

pub struct IoResult {
    id: IoTaskId,
    payload: IoResultPayload,
}

impl std::fmt::Debug for IoResult {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let payload_desc = match &self.payload {
            IoResultPayload::Load(payload) => format!(
                "Load({})",
                payload
                    .as_ref()
                    .map(|b| format!("{} bytes", b.len()))
                    .unwrap_or_else(|| "None".to_string())
            ),
            IoResultPayload::LoadRange(payload) => format!("LoadRange({} keys)", payload.len()),
            IoResultPayload::Put => "Put".to_string(),
            IoResultPayload::Delete => "Delete".to_string(),
        };
        f.debug_struct("IoResult")
            .field("id", &self.id)
            .field("payload", &payload_desc)
            .finish()
    }
}

impl IoResult {
    pub fn load(id: IoTaskId, payload: Option<Vec<u8>>) -> IoResult {
        IoResult {
            id,
            payload: IoResultPayload::Load(payload),
        }
    }

    pub fn load_range(id: IoTaskId, payload: HashMap<StorageKey, Vec<u8>>) -> IoResult {
        IoResult {
            id,
            payload: IoResultPayload::LoadRange(payload),
        }
    }

    pub fn put(id: IoTaskId) -> IoResult {
        IoResult {
            id,
            payload: IoResultPayload::Put,
        }
    }

    pub fn delete(id: IoTaskId) -> IoResult {
        IoResult {
            id,
            payload: IoResultPayload::Delete,
        }
    }

    pub(crate) fn take_payload(self) -> IoResultPayload {
        self.payload
    }

    pub fn id(&self) -> IoTaskId {
        self.id
    }
}

pub(crate) enum IoResultPayload {
    Load(Option<Vec<u8>>),
    LoadRange(HashMap<StorageKey, Vec<u8>>),
    Put,
    Delete,
}
