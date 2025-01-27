use std::collections::{HashMap, HashSet};

use futures::channel::oneshot;

use crate::{
    io::{IoResultPayload, IoTask},
    DocumentId, StorageKey,
};

use super::JobFuture;

pub(super) mod sedimentree;

pub(crate) struct Storage<'a> {
    pub(super) io_handle: &'a crate::io::IoHandle,
}

impl<'a> Storage<'a> {
    pub(crate) fn new(io_handle: &'a crate::io::IoHandle) -> Self {
        Self { io_handle }
    }

    pub(crate) async fn load(&self, key: StorageKey) -> Option<Vec<u8>> {
        let task = IoTask::load(key);
        match self.io_task(task).await {
            IoResultPayload::Load(result) => result,
            _ => {
                tracing::error!("invalid io payload");
                None
            }
        }
    }

    pub(crate) async fn load_range(&self, prefix: StorageKey) -> HashMap<StorageKey, Vec<u8>> {
        let task = IoTask::load_range(prefix.clone());
        match self.io_task(task).await {
            IoResultPayload::LoadRange(result) => result,
            _ => {
                tracing::error!("invalid io payload");
                HashMap::new()
            }
        }
    }

    pub(crate) async fn list_one_level(&self, prefix: StorageKey) -> HashSet<StorageKey> {
        let task = IoTask::list_one_level(prefix);
        match self.io_task(task).await {
            IoResultPayload::ListOneLevel(result) => result.into_iter().collect(),
            _ => {
                tracing::error!("invalid io payload");
                HashSet::new()
            }
        }
    }

    pub(crate) async fn put(&self, key: StorageKey, value: Vec<u8>) {
        let task = IoTask::put(key, value);
        match self.io_task(task).await {
            IoResultPayload::Put => {}
            _ => {
                tracing::error!("invalid io payload");
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) async fn delete(&self, key: StorageKey) {
        let task = IoTask::delete(key);
        match self.io_task(task).await {
            IoResultPayload::Delete => {}
            _ => {
                tracing::error!("invalid io payload");
            }
        }
    }

    pub(crate) fn doc_storage(&self, doc_id: DocumentId) -> sedimentree::DocStorage {
        sedimentree::DocStorage::new(self.io_handle.clone(), doc_id)
    }

    async fn io_task(&self, task: IoTask) -> IoResultPayload {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.io_handle.new_task(task, reply_tx);
        let result = JobFuture(reply_rx).await;
        result.take_payload()
    }
}
