use std::future::Future;

use futures::channel::oneshot;

use crate::{
    network::messages::{Notification, UploadItem},
    snapshots::Snapshot,
    CommitCategory, DocumentId, PeerId,
};

#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Serialize, Hash)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct SubscriptionId([u8; 16]);

#[derive(Debug, Clone)]
pub(crate) struct DocEvent {
    pub(crate) doc: DocumentId,
    pub(crate) source: Source,
    pub(crate) contents: UploadItem,
    pub(crate) category: CommitCategory,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Source {
    Remote(PeerId),
    Local,
}

impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::Remote(peer) => write!(f, "Remote({})", peer),
            Source::Local => write!(f, "Local"),
        }
    }
}

pub(crate) struct Log {
    events: Vec<DocEvent>,
    awaiting_new_events: Vec<oneshot::Sender<()>>,
}

impl Log {
    pub(crate) fn new() -> Self {
        Self {
            events: Vec::new(),
            awaiting_new_events: Vec::new(),
        }
    }

    pub(crate) fn offset(&self) -> usize {
        self.events.len()
    }

    fn push_evt(&mut self, evt: DocEvent) {
        self.events.push(evt);
        for tx in self.awaiting_new_events.drain(..) {
            let _ = tx.send(());
        }
    }

    pub(crate) fn remote_notification(&mut self, from_peer: PeerId, notification: &Notification) {
        self.push_evt(DocEvent {
            doc: notification.doc,
            source: Source::Remote(from_peer),
            contents: notification.data.clone(),
            category: CommitCategory::Content,
        })
    }

    pub(crate) fn new_remote_commit(
        &mut self,
        doc: DocumentId,
        from_peer: PeerId,
        item: UploadItem,
        category: CommitCategory,
    ) {
        self.push_evt(DocEvent {
            doc,
            source: Source::Remote(from_peer),
            contents: item,
            category,
        })
    }

    pub(crate) fn new_local_commit(
        &mut self,
        doc: DocumentId,
        item: UploadItem,
        category: CommitCategory,
    ) {
        self.push_evt(DocEvent {
            doc,
            source: Source::Local,
            contents: item,
            category,
        })
    }

    pub(crate) fn entries_for(
        &self,
        snapshot: &Snapshot,
        from_offset: Option<u64>,
    ) -> Vec<DocEvent> {
        let mut result = Vec::new();
        for event in &self.events[from_offset
            .map(|o| o as usize)
            .unwrap_or(snapshot.local_log_offset())..]
        {
            if snapshot.our_doc_ids().contains(&event.doc)
                && event.category == CommitCategory::Content
            {
                result.push(event.clone())
            }
        }
        result
    }

    pub(crate) fn wait_for_new_events(&mut self) -> impl Future<Output = ()> + 'static {
        let (tx, rx) = oneshot::channel();
        self.awaiting_new_events.push(tx);
        async move {
            rx.await.ok();
        }
    }

    pub(crate) fn has_item(&self, item: &UploadItem) -> bool {
        self.events.iter().any(|event| &event.contents == item)
    }
}
