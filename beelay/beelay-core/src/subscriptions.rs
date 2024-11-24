use std::collections::{HashMap, HashSet};

use crate::{
    messages::{Notification, UploadItem},
    snapshots::Snapshot,
    CommitCategory, DocumentId, PeerId,
};

#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Serialize, Hash)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct SubscriptionId([u8; 16]);

pub(crate) struct DocEvent {
    doc: DocumentId,
    from_peer: PeerId,
    contents: UploadItem,
    category: CommitCategory,
}

pub(crate) struct Log(Vec<DocEvent>);

impl Log {
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn offset(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn remote_notification(&mut self, notification: &Notification) {
        self.0.push(DocEvent {
            doc: notification.doc,
            from_peer: notification.from_peer.clone(),
            contents: notification.data.clone(),
            category: CommitCategory::Content,
        })
    }

    pub(crate) fn new_commit(
        &mut self,
        doc: DocumentId,
        from_peer: PeerId,
        item: UploadItem,
        category: CommitCategory,
    ) {
        self.0.push(DocEvent {
            doc,
            from_peer,
            contents: item,
            category,
        })
    }
}

#[derive(Debug)]
pub(crate) struct Subscription {
    offset: usize,
    peer: PeerId,
    docs: HashSet<DocumentId>,
}

impl Subscription {
    pub(crate) fn new(for_peer: &PeerId, starting_from: &Snapshot) -> Self {
        let mut docs = starting_from.our_docs().clone();
        docs.insert(starting_from.root_doc().clone());
        tracing::trace!(?for_peer, start_docs=?docs, "Creating subscription");
        Subscription {
            offset: starting_from.local_log_offset(),
            peer: for_peer.clone(),
            docs,
        }
    }
}

pub(crate) struct Subscriptions {
    our_peer_id: PeerId,
    subscriptions: Vec<Subscription>,
}

impl Subscriptions {
    pub(crate) fn new(our_peer_id: PeerId) -> Self {
        Self {
            our_peer_id,
            subscriptions: Vec::new(),
        }
    }

    pub(crate) fn add(&mut self, sub: Subscription) {
        self.subscriptions.push(sub)
    }

    pub(crate) fn new_events(&mut self, log: &Log) -> HashMap<PeerId, Vec<Notification>> {
        let mut result = HashMap::new();
        for sub in &mut self.subscriptions {
            let events: &mut Vec<Notification> = result.entry(sub.peer.clone()).or_default();
            for event in &log.0[sub.offset..] {
                if sub.docs.contains(&event.doc)
                    && event.from_peer != sub.peer
                    && event.category == CommitCategory::Content
                {
                    events.push(Notification {
                        from_peer: self.our_peer_id.clone(),
                        doc: event.doc.clone(),
                        data: event.contents.clone(),
                    })
                }
            }
            sub.offset = log.offset();
        }
        result
    }
}
