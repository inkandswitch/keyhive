use std::collections::{HashMap, HashSet};

use crate::{
    messages::{Notification, UploadItem},
    parse,
    sedimentree::{LooseCommit, Stratum},
    snapshots::Snapshot,
    Commit, CommitBundle, CommitCategory, CommitOrBundle, DocumentId, PeerId,
};

#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Serialize, Hash)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct SubscriptionId([u8; 16]);

impl SubscriptionId {
    pub(crate) fn random<R: rand::Rng>(rng: &mut R) -> Self {
        let mut id = [0; 16];
        rng.fill_bytes(&mut id);
        Self(id)
    }

    pub(crate) fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        let (input, id) = parse::arr::<16>(input)?;
        Ok((input, Self(id)))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

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
struct Subscription {
    offset: usize,
    peer: PeerId,
    docs: HashSet<DocumentId>,
}

pub(crate) struct Subscriptions(Vec<Subscription>);

impl Subscriptions {
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn create(&mut self, peer: PeerId, starting_from: &Snapshot) {
        let mut docs = starting_from.our_docs().clone();
        docs.insert(starting_from.root_doc().clone());
        tracing::trace!(?peer, start_docs=?docs, "Creating subscription");
        self.0.push(Subscription {
            offset: starting_from.local_log_offset(),
            peer,
            docs,
        })
    }

    pub(crate) fn new_events(&mut self, log: &Log) -> HashMap<PeerId, Vec<Notification>> {
        let mut result = HashMap::new();
        for sub in &mut self.0 {
            let events: &mut Vec<Notification> = result.entry(sub.peer.clone()).or_default();
            for event in &log.0[sub.offset..] {
                if sub.docs.contains(&event.doc)
                    && event.from_peer != sub.peer
                    && event.category == CommitCategory::Content
                {
                    events.push(Notification {
                        from_peer: event.from_peer.clone(),
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
