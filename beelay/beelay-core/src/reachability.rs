use std::collections::HashMap;

use futures::StreamExt;

use crate::{
    effects::TaskEffects,
    parse,
    sedimentree::{self, MinimalTreeHash},
    CommitCategory, CommitHash, CommitOrBundle, DocumentId, StorageKey,
};

#[derive(Default, Debug)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) struct ReachabilityIndex {
    reachable: Vec<DocumentId>,
}

impl ReachabilityIndex {
    pub(crate) fn new() -> ReachabilityIndex {
        ReachabilityIndex {
            reachable: Vec::new(),
        }
    }

    pub(crate) async fn load<R: rand::Rng>(effects: TaskEffects<R>, doc_id: &DocumentId) -> Self {
        let tree = sedimentree::storage::load(
            effects.clone(),
            StorageKey::sedimentree_root(doc_id, CommitCategory::Index),
        )
        .await
        .unwrap_or_default();
        let items = sedimentree::storage::data(effects.clone(), tree)
            .collect::<Vec<_>>()
            .await;
        let altogether = items
            .into_iter()
            .flat_map(|i| match i {
                CommitOrBundle::Commit(c) => c.contents().to_vec(),
                CommitOrBundle::Bundle(b) => b.bundled_commits().to_vec(),
            })
            .collect::<Vec<_>>();
        let mut result = ReachabilityIndex::new();
        let mut input = parse::Input::new(&altogether);
        while !input.is_empty() {
            let (new_input, entry) = ReachabilityIndexEntry::parse(input).unwrap();
            input = new_input;
            result += entry;
        }
        result
    }
}

impl IntoIterator for ReachabilityIndex {
    type Item = DocumentId;
    type IntoIter = std::vec::IntoIter<DocumentId>;

    fn into_iter(self) -> Self::IntoIter {
        self.reachable.into_iter()
    }
}

impl<'a> IntoIterator for &'a ReachabilityIndex {
    type Item = &'a DocumentId;
    type IntoIter = std::slice::Iter<'a, DocumentId>;

    fn into_iter(self) -> Self::IntoIter {
        self.reachable.iter()
    }
}

impl std::ops::AddAssign<ReachabilityIndex> for ReachabilityIndex {
    fn add_assign(&mut self, other: ReachabilityIndex) {
        self.reachable.extend(other.reachable);
    }
}

impl std::ops::AddAssign<ReachabilityIndexEntry> for ReachabilityIndex {
    fn add_assign(&mut self, other: ReachabilityIndexEntry) {
        self.reachable.push(other.0);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ReachabilityIndexEntry(crate::DocumentId);

#[cfg(test)]
impl<'a> arbitrary::Arbitrary<'a> for ReachabilityIndexEntry {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let doc_id = DocumentId::arbitrary(u)?;
        Ok(ReachabilityIndexEntry::new(doc_id))
    }
}

impl ReachabilityIndexEntry {
    pub(crate) fn new(document_id: DocumentId) -> Self {
        ReachabilityIndexEntry(document_id)
    }

    pub(crate) fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        let (input, doc_id) = DocumentId::parse(input)?;
        Ok((input, ReachabilityIndexEntry::new(doc_id)))
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    pub(crate) fn hash(&self) -> CommitHash {
        let data = self.encode();
        <[u8; 32]>::from(blake3::hash(&data)).into()
    }
}

pub(crate) async fn load_reachable_docs<R: rand::Rng>(
    effects: TaskEffects<R>,
    root: DocumentId,
) -> HashMap<DocumentId, MinimalTreeHash> {
    let mut to_process = vec![root];
    let mut result = HashMap::new();

    while let Some(doc) = to_process.pop() {
        let index = ReachabilityIndex::load(effects.clone(), &doc).await;
        for doc in index.into_iter() {
            to_process.push(doc);
        }
        if let Some(tree) = sedimentree::storage::load(
            effects.clone(),
            StorageKey::sedimentree_root(&doc, CommitCategory::Content),
        )
        .await
        {
            result.insert(doc, tree.minimal_hash());
        }
    }

    result
}
