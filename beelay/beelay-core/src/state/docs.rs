use std::{borrow::Cow, cell::RefCell, collections::HashMap, rc::Rc};

use keyhive_core::{cgka::operation::CgkaOperation, crypto::signed::Signed};

use crate::{
    doc_state::{DocState, NewChange},
    doc_status::DocStatus,
    Commit, CommitBundle, DocumentId, PeerId,
};

pub(crate) struct Docs<'a, R: rand::Rng + rand::CryptoRng> {
    pub(super) state: Cow<'a, Rc<RefCell<super::State<R>>>>,
}

impl<'a, R: rand::Rng + rand::CryptoRng> Docs<'a, R> {
    pub(crate) fn new(state: Cow<'a, Rc<RefCell<super::State<R>>>>) -> Self {
        Self { state }
    }

    pub(crate) fn add_doc(
        &self,
        doc_id: DocumentId,
        tree: crate::sedimentree::Sedimentree,
        _cgka_op: Option<Signed<CgkaOperation>>,
    ) {
        self.state
            .borrow_mut()
            .docs
            .insert(doc_id, DocState::new(tree));
        self.state.borrow_mut().docs_with_changes.insert(doc_id);
    }

    pub(crate) fn mark_changed(&self, doc_id: &DocumentId) {
        self.state.borrow_mut().docs_with_changes.insert(*doc_id);
    }

    pub(crate) fn sedimentree(&self, doc: &DocumentId) -> Option<crate::sedimentree::Sedimentree> {
        self.state
            .borrow()
            .docs
            .get(doc)
            .map(|summary| summary.tree().clone())
    }

    pub(crate) fn doc_status(&self, doc_id: DocumentId) -> crate::doc_status::DocStatus {
        if let Some(summary) = self.state.borrow().docs.get(&doc_id) {
            summary.status()
        } else {
            DocStatus { local_heads: None }
        }
    }

    pub(crate) fn apply_doc_update(&self, mut update: DocUpdateBuilder) {
        let doc_id = *update.doc_id();
        let mut state = self.state.borrow_mut();

        if !update.is_empty() {
            state.docs_with_changes.insert(doc_id);
        }

        let commits = update.take_commits();
        if !commits.is_empty() {
            if let Some(doc) = state.docs.get_mut(&doc_id) {
                doc.add_commits(commits.into_iter(), update.sender);
            } else {
                let mut doc = DocState::new(crate::sedimentree::Sedimentree::default());
                doc.add_commits(commits.into_iter(), update.sender);
                state.docs.insert(doc_id, doc);
            }
        }

        let bundles = update.take_bundles();
        if !bundles.is_empty() {
            if let Some(doc) = state.docs.get_mut(&doc_id) {
                doc.add_bundles(bundles.into_iter(), update.sender);
            } else if !bundles.is_empty() {
                let mut doc = DocState::new(crate::sedimentree::Sedimentree::default());
                doc.add_bundles(bundles.into_iter(), update.sender);
                state.docs.insert(doc_id, doc);
            }
        }
    }

    pub(crate) fn take_doc_changes(&self) -> HashMap<DocumentId, Vec<NewChange>> {
        let mut state = self.state.borrow_mut();

        let mut changes = HashMap::new();
        for doc_id in std::mem::take(&mut state.docs_with_changes) {
            let Some(doc) = state.docs.get_mut(&doc_id) else {
                tracing::warn!("doc marked as changed but not found");
                continue;
            };
            changes.insert(doc_id, doc.take_changes());
        }
        changes
    }
}

/// Builder for updating document components
pub(crate) struct DocUpdateBuilder {
    doc_id: DocumentId,
    commits: Vec<(Commit, Option<Signed<CgkaOperation>>)>,
    bundles: Vec<(CommitBundle, Option<Signed<CgkaOperation>>)>,
    sender: Option<PeerId>,
}

impl DocUpdateBuilder {
    /// Create a new document update builder
    pub(crate) fn new(doc_id: DocumentId, sender: Option<PeerId>) -> Self {
        Self {
            doc_id,
            commits: Vec::new(),
            bundles: Vec::new(),
            sender,
        }
    }

    /// Add a commit to the update
    pub(crate) fn add_commit(
        &mut self,
        commit: Commit,
        cgka_op: Option<Signed<CgkaOperation>>,
    ) -> &mut Self {
        self.commits.push((commit, cgka_op));
        self
    }

    /// Add multiple commits to the update
    pub(crate) fn add_commits<I>(&mut self, commits: I) -> &mut Self
    where
        I: IntoIterator<Item = (Commit, Option<Signed<CgkaOperation>>)>,
    {
        self.commits.extend(commits);
        self
    }

    /// Add a bundle to the update
    pub(crate) fn add_bundle(
        &mut self,
        bundle: CommitBundle,
        cgka_op: Option<Signed<CgkaOperation>>,
    ) -> &mut Self {
        self.bundles.push((bundle, cgka_op));
        self
    }

    /// Add multiple bundles to the update
    pub(crate) fn add_bundles<I>(&mut self, bundles: I) -> &mut Self
    where
        I: IntoIterator<Item = (CommitBundle, Option<Signed<CgkaOperation>>)>,
    {
        self.bundles.extend(bundles);
        self
    }

    /// Get the document ID for this update
    pub(crate) fn doc_id(&self) -> &DocumentId {
        &self.doc_id
    }

    /// Check if this update is empty (contains no changes)
    pub(crate) fn is_empty(&self) -> bool {
        self.commits.is_empty() && self.bundles.is_empty()
    }

    /// Take the commits from this builder
    pub(crate) fn take_commits(&mut self) -> Vec<(Commit, Option<Signed<CgkaOperation>>)> {
        std::mem::take(&mut self.commits)
    }

    /// Take the bundles from this builder
    pub(crate) fn take_bundles(&mut self) -> Vec<(CommitBundle, Option<Signed<CgkaOperation>>)> {
        std::mem::take(&mut self.bundles)
    }
}
