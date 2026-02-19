//! Helpers for working with [`Document`] access capabilties.

use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::signer::async_signer::AsyncSigner,
    listener::membership::MembershipListener,
    principal::document::Document,
};
use derive_where::derive_where;
use dupe::Dupe;
use future_form::FutureForm;
use futures::lock::Mutex;
use std::sync::Arc;

/// [`Ability`] is a helper type for working with [`Document`] access capabilties.
#[derive_where(Debug; T)]
pub struct Ability<K: FutureForm + ?Sized, S: AsyncSigner<K>, T: ContentRef, L: MembershipListener<K, S, T>> {
    pub(crate) doc: Arc<Mutex<Document<K, S, T, L>>>,
    pub(crate) can: Access,
}

impl<K: FutureForm + ?Sized, S: AsyncSigner<K>, T: ContentRef, L: MembershipListener<K, S, T>> Ability<K, S, T, L> {
    /// Getter for the referenced [`Document`].
    pub fn doc(&self) -> Arc<Mutex<Document<K, S, T, L>>> {
        self.doc.dupe()
    }

    /// Access level.
    pub fn can(&self) -> Access {
        self.can
    }
}
