//! Helpers for working with [`Document`] access capabilties.

use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::verifiable::Verifiable,
    listener::no_listener::NoListener,
    principal::document::Document,
};
use derive_where::derive_where;
use dupe::Dupe;
use futures::lock::Mutex;
use std::sync::Arc;

/// [`Ability`] is a helper type for working with [`Document`] access capabilties.
#[derive_where(Debug; T)]
pub struct Ability<S: Verifiable, T: ContentRef = [u8; 32], L = NoListener> {
    pub(crate) doc: Arc<Mutex<Document<S, T, L>>>,
    pub(crate) can: Access,
}

impl<S: Verifiable, T: ContentRef, L> Ability<S, T, L> {
    /// Getter for the referenced [`Document`].
    pub fn doc(&self) -> Arc<Mutex<Document<S, T, L>>> {
        self.doc.dupe()
    }

    /// Access level.
    pub fn can(&self) -> Access {
        self.can
    }
}
