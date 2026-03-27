//! Helpers for working with [`Document`] access capabilties.

use crate::{
    access::Access,
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::document::Document,
};
use derive_where::derive_where;
use dupe::Dupe;
use future_form::FutureForm;
use futures::lock::Mutex;
use keyhive_crypto::{content::reference::ContentRef, signer::async_signer::AsyncSigner};
use std::sync::Arc;

/// [`Ability`] is a helper type for working with [`Document`] access capabilties.
#[derive_where(Debug; T)]
pub struct Ability<
    F: FutureForm,
    S: AsyncSigner<F>,
    T: ContentRef = [u8; 32],
    L: MembershipListener<F, S, T> = NoListener,
> {
    pub(crate) doc: Arc<Mutex<Document<F, S, T, L>>>,
    pub(crate) can: Access,
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    Ability<F, S, T, L>
{
    /// Getter for the referenced [`Document`].
    pub fn doc(&self) -> Arc<Mutex<Document<F, S, T, L>>> {
        self.doc.dupe()
    }

    /// Access level.
    pub fn can(&self) -> Access {
        self.can
    }
}
