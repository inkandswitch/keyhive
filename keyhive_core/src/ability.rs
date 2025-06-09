//! Helpers for working with [`Document`] access capabilties.

use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::signer::async_signer::AsyncSigner,
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::document::Document,
    store::secret_key::traits::ShareSecretStore,
};
use derive_where::derive_where;
use std::{cell::RefCell, rc::Rc};

/// [`Ability`] is a helper type for working with [`Document`] access capabilties.
#[derive_where(Debug; T)]
pub struct Ability<
    'a,
    S: AsyncSigner,
    K: ShareSecretStore,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, K, T> = NoListener,
> {
    pub(crate) doc: &'a Rc<RefCell<Document<S, K, T, L>>>,
    pub(crate) can: Access,
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>>
    Ability<'_, S, K, T, L>
{
    /// Getter for the referenced [`Document`].
    pub fn doc(&self) -> &Rc<RefCell<Document<S, K, T, L>>> {
        self.doc
    }

    /// Access level.
    pub fn can(&self) -> Access {
        self.can
    }
}
